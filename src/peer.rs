use futures_util::{Stream, StreamExt};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
    endpoint::{Connection, presets},
};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

/// Direct-only protocol version used for persistent paired-device text sessions.
pub const PEER_ALPN: &[u8] = b"org.slouching.text/2";
const FRAME_MAGIC: &[u8; 4] = b"SLCH";
const FRAME_VERSION: u16 = 2;
const FRAME_DATA: u8 = 1;
const FRAME_ACK: u8 = 2;
const FRAME_CLOSE: u8 = 3;
const FRAME_CLOSE_ACK: u8 = 4;
const MAX_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_PENDING_MESSAGES: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const ACCEPT_STREAM_TIMEOUT: Duration = Duration::from_secs(8);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(8);

pub struct DirectPeerListener {
    endpoint: Endpoint,
    expected_peer: EndpointId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAcceptError {
    Unauthorized(EndpointId),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCommand {
    Send {
        request_id: u64,
        text: String,
    },
    /// Send only after the application has stored this message in its in-memory transcript.
    AcceptInbound {
        sequence: u64,
    },
    Disconnect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    Connected {
        peer_id: EndpointId,
    },
    Received {
        sequence: u64,
        text: String,
    },
    Acknowledged {
        request_id: u64,
        text: String,
    },
    Rejected {
        request_id: u64,
        reason: String,
    },
    DeliveryUnknown {
        request_id: u64,
        text: String,
    },
    #[allow(dead_code)]
    Unauthorized {
        peer_id: EndpointId,
    },
    Disconnected {
        reason: String,
    },
}

struct PendingSend {
    request_id: u64,
    text: String,
}

pub struct DirectPeerSession {
    endpoint: Endpoint,
    connection: Connection,
    send: iroh::endpoint::SendStream,
    receive: iroh::endpoint::RecvStream,
    peer_id: EndpointId,
}

#[derive(Debug, PartialEq, Eq)]
enum Frame {
    Data { sequence: u64, text: String },
    Ack { sequence: u64 },
    Close,
    CloseAck,
}

impl DirectPeerListener {
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn direct_addresses(&self) -> Vec<SocketAddr> {
        self.endpoint.addr().ip_addrs().copied().collect()
    }

    pub async fn accept_session(&self) -> Result<DirectPeerSession, PeerAcceptError> {
        let connecting = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| PeerAcceptError::Failed("peer endpoint is closed".to_owned()))?;
        let connection = connecting
            .await
            .map_err(|error| PeerAcceptError::Failed(format!("QUIC accept failed: {error}")))?;
        let peer_id = connection.remote_id();
        if peer_id != self.expected_peer {
            connection.close(1_u32.into(), b"unexpected device identity");
            return Err(PeerAcceptError::Unauthorized(peer_id));
        }
        let (send, receive) = tokio::time::timeout(ACCEPT_STREAM_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| {
                PeerAcceptError::Failed("timed out waiting for the session stream".to_owned())
            })?
            .map_err(|error| {
                PeerAcceptError::Failed(format!("could not accept session stream: {error}"))
            })?;
        Ok(DirectPeerSession {
            endpoint: self.endpoint.clone(),
            connection,
            send,
            receive,
            peer_id,
        })
    }

    /// Temporary compatibility helper for the still-present diagnostic CLI.
    #[allow(dead_code)]
    pub async fn receive_once(self) -> Result<String, String> {
        let session = self
            .accept_session()
            .await
            .map_err(|error| format!("could not accept pinned peer: {error:?}"))?;
        let (commands, receiver) = mpsc::channel(4);
        let mut events = Box::pin(session.run(receiver));
        let mut received = None;
        while let Some(event) = tokio::time::timeout(Duration::from_secs(30), events.next())
            .await
            .map_err(|_| "timed out waiting for the one-shot message".to_owned())?
        {
            match event {
                PeerEvent::Received { sequence, text } => {
                    received = Some(text);
                    commands
                        .send(PeerCommand::AcceptInbound { sequence })
                        .await
                        .map_err(|error| {
                            format!("could not acknowledge received message: {error}")
                        })?;
                }
                PeerEvent::Disconnected { .. } => {
                    return received
                        .ok_or_else(|| "peer disconnected before sending text".to_owned());
                }
                PeerEvent::Unauthorized { .. } => {
                    return Err("incoming peer did not match the pinned identity".to_owned());
                }
                PeerEvent::Connected { .. }
                | PeerEvent::Acknowledged { .. }
                | PeerEvent::Rejected { .. }
                | PeerEvent::DeliveryUnknown { .. } => {}
            }
        }
        received.ok_or_else(|| "peer session ended before receiving text".to_owned())
    }

    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.endpoint.is_closed()
    }
}

impl DirectPeerSession {
    pub fn run(
        mut self,
        mut commands: mpsc::Receiver<PeerCommand>,
    ) -> impl Stream<Item = PeerEvent> + Send + 'static {
        async_stream::stream! {
            let mut pending_sends = HashMap::<u64, PendingSend>::new();
            let mut pending_inbound = std::collections::HashSet::<u64>::new();
            let mut next_out_sequence = 1_u64;
            let mut next_in_sequence = 1_u64;
            let mut closing = false;
            let mut close_deadline = Box::pin(tokio::time::sleep(CLOSE_TIMEOUT));
            yield PeerEvent::Connected { peer_id: self.peer_id };

            let disconnect_reason = 'session: loop {
                tokio::select! {
                    frame = read_frame(&mut self.receive) => {
                        match frame {
                            Ok(Frame::Data { sequence, text }) => {
                                if closing {
                                    break 'session "peer sent application data while disconnecting".to_owned();
                                }
                                if sequence != next_in_sequence {
                                    break 'session format!("peer data sequence {sequence} did not match expected {next_in_sequence}");
                                }
                                if pending_inbound.len() >= MAX_PENDING_MESSAGES {
                                    break 'session "peer exceeded the inbound pending-message limit".to_owned();
                                }
                                let Some(next) = next_in_sequence.checked_add(1) else {
                                    break 'session "inbound message sequence exhausted".to_owned();
                                };
                                next_in_sequence = next;
                                pending_inbound.insert(sequence);
                                yield PeerEvent::Received { sequence, text };
                            }
                            Ok(Frame::Ack { sequence }) => {
                                let Some(pending) = pending_sends.remove(&sequence) else {
                                    break 'session format!("peer acknowledged sequence {sequence} that is not outstanding");
                                };
                                yield PeerEvent::Acknowledged {
                                    request_id: pending.request_id,
                                    text: pending.text,
                                };
                            }
                            Ok(Frame::Close) => {
                                if write_frame(&mut self.send, FRAME_CLOSE_ACK, 0, &[]).await.is_err() {
                                    break 'session "could not acknowledge peer disconnect".to_owned();
                                }
                                if self.send.finish().is_err() {
                                    break 'session "could not finish peer disconnect acknowledgement".to_owned();
                                }
                                let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.send.stopped()).await;
                                break 'session "peer disconnected".to_owned();
                            }
                            Ok(Frame::CloseAck) if closing => {
                                break 'session "local disconnect completed".to_owned();
                            }
                            Ok(Frame::CloseAck) => {
                                break 'session "unsolicited disconnect acknowledgement".to_owned();
                            }
                            Err(error) => break 'session error,
                        }
                    }
                    command = commands.recv(), if !closing => {
                        match command {
                            Some(PeerCommand::Send { request_id, text }) => {
                                if text.is_empty() || text.len() > MAX_TEXT_BYTES {
                                    yield PeerEvent::Rejected {
                                        request_id,
                                        reason: format!("message must contain 1 to {MAX_TEXT_BYTES} UTF-8 bytes"),
                                    };
                                    continue;
                                }
                                if pending_sends.len() >= MAX_PENDING_MESSAGES {
                                    yield PeerEvent::Rejected {
                                        request_id,
                                        reason: format!("at most {MAX_PENDING_MESSAGES} messages may await acknowledgement"),
                                    };
                                    continue;
                                }
                                let sequence = next_out_sequence;
                                let Some(next) = next_out_sequence.checked_add(1) else {
                                    break 'session "outbound message sequence exhausted".to_owned();
                                };
                                pending_sends.insert(sequence, PendingSend { request_id, text: text.clone() });
                                if let Err(error) = write_frame(&mut self.send, FRAME_DATA, sequence, text.as_bytes()).await {
                                    break 'session format!("could not send peer message: {error}");
                                }
                                next_out_sequence = next;
                            }
                            Some(PeerCommand::AcceptInbound { sequence }) => {
                                if !pending_inbound.remove(&sequence) {
                                    break 'session format!("cannot acknowledge inbound sequence {sequence}: no pending delivery");
                                }
                                if let Err(error) = write_frame(&mut self.send, FRAME_ACK, sequence, &[]).await {
                                    break 'session format!("could not acknowledge peer message: {error}");
                                }
                            }
                            Some(PeerCommand::Disconnect) | None => {
                                closing = true;
                                if let Err(error) = write_frame(&mut self.send, FRAME_CLOSE, 0, &[]).await {
                                    break 'session format!("could not send disconnect frame: {error}");
                                }
                                if let Err(error) = self.send.finish() {
                                    break 'session format!("could not finish disconnect frame: {error}");
                                }
                                close_deadline.as_mut().reset(tokio::time::Instant::now() + CLOSE_TIMEOUT);
                            }
                        }
                    }
                    _ = self.connection.closed() => {
                        break 'session "QUIC connection closed by peer".to_owned();
                    }
                    _ = &mut close_deadline, if closing => {
                        break 'session "timed out waiting for disconnect acknowledgement".to_owned();
                    }
                }
            };

            for (_, pending) in pending_sends {
                yield PeerEvent::DeliveryUnknown {
                    request_id: pending.request_id,
                    text: pending.text,
                };
            }
            self.connection.close(0_u32.into(), b"Slouching session ended");
            self.endpoint.close().await;
            yield PeerEvent::Disconnected { reason: disconnect_reason };
        }
    }
}

pub async fn bind_listener(
    local_identity: SecretKey,
    bind_address: SocketAddr,
    expected_peer: EndpointId,
) -> Result<DirectPeerListener, String> {
    let endpoint = bind_endpoint(local_identity, bind_address).await?;
    Ok(DirectPeerListener {
        endpoint,
        expected_peer,
    })
}

pub async fn connect_peer(
    local_identity: SecretKey,
    expected_peer: EndpointId,
    peer_address: SocketAddr,
) -> Result<DirectPeerSession, String> {
    let endpoint = bind_endpoint(
        local_identity,
        "0.0.0.0:0".parse().expect("valid bind addr"),
    )
    .await?;
    let remote = EndpointAddr::new(expected_peer).with_ip_addr(peer_address);
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(remote, PEER_ALPN))
        .await
        .map_err(|_| "timed out connecting to direct LAN peer".to_owned())?
        .map_err(|error| format!("could not connect to pinned LAN peer: {error}"))?;
    if connection.remote_id() != expected_peer {
        connection.close(1_u32.into(), b"unexpected device identity");
        endpoint.close().await;
        return Err("connected peer does not match the pinned device identity".to_owned());
    }
    let (send, receive) = tokio::time::timeout(ACCEPT_STREAM_TIMEOUT, connection.open_bi())
        .await
        .map_err(|_| "timed out opening the peer session stream".to_owned())?
        .map_err(|error| format!("could not open peer session stream: {error}"))?;
    Ok(DirectPeerSession {
        endpoint,
        connection,
        send,
        receive,
        peer_id: expected_peer,
    })
}

/// Temporary compatibility helper for the still-present diagnostic CLI.
#[allow(dead_code)]
pub async fn send_once(
    local_identity: SecretKey,
    expected_peer: EndpointId,
    peer_address: SocketAddr,
    text: &str,
) -> Result<String, String> {
    let session = connect_peer(local_identity, expected_peer, peer_address).await?;
    let text = text.to_owned();
    let (commands, receiver) = mpsc::channel(4);
    let mut events = Box::pin(session.run(receiver));
    commands
        .send(PeerCommand::Send {
            request_id: 1,
            text: text.clone(),
        })
        .await
        .map_err(|error| format!("could not send peer text: {error}"))?;
    let mut acknowledged = false;
    while let Some(event) = tokio::time::timeout(Duration::from_secs(30), events.next())
        .await
        .map_err(|_| "timed out waiting for peer acknowledgement".to_owned())?
    {
        match event {
            PeerEvent::Received { sequence, .. } => {
                commands
                    .send(PeerCommand::AcceptInbound { sequence })
                    .await
                    .map_err(|error| format!("could not acknowledge peer text: {error}"))?;
            }
            PeerEvent::Acknowledged { request_id: 1, .. } => {
                acknowledged = true;
                commands
                    .send(PeerCommand::Disconnect)
                    .await
                    .map_err(|error| format!("could not close peer session: {error}"))?;
            }
            PeerEvent::Disconnected { .. } => {
                if acknowledged {
                    return Ok(format!("received {} bytes", text.len()));
                }
                return Err("peer disconnected before acknowledging text".to_owned());
            }
            PeerEvent::Rejected { reason, .. } => return Err(reason),
            PeerEvent::DeliveryUnknown { .. } => {
                return Err("delivery could not be confirmed before disconnect".to_owned());
            }
            PeerEvent::Connected { .. }
            | PeerEvent::Acknowledged { .. }
            | PeerEvent::Unauthorized { .. } => {}
        }
    }
    Err("peer session ended before acknowledgement".to_owned())
}

async fn bind_endpoint(
    local_identity: SecretKey,
    bind_address: SocketAddr,
) -> Result<Endpoint, String> {
    Endpoint::builder(presets::Minimal)
        .secret_key(local_identity)
        .alpns(vec![PEER_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind_addr(bind_address)
        .map_err(|error| format!("invalid direct peer bind address: {error}"))?
        .bind()
        .await
        .map_err(|error| format!("could not start direct peer endpoint: {error}"))
}

async fn read_frame<R>(reader: &mut R) -> Result<Frame, String>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 19];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|error| format!("could not read session frame header: {error}"))?;
    if &header[..4] != FRAME_MAGIC {
        return Err("peer sent an invalid session frame marker".to_owned());
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != FRAME_VERSION {
        return Err(format!("unsupported peer session version: {version}"));
    }
    let kind = header[6];
    let sequence = u64::from_be_bytes(header[7..15].try_into().expect("eight bytes"));
    let length = u32::from_be_bytes(header[15..19].try_into().expect("four bytes")) as usize;
    match kind {
        FRAME_DATA => {
            if length == 0 || length > MAX_TEXT_BYTES {
                return Err(format!(
                    "peer data length must be between 1 and {MAX_TEXT_BYTES}"
                ));
            }
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read peer message: {error}"))?;
            let text = String::from_utf8(bytes)
                .map_err(|error| format!("peer message is not valid UTF-8: {error}"))?;
            Ok(Frame::Data { sequence, text })
        }
        FRAME_ACK if length == 0 && sequence != 0 => Ok(Frame::Ack { sequence }),
        FRAME_ACK => Err("peer sent an invalid ACK frame".to_owned()),
        FRAME_CLOSE if length == 0 && sequence == 0 => Ok(Frame::Close),
        FRAME_CLOSE => Err("peer sent an invalid disconnect frame".to_owned()),
        FRAME_CLOSE_ACK if length == 0 && sequence == 0 => Ok(Frame::CloseAck),
        FRAME_CLOSE_ACK => Err("peer sent an invalid disconnect acknowledgement".to_owned()),
        _ => Err(format!("unknown peer session frame type: {kind}")),
    }
}

async fn write_frame<W>(
    writer: &mut W,
    kind: u8,
    sequence: u64,
    payload: &[u8],
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > u32::MAX as usize {
        return Err("session frame payload is too large".to_owned());
    }
    writer
        .write_all(FRAME_MAGIC)
        .await
        .map_err(|error| format!("could not write session frame marker: {error}"))?;
    writer
        .write_all(&FRAME_VERSION.to_be_bytes())
        .await
        .map_err(|error| format!("could not write session frame version: {error}"))?;
    writer
        .write_all(&[kind])
        .await
        .map_err(|error| format!("could not write session frame type: {error}"))?;
    writer
        .write_all(&sequence.to_be_bytes())
        .await
        .map_err(|error| format!("could not write session sequence: {error}"))?;
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|error| format!("could not write session frame length: {error}"))?;
    writer
        .write_all(payload)
        .await
        .map_err(|error| format!("could not write session frame payload: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn closing_idle_listener_unblocks_accept_and_releases_endpoint() {
        let listener = bind_listener(
            SecretKey::from_bytes(&[0x44; 32]),
            "127.0.0.1:0".parse().unwrap(),
            SecretKey::from_bytes(&[0x55; 32]).public(),
        )
        .await
        .unwrap();
        listener.close().await;
        assert!(listener.is_closed());
        assert!(matches!(
            listener.accept_session().await,
            Err(PeerAcceptError::Failed(_))
        ));
    }

    #[tokio::test]
    async fn strict_v2_frames_reject_unknown_and_malformed_data() {
        let (mut writer, mut reader) = duplex(128);
        write_frame(&mut writer, FRAME_DATA, 1, "hello".as_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Frame::Data {
                sequence: 1,
                text: "hello".to_owned()
            }
        );

        for (kind, sequence, payload, message) in [
            (FRAME_DATA, 2, &b""[..], "peer data length"),
            (FRAME_ACK, 2, &b"x"[..], "invalid ACK"),
            (99, 2, &b""[..], "unknown peer session frame type"),
        ] {
            let (mut writer, mut reader) = duplex(128);
            write_frame(&mut writer, kind, sequence, payload)
                .await
                .unwrap();
            assert!(read_frame(&mut reader).await.unwrap_err().contains(message));
        }

        let (mut writer, mut reader) = duplex(64);
        writer
            .write_all(&[
                b'S', b'L', b'C', b'H', 0, 2, FRAME_DATA, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x40, 0, 1,
            ])
            .await
            .unwrap();
        assert!(
            read_frame(&mut reader)
                .await
                .unwrap_err()
                .contains("length")
        );

        let (mut writer, mut reader) = duplex(128);
        writer
            .write_all(&[
                b'S', b'L', b'C', b'H', 0, 9, FRAME_DATA, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, b'x',
            ])
            .await
            .unwrap();
        assert!(
            read_frame(&mut reader)
                .await
                .unwrap_err()
                .contains("version")
        );

        let (mut writer, mut reader) = duplex(128);
        write_frame(&mut writer, FRAME_DATA, 1, &[0xff])
            .await
            .unwrap();
        assert!(read_frame(&mut reader).await.unwrap_err().contains("UTF-8"));
    }
}
