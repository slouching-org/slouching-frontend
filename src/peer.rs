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
pub const PEER_ALPN: &[u8] = b"org.slouching.peer/3";
const FRAME_MAGIC: &[u8; 4] = b"SLCH";
const FRAME_VERSION: u16 = 3;
const FRAME_DATA: u8 = 1;
const FRAME_ACK: u8 = 2;
const FRAME_CLOSE: u8 = 3;
const FRAME_CLOSE_ACK: u8 = 4;
const FRAME_MLS_EVENT: u8 = 5;
const MLS_EVENT_MAGIC: &[u8; 4] = b"SLME";
const MLS_EVENT_VERSION: u16 = 1;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_MLS_EVENT_BYTES: usize = 64 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 16 * 1024;
pub const MAX_PENDING_MESSAGES: usize = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const ACCEPT_STREAM_TIMEOUT: Duration = Duration::from_secs(8);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(8);

pub struct DirectPeerListener {
    endpoint: Endpoint,
    expected_peer: EndpointId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsEventEnvelope {
    pub event_id: [u8; 16],
    pub author_device: [u8; 32],
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub checkpoint: Option<Vec<u8>>,
    pub expires_at_unix: i64,
    pub ciphertext: Vec<u8>,
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
    SendMlsEvent {
        request_id: u64,
        event: MlsEventEnvelope,
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
    MlsEventReceived {
        sequence: u64,
        event: MlsEventEnvelope,
    },
    MlsEventAcknowledged {
        request_id: u64,
    },
    MlsEventRejected {
        request_id: u64,
        reason: String,
    },
    Rejected {
        request_id: u64,
        reason: String,
    },
    DeliveryUnknown {
        request_id: u64,
        text: String,
    },
    MlsEventDeliveryUnknown {
        request_id: u64,
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

enum PendingOutbound {
    Text(PendingSend),
    MlsEvent { request_id: u64 },
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
    Data {
        sequence: u64,
        text: String,
    },
    MlsEvent {
        sequence: u64,
        event: MlsEventEnvelope,
    },
    Ack {
        sequence: u64,
    },
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
                | PeerEvent::MlsEventReceived { .. }
                | PeerEvent::MlsEventAcknowledged { .. }
                | PeerEvent::MlsEventRejected { .. }
                | PeerEvent::Rejected { .. }
                | PeerEvent::DeliveryUnknown { .. }
                | PeerEvent::MlsEventDeliveryUnknown { .. } => {}
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
            let mut pending_sends = HashMap::<u64, PendingOutbound>::new();
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
                            Ok(Frame::MlsEvent { sequence, event }) => {
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
                                yield PeerEvent::MlsEventReceived { sequence, event };
                            }
                            Ok(Frame::Ack { sequence }) => {
                                let Some(pending) = pending_sends.remove(&sequence) else {
                                    break 'session format!("peer acknowledged sequence {sequence} that is not outstanding");
                                };
                                match pending {
                                    PendingOutbound::Text(pending) => yield PeerEvent::Acknowledged {
                                        request_id: pending.request_id,
                                        text: pending.text,
                                    },
                                    PendingOutbound::MlsEvent { request_id } => {
                                        yield PeerEvent::MlsEventAcknowledged { request_id };
                                    }
                                }
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
                                pending_sends.insert(sequence, PendingOutbound::Text(PendingSend { request_id, text: text.clone() }));
                                if let Err(error) = write_frame(&mut self.send, FRAME_DATA, sequence, text.as_bytes()).await {
                                    break 'session format!("could not send peer message: {error}");
                                }
                                next_out_sequence = next;
                            }
                            Some(PeerCommand::SendMlsEvent { request_id, event }) => {
                                let payload = match encode_mls_event(&event) {
                                    Ok(payload) => payload,
                                    Err(reason) => {
                                        yield PeerEvent::MlsEventRejected { request_id, reason };
                                        continue;
                                    }
                                };
                                if pending_sends.len() >= MAX_PENDING_MESSAGES {
                                    yield PeerEvent::MlsEventRejected {
                                        request_id,
                                        reason: format!("at most {MAX_PENDING_MESSAGES} messages may await acknowledgement"),
                                    };
                                    continue;
                                }
                                let sequence = next_out_sequence;
                                let Some(next) = next_out_sequence.checked_add(1) else {
                                    break 'session "outbound message sequence exhausted".to_owned();
                                };
                                pending_sends.insert(sequence, PendingOutbound::MlsEvent { request_id });
                                if let Err(error) = write_frame(&mut self.send, FRAME_MLS_EVENT, sequence, &payload).await {
                                    break 'session format!("could not send MLS event: {error}");
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
                match pending {
                    PendingOutbound::Text(pending) => yield PeerEvent::DeliveryUnknown {
                        request_id: pending.request_id,
                        text: pending.text,
                    },
                    PendingOutbound::MlsEvent { request_id } => {
                        yield PeerEvent::MlsEventDeliveryUnknown { request_id };
                    }
                }
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
            | PeerEvent::MlsEventReceived { .. }
            | PeerEvent::MlsEventAcknowledged { .. }
            | PeerEvent::MlsEventRejected { .. }
            | PeerEvent::Unauthorized { .. } => {}
            PeerEvent::MlsEventDeliveryUnknown { .. } => {
                return Err("MLS event delivery could not be confirmed".to_owned());
            }
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
        FRAME_MLS_EVENT => {
            if length == 0 || length > MAX_MLS_EVENT_BYTES {
                return Err(format!(
                    "MLS event length must be between 1 and {MAX_MLS_EVENT_BYTES}"
                ));
            }
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read MLS event frame: {error}"))?;
            Ok(Frame::MlsEvent {
                sequence,
                event: decode_mls_event(&bytes)?,
            })
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

fn encode_mls_event(event: &MlsEventEnvelope) -> Result<Vec<u8>, String> {
    if event.event_id.iter().all(|byte| *byte == 0)
        || event.author_device.iter().all(|byte| *byte == 0)
        || event.group_id.len() != 16
        || event.epoch > i64::MAX as u64
        || event.expires_at_unix <= 0
        || event.ciphertext.is_empty()
        || event.ciphertext.len() > MAX_MLS_EVENT_BYTES
        || event
            .checkpoint
            .as_ref()
            .is_some_and(|value| value.len() > MAX_CHECKPOINT_BYTES)
    {
        return Err("MLS event has an invalid or oversized envelope".to_owned());
    }
    let checkpoint = event.checkpoint.as_deref().unwrap_or_default();
    let mut output = Vec::with_capacity(
        4 + 2
            + 16
            + 32
            + 2
            + event.group_id.len()
            + 8
            + 8
            + 1
            + 2
            + 4
            + checkpoint.len()
            + event.ciphertext.len(),
    );
    output.extend_from_slice(MLS_EVENT_MAGIC);
    output.extend_from_slice(&MLS_EVENT_VERSION.to_be_bytes());
    output.extend_from_slice(&event.event_id);
    output.extend_from_slice(&event.author_device);
    output.extend_from_slice(&(event.group_id.len() as u16).to_be_bytes());
    output.extend_from_slice(&event.group_id);
    output.extend_from_slice(&event.epoch.to_be_bytes());
    output.extend_from_slice(&event.expires_at_unix.to_be_bytes());
    output.push(u8::from(event.checkpoint.is_some()));
    output.extend_from_slice(&(checkpoint.len() as u16).to_be_bytes());
    output.extend_from_slice(&(event.ciphertext.len() as u32).to_be_bytes());
    output.extend_from_slice(checkpoint);
    output.extend_from_slice(&event.ciphertext);
    if output.len() > MAX_MLS_EVENT_BYTES {
        return Err("serialized MLS event exceeds the transport limit".to_owned());
    }
    Ok(output)
}

fn decode_mls_event(bytes: &[u8]) -> Result<MlsEventEnvelope, String> {
    const FIXED: usize = 4 + 2 + 16 + 32 + 2 + 8 + 8 + 1 + 2 + 4;
    if bytes.len() < FIXED || bytes.len() > MAX_MLS_EVENT_BYTES || &bytes[..4] != MLS_EVENT_MAGIC {
        return Err("invalid or oversized MLS event envelope".to_owned());
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != MLS_EVENT_VERSION {
        return Err(format!("unsupported MLS event envelope version: {version}"));
    }
    let mut cursor = 6;
    let event_id = bytes[cursor..cursor + 16]
        .try_into()
        .expect("fixed event id");
    cursor += 16;
    let author_device = bytes[cursor..cursor + 32]
        .try_into()
        .expect("fixed author key");
    cursor += 32;
    let group_len = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2;
    if group_len != 16 || bytes.len() < cursor + group_len + 8 + 8 + 1 + 2 + 4 {
        return Err("MLS event has an invalid group id length".to_owned());
    }
    let group_id = bytes[cursor..cursor + group_len].to_vec();
    cursor += group_len;
    let epoch = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let expires_at_unix = i64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let has_checkpoint = match bytes[cursor] {
        0 => false,
        1 => true,
        _ => return Err("MLS event checkpoint flag is invalid".to_owned()),
    };
    cursor += 1;
    let checkpoint_len = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2;
    let ciphertext_len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    if checkpoint_len > MAX_CHECKPOINT_BYTES
        || has_checkpoint != (checkpoint_len > 0)
        || ciphertext_len == 0
        || cursor
            .checked_add(checkpoint_len)
            .and_then(|end| end.checked_add(ciphertext_len))
            != Some(bytes.len())
    {
        return Err("MLS event envelope lengths are invalid".to_owned());
    }
    let checkpoint = has_checkpoint.then(|| bytes[cursor..cursor + checkpoint_len].to_vec());
    cursor += checkpoint_len;
    let event = MlsEventEnvelope {
        event_id,
        author_device,
        group_id,
        epoch,
        checkpoint,
        expires_at_unix,
        ciphertext: bytes[cursor..].to_vec(),
    };
    if event.event_id.iter().all(|byte| *byte == 0)
        || event.author_device.iter().all(|byte| *byte == 0)
        || event.epoch > i64::MAX as u64
        || event.expires_at_unix <= 0
    {
        return Err("MLS event metadata is invalid".to_owned());
    }
    Ok(event)
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
    async fn strict_v3_frames_reject_unknown_and_malformed_data() {
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
                b'S',
                b'L',
                b'C',
                b'H',
                FRAME_VERSION.to_be_bytes()[0],
                FRAME_VERSION.to_be_bytes()[1],
                FRAME_DATA,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                0,
                0x40,
                0,
                1,
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

    #[test]
    fn mls_event_envelope_round_trips_and_rejects_length_tampering() {
        let event = MlsEventEnvelope {
            event_id: [0x11; 16],
            author_device: [0x22; 32],
            group_id: [0x33; 16].to_vec(),
            epoch: 9,
            checkpoint: Some(vec![0x44, 0x45]),
            expires_at_unix: 2_000_000_000,
            ciphertext: vec![0x55; 64],
        };
        let encoded = encode_mls_event(&event).expect("valid event should serialize");
        assert_eq!(decode_mls_event(&encoded).unwrap(), event);

        let mut forged_length = encoded;
        let checkpoint_length_offset = 4 + 2 + 16 + 32 + 2 + 16 + 8 + 8 + 1;
        forged_length[checkpoint_length_offset..checkpoint_length_offset + 2]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode_mls_event(&forged_length).is_err());

        let mut invalid = event;
        invalid.author_device = [0; 32];
        assert!(encode_mls_event(&invalid).is_err());
    }

    #[tokio::test]
    async fn strict_session_parser_round_trips_mls_event_frame() {
        let event = MlsEventEnvelope {
            event_id: [0x61; 16],
            author_device: [0x62; 32],
            group_id: [0x63; 16].to_vec(),
            epoch: 4,
            checkpoint: None,
            expires_at_unix: 2_000_000_001,
            ciphertext: vec![0x64; 24],
        };
        let payload = encode_mls_event(&event).unwrap();
        let (mut writer, mut reader) = duplex(1024);
        write_frame(&mut writer, FRAME_MLS_EVENT, 7, &payload)
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Frame::MlsEvent { sequence: 7, event }
        );
    }
}
