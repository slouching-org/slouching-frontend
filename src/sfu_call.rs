//! Authenticated signaling transport for optional Elixir-hosted SFU calls.

use crate::protocol;
use futures_util::{SinkExt, StreamExt};
use iroh::SecretKey;
use prost::Message as ProstMessage;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use webrtc::peer_connection::RTCIceCandidateInit;

const ROSTER_DOMAIN: &[u8] = b"slouching/sfu-roster/v1\0";
const MAX_SIGNAL_BYTES: usize = 128 * 1024;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Debug, Clone)]
pub enum SfuCallEvent {
    Answer(Vec<u8>),
    IceCandidate(RTCIceCandidateInit),
    Rejected { code: String, message: String },
    Disconnected(String),
}

enum Command {
    Offer(Vec<u8>),
    IceCandidate(RTCIceCandidateInit),
    Leave,
}

/// Owns the authenticated call signaling socket for one SFU room.
#[derive(Debug)]
pub struct SfuCallTransport {
    call_id: [u8; 16],
    commands: mpsc::Sender<Command>,
    events: Option<mpsc::Receiver<SfuCallEvent>>,
}

impl SfuCallTransport {
    pub async fn connect_and_join(
        ws_url: &str,
        call_id: [u8; 16],
        group_id: [u8; 16],
        epoch: u64,
        roster: &[[u8; 32]],
        secret_key: SecretKey,
    ) -> Result<Self, String> {
        let ws_url = normalize_ws_url(ws_url)?;
        validate_roster(roster)?;

        let device_key = *secret_key.public().as_bytes();
        if !roster.contains(&device_key) {
            return Err("this device is not a member of the call MLS roster".to_owned());
        }

        let signature_payload = roster_payload(&call_id, &group_id, epoch, roster);
        let signature = secret_key.sign(&signature_payload).to_bytes().to_vec();
        let (mut socket, hello) = crate::connect_transport_with_key(&ws_url, secret_key)
            .await
            .map_err(|error| format!("could not authenticate to the SFU helper: {error:?}"))?;

        if !hello.calls_available {
            return Err("the configured helper does not advertise SFU call support".to_owned());
        }

        let join = protocol::ClientFrame {
            payload: Some(protocol::client_frame::Payload::SfuCallJoin(
                protocol::SfuCallJoin {
                    call_id: call_id.to_vec(),
                    group_id: group_id.to_vec(),
                    epoch,
                    roster: roster.iter().map(|key| key.to_vec()).collect(),
                    roster_signature: signature,
                },
            )),
        };
        socket
            .send(WsMessage::Binary(join.encode_to_vec().into()))
            .await
            .map_err(|error| format!("could not join the SFU call: {error}"))?;

        match receive_server_frame(&mut socket).await? {
            protocol::server_frame::Payload::SfuCallJoined(joined)
                if joined.call_id == call_id && joined.roster.len() == roster.len() => {}
            protocol::server_frame::Payload::SfuCallError(error) => {
                return Err(format!("SFU call join rejected: {}", error.code));
            }
            _ => return Err("SFU helper returned an unexpected call-join response".to_owned()),
        }

        let (mut sink, mut stream) = socket.split();
        let (command_tx, mut command_rx) = mpsc::channel(16);
        let (event_tx, event_rx) = mpsc::channel(64);

        tokio::spawn(async move {
            let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(5));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = heartbeat.tick() => {
                        if let Err(error) = sink.send(WsMessage::Ping(b"slouching-call-v1".to_vec().into())).await {
                            let _ = event_tx.send(SfuCallEvent::Disconnected(error.to_string())).await;
                            break;
                        }
                    }
                    command = command_rx.recv() => {
                        let Some(command) = command else { break };
                        let leaving = matches!(&command, Command::Leave);
                        let frame = match command {
                            Command::Offer(sdp) => protocol::ClientFrame {
                                payload: Some(protocol::client_frame::Payload::SfuCallOffer(
                                    protocol::SfuCallOffer { call_id: call_id.to_vec(), sdp }
                                )),
                            },
                            Command::IceCandidate(candidate) => protocol::ClientFrame {
                                payload: Some(protocol::client_frame::Payload::SfuIceCandidate(
                                    protocol::SfuIceCandidate {
                                        call_id: call_id.to_vec(),
                                        candidate: candidate.candidate,
                                        sdp_mid: candidate.sdp_mid.unwrap_or_default(),
                                        sdp_m_line_index: candidate.sdp_mline_index.unwrap_or_default().into(),
                                        username_fragment: candidate.username_fragment.unwrap_or_default(),
                                    }
                                )),
                            },
                            Command::Leave => protocol::ClientFrame {
                                payload: Some(protocol::client_frame::Payload::SfuCallLeave(
                                    protocol::SfuCallLeave { call_id: call_id.to_vec() }
                                )),
                            },
                        };
                        if let Err(error) = sink.send(WsMessage::Binary(frame.encode_to_vec().into())).await {
                            let _ = event_tx.send(SfuCallEvent::Disconnected(error.to_string())).await;
                            break;
                        }
                        if leaving { break; }
                    }
                    incoming = stream.next() => {
                        let Some(incoming) = incoming else {
                            let _ = event_tx.send(SfuCallEvent::Disconnected("SFU helper closed the WebSocket".to_owned())).await;
                            break;
                        };
                        match incoming {
                            Ok(WsMessage::Binary(bytes)) => match protocol::ServerFrame::decode(bytes) {
                                Ok(frame) => match frame.payload {
                                    Some(protocol::server_frame::Payload::SfuCallAnswer(answer))
                                        if answer.call_id == call_id && answer.sdp.len() <= MAX_SIGNAL_BYTES => {
                                            let delivered = event_tx.send(SfuCallEvent::Answer(answer.sdp)).await.is_ok();
                                            if !delivered { break; }
                                        }
                                    Some(protocol::server_frame::Payload::SfuIceCandidate(candidate))
                                        if candidate.call_id == call_id => {
                                            let candidate = RTCIceCandidateInit {
                                                candidate: candidate.candidate,
                                                sdp_mid: nonempty(candidate.sdp_mid),
                                                sdp_mline_index: Some(candidate.sdp_m_line_index.min(u16::MAX.into()) as u16),
                                                username_fragment: nonempty(candidate.username_fragment),
                                                url: None,
                                            };
                                            if event_tx.send(SfuCallEvent::IceCandidate(candidate)).await.is_err() { break; }
                                        }
                                    Some(protocol::server_frame::Payload::SfuCallError(error))
                                        if error.call_id.is_empty() || error.call_id == call_id => {
                                            let delivered = event_tx.send(SfuCallEvent::Rejected { code: error.code, message: error.message }).await.is_ok();
                                            if !delivered { break; }
                                        }
                                    _ => {}
                                },
                                Err(error) => {
                                    let _ = event_tx.send(SfuCallEvent::Disconnected(format!("invalid SFU protobuf frame: {error}"))).await;
                                    break;
                                }
                            },
                            Ok(WsMessage::Ping(payload)) => {
                                if sink.send(WsMessage::Pong(payload)).await.is_err() { break; }
                            }
                            Ok(WsMessage::Close(_)) => {
                                let _ = event_tx.send(SfuCallEvent::Disconnected("SFU helper closed the WebSocket".to_owned())).await;
                                break;
                            }
                            Ok(_) => {}
                            Err(error) => {
                                let _ = event_tx.send(SfuCallEvent::Disconnected(error.to_string())).await;
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            call_id,
            commands: command_tx,
            events: Some(event_rx),
        })
    }

    pub fn call_id(&self) -> [u8; 16] {
        self.call_id
    }

    pub async fn send_offer(&self, sdp: Vec<u8>) -> Result<(), String> {
        if sdp.is_empty() || sdp.len() > MAX_SIGNAL_BYTES {
            return Err("SFU offer is empty or exceeds 128 KiB".to_owned());
        }
        self.commands
            .send(Command::Offer(sdp))
            .await
            .map_err(|_| "SFU call signaling task has stopped".to_owned())
    }

    pub async fn send_ice_candidate(&self, candidate: RTCIceCandidateInit) -> Result<(), String> {
        if candidate.candidate.is_empty() || candidate.candidate.len() > 2_048 {
            return Err("ICE candidate is empty or too large".to_owned());
        }
        self.commands
            .send(Command::IceCandidate(candidate))
            .await
            .map_err(|_| "SFU call signaling task has stopped".to_owned())
    }

    pub fn take_events(&mut self) -> Option<mpsc::Receiver<SfuCallEvent>> {
        self.events.take()
    }

    pub async fn leave(&self) -> Result<(), String> {
        self.commands
            .send(Command::Leave)
            .await
            .map_err(|_| "SFU call signaling task has stopped".to_owned())
    }
}

pub fn roster_payload(
    call_id: &[u8; 16],
    group_id: &[u8; 16],
    epoch: u64,
    roster: &[[u8; 32]],
) -> Vec<u8> {
    let mut keys = roster.to_vec();
    keys.sort_unstable();
    let mut payload = Vec::with_capacity(ROSTER_DOMAIN.len() + 16 + 16 + 8 + 2 + keys.len() * 32);
    payload.extend_from_slice(ROSTER_DOMAIN);
    payload.extend_from_slice(call_id);
    payload.extend_from_slice(group_id);
    payload.extend_from_slice(&epoch.to_be_bytes());
    payload.extend_from_slice(&(keys.len() as u16).to_be_bytes());
    for key in keys {
        payload.extend_from_slice(&key);
    }
    payload
}

fn validate_roster(roster: &[[u8; 32]]) -> Result<(), String> {
    if !(2..=16).contains(&roster.len()) {
        return Err("SFU roster must contain 2 to 16 devices".to_owned());
    }
    let mut unique = roster.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != roster.len() {
        return Err("SFU roster contains a duplicate device".to_owned());
    }
    Ok(())
}

fn normalize_ws_url(value: &str) -> Result<String, String> {
    let mut url =
        url::Url::parse(value).map_err(|error| format!("invalid SFU WebSocket URL: {error}"))?;
    if !matches!(url.scheme(), "ws" | "wss")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "/" | "/ws")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("SFU URL must be ws://host[:port][/ws] or wss://host[:port][/ws]".to_owned());
    }
    if url.path() == "/" {
        url.set_path("/ws");
    }
    Ok(url.to_string())
}

async fn receive_server_frame(
    socket: &mut WsStream,
) -> Result<protocol::server_frame::Payload, String> {
    let response = tokio::time::timeout(std::time::Duration::from_secs(10), socket.next())
        .await
        .map_err(|_| "SFU helper response timed out".to_owned())?
        .ok_or_else(|| "SFU helper closed before replying".to_owned())?
        .map_err(|error| error.to_string())?;

    let WsMessage::Binary(bytes) = response else {
        return Err("SFU helper returned a non-binary protocol frame".to_owned());
    };

    protocol::ServerFrame::decode(bytes)
        .map_err(|error| format!("invalid SFU helper protobuf frame: {error}"))?
        .payload
        .ok_or_else(|| "SFU helper returned an empty protocol frame".to_owned())
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
