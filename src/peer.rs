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
pub const PEER_ALPN: &[u8] = b"org.slouching.peer/5";
const FRAME_MAGIC: &[u8; 4] = b"SLCH";
const FRAME_VERSION: u16 = 5;
const FRAME_DATA: u8 = 1;
const FRAME_ACK: u8 = 2;
const FRAME_CLOSE: u8 = 3;
const FRAME_CLOSE_ACK: u8 = 4;
const FRAME_MLS_EVENT: u8 = 5;
const FRAME_MLS_COMMIT: u8 = 6;
const FRAME_REJECT: u8 = 7;
const FRAME_MLS_COMMIT_REQUEST: u8 = 8;
const FRAME_MLS_PROPOSAL: u8 = 9;
const MLS_EVENT_MAGIC: &[u8; 4] = b"SLME";
const MLS_EVENT_VERSION: u16 = 1;
const MLS_COMMIT_MAGIC: &[u8; 4] = b"SLMC";
const MLS_COMMIT_VERSION: u16 = 1;
const MLS_PROPOSAL_MAGIC: &[u8; 4] = b"SLMP";
const MLS_PROPOSAL_VERSION: u16 = 1;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_MLS_EVENT_BYTES: usize = 64 * 1024;
const MAX_MLS_COMMIT_BYTES: usize = 64 * 1024;
const MAX_MLS_PROPOSAL_BYTES: usize = 64 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 16 * 1024;
pub const MAX_PENDING_MESSAGES: usize = 16;
const MAX_MLS_COMMIT_REQUESTS_PER_SESSION: u8 = 16;
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
pub struct MlsCommitEnvelope {
    pub event_id: [u8; 16],
    pub author_device: [u8; 32],
    pub group_id: Vec<u8>,
    pub predecessor_epoch: u64,
    pub epoch: u64,
    pub commit: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsProposalEnvelope {
    pub event_id: [u8; 16],
    pub author_device: [u8; 32],
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub proposal: Vec<u8>,
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
    SendMlsCommit {
        request_id: u64,
        commit: MlsCommitEnvelope,
    },
    SendMlsProposal {
        request_id: u64,
        proposal: MlsProposalEnvelope,
    },
    RequestMlsCommit {
        group_id: Vec<u8>,
        predecessor_epoch: u64,
    },
    /// Send only after the application has stored this message in its in-memory transcript.
    AcceptInbound {
        sequence: u64,
    },
    RejectInbound {
        sequence: u64,
        reason: String,
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
    MlsCommitReceived {
        sequence: u64,
        commit: MlsCommitEnvelope,
    },
    MlsProposalReceived {
        sequence: u64,
        peer_id: EndpointId,
        proposal: MlsProposalEnvelope,
    },
    MlsCommitRequested {
        peer_id: EndpointId,
        group_id: Vec<u8>,
        predecessor_epoch: u64,
    },
    MlsEventAcknowledged {
        request_id: u64,
    },
    MlsCommitAcknowledged {
        request_id: u64,
    },
    MlsProposalAcknowledged {
        request_id: u64,
    },
    MlsEventRejected {
        request_id: u64,
        reason: String,
    },
    MlsCommitRejected {
        request_id: u64,
        reason: String,
    },
    MlsProposalRejected {
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
    MlsCommitDeliveryUnknown {
        request_id: u64,
    },
    MlsProposalDeliveryUnknown {
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
    MlsCommit { request_id: u64 },
    MlsProposal { request_id: u64 },
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
    MlsCommit {
        sequence: u64,
        commit: MlsCommitEnvelope,
    },
    MlsProposal {
        sequence: u64,
        proposal: MlsProposalEnvelope,
    },
    MlsCommitRequest {
        group_id: Vec<u8>,
        predecessor_epoch: u64,
    },
    Ack {
        sequence: u64,
    },
    Reject {
        sequence: u64,
        reason: String,
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
                | PeerEvent::MlsCommitReceived { .. }
                | PeerEvent::MlsProposalReceived { .. }
                | PeerEvent::MlsCommitRequested { .. }
                | PeerEvent::MlsEventAcknowledged { .. }
                | PeerEvent::MlsCommitAcknowledged { .. }
                | PeerEvent::MlsProposalAcknowledged { .. }
                | PeerEvent::MlsEventRejected { .. }
                | PeerEvent::MlsCommitRejected { .. }
                | PeerEvent::MlsProposalRejected { .. }
                | PeerEvent::Rejected { .. }
                | PeerEvent::DeliveryUnknown { .. }
                | PeerEvent::MlsEventDeliveryUnknown { .. }
                | PeerEvent::MlsCommitDeliveryUnknown { .. }
                | PeerEvent::MlsProposalDeliveryUnknown { .. } => {}
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
            let mut received_commit_requests = 0_u8;
            let mut seen_commit_requests = std::collections::HashSet::new();
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
                            Ok(Frame::MlsCommit { sequence, commit }) => {
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
                                yield PeerEvent::MlsCommitReceived { sequence, commit };
                            }
                            Ok(Frame::MlsProposal { sequence, proposal }) => {
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
                                yield PeerEvent::MlsProposalReceived {
                                    sequence,
                                    peer_id: self.peer_id,
                                    proposal,
                                };
                            }
                            Ok(Frame::MlsCommitRequest { group_id, predecessor_epoch }) => {
                                received_commit_requests = received_commit_requests.saturating_add(1);
                                if received_commit_requests > MAX_MLS_COMMIT_REQUESTS_PER_SESSION {
                                    break 'session "peer exceeded the MLS predecessor request limit".to_owned();
                                }
                                if !seen_commit_requests.insert((group_id.clone(), predecessor_epoch)) {
                                    continue;
                                }
                                yield PeerEvent::MlsCommitRequested {
                                    peer_id: self.peer_id,
                                    group_id,
                                    predecessor_epoch,
                                };
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
                                    PendingOutbound::MlsCommit { request_id } => {
                                        yield PeerEvent::MlsCommitAcknowledged { request_id };
                                    }
                                    PendingOutbound::MlsProposal { request_id } => {
                                        yield PeerEvent::MlsProposalAcknowledged { request_id };
                                    }
                                }
                            }
                            Ok(Frame::Reject { sequence, reason }) => {
                                let Some(pending) = pending_sends.remove(&sequence) else {
                                    break 'session format!("peer rejected sequence {sequence} that is not outstanding");
                                };
                                match pending {
                                    PendingOutbound::Text(pending) => yield PeerEvent::Rejected { request_id: pending.request_id, reason },
                                    PendingOutbound::MlsEvent { request_id } => yield PeerEvent::MlsEventRejected { request_id, reason },
                                    PendingOutbound::MlsCommit { request_id } => yield PeerEvent::MlsCommitRejected { request_id, reason },
                                    PendingOutbound::MlsProposal { request_id } => yield PeerEvent::MlsProposalRejected { request_id, reason },
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
                            Some(PeerCommand::SendMlsCommit { request_id, commit }) => {
                                let payload = match encode_mls_commit(&commit) {
                                    Ok(payload) => payload,
                                    Err(reason) => {
                                        yield PeerEvent::MlsCommitRejected { request_id, reason };
                                        continue;
                                    }
                                };
                                if pending_sends.len() >= MAX_PENDING_MESSAGES {
                                    yield PeerEvent::MlsCommitRejected {
                                        request_id,
                                        reason: format!("at most {MAX_PENDING_MESSAGES} messages may await acknowledgement"),
                                    };
                                    continue;
                                }
                                let sequence = next_out_sequence;
                                let Some(next) = next_out_sequence.checked_add(1) else {
                                    break 'session "outbound message sequence exhausted".to_owned();
                                };
                                pending_sends.insert(sequence, PendingOutbound::MlsCommit { request_id });
                                if let Err(error) = write_frame(&mut self.send, FRAME_MLS_COMMIT, sequence, &payload).await {
                                    break 'session format!("could not send MLS Commit: {error}");
                                }
                                next_out_sequence = next;
                            }
                            Some(PeerCommand::SendMlsProposal { request_id, proposal }) => {
                                let payload = match encode_mls_proposal(&proposal) {
                                    Ok(payload) => payload,
                                    Err(reason) => {
                                        yield PeerEvent::MlsProposalRejected { request_id, reason };
                                        continue;
                                    }
                                };
                                if pending_sends.len() >= MAX_PENDING_MESSAGES {
                                    yield PeerEvent::MlsProposalRejected {
                                        request_id,
                                        reason: format!("at most {MAX_PENDING_MESSAGES} messages may await acknowledgement"),
                                    };
                                    continue;
                                }
                                let sequence = next_out_sequence;
                                let Some(next) = next_out_sequence.checked_add(1) else {
                                    break 'session "outbound message sequence exhausted".to_owned();
                                };
                                pending_sends.insert(sequence, PendingOutbound::MlsProposal { request_id });
                                if let Err(error) = write_frame(&mut self.send, FRAME_MLS_PROPOSAL, sequence, &payload).await {
                                    break 'session format!("could not send MLS proposal: {error}");
                                }
                                next_out_sequence = next;
                            }
                            Some(PeerCommand::RequestMlsCommit { group_id, predecessor_epoch }) => {
                                if group_id.len() != 16 || predecessor_epoch > i64::MAX as u64 {
                                    continue;
                                }
                                let mut payload = Vec::with_capacity(24);
                                payload.extend_from_slice(&group_id);
                                payload.extend_from_slice(&predecessor_epoch.to_be_bytes());
                                if let Err(error) = write_frame(&mut self.send, FRAME_MLS_COMMIT_REQUEST, 0, &payload).await {
                                    break 'session format!("could not request missing MLS Commit: {error}");
                                }
                            }
                            Some(PeerCommand::AcceptInbound { sequence }) => {
                                if !pending_inbound.remove(&sequence) {
                                    break 'session format!("cannot acknowledge inbound sequence {sequence}: no pending delivery");
                                }
                                if let Err(error) = write_frame(&mut self.send, FRAME_ACK, sequence, &[]).await {
                                    break 'session format!("could not acknowledge peer message: {error}");
                                }
                            }
                            Some(PeerCommand::RejectInbound { sequence, reason }) => {
                                if !pending_inbound.remove(&sequence) {
                                    break 'session format!("cannot reject inbound sequence {sequence}: no pending delivery");
                                }
                                let reason = reason.chars().take(256).collect::<String>();
                                if reason.is_empty() {
                                    break 'session "inbound rejection reason cannot be empty".to_owned();
                                }
                                if let Err(error) = write_frame(&mut self.send, FRAME_REJECT, sequence, reason.as_bytes()).await {
                                    break 'session format!("could not reject peer message: {error}");
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
                    PendingOutbound::MlsCommit { request_id } => {
                        yield PeerEvent::MlsCommitDeliveryUnknown { request_id };
                    }
                    PendingOutbound::MlsProposal { request_id } => {
                        yield PeerEvent::MlsProposalDeliveryUnknown { request_id };
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
            | PeerEvent::MlsCommitReceived { .. }
            | PeerEvent::MlsProposalReceived { .. }
            | PeerEvent::MlsCommitRequested { .. }
            | PeerEvent::MlsEventAcknowledged { .. }
            | PeerEvent::MlsCommitAcknowledged { .. }
            | PeerEvent::MlsProposalAcknowledged { .. }
            | PeerEvent::MlsEventRejected { .. }
            | PeerEvent::MlsCommitRejected { .. }
            | PeerEvent::MlsProposalRejected { .. }
            | PeerEvent::Unauthorized { .. } => {}
            PeerEvent::MlsEventDeliveryUnknown { .. } => {
                return Err("MLS event delivery could not be confirmed".to_owned());
            }
            PeerEvent::MlsCommitDeliveryUnknown { .. } => {
                return Err("MLS Commit delivery could not be confirmed".to_owned());
            }
            PeerEvent::MlsProposalDeliveryUnknown { .. } => {
                return Err("MLS proposal delivery could not be confirmed".to_owned());
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
        FRAME_MLS_COMMIT => {
            if length == 0 || length > MAX_MLS_COMMIT_BYTES {
                return Err(format!(
                    "MLS Commit length must be between 1 and {MAX_MLS_COMMIT_BYTES}"
                ));
            }
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read MLS Commit frame: {error}"))?;
            Ok(Frame::MlsCommit {
                sequence,
                commit: decode_mls_commit(&bytes)?,
            })
        }
        FRAME_MLS_PROPOSAL => {
            if length == 0 || length > MAX_MLS_PROPOSAL_BYTES {
                return Err(format!(
                    "MLS proposal length must be between 1 and {MAX_MLS_PROPOSAL_BYTES}"
                ));
            }
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read MLS proposal frame: {error}"))?;
            Ok(Frame::MlsProposal {
                sequence,
                proposal: decode_mls_proposal(&bytes)?,
            })
        }
        FRAME_MLS_COMMIT_REQUEST if length == 24 && sequence == 0 => {
            let mut group_id = vec![0; 16];
            reader
                .read_exact(&mut group_id)
                .await
                .map_err(|error| format!("could not read MLS Commit request group ID: {error}"))?;
            let mut epoch = [0; 8];
            reader
                .read_exact(&mut epoch)
                .await
                .map_err(|error| format!("could not read MLS Commit request epoch: {error}"))?;
            let predecessor_epoch = u64::from_be_bytes(epoch);
            if predecessor_epoch > i64::MAX as u64 {
                return Err("MLS Commit request epoch exceeds the local limit".to_owned());
            }
            Ok(Frame::MlsCommitRequest {
                group_id,
                predecessor_epoch,
            })
        }
        FRAME_MLS_COMMIT_REQUEST => Err("peer sent an invalid MLS Commit request frame".to_owned()),
        FRAME_ACK if length == 0 && sequence != 0 => Ok(Frame::Ack { sequence }),
        FRAME_ACK => Err("peer sent an invalid ACK frame".to_owned()),
        FRAME_REJECT if (1..=1024).contains(&length) && sequence != 0 => {
            let mut bytes = vec![0; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read peer rejection reason: {error}"))?;
            let reason = String::from_utf8(bytes)
                .map_err(|error| format!("peer rejection reason is not valid UTF-8: {error}"))?;
            Ok(Frame::Reject { sequence, reason })
        }
        FRAME_REJECT => Err("peer sent an invalid rejection frame".to_owned()),
        FRAME_CLOSE if length == 0 && sequence == 0 => Ok(Frame::Close),
        FRAME_CLOSE => Err("peer sent an invalid disconnect frame".to_owned()),
        FRAME_CLOSE_ACK if length == 0 && sequence == 0 => Ok(Frame::CloseAck),
        FRAME_CLOSE_ACK => Err("peer sent an invalid disconnect acknowledgement".to_owned()),
        _ => Err(format!("unknown peer session frame type: {kind}")),
    }
}

fn encode_mls_proposal(proposal: &MlsProposalEnvelope) -> Result<Vec<u8>, String> {
    if proposal.event_id.iter().all(|byte| *byte == 0)
        || proposal.author_device.iter().all(|byte| *byte == 0)
        || proposal.group_id.len() != 16
        || proposal.epoch > i64::MAX as u64
        || proposal.proposal.is_empty()
        || proposal.proposal.len() > MAX_MLS_PROPOSAL_BYTES
        || proposal.event_id.as_slice() != &blake3::hash(&proposal.proposal).as_bytes()[..16]
    {
        return Err("MLS proposal has an invalid or oversized envelope".to_owned());
    }
    let mut output = Vec::with_capacity(84 + proposal.proposal.len());
    output.extend_from_slice(MLS_PROPOSAL_MAGIC);
    output.extend_from_slice(&MLS_PROPOSAL_VERSION.to_be_bytes());
    output.extend_from_slice(&proposal.event_id);
    output.extend_from_slice(&proposal.author_device);
    output.extend_from_slice(&(proposal.group_id.len() as u16).to_be_bytes());
    output.extend_from_slice(&proposal.group_id);
    output.extend_from_slice(&proposal.epoch.to_be_bytes());
    output.extend_from_slice(&(proposal.proposal.len() as u32).to_be_bytes());
    output.extend_from_slice(&proposal.proposal);
    if output.len() > MAX_MLS_PROPOSAL_BYTES {
        return Err("serialized MLS proposal exceeds the transport limit".to_owned());
    }
    Ok(output)
}

fn decode_mls_proposal(bytes: &[u8]) -> Result<MlsProposalEnvelope, String> {
    const FIXED: usize = 4 + 2 + 16 + 32 + 2 + 16 + 8 + 4;
    if bytes.len() < FIXED
        || bytes.len() > MAX_MLS_PROPOSAL_BYTES
        || &bytes[..4] != MLS_PROPOSAL_MAGIC
    {
        return Err("invalid or oversized MLS proposal envelope".to_owned());
    }
    let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    if version != MLS_PROPOSAL_VERSION {
        return Err(format!(
            "unsupported MLS proposal envelope version: {version}"
        ));
    }
    let mut cursor = 6;
    let event_id: [u8; 16] = bytes[cursor..cursor + 16].try_into().unwrap();
    cursor += 16;
    let author_device: [u8; 32] = bytes[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let group_len = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2;
    if group_len != 16 {
        return Err("MLS proposal group ID must be 16 bytes".to_owned());
    }
    let group_id = bytes[cursor..cursor + group_len].to_vec();
    cursor += group_len;
    let epoch = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let proposal_len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    if event_id.iter().all(|byte| *byte == 0)
        || author_device.iter().all(|byte| *byte == 0)
        || epoch > i64::MAX as u64
        || proposal_len == 0
        || cursor.checked_add(proposal_len) != Some(bytes.len())
    {
        return Err("MLS proposal envelope metadata or lengths are invalid".to_owned());
    }
    let proposal = bytes[cursor..].to_vec();
    if event_id.as_slice() != &blake3::hash(&proposal).as_bytes()[..16] {
        return Err("MLS proposal event ID does not match its bytes".to_owned());
    }
    Ok(MlsProposalEnvelope {
        event_id,
        author_device,
        group_id,
        epoch,
        proposal,
    })
}

fn encode_mls_commit(commit: &MlsCommitEnvelope) -> Result<Vec<u8>, String> {
    if commit.event_id.iter().all(|byte| *byte == 0)
        || commit.author_device.iter().all(|byte| *byte == 0)
        || commit.group_id.len() != 16
        || commit.predecessor_epoch > i64::MAX as u64
        || commit.epoch != commit.predecessor_epoch.saturating_add(1)
        || commit.commit.is_empty()
        || commit.commit.len() > MAX_MLS_COMMIT_BYTES
    {
        return Err("MLS Commit has an invalid or oversized envelope".to_owned());
    }
    let mut output = Vec::with_capacity(4 + 2 + 16 + 32 + 2 + 16 + 8 + 8 + 4 + commit.commit.len());
    output.extend_from_slice(MLS_COMMIT_MAGIC);
    output.extend_from_slice(&MLS_COMMIT_VERSION.to_be_bytes());
    output.extend_from_slice(&commit.event_id);
    output.extend_from_slice(&commit.author_device);
    output.extend_from_slice(&(commit.group_id.len() as u16).to_be_bytes());
    output.extend_from_slice(&commit.group_id);
    output.extend_from_slice(&commit.predecessor_epoch.to_be_bytes());
    output.extend_from_slice(&commit.epoch.to_be_bytes());
    output.extend_from_slice(&(commit.commit.len() as u32).to_be_bytes());
    output.extend_from_slice(&commit.commit);
    if output.len() > MAX_MLS_COMMIT_BYTES {
        return Err("serialized MLS Commit exceeds the transport limit".to_owned());
    }
    Ok(output)
}

fn decode_mls_commit(bytes: &[u8]) -> Result<MlsCommitEnvelope, String> {
    const FIXED: usize = 4 + 2 + 16 + 32 + 2 + 16 + 8 + 8 + 4;
    if bytes.len() < FIXED || bytes.len() > MAX_MLS_COMMIT_BYTES || &bytes[..4] != MLS_COMMIT_MAGIC
    {
        return Err("invalid or oversized MLS Commit envelope".to_owned());
    }
    let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    if version != MLS_COMMIT_VERSION {
        return Err(format!(
            "unsupported MLS Commit envelope version: {version}"
        ));
    }
    let mut cursor = 6;
    let event_id: [u8; 16] = bytes[cursor..cursor + 16].try_into().unwrap();
    cursor += 16;
    let author_device: [u8; 32] = bytes[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let group_len = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2;
    if group_len != 16 {
        return Err("MLS Commit group ID must be 16 bytes".to_owned());
    }
    let group_id = bytes[cursor..cursor + group_len].to_vec();
    cursor += group_len;
    let predecessor_epoch = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let epoch = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let commit_len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    if commit_len == 0
        || cursor.checked_add(commit_len) != Some(bytes.len())
        || event_id.iter().all(|byte| *byte == 0)
        || author_device.iter().all(|byte| *byte == 0)
        || predecessor_epoch > i64::MAX as u64
        || epoch != predecessor_epoch.saturating_add(1)
    {
        return Err("MLS Commit envelope metadata or lengths are invalid".to_owned());
    }
    Ok(MlsCommitEnvelope {
        event_id,
        author_device,
        group_id,
        predecessor_epoch,
        epoch,
        commit: bytes[cursor..].to_vec(),
    })
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
    async fn direct_sessions_exchange_and_ack_persistable_mls_proposals() {
        let listener_seed = [0x46; 32];
        let sender_seed = [0x47; 32];
        let sender_key = SecretKey::from_bytes(&sender_seed);
        let listener = bind_listener(
            SecretKey::from_bytes(&listener_seed),
            "127.0.0.1:0".parse().unwrap(),
            sender_key.public(),
        )
        .await
        .expect("proposal receiver should bind a loopback endpoint");
        let listener_id = listener.id();
        let sender_public = *sender_key.public().as_bytes();
        let address = listener
            .direct_addresses()
            .into_iter()
            .find(|address| address.ip().is_loopback())
            .expect("listener should announce its loopback socket");
        let receiver_task = tokio::spawn(async move {
            let session = listener
                .accept_session()
                .await
                .expect("listener should accept pinned sender");
            let (commands, receiver) = mpsc::channel(4);
            let mut events = Box::pin(session.run(receiver));
            while let Some(event) = events.next().await {
                if let PeerEvent::MlsProposalReceived {
                    sequence, proposal, ..
                } = event
                {
                    commands
                        .send(PeerCommand::AcceptInbound { sequence })
                        .await
                        .expect("receiver should queue ACK after persistence");
                    commands
                        .send(PeerCommand::Disconnect)
                        .await
                        .expect("receiver should keep the session open until ACK is written");
                    while let Some(event) = events.next().await {
                        if matches!(event, PeerEvent::Disconnected { .. }) {
                            return proposal;
                        }
                    }
                    panic!("receiver session ended before disconnect completed");
                }
            }
            panic!("receiver session ended before the MLS proposal arrived");
        });

        let session = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_peer(sender_key, listener_id, address),
        )
        .await
        .expect("sender should connect before deadline")
        .expect("sender should connect to pinned listener");
        let (commands, receiver) = mpsc::channel(4);
        let mut events = Box::pin(session.run(receiver));
        let proposal_bytes = vec![0x57; 48];
        let digest = blake3::hash(&proposal_bytes);
        let mut event_id = [0; 16];
        event_id.copy_from_slice(&digest.as_bytes()[..16]);
        let proposal = MlsProposalEnvelope {
            event_id,
            author_device: sender_public,
            group_id: vec![0x48; 16],
            epoch: 1,
            proposal: proposal_bytes,
        };
        commands
            .send(PeerCommand::SendMlsProposal {
                request_id: 8,
                proposal: proposal.clone(),
            })
            .await
            .expect("sender should queue the proposal frame");
        let mut acknowledged = false;
        while let Some(event) = tokio::time::timeout(Duration::from_secs(8), events.next())
            .await
            .expect("proposal ACK should arrive before deadline")
        {
            match event {
                PeerEvent::MlsProposalAcknowledged { request_id: 8 } => {
                    acknowledged = true;
                    break;
                }
                PeerEvent::Connected { .. } => {}
                other => panic!("unexpected sender proposal event: {other:?}"),
            }
        }
        assert!(
            acknowledged,
            "accepted proposal should receive a transport ACK"
        );
        commands
            .send(PeerCommand::Disconnect)
            .await
            .expect("sender should close the proposal test session");
        let received = tokio::time::timeout(Duration::from_secs(8), receiver_task)
            .await
            .expect("receiver task should return");
        assert_eq!(received.unwrap(), proposal);
    }

    #[tokio::test]
    async fn strict_session_frames_reject_unknown_and_malformed_data() {
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
            (FRAME_REJECT, 0, &b"bad"[..], "invalid rejection"),
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

    #[test]
    fn mls_commit_envelope_round_trips_and_rejects_wrong_epoch() {
        let commit = MlsCommitEnvelope {
            event_id: [0x71; 16],
            author_device: [0x72; 32],
            group_id: [0x73; 16].to_vec(),
            predecessor_epoch: 8,
            epoch: 9,
            commit: vec![0x74; 96],
        };
        let encoded = encode_mls_commit(&commit).expect("valid Commit should serialize");
        assert_eq!(decode_mls_commit(&encoded).unwrap(), commit);

        let mut tampered = encoded;
        tampered[6 + 16 + 32 + 2 + 16 + 8 + 7] = 10;
        assert!(decode_mls_commit(&tampered).is_err());

        let mut invalid = commit;
        invalid.epoch = 11;
        assert!(encode_mls_commit(&invalid).is_err());
    }

    #[test]
    fn mls_proposal_envelope_round_trips_and_binds_event_id_to_bytes() {
        let proposal_bytes = vec![0x75; 64];
        let digest = blake3::hash(&proposal_bytes);
        let mut event_id = [0; 16];
        event_id.copy_from_slice(&digest.as_bytes()[..16]);
        let proposal = MlsProposalEnvelope {
            event_id,
            author_device: [0x72; 32],
            group_id: [0x73; 16].to_vec(),
            epoch: 9,
            proposal: proposal_bytes,
        };
        let encoded = encode_mls_proposal(&proposal).expect("valid proposal should serialize");
        assert_eq!(decode_mls_proposal(&encoded).unwrap(), proposal);

        let mut tampered = proposal.clone();
        tampered.proposal[0] ^= 1;
        assert!(encode_mls_proposal(&tampered).is_err());

        let mut invalid = proposal;
        invalid.epoch = u64::MAX;
        assert!(encode_mls_proposal(&invalid).is_err());
    }

    #[tokio::test]
    async fn strict_session_parser_round_trips_mls_proposal_frame() {
        let proposal_bytes = vec![0x84; 48];
        let digest = blake3::hash(&proposal_bytes);
        let mut event_id = [0; 16];
        event_id.copy_from_slice(&digest.as_bytes()[..16]);
        let proposal = MlsProposalEnvelope {
            event_id,
            author_device: [0x82; 32],
            group_id: [0x83; 16].to_vec(),
            epoch: 3,
            proposal: proposal_bytes,
        };
        let payload = encode_mls_proposal(&proposal).unwrap();
        let (mut writer, mut reader) = duplex(1024);
        write_frame(&mut writer, FRAME_MLS_PROPOSAL, 4, &payload)
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Frame::MlsProposal {
                sequence: 4,
                proposal,
            }
        );
    }

    #[tokio::test]
    async fn strict_session_parser_round_trips_mls_commit_frame() {
        let commit = MlsCommitEnvelope {
            event_id: [0x81; 16],
            author_device: [0x82; 32],
            group_id: [0x83; 16].to_vec(),
            predecessor_epoch: 0,
            epoch: 1,
            commit: vec![0x84; 64],
        };
        let payload = encode_mls_commit(&commit).unwrap();
        let (mut writer, mut reader) = duplex(1024);
        write_frame(&mut writer, FRAME_MLS_COMMIT, 3, &payload)
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Frame::MlsCommit {
                sequence: 3,
                commit
            }
        );
    }

    #[tokio::test]
    async fn strict_session_parser_round_trips_and_bounds_commit_requests() {
        let mut payload = vec![0x91; 16];
        payload.extend_from_slice(&7_u64.to_be_bytes());
        let (mut writer, mut reader) = duplex(128);
        write_frame(&mut writer, FRAME_MLS_COMMIT_REQUEST, 0, &payload)
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Frame::MlsCommitRequest {
                group_id: vec![0x91; 16],
                predecessor_epoch: 7,
            }
        );

        let mut oversized_epoch = vec![0x92; 16];
        oversized_epoch.extend_from_slice(&u64::MAX.to_be_bytes());
        let (mut writer, mut reader) = duplex(128);
        write_frame(&mut writer, FRAME_MLS_COMMIT_REQUEST, 0, &oversized_epoch)
            .await
            .unwrap();
        assert!(read_frame(&mut reader).await.is_err());
    }
}
