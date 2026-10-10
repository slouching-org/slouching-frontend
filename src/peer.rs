use crate::{blob_store::EncryptedBlobStore, file_transfer::FileOffer};
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

/// Direct-only protocol version used for persistent paired-device sessions.
pub const PEER_ALPN: &[u8] = b"org.slouching.peer/10";
const FRAME_MAGIC: &[u8; 4] = b"SLCH";
const FRAME_VERSION: u16 = 10;
const FRAME_DATA: u8 = 1;
const FRAME_ACK: u8 = 2;
const FRAME_CLOSE: u8 = 3;
const FRAME_CLOSE_ACK: u8 = 4;
const FRAME_MLS_EVENT: u8 = 5;
const FRAME_MLS_COMMIT: u8 = 6;
const FRAME_REJECT: u8 = 7;
const FRAME_MLS_COMMIT_REQUEST: u8 = 8;
const FRAME_MLS_PROPOSAL: u8 = 9;
const FRAME_MLS_KEY_PACKAGE: u8 = 10;
const FRAME_MLS_WELCOME: u8 = 11;
const FRAME_MLS_DELEGATED_COPY: u8 = 12;
const FRAME_MLS_COPY_FETCH: u8 = 13;
const FRAME_CALL_SIGNAL: u8 = 14;
const ATTACHMENT_STREAM_MAGIC: &[u8; 4] = b"SLAB";
const ATTACHMENT_STREAM_VERSION: u16 = 1;
const ATTACHMENT_STREAM_HEADER_BYTES: usize = 4 + 2 + 16 + 16 + 32 + 8;
const MLS_EVENT_MAGIC: &[u8; 4] = b"SLME";
const MLS_EVENT_VERSION: u16 = 1;
const MLS_COMMIT_MAGIC: &[u8; 4] = b"SLMC";
const MLS_COMMIT_VERSION: u16 = 1;
const MLS_PROPOSAL_MAGIC: &[u8; 4] = b"SLMP";
const MLS_PROPOSAL_VERSION: u16 = 1;
const MLS_KEY_PACKAGE_MAGIC: &[u8; 4] = b"SLKP";
const MLS_KEY_PACKAGE_VERSION: u16 = 1;
const MLS_WELCOME_MAGIC: &[u8; 4] = b"SLMW";
const MLS_WELCOME_VERSION: u16 = 2;
const MLS_DELEGATED_COPY_MAGIC: &[u8; 4] = b"SLDG";
const MLS_DELEGATED_COPY_VERSION: u16 = 1;
const CALL_SIGNAL_MAGIC: &[u8; 4] = b"SLCS";
const CALL_SIGNAL_VERSION: u16 = 1;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_MLS_EVENT_BYTES: usize = 64 * 1024;
const MAX_MLS_COMMIT_BYTES: usize = 64 * 1024;
const MAX_MLS_PROPOSAL_BYTES: usize = 64 * 1024;
const MAX_MLS_KEY_PACKAGE_BYTES: usize = 64 * 1024;
const MAX_MLS_WELCOME_BYTES: usize = 256 * 1024;
const MAX_MLS_DELEGATED_COPY_BYTES: usize = 96 * 1024;
const MAX_CALL_SIGNAL_BYTES: usize = 128 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 16 * 1024;
pub const MAX_PENDING_MESSAGES: usize = 16;
const MAX_MLS_COMMIT_REQUESTS_PER_SESSION: u8 = 16;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const ACCEPT_STREAM_TIMEOUT: Duration = Duration::from_secs(8);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(8);

pub struct DirectPeerListener {
    endpoint: Endpoint,
    expected_peer: Option<EndpointId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantRelay {
    pub url: iroh::RelayUrl,
    pub access_token: String,
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
pub struct MlsKeyPackageEnvelope {
    pub event_id: [u8; 16],
    pub invitee_device: [u8; 32],
    pub group_id: Vec<u8>,
    pub key_package: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsWelcomeEnvelope {
    pub event_id: [u8; 16],
    pub invitee_device: [u8; 32],
    pub group_id: Vec<u8>,
    pub purpose: MlsGroupPurpose,
    pub welcome: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CallSignalKind {
    Offer = 1,
    Answer = 2,
    IceCandidate = 3,
    End = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSignal {
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub kind: CallSignalKind,
    /// Opaque, bounded JSON payload for SDP or an ICE candidate; empty for End.
    pub payload: Vec<u8>,
}

/// The application-level use of an MLS group. Call media keys are never
/// exported from conversation groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MlsGroupPurpose {
    Conversation = 0,
    Call = 1,
}

impl TryFrom<u8> for MlsGroupPurpose {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Conversation),
            1 => Ok(Self::Call),
            _ => Err("MLS group purpose is invalid".to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedMlsCopyGrant {
    pub event_id: [u8; 16],
    pub author_device: [u8; 32],
    pub recipient_device: [u8; 32],
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub expires_at_unix: i64,
    pub checkpoint: Option<Vec<u8>>,
    pub ciphertext_digest: [u8; 32],
    pub signature: [u8; 64],
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
    SendMlsKeyPackage {
        request_id: u64,
        key_package: MlsKeyPackageEnvelope,
    },
    SendMlsWelcome {
        request_id: u64,
        welcome: MlsWelcomeEnvelope,
    },
    #[allow(dead_code)] // Used by the WebRTC negotiation flow added next.
    SendCallSignal {
        request_id: u64,
        signal: CallSignal,
    },
    SendAttachmentBlob {
        request_id: u64,
        group_id: [u8; 16],
        transfer_id: [u8; 16],
        ciphertext_hash: [u8; 32],
    },
    #[allow(dead_code)]
    SendDelegatedMlsCopy {
        request_id: u64,
        #[allow(dead_code)]
        grant: Box<DelegatedMlsCopyGrant>,
        #[allow(dead_code)]
        event: Box<MlsEventEnvelope>,
    },
    #[allow(dead_code)]
    RequestDelegatedMlsCopies,
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
        direct_address: Option<SocketAddr>,
    },
    AttachmentBlobSent {
        request_id: u64,
        result: Result<(), String>,
    },
    AttachmentBlobReceived {
        group_id: [u8; 16],
        transfer_id: [u8; 16],
        result: Result<(), String>,
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
    MlsKeyPackageReceived {
        sequence: u64,
        peer_id: EndpointId,
        key_package: MlsKeyPackageEnvelope,
    },
    MlsWelcomeReceived {
        sequence: u64,
        peer_id: EndpointId,
        welcome: MlsWelcomeEnvelope,
    },
    CallSignalReceived {
        sequence: u64,
        peer_id: EndpointId,
        signal: CallSignal,
    },
    DelegatedMlsCopyReceived {
        sequence: u64,
        peer_id: EndpointId,
        grant: Box<DelegatedMlsCopyGrant>,
        event: Box<MlsEventEnvelope>,
    },
    DelegatedMlsCopiesRequested {
        peer_id: EndpointId,
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
    MlsKeyPackageAcknowledged {
        request_id: u64,
    },
    MlsWelcomeAcknowledged {
        request_id: u64,
    },
    CallSignalAcknowledged {
        request_id: u64,
    },
    DelegatedMlsCopyAcknowledged {
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
    MlsKeyPackageRejected {
        request_id: u64,
        reason: String,
    },
    MlsWelcomeRejected {
        request_id: u64,
        reason: String,
    },
    CallSignalRejected {
        request_id: u64,
        reason: String,
    },
    DelegatedMlsCopyRejected {
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
    MlsKeyPackageDeliveryUnknown {
        request_id: u64,
    },
    MlsWelcomeDeliveryUnknown {
        request_id: u64,
    },
    CallSignalDeliveryUnknown {
        request_id: u64,
    },
    DelegatedMlsCopyDeliveryUnknown {
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
    MlsKeyPackage { request_id: u64 },
    MlsWelcome { request_id: u64 },
    CallSignal { request_id: u64 },
    DelegatedMlsCopy { request_id: u64 },
}

pub struct DirectPeerSession {
    endpoint: Endpoint,
    close_endpoint: bool,
    connection: Connection,
    send: iroh::endpoint::SendStream,
    receive: iroh::endpoint::RecvStream,
    peer_id: EndpointId,
}

/// Send one ciphertext blob over a separate unidirectional stream on an
/// already authenticated peer connection. The offer must come from the
/// sender's authenticated SQLCipher MLS manifest.
pub async fn send_attachment_blob(
    connection: &Connection,
    store: &EncryptedBlobStore,
    group_id: [u8; 16],
    offer: &FileOffer,
    ciphertext_hash: [u8; 32],
) -> Result<(), String> {
    offer.encode()?;
    let ciphertext_bytes = offer
        .total_bytes
        .checked_add(u64::from(offer.chunk_count).saturating_mul(16))
        .ok_or_else(|| "encrypted attachment size overflowed".to_owned())?;
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| format!("could not open attachment QUIC stream: {error}"))?;
    stream
        .write_all(ATTACHMENT_STREAM_MAGIC)
        .await
        .map_err(|error| format!("could not write attachment stream marker: {error}"))?;
    stream
        .write_all(&ATTACHMENT_STREAM_VERSION.to_be_bytes())
        .await
        .map_err(|error| format!("could not write attachment stream version: {error}"))?;
    stream
        .write_all(&group_id)
        .await
        .map_err(|error| format!("could not write attachment group ID: {error}"))?;
    stream
        .write_all(&offer.transfer_id)
        .await
        .map_err(|error| format!("could not write attachment transfer ID: {error}"))?;
    stream
        .write_all(&ciphertext_hash)
        .await
        .map_err(|error| format!("could not write attachment ciphertext hash: {error}"))?;
    stream
        .write_all(&ciphertext_bytes.to_be_bytes())
        .await
        .map_err(|error| format!("could not write attachment ciphertext size: {error}"))?;
    let mut reader = store
        .ciphertext_reader(ciphertext_hash)
        .take(ciphertext_bytes);
    let transferred = tokio::io::copy(&mut reader, &mut stream)
        .await
        .map_err(|error| format!("could not stream encrypted attachment: {error}"))?;
    if transferred != ciphertext_bytes {
        return Err("stored encrypted attachment is shorter than its MLS offer".to_owned());
    }
    stream
        .finish()
        .map_err(|error| format!("could not finish attachment QUIC stream: {error}"))
}

/// Receive and persist one ciphertext blob. `offer` and `ciphertext_hash`
/// must have been loaded from the local SQLCipher manifest after MLS
/// authentication; the stream header must match them exactly.
#[cfg(test)]
pub async fn receive_attachment_blob(
    connection: &Connection,
    store: &EncryptedBlobStore,
    expected_group_id: [u8; 16],
    offer: &FileOffer,
    expected_hash: [u8; 32],
) -> Result<(), String> {
    offer.encode()?;
    let mut stream = connection
        .accept_uni()
        .await
        .map_err(|error| format!("could not accept attachment QUIC stream: {error}"))?;
    let header = read_attachment_blob_header(&mut stream).await?;
    let expected_ciphertext_bytes = offer
        .total_bytes
        .checked_add(u64::from(offer.chunk_count).saturating_mul(16))
        .ok_or_else(|| "encrypted attachment size overflowed".to_owned())?;
    if header.group_id != expected_group_id
        || header.transfer_id != offer.transfer_id
        || header.ciphertext_hash != expected_hash
        || header.ciphertext_bytes != expected_ciphertext_bytes
    {
        return Err("attachment stream does not match its authenticated MLS offer".to_owned());
    }
    store
        .import_ciphertext_stream(stream, offer, expected_hash)
        .await
}

/// Receive a stream only when the local MLS manifest exists and the connected
/// device is a verified member of that exact group.
async fn receive_authorized_attachment_stream<R>(
    mut stream: R,
    peer_id: EndpointId,
) -> Result<([u8; 16], [u8; 16]), String>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let header = read_attachment_blob_header(&mut stream).await?;
    let offer = load_authorized_attachment(
        header.group_id,
        header.transfer_id,
        header.ciphertext_hash,
        peer_id,
    )
    .await?;
    let expected_ciphertext_bytes = offer
        .total_bytes
        .checked_add(u64::from(offer.chunk_count).saturating_mul(16))
        .ok_or_else(|| "encrypted attachment size overflowed".to_owned())?;
    if header.ciphertext_bytes != expected_ciphertext_bytes {
        return Err("attachment stream size does not match its MLS offer".to_owned());
    }
    let store = EncryptedBlobStore::open_default().await?;
    store
        .import_ciphertext_stream(stream, &offer, header.ciphertext_hash)
        .await?;
    store.shutdown().await?;
    Ok((header.group_id, header.transfer_id))
}

async fn load_authorized_attachment(
    group_id: [u8; 16],
    transfer_id: [u8; 16],
    ciphertext_hash: [u8; 32],
    peer_id: EndpointId,
) -> Result<FileOffer, String> {
    tokio::task::spawn_blocking(move || {
        let member_devices = crate::storage::list_mls_group_member_devices(group_id)?;
        if !member_devices.contains(peer_id.as_bytes()) {
            return Err("connected device is not a member of the attachment MLS group".to_owned());
        }
        crate::storage::list_file_attachments(group_id)?
            .into_iter()
            .find(|attachment| {
                attachment.offer.transfer_id == transfer_id
                    && attachment.ciphertext_hash == ciphertext_hash
            })
            .map(|attachment| attachment.offer)
            .ok_or_else(|| "attachment is not present in the authenticated MLS manifest".to_owned())
    })
    .await
    .map_err(|error| format!("attachment authorization task failed: {error}"))?
}

struct AttachmentBlobHeader {
    group_id: [u8; 16],
    transfer_id: [u8; 16],
    ciphertext_hash: [u8; 32],
    ciphertext_bytes: u64,
}

async fn read_attachment_blob_header<R>(reader: &mut R) -> Result<AttachmentBlobHeader, String>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0; ATTACHMENT_STREAM_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|error| format!("attachment stream header is incomplete: {error}"))?;
    if &header[..4] != ATTACHMENT_STREAM_MAGIC {
        return Err("attachment stream has an invalid marker".to_owned());
    }
    let version = u16::from_be_bytes(header[4..6].try_into().unwrap());
    if version != ATTACHMENT_STREAM_VERSION {
        return Err(format!("unsupported attachment stream version: {version}"));
    }
    Ok(AttachmentBlobHeader {
        group_id: header[6..22].try_into().unwrap(),
        transfer_id: header[22..38].try_into().unwrap(),
        ciphertext_hash: header[38..70].try_into().unwrap(),
        ciphertext_bytes: u64::from_be_bytes(header[70..78].try_into().unwrap()),
    })
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
    MlsKeyPackage {
        sequence: u64,
        key_package: MlsKeyPackageEnvelope,
    },
    MlsWelcome {
        sequence: u64,
        welcome: MlsWelcomeEnvelope,
    },
    CallSignal {
        sequence: u64,
        signal: CallSignal,
    },
    DelegatedMlsCopy {
        sequence: u64,
        grant: Box<DelegatedMlsCopyGrant>,
        event: Box<MlsEventEnvelope>,
    },
    MlsCopyFetch,
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
        if self
            .expected_peer
            .is_some_and(|expected| peer_id != expected)
        {
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
            close_endpoint: false,
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
                | PeerEvent::AttachmentBlobSent { .. }
                | PeerEvent::AttachmentBlobReceived { .. }
                | PeerEvent::Acknowledged { .. }
                | PeerEvent::MlsEventReceived { .. }
                | PeerEvent::MlsCommitReceived { .. }
                | PeerEvent::MlsProposalReceived { .. }
                | PeerEvent::MlsKeyPackageReceived { .. }
                | PeerEvent::MlsWelcomeReceived { .. }
                | PeerEvent::CallSignalReceived { .. }
                | PeerEvent::DelegatedMlsCopyReceived { .. }
                | PeerEvent::DelegatedMlsCopiesRequested { .. }
                | PeerEvent::MlsCommitRequested { .. }
                | PeerEvent::MlsEventAcknowledged { .. }
                | PeerEvent::MlsCommitAcknowledged { .. }
                | PeerEvent::MlsProposalAcknowledged { .. }
                | PeerEvent::MlsKeyPackageAcknowledged { .. }
                | PeerEvent::MlsWelcomeAcknowledged { .. }
                | PeerEvent::CallSignalAcknowledged { .. }
                | PeerEvent::DelegatedMlsCopyAcknowledged { .. }
                | PeerEvent::MlsEventRejected { .. }
                | PeerEvent::MlsCommitRejected { .. }
                | PeerEvent::MlsProposalRejected { .. }
                | PeerEvent::MlsKeyPackageRejected { .. }
                | PeerEvent::MlsWelcomeRejected { .. }
                | PeerEvent::CallSignalRejected { .. }
                | PeerEvent::DelegatedMlsCopyRejected { .. }
                | PeerEvent::Rejected { .. }
                | PeerEvent::DeliveryUnknown { .. }
                | PeerEvent::MlsEventDeliveryUnknown { .. }
                | PeerEvent::MlsCommitDeliveryUnknown { .. }
                | PeerEvent::MlsProposalDeliveryUnknown { .. }
                | PeerEvent::MlsKeyPackageDeliveryUnknown { .. }
                | PeerEvent::MlsWelcomeDeliveryUnknown { .. }
                | PeerEvent::CallSignalDeliveryUnknown { .. }
                | PeerEvent::DelegatedMlsCopyDeliveryUnknown { .. } => {}
            }
        }
        received.ok_or_else(|| "peer session ended before receiving text".to_owned())
    }

    #[allow(dead_code)]
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
            let mut received_copy_fetch = false;
            let mut seen_commit_requests = std::collections::HashSet::new();
            let mut closing = false;
            let mut close_deadline = Box::pin(tokio::time::sleep(CLOSE_TIMEOUT));
            let mut receive = self.receive;
            let (frame_sender, mut frame_receiver) = mpsc::channel(1);
            // Keep partial QUIC frame reads alive while the session handles commands.
            let _reader = tokio::spawn(async move {
                loop {
                    let frame = read_frame(&mut receive).await;
                    let finished = frame.is_err();
                    if frame_sender.send(frame).await.is_err() || finished {
                        break;
                    }
                }
            });
            let (side_event_sender, mut side_event_receiver) = mpsc::channel(8);
            let attachment_connection = self.connection.clone();
            let attachment_peer = self.peer_id;
            let attachment_events = side_event_sender.clone();
            let _attachment_reader = tokio::spawn(async move {
                loop {
                    let stream = match attachment_connection.accept_uni().await {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    let result = receive_authorized_attachment_stream(stream, attachment_peer).await;
                    let event = match result {
                        Ok((group_id, transfer_id)) => PeerEvent::AttachmentBlobReceived {
                            group_id,
                            transfer_id,
                            result: Ok(()),
                        },
                        Err(error) => PeerEvent::AttachmentBlobReceived {
                            group_id: [0; 16],
                            transfer_id: [0; 16],
                            result: Err(error),
                        },
                    };
                    if attachment_events.send(event).await.is_err() {
                        break;
                    }
                }
            });
            let direct_address = self
                .endpoint
                .remote_info(self.peer_id)
                .await
                .and_then(|info| {
                    info.addrs().find_map(|address| {
                        if !matches!(
                            address.usage(),
                            iroh::endpoint::TransportAddrUsage::Active
                        ) {
                            return None;
                        }
                        match address.addr() {
                            iroh::TransportAddr::Ip(address)
                                if address.port() != 0
                                    && !address.ip().is_unspecified()
                                    && !address.ip().is_multicast() =>
                            {
                                Some(*address)
                            }
                            _ => None,
                        }
                    })
                });
            yield PeerEvent::Connected {
                peer_id: self.peer_id,
                direct_address,
            };

            let disconnect_reason = 'session: loop {
                tokio::select! {
                    frame = frame_receiver.recv() => {
                        match frame {
                            Some(Ok(Frame::Data { sequence, text })) => {
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
                            Some(Ok(Frame::MlsEvent { sequence, event })) => {
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
                            Some(Ok(Frame::MlsCommit { sequence, commit })) => {
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
                            Some(Ok(Frame::DelegatedMlsCopy { sequence, grant, event })) => {
                                if closing || sequence != next_in_sequence || pending_inbound.len() >= MAX_PENDING_MESSAGES {
                                    break 'session "invalid or excessive delegated-copy sequence".to_owned();
                                }
                                let Some(next) = next_in_sequence.checked_add(1) else {
                                    break 'session "inbound message sequence exhausted".to_owned();
                                };
                                next_in_sequence = next;
                                pending_inbound.insert(sequence);
                                yield PeerEvent::DelegatedMlsCopyReceived { sequence, peer_id: self.peer_id, grant, event };
                            }
                            Some(Ok(Frame::MlsCopyFetch)) => {
                                if received_copy_fetch {
                                    break 'session "peer requested delegated copies more than once".to_owned();
                                }
                                received_copy_fetch = true;
                                yield PeerEvent::DelegatedMlsCopiesRequested { peer_id: self.peer_id };
                            }
                            Some(Ok(Frame::MlsProposal { sequence, proposal })) => {
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
                            Some(Ok(Frame::MlsKeyPackage { sequence, key_package })) => {
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
                                yield PeerEvent::MlsKeyPackageReceived {
                                    sequence,
                                    peer_id: self.peer_id,
                                    key_package,
                                };
                            }
                            Some(Ok(Frame::MlsWelcome { sequence, welcome })) => {
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
                                yield PeerEvent::MlsWelcomeReceived {
                                    sequence,
                                    peer_id: self.peer_id,
                                    welcome,
                                };
                            }
                            Some(Ok(Frame::CallSignal { sequence, signal })) => {
                                if closing || sequence != next_in_sequence || pending_inbound.len() >= MAX_PENDING_MESSAGES {
                                    break 'session "invalid or excessive call signaling sequence".to_owned();
                                }
                                let Some(next) = next_in_sequence.checked_add(1) else {
                                    break 'session "inbound message sequence exhausted".to_owned();
                                };
                                next_in_sequence = next;
                                pending_inbound.insert(sequence);
                                yield PeerEvent::CallSignalReceived {
                                    sequence,
                                    peer_id: self.peer_id,
                                    signal,
                                };
                            }
                            Some(Ok(Frame::MlsCommitRequest { group_id, predecessor_epoch })) => {
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
                            Some(Ok(Frame::Ack { sequence })) => {
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
                                    PendingOutbound::MlsKeyPackage { request_id } => {
                                        yield PeerEvent::MlsKeyPackageAcknowledged { request_id };
                                    }
                                    PendingOutbound::MlsWelcome { request_id } => {
                                        yield PeerEvent::MlsWelcomeAcknowledged { request_id };
                                    }
                                    PendingOutbound::CallSignal { request_id } => {
                                        yield PeerEvent::CallSignalAcknowledged { request_id };
                                    }
                                    PendingOutbound::DelegatedMlsCopy { request_id } => {
                                        yield PeerEvent::DelegatedMlsCopyAcknowledged { request_id };
                                    }
                                }
                            }
                            Some(Ok(Frame::Reject { sequence, reason })) => {
                                let Some(pending) = pending_sends.remove(&sequence) else {
                                    break 'session format!("peer rejected sequence {sequence} that is not outstanding");
                                };
                                match pending {
                                    PendingOutbound::Text(pending) => yield PeerEvent::Rejected { request_id: pending.request_id, reason },
                                    PendingOutbound::MlsEvent { request_id } => yield PeerEvent::MlsEventRejected { request_id, reason },
                                    PendingOutbound::MlsCommit { request_id } => yield PeerEvent::MlsCommitRejected { request_id, reason },
                                    PendingOutbound::MlsProposal { request_id } => yield PeerEvent::MlsProposalRejected { request_id, reason },
                                    PendingOutbound::MlsKeyPackage { request_id } => yield PeerEvent::MlsKeyPackageRejected { request_id, reason },
                                    PendingOutbound::MlsWelcome { request_id } => yield PeerEvent::MlsWelcomeRejected { request_id, reason },
                                    PendingOutbound::CallSignal { request_id } => yield PeerEvent::CallSignalRejected { request_id, reason },
                                    PendingOutbound::DelegatedMlsCopy { request_id } => yield PeerEvent::DelegatedMlsCopyRejected { request_id, reason },
                                }
                            }
                            Some(Ok(Frame::Close)) => {
                                if write_frame(&mut self.send, FRAME_CLOSE_ACK, 0, &[]).await.is_err() {
                                    break 'session "could not acknowledge peer disconnect".to_owned();
                                }
                                if self.send.finish().is_err() {
                                    break 'session "could not finish peer disconnect acknowledgement".to_owned();
                                }
                                let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.send.stopped()).await;
                                break 'session "peer disconnected".to_owned();
                            }
                            Some(Ok(Frame::CloseAck)) if closing => {
                                break 'session "local disconnect completed".to_owned();
                            }
                            Some(Ok(Frame::CloseAck)) => {
                                break 'session "unsolicited disconnect acknowledgement".to_owned();
                            }
                            Some(Err(error)) => break 'session error,
                            None => break 'session "peer session reader stopped".to_owned(),
                        }
                    }
                    event = side_event_receiver.recv() => {
                        if let Some(event) = event {
                            yield event;
                        }
                    }
                    command = commands.recv(), if !closing => {
                        match command {
                            Some(PeerCommand::SendAttachmentBlob { request_id, group_id, transfer_id, ciphertext_hash }) => {
                                let connection = self.connection.clone();
                                let peer_id = self.peer_id;
                                let event_sender = side_event_sender.clone();
                                tokio::spawn(async move {
                                    let result = async {
                                        let offer = load_authorized_attachment(group_id, transfer_id, ciphertext_hash, peer_id).await?;
                                        let store = EncryptedBlobStore::open_default().await?;
                                        let sent = send_attachment_blob(&connection, &store, group_id, &offer, ciphertext_hash).await;
                                        let shutdown = store.shutdown().await;
                                        sent.and(shutdown)
                                    }.await;
                                    let _ = event_sender.send(PeerEvent::AttachmentBlobSent { request_id, result }).await;
                                });
                            }
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
                            Some(PeerCommand::SendMlsKeyPackage { request_id, key_package }) => {
                                let payload = match encode_mls_key_package(&key_package) {
                                    Ok(payload) => payload,
                                    Err(reason) => {
                                        yield PeerEvent::MlsKeyPackageRejected { request_id, reason };
                                        continue;
                                    }
                                };
                                if pending_sends.len() >= MAX_PENDING_MESSAGES {
                                    yield PeerEvent::MlsKeyPackageRejected {
                                        request_id,
                                        reason: format!("at most {MAX_PENDING_MESSAGES} messages may await acknowledgement"),
                                    };
                                    continue;
                                }
                                let sequence = next_out_sequence;
                                let Some(next) = next_out_sequence.checked_add(1) else {
                                    break 'session "outbound message sequence exhausted".to_owned();
                                };
                                pending_sends.insert(sequence, PendingOutbound::MlsKeyPackage { request_id });
                                if let Err(error) = write_frame(&mut self.send, FRAME_MLS_KEY_PACKAGE, sequence, &payload).await {
                                    break 'session format!("could not send MLS KeyPackage: {error}");
                                }
                                next_out_sequence = next;
                            }
                            Some(PeerCommand::SendMlsWelcome { request_id, welcome }) => {
                                let payload = match encode_mls_welcome(&welcome) {
                                    Ok(payload) => payload,
                                    Err(reason) => {
                                        yield PeerEvent::MlsWelcomeRejected { request_id, reason };
                                        continue;
                                    }
                                };
                                if pending_sends.len() >= MAX_PENDING_MESSAGES {
                                    yield PeerEvent::MlsWelcomeRejected {
                                        request_id,
                                        reason: format!("at most {MAX_PENDING_MESSAGES} messages may await acknowledgement"),
                                    };
                                    continue;
                                }
                                let sequence = next_out_sequence;
                                let Some(next) = next_out_sequence.checked_add(1) else {
                                    break 'session "outbound message sequence exhausted".to_owned();
                                };
                                pending_sends.insert(sequence, PendingOutbound::MlsWelcome { request_id });
                                if let Err(error) = write_frame(&mut self.send, FRAME_MLS_WELCOME, sequence, &payload).await {
                                    break 'session format!("could not send MLS Welcome: {error}");
                                }
                                next_out_sequence = next;
                            }
                            Some(PeerCommand::SendCallSignal { request_id, signal }) => {
                                let payload = match encode_call_signal(&signal) {
                                    Ok(payload) => payload,
                                    Err(reason) => {
                                        yield PeerEvent::CallSignalRejected { request_id, reason };
                                        continue;
                                    }
                                };
                                if pending_sends.len() >= MAX_PENDING_MESSAGES {
                                    yield PeerEvent::CallSignalRejected {
                                        request_id,
                                        reason: "too many pending peer messages".into(),
                                    };
                                    continue;
                                }
                                let sequence = next_out_sequence;
                                let Some(next) = next_out_sequence.checked_add(1) else {
                                    break 'session "outbound message sequence exhausted".to_owned();
                                };
                                pending_sends.insert(sequence, PendingOutbound::CallSignal { request_id });
                                if let Err(error) = write_frame(&mut self.send, FRAME_CALL_SIGNAL, sequence, &payload).await {
                                    break 'session format!("could not send call signaling frame: {error}");
                                }
                                next_out_sequence = next;
                            }
                            Some(PeerCommand::SendDelegatedMlsCopy { request_id, grant, event }) => {
                                let payload = match encode_delegated_mls_copy(&grant, &event) {
                                    Ok(payload) => payload,
                                    Err(reason) => {
                                        yield PeerEvent::DelegatedMlsCopyRejected { request_id, reason };
                                        continue;
                                    }
                                };
                                if pending_sends.len() >= MAX_PENDING_MESSAGES {
                                    yield PeerEvent::DelegatedMlsCopyRejected { request_id, reason: "too many pending peer messages".into() };
                                    continue;
                                }
                                let sequence = next_out_sequence;
                                let Some(next) = next_out_sequence.checked_add(1) else {
                                    break 'session "outbound message sequence exhausted".to_owned();
                                };
                                pending_sends.insert(sequence, PendingOutbound::DelegatedMlsCopy { request_id });
                                if let Err(error) = write_frame(&mut self.send, FRAME_MLS_DELEGATED_COPY, sequence, &payload).await {
                                    break 'session format!("could not send delegated MLS copy: {error}");
                                }
                                next_out_sequence = next;
                            }
                            Some(PeerCommand::RequestDelegatedMlsCopies) => {
                                if let Err(error) = write_frame(&mut self.send, FRAME_MLS_COPY_FETCH, 0, &[]).await {
                                    break 'session format!("could not request delegated MLS copies: {error}");
                                }
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
                    PendingOutbound::MlsKeyPackage { request_id } => {
                        yield PeerEvent::MlsKeyPackageDeliveryUnknown { request_id };
                    }
                    PendingOutbound::MlsWelcome { request_id } => {
                        yield PeerEvent::MlsWelcomeDeliveryUnknown { request_id };
                    }
                    PendingOutbound::CallSignal { request_id } => {
                        yield PeerEvent::CallSignalDeliveryUnknown { request_id };
                    }
                    PendingOutbound::DelegatedMlsCopy { request_id } => {
                        yield PeerEvent::DelegatedMlsCopyDeliveryUnknown { request_id };
                    }
                }
            }
            self.connection.close(0_u32.into(), b"Slouching session ended");
            if self.close_endpoint {
                self.endpoint.close().await;
            }
            yield PeerEvent::Disconnected { reason: disconnect_reason };
        }
    }
}

pub async fn bind_listener(
    local_identity: SecretKey,
    bind_address: SocketAddr,
    expected_peer: EndpointId,
) -> Result<DirectPeerListener, String> {
    bind_listener_with_relay(local_identity, bind_address, expected_peer, None).await
}

pub async fn bind_listener_with_relay(
    local_identity: SecretKey,
    bind_address: SocketAddr,
    expected_peer: EndpointId,
    relay: Option<ParticipantRelay>,
) -> Result<DirectPeerListener, String> {
    let endpoint = bind_endpoint_with_relay(local_identity, bind_address, relay).await?;
    Ok(DirectPeerListener {
        endpoint,
        expected_peer: Some(expected_peer),
    })
}

/// Binds a helper listener that accepts any authenticated device identity.
/// Application frames still require their own author/device binding checks;
/// delegated copy frames require the signed grant author to match this peer.
#[allow(dead_code)]
pub async fn bind_helper_listener(
    local_identity: SecretKey,
    bind_address: SocketAddr,
) -> Result<DirectPeerListener, String> {
    bind_helper_listener_with_relay(local_identity, bind_address, None).await
}

pub async fn bind_helper_listener_with_relay(
    local_identity: SecretKey,
    bind_address: SocketAddr,
    relay: Option<ParticipantRelay>,
) -> Result<DirectPeerListener, String> {
    let endpoint = bind_endpoint_with_relay(local_identity, bind_address, relay).await?;
    Ok(DirectPeerListener {
        endpoint,
        expected_peer: None,
    })
}

pub async fn connect_peer(
    local_identity: SecretKey,
    expected_peer: EndpointId,
    peer_address: SocketAddr,
) -> Result<DirectPeerSession, String> {
    connect_peer_with_relay(local_identity, expected_peer, Some(peer_address), None).await
}

pub async fn connect_peer_with_relay(
    local_identity: SecretKey,
    expected_peer: EndpointId,
    peer_address: Option<SocketAddr>,
    relay: Option<ParticipantRelay>,
) -> Result<DirectPeerSession, String> {
    if peer_address.is_none() && relay.is_none() {
        return Err("enter a reachable peer address or configure the group's relay".to_owned());
    }
    let endpoint = bind_endpoint_with_relay(
        local_identity,
        "0.0.0.0:0".parse().expect("valid bind addr"),
        relay.clone(),
    )
    .await?;
    let mut remote = EndpointAddr::new(expected_peer);
    if let Some(peer_address) = peer_address {
        remote = remote.with_ip_addr(peer_address);
    }
    if let Some(relay) = relay {
        remote = remote.with_relay_url(relay.url);
    }
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(remote, PEER_ALPN))
        .await
        .map_err(|_| "timed out connecting to direct peer".to_owned())?
        .map_err(|error| format!("could not connect to pinned peer: {error}"))?;
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
        close_endpoint: true,
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
            | PeerEvent::AttachmentBlobSent { .. }
            | PeerEvent::AttachmentBlobReceived { .. }
            | PeerEvent::Acknowledged { .. }
            | PeerEvent::MlsEventReceived { .. }
            | PeerEvent::MlsCommitReceived { .. }
            | PeerEvent::MlsProposalReceived { .. }
            | PeerEvent::MlsKeyPackageReceived { .. }
            | PeerEvent::MlsWelcomeReceived { .. }
            | PeerEvent::CallSignalReceived { .. }
            | PeerEvent::DelegatedMlsCopyReceived { .. }
            | PeerEvent::DelegatedMlsCopiesRequested { .. }
            | PeerEvent::MlsCommitRequested { .. }
            | PeerEvent::MlsEventAcknowledged { .. }
            | PeerEvent::MlsCommitAcknowledged { .. }
            | PeerEvent::MlsProposalAcknowledged { .. }
            | PeerEvent::MlsKeyPackageAcknowledged { .. }
            | PeerEvent::MlsWelcomeAcknowledged { .. }
            | PeerEvent::CallSignalAcknowledged { .. }
            | PeerEvent::DelegatedMlsCopyAcknowledged { .. }
            | PeerEvent::MlsEventRejected { .. }
            | PeerEvent::MlsCommitRejected { .. }
            | PeerEvent::MlsProposalRejected { .. }
            | PeerEvent::MlsKeyPackageRejected { .. }
            | PeerEvent::MlsWelcomeRejected { .. }
            | PeerEvent::CallSignalRejected { .. }
            | PeerEvent::DelegatedMlsCopyRejected { .. }
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
            PeerEvent::MlsKeyPackageDeliveryUnknown { .. } => {
                return Err("MLS KeyPackage delivery could not be confirmed".to_owned());
            }
            PeerEvent::MlsWelcomeDeliveryUnknown { .. } => {
                return Err("MLS Welcome delivery could not be confirmed".to_owned());
            }
            PeerEvent::CallSignalDeliveryUnknown { .. } => {
                return Err("call signaling delivery could not be confirmed".to_owned());
            }
            PeerEvent::DelegatedMlsCopyDeliveryUnknown { .. } => {
                return Err("delegated MLS copy delivery could not be confirmed".to_owned());
            }
        }
    }
    Err("peer session ended before acknowledgement".to_owned())
}

async fn bind_endpoint_with_relay(
    local_identity: SecretKey,
    bind_address: SocketAddr,
    relay: Option<ParticipantRelay>,
) -> Result<Endpoint, String> {
    let relay_mode = match relay {
        Some(relay) => RelayMode::Custom(iroh::RelayMap::from_iter([iroh::RelayConfig::new(
            relay.url, None,
        )
        .with_auth_token(relay.access_token)])),
        None => RelayMode::Disabled,
    };
    Endpoint::builder(presets::Minimal)
        .secret_key(local_identity)
        .alpns(vec![PEER_ALPN.to_vec()])
        .relay_mode(relay_mode)
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
        FRAME_MLS_KEY_PACKAGE => {
            if length == 0 || length > MAX_MLS_KEY_PACKAGE_BYTES {
                return Err(format!(
                    "MLS KeyPackage length must be between 1 and {MAX_MLS_KEY_PACKAGE_BYTES}"
                ));
            }
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read MLS KeyPackage frame: {error}"))?;
            Ok(Frame::MlsKeyPackage {
                sequence,
                key_package: decode_mls_key_package(&bytes)?,
            })
        }
        FRAME_MLS_WELCOME => {
            if length == 0 || length > MAX_MLS_WELCOME_BYTES {
                return Err(format!(
                    "MLS Welcome length must be between 1 and {MAX_MLS_WELCOME_BYTES}"
                ));
            }
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read MLS Welcome frame: {error}"))?;
            Ok(Frame::MlsWelcome {
                sequence,
                welcome: decode_mls_welcome(&bytes)?,
            })
        }
        FRAME_CALL_SIGNAL if (1..=MAX_CALL_SIGNAL_BYTES).contains(&length) && sequence != 0 => {
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read call signaling frame: {error}"))?;
            Ok(Frame::CallSignal {
                sequence,
                signal: decode_call_signal(&bytes)?,
            })
        }
        FRAME_CALL_SIGNAL => Err("peer sent an invalid call signaling frame".to_owned()),
        FRAME_MLS_DELEGATED_COPY
            if (1..=MAX_MLS_DELEGATED_COPY_BYTES).contains(&length) && sequence != 0 =>
        {
            let mut bytes = vec![0_u8; length];
            reader
                .read_exact(&mut bytes)
                .await
                .map_err(|error| format!("could not read delegated MLS copy: {error}"))?;
            let (grant, event) = decode_delegated_mls_copy(&bytes)?;
            Ok(Frame::DelegatedMlsCopy {
                sequence,
                grant: Box::new(grant),
                event: Box::new(event),
            })
        }
        FRAME_MLS_DELEGATED_COPY => Err("peer sent an invalid delegated MLS copy frame".to_owned()),
        FRAME_MLS_COPY_FETCH if length == 0 && sequence == 0 => Ok(Frame::MlsCopyFetch),
        FRAME_MLS_COPY_FETCH => Err("peer sent an invalid delegated MLS copy request".to_owned()),
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

fn encode_mls_key_package(envelope: &MlsKeyPackageEnvelope) -> Result<Vec<u8>, String> {
    if envelope.event_id.iter().all(|byte| *byte == 0)
        || envelope.invitee_device.iter().all(|byte| *byte == 0)
        || envelope.group_id.len() != 16
        || envelope.key_package.is_empty()
        || envelope.key_package.len() > MAX_MLS_KEY_PACKAGE_BYTES
        || envelope.event_id.as_slice() != &blake3::hash(&envelope.key_package).as_bytes()[..16]
    {
        return Err("MLS KeyPackage has an invalid or oversized envelope".to_owned());
    }
    let mut output = Vec::with_capacity(76 + envelope.key_package.len());
    output.extend_from_slice(MLS_KEY_PACKAGE_MAGIC);
    output.extend_from_slice(&MLS_KEY_PACKAGE_VERSION.to_be_bytes());
    output.extend_from_slice(&envelope.event_id);
    output.extend_from_slice(&envelope.invitee_device);
    output.extend_from_slice(&envelope.group_id);
    output.extend_from_slice(&(envelope.key_package.len() as u32).to_be_bytes());
    output.extend_from_slice(&envelope.key_package);
    if output.len() > MAX_MLS_KEY_PACKAGE_BYTES {
        return Err("serialized MLS KeyPackage exceeds the transport limit".to_owned());
    }
    Ok(output)
}

fn decode_mls_key_package(bytes: &[u8]) -> Result<MlsKeyPackageEnvelope, String> {
    const FIXED: usize = 4 + 2 + 16 + 32 + 16 + 4;
    if bytes.len() < FIXED
        || bytes.len() > MAX_MLS_KEY_PACKAGE_BYTES
        || &bytes[..4] != MLS_KEY_PACKAGE_MAGIC
    {
        return Err("invalid or oversized MLS KeyPackage envelope".to_owned());
    }
    let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    if version != MLS_KEY_PACKAGE_VERSION {
        return Err(format!(
            "unsupported MLS KeyPackage envelope version: {version}"
        ));
    }
    let mut cursor = 6;
    let event_id: [u8; 16] = bytes[cursor..cursor + 16].try_into().unwrap();
    cursor += 16;
    let invitee_device: [u8; 32] = bytes[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let group_id = bytes[cursor..cursor + 16].to_vec();
    cursor += 16;
    let package_len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    if event_id.iter().all(|byte| *byte == 0)
        || invitee_device.iter().all(|byte| *byte == 0)
        || package_len == 0
        || cursor.checked_add(package_len) != Some(bytes.len())
    {
        return Err("MLS KeyPackage envelope metadata or lengths are invalid".to_owned());
    }
    let key_package = bytes[cursor..].to_vec();
    if event_id.as_slice() != &blake3::hash(&key_package).as_bytes()[..16] {
        return Err("MLS KeyPackage event ID does not match its bytes".to_owned());
    }
    Ok(MlsKeyPackageEnvelope {
        event_id,
        invitee_device,
        group_id,
        key_package,
    })
}

fn encode_mls_welcome(envelope: &MlsWelcomeEnvelope) -> Result<Vec<u8>, String> {
    let total_artifact_len = envelope
        .welcome
        .len()
        .saturating_add(envelope.ratchet_tree.len());
    let mut hash = blake3::Hasher::new();
    hash.update(&(envelope.welcome.len() as u32).to_be_bytes());
    hash.update(&envelope.welcome);
    hash.update(&(envelope.ratchet_tree.len() as u32).to_be_bytes());
    hash.update(&envelope.ratchet_tree);
    if envelope.event_id.iter().all(|byte| *byte == 0)
        || envelope.invitee_device.iter().all(|byte| *byte == 0)
        || envelope.group_id.len() != 16
        || envelope.welcome.is_empty()
        || envelope.ratchet_tree.is_empty()
        || total_artifact_len > MAX_MLS_WELCOME_BYTES
        || envelope.event_id.as_slice() != &hash.finalize().as_bytes()[..16]
    {
        return Err("MLS Welcome has an invalid or oversized envelope".to_owned());
    }
    let mut output = Vec::with_capacity(79 + total_artifact_len);
    output.extend_from_slice(MLS_WELCOME_MAGIC);
    output.extend_from_slice(&MLS_WELCOME_VERSION.to_be_bytes());
    output.extend_from_slice(&envelope.event_id);
    output.extend_from_slice(&envelope.invitee_device);
    output.extend_from_slice(&envelope.group_id);
    output.push(envelope.purpose as u8);
    output.extend_from_slice(&(envelope.welcome.len() as u32).to_be_bytes());
    output.extend_from_slice(&envelope.welcome);
    output.extend_from_slice(&(envelope.ratchet_tree.len() as u32).to_be_bytes());
    output.extend_from_slice(&envelope.ratchet_tree);
    if output.len() > MAX_MLS_WELCOME_BYTES {
        return Err("serialized MLS Welcome exceeds the transport limit".to_owned());
    }
    Ok(output)
}

fn decode_mls_welcome(bytes: &[u8]) -> Result<MlsWelcomeEnvelope, String> {
    const FIXED: usize = 4 + 2 + 16 + 32 + 16 + 1 + 4 + 4;
    if bytes.len() < FIXED
        || bytes.len() > MAX_MLS_WELCOME_BYTES
        || &bytes[..4] != MLS_WELCOME_MAGIC
    {
        return Err("invalid or oversized MLS Welcome envelope".to_owned());
    }
    let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    if version != MLS_WELCOME_VERSION {
        return Err(format!(
            "unsupported MLS Welcome envelope version: {version}"
        ));
    }
    let mut cursor = 6;
    let event_id = bytes[cursor..cursor + 16].try_into().unwrap();
    cursor += 16;
    let invitee_device = bytes[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let group_id = bytes[cursor..cursor + 16].to_vec();
    cursor += 16;
    let purpose = MlsGroupPurpose::try_from(bytes[cursor])?;
    cursor += 1;
    let welcome_len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    if welcome_len == 0
        || cursor
            .checked_add(welcome_len + 4)
            .is_none_or(|end| end > bytes.len())
    {
        return Err("MLS Welcome length is invalid".to_owned());
    }
    let welcome = bytes[cursor..cursor + welcome_len].to_vec();
    cursor += welcome_len;
    let tree_len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    if tree_len == 0 || cursor.checked_add(tree_len) != Some(bytes.len()) {
        return Err("MLS ratchet tree length is invalid".to_owned());
    }
    let ratchet_tree = bytes[cursor..].to_vec();
    let envelope = MlsWelcomeEnvelope {
        event_id,
        invitee_device,
        group_id,
        purpose,
        welcome,
        ratchet_tree,
    };
    let mut hash = blake3::Hasher::new();
    hash.update(&(envelope.welcome.len() as u32).to_be_bytes());
    hash.update(&envelope.welcome);
    hash.update(&(envelope.ratchet_tree.len() as u32).to_be_bytes());
    hash.update(&envelope.ratchet_tree);
    if envelope.event_id.iter().all(|byte| *byte == 0)
        || envelope.invitee_device.iter().all(|byte| *byte == 0)
        || envelope.event_id.as_slice() != &hash.finalize().as_bytes()[..16]
    {
        return Err("MLS Welcome envelope identity or content digest is invalid".to_owned());
    }
    Ok(envelope)
}

fn encode_call_signal(signal: &CallSignal) -> Result<Vec<u8>, String> {
    if signal.group_id.iter().all(|byte| *byte == 0)
        || signal.epoch > i64::MAX as u64
        || signal.payload.len() > MAX_CALL_SIGNAL_BYTES
        || (signal.kind == CallSignalKind::End && !signal.payload.is_empty())
        || (signal.kind != CallSignalKind::End && signal.payload.is_empty())
    {
        return Err("call signaling envelope is invalid or oversized".to_owned());
    }
    let mut output = Vec::with_capacity(35 + signal.payload.len());
    output.extend_from_slice(CALL_SIGNAL_MAGIC);
    output.extend_from_slice(&CALL_SIGNAL_VERSION.to_be_bytes());
    output.extend_from_slice(&signal.group_id);
    output.extend_from_slice(&signal.epoch.to_be_bytes());
    output.push(signal.kind as u8);
    output.extend_from_slice(&(signal.payload.len() as u32).to_be_bytes());
    output.extend_from_slice(&signal.payload);
    Ok(output)
}

fn decode_call_signal(bytes: &[u8]) -> Result<CallSignal, String> {
    const HEADER_BYTES: usize = 4 + 2 + 16 + 8 + 1 + 4;
    if bytes.len() < HEADER_BYTES || bytes.len() > HEADER_BYTES + MAX_CALL_SIGNAL_BYTES {
        return Err("call signaling envelope length is invalid".to_owned());
    }
    if &bytes[..4] != CALL_SIGNAL_MAGIC {
        return Err("call signaling envelope marker is invalid".to_owned());
    }
    let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    if version != CALL_SIGNAL_VERSION {
        return Err(format!("unsupported call signaling version: {version}"));
    }
    let group_id = bytes[6..22].try_into().unwrap();
    let epoch = u64::from_be_bytes(bytes[22..30].try_into().unwrap());
    let kind = match bytes[30] {
        1 => CallSignalKind::Offer,
        2 => CallSignalKind::Answer,
        3 => CallSignalKind::IceCandidate,
        4 => CallSignalKind::End,
        _ => return Err("call signaling kind is invalid".to_owned()),
    };
    let payload_len = u32::from_be_bytes(bytes[31..35].try_into().unwrap()) as usize;
    if payload_len > MAX_CALL_SIGNAL_BYTES || HEADER_BYTES + payload_len != bytes.len() {
        return Err("call signaling payload length is invalid".to_owned());
    }
    let signal = CallSignal {
        group_id,
        epoch,
        kind,
        payload: bytes[HEADER_BYTES..].to_vec(),
    };
    // Share the encoder's canonical bounds for both received and sent envelopes.
    encode_call_signal(&signal)?;
    Ok(signal)
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

pub fn encode_delegated_mls_copy(
    grant: &DelegatedMlsCopyGrant,
    event: &MlsEventEnvelope,
) -> Result<Vec<u8>, String> {
    let event_bytes = encode_mls_event(event)?;
    let checkpoint = grant.checkpoint.as_deref().unwrap_or_default();
    if checkpoint.len() > MAX_CHECKPOINT_BYTES
        || event_bytes.len().saturating_add(checkpoint.len()) > MAX_MLS_DELEGATED_COPY_BYTES
        || grant.event_id != event.event_id
        || grant.author_device != event.author_device
        || grant.group_id.as_slice() != event.group_id.as_slice()
        || grant.epoch != event.epoch
        || grant.expires_at_unix != event.expires_at_unix
        || grant.checkpoint != event.checkpoint
        || blake3::hash(&event.ciphertext).as_bytes() != &grant.ciphertext_digest
    {
        return Err("delegated MLS grant does not match its event envelope".to_owned());
    }
    let mut output = Vec::with_capacity(224 + checkpoint.len() + event_bytes.len());
    output.extend_from_slice(MLS_DELEGATED_COPY_MAGIC);
    output.extend_from_slice(&MLS_DELEGATED_COPY_VERSION.to_be_bytes());
    output.extend_from_slice(&grant.event_id);
    output.extend_from_slice(&grant.author_device);
    output.extend_from_slice(&grant.recipient_device);
    output.extend_from_slice(&grant.group_id);
    output.extend_from_slice(&grant.epoch.to_be_bytes());
    output.extend_from_slice(&grant.expires_at_unix.to_be_bytes());
    output.extend_from_slice(&(checkpoint.len() as u32).to_be_bytes());
    output.extend_from_slice(checkpoint);
    output.extend_from_slice(&grant.ciphertext_digest);
    output.extend_from_slice(&grant.signature);
    output.extend_from_slice(&(event_bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(&event_bytes);
    if output.len() > MAX_MLS_DELEGATED_COPY_BYTES {
        return Err("delegated MLS copy exceeds the transport limit".to_owned());
    }
    Ok(output)
}

pub fn decode_delegated_mls_copy(
    bytes: &[u8],
) -> Result<(DelegatedMlsCopyGrant, MlsEventEnvelope), String> {
    const FIXED: usize = 4 + 2 + 16 + 32 + 32 + 16 + 8 + 8 + 4 + 32 + 64 + 4;
    if bytes.len() < FIXED
        || bytes.len() > MAX_MLS_DELEGATED_COPY_BYTES
        || &bytes[..4] != MLS_DELEGATED_COPY_MAGIC
    {
        return Err("invalid or oversized delegated MLS copy".to_owned());
    }
    let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    if version != MLS_DELEGATED_COPY_VERSION {
        return Err(format!("unsupported delegated MLS copy version: {version}"));
    }
    let mut cursor = 6;
    let event_id = bytes[cursor..cursor + 16].try_into().unwrap();
    cursor += 16;
    let author_device = bytes[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let recipient_device = bytes[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let group_id = bytes[cursor..cursor + 16].try_into().unwrap();
    cursor += 16;
    let epoch = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let expires_at_unix = i64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let checkpoint_len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    if checkpoint_len > MAX_CHECKPOINT_BYTES
        || cursor
            .checked_add(checkpoint_len + 32 + 64 + 4)
            .is_none_or(|end| end > bytes.len())
    {
        return Err("delegated MLS checkpoint length is invalid".to_owned());
    }
    let checkpoint = (checkpoint_len > 0).then(|| bytes[cursor..cursor + checkpoint_len].to_vec());
    cursor += checkpoint_len;
    let ciphertext_digest = bytes[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let signature = bytes[cursor..cursor + 64].try_into().unwrap();
    cursor += 64;
    let event_len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    if event_len == 0 || cursor.checked_add(event_len) != Some(bytes.len()) {
        return Err("delegated MLS event length is invalid".to_owned());
    }
    let grant = DelegatedMlsCopyGrant {
        event_id,
        author_device,
        recipient_device,
        group_id,
        epoch,
        expires_at_unix,
        checkpoint,
        ciphertext_digest,
        signature,
    };
    let event = decode_mls_event(&bytes[cursor..])?;
    if grant.event_id != event.event_id
        || grant.author_device != event.author_device
        || grant.group_id.as_slice() != event.group_id.as_slice()
        || grant.epoch != event.epoch
        || grant.expires_at_unix != event.expires_at_unix
        || grant.checkpoint != event.checkpoint
        || blake3::hash(&event.ciphertext).as_bytes() != &grant.ciphertext_digest
    {
        return Err("delegated MLS grant metadata or ciphertext digest does not match".to_owned());
    }
    Ok((grant, event))
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
    use iroh_relay::server::{
        Access, AccessControl, ClientRequest, RelayConfig, Server, ServerConfig,
    };
    use std::sync::Arc;
    use tokio::io::duplex;

    #[derive(Debug)]
    struct RelayTestToken(String);

    #[tokio::test]
    async fn direct_peer_transfers_ciphertext_blob_over_a_separate_quic_stream() {
        let root = std::env::temp_dir().join(format!(
            "slouching-quic-attachment-{}-{}",
            std::process::id(),
            getrandom::u32().unwrap()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source_path = root.join("map.bin");
        let source = vec![0x37; crate::file_transfer::FILE_CHUNK_PLAINTEXT_BYTES + 39];
        tokio::fs::write(&source_path, &source).await.unwrap();
        let sender_store = EncryptedBlobStore::open(root.join("sender-store"))
            .await
            .unwrap();
        let receiver_store = EncryptedBlobStore::open(root.join("receiver-store"))
            .await
            .unwrap();
        let stored = sender_store.import_file(&source_path).await.unwrap();
        let receiver_offer = FileOffer::decode(&stored.offer.encode().unwrap()).unwrap();
        let expected_hash = stored.ciphertext_hash;
        let group_id = [0x91; 16];

        let sender_key = SecretKey::from_bytes(&[0x92; 32]);
        let receiver_key = SecretKey::from_bytes(&[0x93; 32]);
        let listener = bind_listener(
            receiver_key,
            "127.0.0.1:0".parse().unwrap(),
            sender_key.public(),
        )
        .await
        .unwrap();
        let address = listener.direct_addresses()[0];
        let receiver_id = listener.id();
        let output_path = root.join("saved-map.bin");
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        let receive_task = tokio::spawn(async move {
            let session = listener.accept_session().await.unwrap();
            let _ = ready_sender.send(());
            receive_attachment_blob(
                &session.connection,
                &receiver_store,
                group_id,
                &receiver_offer,
                expected_hash,
            )
            .await
            .unwrap();
            receiver_store
                .save_decrypted_file(receiver_offer, expected_hash, &output_path)
                .await
                .unwrap();
            assert_eq!(tokio::fs::read(output_path).await.unwrap(), source);
            receiver_store.shutdown().await.unwrap();
        });

        let mut sender = connect_peer(sender_key, receiver_id, address)
            .await
            .unwrap();
        write_frame(&mut sender.send, FRAME_MLS_COPY_FETCH, 0, &[])
            .await
            .unwrap();
        ready_receiver.await.unwrap();
        send_attachment_blob(
            &sender.connection,
            &sender_store,
            group_id,
            &stored.offer,
            expected_hash,
        )
        .await
        .unwrap();
        receive_task.await.unwrap();
        sender.endpoint.close().await;
        sender_store.shutdown().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    impl AccessControl for RelayTestToken {
        async fn on_connect(&self, request: &ClientRequest) -> Access {
            if request.auth_token().as_deref() == Some(&self.0) {
                Access::Allow
            } else {
                Access::Deny { reason: None }
            }
        }
    }

    #[tokio::test]
    async fn custom_authenticated_relay_carries_pinned_text_and_mls_events() {
        let token = "integration-test-shared-token";
        let mut config = ServerConfig::default();
        let mut relay_config = RelayConfig::new("127.0.0.1:0".parse::<SocketAddr>().unwrap());
        relay_config.access = Arc::new(RelayTestToken(token.to_owned()));
        config.relay = Some(relay_config);
        let server = Server::spawn(config)
            .await
            .expect("test relay should start on an ephemeral loopback port");
        let relay_url = format!("http://{}", server.http_addr().expect("HTTP relay address"))
            .parse::<iroh::RelayUrl>()
            .expect("loopback relay URL should parse");
        let relay = ParticipantRelay {
            url: relay_url,
            access_token: token.to_owned(),
        };

        let receiver_key = SecretKey::from_bytes(&[0x71; 32]);
        let sender_key = SecretKey::from_bytes(&[0x72; 32]);
        let expected_event = MlsEventEnvelope {
            event_id: [0x73; 16],
            author_device: *sender_key.public().as_bytes(),
            group_id: vec![0x74; 16],
            epoch: 2,
            checkpoint: Some(vec![0x75; 32]),
            expires_at_unix: 1_900_000_000,
            ciphertext: vec![0x76; 48],
        };
        let expected_event_at_receiver = expected_event.clone();
        let receiver = bind_listener_with_relay(
            receiver_key.clone(),
            "127.0.0.1:0".parse().unwrap(),
            sender_key.public(),
            Some(relay.clone()),
        )
        .await
        .expect("receiver should bind with its configured relay");
        let receiver_id = receiver.id();
        let receiver_task = tokio::spawn(async move {
            let session = tokio::time::timeout(Duration::from_secs(12), receiver.accept_session())
                .await
                .expect("relay-routed connection should arrive")
                .expect("receiver should accept the pinned sender");
            let (commands, command_rx) = mpsc::channel(4);
            let mut events = Box::pin(session.run(command_rx));
            let mut received_message = false;
            let mut received_mls_event = false;
            while let Some(event) = tokio::time::timeout(Duration::from_secs(12), events.next())
                .await
                .expect("relay-routed message should arrive")
            {
                match event {
                    PeerEvent::Received { sequence, text } => {
                        assert_eq!(text, "message through the participant relay");
                        received_message = true;
                        commands
                            .send(PeerCommand::AcceptInbound { sequence })
                            .await
                            .expect("receiver should acknowledge the saved message");
                    }
                    PeerEvent::MlsEventReceived { sequence, event } => {
                        assert_eq!(event, expected_event_at_receiver);
                        received_mls_event = true;
                        commands
                            .send(PeerCommand::AcceptInbound { sequence })
                            .await
                            .expect("receiver should acknowledge the MLS event");
                    }
                    PeerEvent::Disconnected { .. } => {
                        return received_message && received_mls_event;
                    }
                    _ => {}
                }
            }
            received_message
        });

        let sender = connect_peer_with_relay(sender_key, receiver_id, None, Some(relay))
            .await
            .expect("peer should connect through the relay without a direct address");
        let (commands, command_rx) = mpsc::channel(4);
        let mut events = Box::pin(sender.run(command_rx));
        commands
            .send(PeerCommand::Send {
                request_id: 1,
                text: "message through the participant relay".to_owned(),
            })
            .await
            .unwrap();
        commands
            .send(PeerCommand::SendMlsEvent {
                request_id: 2,
                event: expected_event,
            })
            .await
            .unwrap();
        let mut text_acknowledged = false;
        let mut mls_acknowledged = false;
        while let Some(event) = tokio::time::timeout(Duration::from_secs(12), events.next())
            .await
            .expect("relay-routed message should receive an ACK")
        {
            if matches!(event, PeerEvent::Acknowledged { request_id: 1, .. }) {
                text_acknowledged = true;
            }
            if matches!(event, PeerEvent::MlsEventAcknowledged { request_id: 2 }) {
                mls_acknowledged = true;
            }
            if text_acknowledged && mls_acknowledged {
                commands.send(PeerCommand::Disconnect).await.unwrap();
            }
            if matches!(event, PeerEvent::Disconnected { .. }) {
                break;
            }
        }
        assert!(
            text_acknowledged,
            "receiver text ACK should reach the sender over relay"
        );
        assert!(
            mls_acknowledged,
            "receiver MLS ACK should reach sender over relay"
        );
        assert!(receiver_task.await.unwrap());
        server
            .shutdown()
            .await
            .expect("test relay should shut down");
    }

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
    async fn pinned_sessions_exchange_acknowledged_call_signaling() {
        let listener_key = SecretKey::from_bytes(&[0x56; 32]);
        let sender_key = SecretKey::from_bytes(&[0x57; 32]);
        let listener = bind_listener(
            listener_key,
            "127.0.0.1:0".parse().unwrap(),
            sender_key.public(),
        )
        .await
        .expect("call signaling receiver should bind a loopback endpoint");
        let listener_id = listener.id();
        let address = listener
            .direct_addresses()
            .into_iter()
            .find(|address| address.ip().is_loopback())
            .expect("listener should announce its loopback socket");
        let receiver_task = tokio::spawn(async move {
            let session = listener
                .accept_session()
                .await
                .expect("listener should accept the pinned sender");
            let (commands, receiver) = mpsc::channel(4);
            let mut events = Box::pin(session.run(receiver));
            while let Some(event) = events.next().await {
                if let PeerEvent::CallSignalReceived {
                    sequence, signal, ..
                } = event
                {
                    commands
                        .send(PeerCommand::AcceptInbound { sequence })
                        .await
                        .expect("receiver should ACK after accepting the signal");
                    commands
                        .send(PeerCommand::Disconnect)
                        .await
                        .expect("receiver should close after ACKing the signal");
                    while let Some(event) = events.next().await {
                        if matches!(event, PeerEvent::Disconnected { .. }) {
                            return signal;
                        }
                    }
                    panic!("receiver disconnected before completing call signaling ACK");
                }
            }
            panic!("session ended before call signaling arrived");
        });

        let session = connect_peer(sender_key, listener_id, address)
            .await
            .expect("sender should connect to the pinned call peer");
        let (commands, receiver) = mpsc::channel(4);
        let mut events = Box::pin(session.run(receiver));
        let signal = CallSignal {
            group_id: [0x58; 16],
            epoch: 3,
            kind: CallSignalKind::Offer,
            payload: br#"{"type":"offer","sdp":"v=0"}"#.to_vec(),
        };
        commands
            .send(PeerCommand::SendCallSignal {
                request_id: 10,
                signal: signal.clone(),
            })
            .await
            .expect("sender should queue the call offer");
        let mut acknowledged = false;
        while let Some(event) = tokio::time::timeout(Duration::from_secs(8), events.next())
            .await
            .expect("call signaling ACK should arrive before deadline")
        {
            if matches!(event, PeerEvent::CallSignalAcknowledged { request_id: 10 }) {
                acknowledged = true;
                break;
            }
        }
        assert!(acknowledged, "call offer should receive a transport ACK");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(8), receiver_task)
                .await
                .expect("receiver should complete")
                .unwrap(),
            signal
        );
    }

    #[test]
    fn call_signal_codec_checks_group_epoch_kind_and_bounds() {
        let offer = CallSignal {
            group_id: [0x61; 16],
            epoch: 4,
            kind: CallSignalKind::Offer,
            payload: b"{\"sdp\":\"offer\"}".to_vec(),
        };
        let bytes = encode_call_signal(&offer).unwrap();
        assert_eq!(decode_call_signal(&bytes).unwrap(), offer);

        for invalid in [
            CallSignal {
                group_id: [0; 16],
                epoch: 0,
                kind: CallSignalKind::Offer,
                payload: b"offer".to_vec(),
            },
            CallSignal {
                group_id: [1; 16],
                epoch: u64::MAX,
                kind: CallSignalKind::Answer,
                payload: b"answer".to_vec(),
            },
            CallSignal {
                group_id: [1; 16],
                epoch: 0,
                kind: CallSignalKind::End,
                payload: b"unexpected".to_vec(),
            },
            CallSignal {
                group_id: [1; 16],
                epoch: 0,
                kind: CallSignalKind::IceCandidate,
                payload: vec![0x62; MAX_CALL_SIGNAL_BYTES + 1],
            },
        ] {
            assert!(encode_call_signal(&invalid).is_err());
        }
        let end = CallSignal {
            group_id: [0x61; 16],
            epoch: 4,
            kind: CallSignalKind::End,
            payload: Vec::new(),
        };
        assert_eq!(
            decode_call_signal(&encode_call_signal(&end).unwrap()).unwrap(),
            end
        );
        let mut corrupt = bytes;
        corrupt[30] = 255;
        assert!(decode_call_signal(&corrupt).is_err());
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

    #[test]
    fn mls_key_package_envelope_round_trips_and_binds_event_id_to_bytes() {
        let package_bytes = vec![0x75; 64];
        let digest = blake3::hash(&package_bytes);
        let mut event_id = [0; 16];
        event_id.copy_from_slice(&digest.as_bytes()[..16]);
        let envelope = MlsKeyPackageEnvelope {
            event_id,
            invitee_device: [0x72; 32],
            group_id: [0x73; 16].to_vec(),
            key_package: package_bytes,
        };
        let encoded = encode_mls_key_package(&envelope).expect("valid KeyPackage should serialize");
        assert_eq!(decode_mls_key_package(&encoded).unwrap(), envelope);

        let mut tampered = envelope.clone();
        tampered.key_package[0] ^= 1;
        assert!(encode_mls_key_package(&tampered).is_err());

        let mut invalid = envelope;
        invalid.group_id.pop();
        assert!(encode_mls_key_package(&invalid).is_err());
    }

    #[test]
    fn mls_welcome_envelope_round_trips_and_binds_both_artifacts() {
        let welcome = vec![0x75; 64];
        let ratchet_tree = vec![0x76; 32];
        let mut digest = blake3::Hasher::new();
        digest.update(&(welcome.len() as u32).to_be_bytes());
        digest.update(&welcome);
        digest.update(&(ratchet_tree.len() as u32).to_be_bytes());
        digest.update(&ratchet_tree);
        let mut event_id = [0; 16];
        event_id.copy_from_slice(&digest.finalize().as_bytes()[..16]);
        let envelope = MlsWelcomeEnvelope {
            event_id,
            invitee_device: [0x72; 32],
            group_id: [0x73; 16].to_vec(),
            purpose: MlsGroupPurpose::Call,
            welcome,
            ratchet_tree,
        };
        let encoded = encode_mls_welcome(&envelope).expect("valid Welcome should serialize");
        assert_eq!(decode_mls_welcome(&encoded).unwrap(), envelope);

        let mut tampered = envelope.clone();
        tampered.ratchet_tree[0] ^= 1;
        assert!(encode_mls_welcome(&tampered).is_err());

        let mut invalid = envelope;
        invalid.group_id.pop();
        assert!(encode_mls_welcome(&invalid).is_err());
    }

    #[tokio::test]
    async fn strict_session_parser_round_trips_mls_welcome_frame() {
        let welcome = vec![0x84; 48];
        let ratchet_tree = vec![0x85; 16];
        let mut digest = blake3::Hasher::new();
        digest.update(&(welcome.len() as u32).to_be_bytes());
        digest.update(&welcome);
        digest.update(&(ratchet_tree.len() as u32).to_be_bytes());
        digest.update(&ratchet_tree);
        let mut event_id = [0; 16];
        event_id.copy_from_slice(&digest.finalize().as_bytes()[..16]);
        let welcome = MlsWelcomeEnvelope {
            event_id,
            invitee_device: [0x82; 32],
            group_id: [0x83; 16].to_vec(),
            purpose: MlsGroupPurpose::Conversation,
            welcome,
            ratchet_tree,
        };
        let payload = encode_mls_welcome(&welcome).unwrap();
        let (mut writer, mut reader) = duplex(1024);
        write_frame(&mut writer, FRAME_MLS_WELCOME, 4, &payload)
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Frame::MlsWelcome {
                sequence: 4,
                welcome,
            }
        );
    }

    #[tokio::test]
    async fn delegated_mls_copy_frame_round_trips_and_binds_ciphertext() {
        let ciphertext = vec![0x91; 96];
        let event = MlsEventEnvelope {
            event_id: [0x92; 16],
            author_device: [0x93; 32],
            group_id: [0x94; 16].to_vec(),
            epoch: 7,
            checkpoint: Some(vec![0x95; 8]),
            expires_at_unix: 1_900_000_000,
            ciphertext,
        };
        let grant = DelegatedMlsCopyGrant {
            event_id: event.event_id,
            author_device: event.author_device,
            recipient_device: [0x96; 32],
            group_id: [0x94; 16],
            epoch: event.epoch,
            expires_at_unix: event.expires_at_unix,
            checkpoint: event.checkpoint.clone(),
            ciphertext_digest: *blake3::hash(&event.ciphertext).as_bytes(),
            signature: [0x97; 64],
        };
        let payload = encode_delegated_mls_copy(&grant, &event).unwrap();
        assert_eq!(
            decode_delegated_mls_copy(&payload).unwrap(),
            (grant.clone(), event.clone())
        );
        let (mut writer, mut reader) = duplex(2048);
        write_frame(&mut writer, FRAME_MLS_DELEGATED_COPY, 6, &payload)
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Frame::DelegatedMlsCopy {
                sequence: 6,
                grant: Box::new(grant),
                event: Box::new(event)
            }
        );

        let mut tampered = payload;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decode_delegated_mls_copy(&tampered).is_err());
    }

    #[tokio::test]
    async fn delegated_mls_copy_fetch_is_a_zero_sequence_control_frame() {
        let (mut writer, mut reader) = duplex(64);
        write_frame(&mut writer, FRAME_MLS_COPY_FETCH, 0, &[])
            .await
            .unwrap();
        assert_eq!(read_frame(&mut reader).await.unwrap(), Frame::MlsCopyFetch);
    }

    #[tokio::test]
    async fn direct_session_fetches_delegated_copy_and_acks_recipient_delivery() {
        let holder_key = SecretKey::from_bytes(&[0x61; 32]);
        let recipient_key = SecretKey::from_bytes(&[0x62; 32]);
        let recipient_device = *recipient_key.public().as_bytes();
        let listener = bind_listener(
            holder_key.clone(),
            "127.0.0.1:0".parse().unwrap(),
            recipient_key.public(),
        )
        .await
        .unwrap();
        let holder_id = listener.id();
        let address = listener
            .direct_addresses()
            .into_iter()
            .find(|address| address.ip().is_loopback())
            .unwrap();
        let event = MlsEventEnvelope {
            event_id: [0x63; 16],
            author_device: [0x64; 32],
            group_id: [0x65; 16].to_vec(),
            epoch: 3,
            checkpoint: None,
            expires_at_unix: 1_900_000_000,
            ciphertext: vec![0x66; 64],
        };
        let grant = DelegatedMlsCopyGrant {
            event_id: event.event_id,
            author_device: event.author_device,
            recipient_device,
            group_id: [0x65; 16],
            epoch: event.epoch,
            expires_at_unix: event.expires_at_unix,
            checkpoint: None,
            ciphertext_digest: *blake3::hash(&event.ciphertext).as_bytes(),
            signature: [0x67; 64],
        };
        let copy_event = event.clone();
        let expected_grant = grant.clone();
        let holder_task = tokio::spawn(async move {
            let session = listener.accept_session().await.unwrap();
            let (commands, receiver) = mpsc::channel(4);
            let mut events = Box::pin(session.run(receiver));
            while let Some(event) = events.next().await {
                match event {
                    PeerEvent::Connected { .. } => {}
                    PeerEvent::DelegatedMlsCopiesRequested { peer_id } => {
                        assert_eq!(*peer_id.as_bytes(), recipient_device);
                        commands
                            .send(PeerCommand::SendDelegatedMlsCopy {
                                request_id: 77,
                                grant: Box::new(grant.clone()),
                                event: Box::new(copy_event.clone()),
                            })
                            .await
                            .unwrap();
                    }
                    PeerEvent::DelegatedMlsCopyAcknowledged { request_id } => {
                        assert_eq!(request_id, 77);
                        commands.send(PeerCommand::Disconnect).await.unwrap();
                    }
                    PeerEvent::Disconnected { .. } => return true,
                    other => panic!("unexpected helper-side event: {other:?}"),
                }
            }
            false
        });
        let session = connect_peer(recipient_key, holder_id, address)
            .await
            .unwrap();
        let (commands, receiver) = mpsc::channel(4);
        let mut events = Box::pin(session.run(receiver));
        assert!(matches!(
            events.next().await,
            Some(PeerEvent::Connected { .. })
        ));
        commands
            .send(PeerCommand::RequestDelegatedMlsCopies)
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(8), events.next())
            .await
            .unwrap()
            .unwrap();
        let sequence = match received {
            PeerEvent::DelegatedMlsCopyReceived {
                sequence,
                peer_id,
                grant: received_grant,
                event: received_event,
            } => {
                assert_eq!(peer_id, holder_id);
                assert_eq!(*received_grant, expected_grant);
                assert_eq!(*received_event, event);
                sequence
            }
            other => panic!("unexpected recipient-side event: {other:?}"),
        };
        commands
            .send(PeerCommand::AcceptInbound { sequence })
            .await
            .unwrap();
        commands.send(PeerCommand::Disconnect).await.unwrap();
        while let Some(event) = tokio::time::timeout(Duration::from_secs(8), events.next())
            .await
            .unwrap()
        {
            if matches!(event, PeerEvent::Disconnected { .. }) {
                break;
            }
        }
        assert!(holder_task.await.unwrap());
    }

    #[tokio::test]
    async fn helper_listener_accepts_author_then_different_recipient() {
        let helper_key = SecretKey::from_bytes(&[0x68; 32]);
        let author_key = SecretKey::from_bytes(&[0x69; 32]);
        let recipient_key = SecretKey::from_bytes(&[0x6a; 32]);
        let author_device = *author_key.public().as_bytes();
        let recipient_device = *recipient_key.public().as_bytes();
        let listener = bind_helper_listener(helper_key.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let helper_id = listener.id();
        let address = listener
            .direct_addresses()
            .into_iter()
            .find(|address| address.ip().is_loopback())
            .unwrap();
        let event = MlsEventEnvelope {
            event_id: [0x6b; 16],
            author_device,
            group_id: [0x6c; 16].to_vec(),
            epoch: 2,
            checkpoint: None,
            expires_at_unix: 1_900_000_000,
            ciphertext: vec![0x6d; 64],
        };
        let grant = DelegatedMlsCopyGrant {
            event_id: event.event_id,
            author_device,
            recipient_device,
            group_id: [0x6c; 16],
            epoch: event.epoch,
            expires_at_unix: event.expires_at_unix,
            checkpoint: None,
            ciphertext_digest: *blake3::hash(&event.ciphertext).as_bytes(),
            signature: [0x6e; 64],
        };
        let expected_grant = grant.clone();
        let expected_event = event.clone();
        let helper_task = tokio::spawn(async move {
            let author_session = listener.accept_session().await.unwrap();
            let (commands, receiver) = mpsc::channel(4);
            let mut stream = Box::pin(author_session.run(receiver));
            let mut retained = None;
            while let Some(event) = stream.next().await {
                match event {
                    PeerEvent::Connected {
                        peer_id,
                        direct_address,
                    } => {
                        assert_eq!(*peer_id.as_bytes(), author_device);
                        let address = direct_address.expect("direct route should be observed");
                        assert!(address.ip().is_loopback());
                        assert_ne!(address.port(), 0);
                    }
                    PeerEvent::DelegatedMlsCopyReceived {
                        sequence,
                        peer_id,
                        grant,
                        event,
                    } => {
                        assert_eq!(*peer_id.as_bytes(), author_device);
                        retained = Some((*grant, *event));
                        commands
                            .send(PeerCommand::AcceptInbound { sequence })
                            .await
                            .unwrap();
                    }
                    PeerEvent::Disconnected { .. } => break,
                    other => panic!("unexpected author session event: {other:?}"),
                }
            }
            let (retained_grant, retained_event) =
                retained.expect("helper should retain author's copy");

            let recipient_session = listener.accept_session().await.unwrap();
            let (commands, receiver) = mpsc::channel(4);
            let mut stream = Box::pin(recipient_session.run(receiver));
            while let Some(event) = stream.next().await {
                match event {
                    PeerEvent::Connected { peer_id, .. } => {
                        assert_eq!(*peer_id.as_bytes(), recipient_device)
                    }
                    PeerEvent::DelegatedMlsCopiesRequested { peer_id } => {
                        assert_eq!(*peer_id.as_bytes(), recipient_device);
                        commands
                            .send(PeerCommand::SendDelegatedMlsCopy {
                                request_id: 91,
                                grant: Box::new(retained_grant.clone()),
                                event: Box::new(retained_event.clone()),
                            })
                            .await
                            .unwrap();
                    }
                    PeerEvent::DelegatedMlsCopyAcknowledged { request_id } => {
                        assert_eq!(request_id, 91);
                        commands.send(PeerCommand::Disconnect).await.unwrap();
                    }
                    PeerEvent::Disconnected { .. } => return true,
                    other => panic!("unexpected recipient session event: {other:?}"),
                }
            }
            false
        });

        let author_session = connect_peer(author_key, helper_id, address).await.unwrap();
        let (commands, receiver) = mpsc::channel(4);
        let mut stream = Box::pin(author_session.run(receiver));
        assert!(matches!(
            stream.next().await,
            Some(PeerEvent::Connected { .. })
        ));
        commands
            .send(PeerCommand::SendDelegatedMlsCopy {
                request_id: 90,
                grant: Box::new(grant),
                event: Box::new(event),
            })
            .await
            .unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(8), stream.next())
                .await
                .unwrap()
                .unwrap()
            {
                PeerEvent::DelegatedMlsCopyAcknowledged { request_id: 90 } => break,
                PeerEvent::Connected { .. } => continue,
                other => panic!("unexpected author ACK event: {other:?}"),
            }
        }
        commands.send(PeerCommand::Disconnect).await.unwrap();
        while let Some(event) = stream.next().await {
            if matches!(event, PeerEvent::Disconnected { .. }) {
                break;
            }
        }

        let recipient_session = connect_peer(recipient_key, helper_id, address)
            .await
            .unwrap();
        let (commands, receiver) = mpsc::channel(4);
        let mut stream = Box::pin(recipient_session.run(receiver));
        assert!(matches!(
            stream.next().await,
            Some(PeerEvent::Connected { .. })
        ));
        commands
            .send(PeerCommand::RequestDelegatedMlsCopies)
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(8), stream.next())
            .await
            .unwrap()
            .unwrap();
        match received {
            PeerEvent::DelegatedMlsCopyReceived {
                sequence,
                peer_id,
                grant,
                event,
            } => {
                assert_eq!(peer_id, helper_id);
                assert_eq!(*grant, expected_grant);
                assert_eq!(*event, expected_event);
                commands
                    .send(PeerCommand::AcceptInbound { sequence })
                    .await
                    .unwrap();
            }
            other => panic!("unexpected recipient copy event: {other:?}"),
        }
        commands.send(PeerCommand::Disconnect).await.unwrap();
        while let Some(event) = stream.next().await {
            if matches!(event, PeerEvent::Disconnected { .. }) {
                break;
            }
        }
        assert!(helper_task.await.unwrap());
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
    async fn strict_session_parser_round_trips_mls_key_package_frame() {
        let package_bytes = vec![0x84; 48];
        let digest = blake3::hash(&package_bytes);
        let mut event_id = [0; 16];
        event_id.copy_from_slice(&digest.as_bytes()[..16]);
        let key_package = MlsKeyPackageEnvelope {
            event_id,
            invitee_device: [0x82; 32],
            group_id: [0x83; 16].to_vec(),
            key_package: package_bytes,
        };
        let payload = encode_mls_key_package(&key_package).unwrap();
        let (mut writer, mut reader) = duplex(1024);
        write_frame(&mut writer, FRAME_MLS_KEY_PACKAGE, 4, &payload)
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            Frame::MlsKeyPackage {
                sequence: 4,
                key_package,
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
