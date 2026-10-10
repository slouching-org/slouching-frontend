use futures_util::{SinkExt, StreamExt};
use iced::{Element, Task, Theme, task::Handle};

pub mod blob_store;
pub mod file_transfer;
pub mod identity;
mod peer;
pub mod storage;
mod ui;
use prost::Message as ProstMessage;
use serde::Deserialize;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

mod protocol {
    include!(concat!(env!("OUT_DIR"), "/slouching.v1.rs"));
}

const STATUS_URL: &str = "http://127.0.0.1:3707/api/status";
const WS_URL: &str = "ws://127.0.0.1:3707/ws";
const CONTRACT_VERSION: u32 = 1;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
const PING_PAYLOAD: &[u8] = b"slouching-v1";

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Debug, Clone, Deserialize)]
struct BackendStatus {
    contract_version: u32,
    backend: String,
    identity: CapabilityStatus,
    messaging: CapabilityStatus,
    calls: CapabilityStatus,
    peer_connections: u32,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CapabilityStatus {
    NotImplemented,
}

#[derive(Debug, Clone)]
enum BackendConnection {
    Connecting,
    Unavailable(String),
    ContractMismatch(String),
    Connected(BackendStatus),
}

#[derive(Debug, Clone)]
enum FetchError {
    Unavailable(String),
    ContractMismatch(String),
}

#[derive(Debug, Clone)]
enum TransportState {
    Connecting(u32),
    Disconnected {
        reason: String,
        retry_seconds: u64,
    },
    ProtocolError(String),
    Active {
        hello: protocol::ServerHello,
        heartbeats: u64,
    },
}

#[derive(Debug, Clone)]
enum HandshakeError {
    Unavailable(String),
    Protocol(String),
}

#[derive(Debug, Clone)]
enum TransportEvent {
    Connecting(u32),
    Connected(protocol::ServerHello),
    Heartbeat,
    Disconnected { reason: String, retry_seconds: u64 },
    ProtocolError(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Screen {
    Components,
    Familiar,
    Settings,
    Lobby,
    Connecting,
    Share,
    Chat,
    Mls,
    Incoming,
    Verify,
    #[default]
    Home,
    Call,
}

impl Screen {
    const ALL: [Self; 12] = [
        Self::Components,
        Self::Familiar,
        Self::Settings,
        Self::Lobby,
        Self::Connecting,
        Self::Share,
        Self::Chat,
        Self::Mls,
        Self::Incoming,
        Self::Verify,
        Self::Home,
        Self::Call,
    ];

    fn slug(self) -> &'static str {
        match self {
            Self::Components => "00-components",
            Self::Familiar => "01-familiar",
            Self::Settings => "02-settings",
            Self::Lobby => "03-lobby",
            Self::Connecting => "04-connecting",
            Self::Share => "05-share",
            Self::Chat => "06-chat",
            Self::Mls => "11-mls",
            Self::Incoming => "07-incoming",
            Self::Verify => "08-verify",
            Self::Home => "09-home",
            Self::Call => "10-call",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Components => "Identidade & componentes",
            Self::Familiar => "Escolha seu familiar",
            Self::Settings => "Configurações",
            Self::Lobby => "Lobby",
            Self::Connecting => "Conectando & fallback",
            Self::Share => "Escolher tela",
            Self::Chat => "Texto direto · LAN/VPN",
            Self::Mls => "Grupo MLS · local",
            Self::Incoming => "Chamada recebida",
            Self::Verify => "Verificar selo",
            Self::Home => "Início",
            Self::Call => "Chamada em grupo",
        }
    }
}

type PendingPeerKeyPackage = (u64, [u8; 32], Vec<u8>, Vec<u8>);
type PendingPeerWelcome = (u64, [u8; 32], [u8; 16], Vec<u8>, Vec<u8>, Vec<u8>);

#[derive(Debug, Clone)]
struct MlsCommitFanoutReport {
    recipients: usize,
    commits_acked: usize,
    failures: Vec<String>,
}

#[derive(Debug, Default)]
struct MlsCommitFanoutPeerOutcome {
    commits_acked: usize,
    failure: Option<String>,
}

#[derive(Debug, Clone)]
struct MlsEventFanoutReport {
    recipients: usize,
    events_acked: usize,
    copies_held: usize,
    events_expired: usize,
    failures: Vec<String>,
}

struct Slouching {
    backend: BackendConnection,
    transport: TransportState,
    transport_handle: Option<Handle>,
    transport_generation: u64,
    screen: Screen,
    invite: String,
    name: String,
    familiar: &'static str,
    show_gallery: bool,
    settings_tab: u8,
    share_tab: u8,
    selected_source: u8,
    draft: String,
    texture: bool,
    note: Option<&'static str>,
    capture_dir: Option<std::path::PathBuf>,
    capture_index: usize,
    capture_once: bool,
    profile_status: ProfileStatus,
    identity_status: IdentityStatus,
    delegated_mls_storage: Option<storage::DelegatedMlsStorageStatus>,
    delegated_mls_storage_error: Option<String>,
    peer_public_key: String,
    peer_verification_loaded_for: Option<String>,
    peer_key_verified: bool,
    peer_verification_status: String,
    active_peer_device: Option<[u8; 32]>,
    helper_listener_active: bool,
    peer_listener_port: Option<u16>,
    peer_listener_addresses: Vec<std::net::SocketAddr>,
    peer_routes: Vec<storage::StoredPeerRoute>,
    peer_routes_error: Option<String>,
    peer_listen_port: String,
    peer_address: String,
    peer_relay_url: String,
    peer_relay_token: String,
    peer_relay_config: storage::PeerRelayConfig,
    peer_relay_config_status: String,
    peer_relay_config_loaded: bool,
    peer_relay_config_dirty: bool,
    peer_draft: String,
    peer_listen_status: PeerListenStatus,
    peer_send_status: PeerSendStatus,
    peer_transcript: Vec<PeerTranscriptEntry>,
    peer_history_loaded_for: Option<String>,
    peer_history_generation: u64,
    peer_history_clear_confirmation: bool,
    peer_history_clearing: bool,
    peer_listener_handle: Option<Handle>,
    peer_listener_generation: u64,
    peer_session_commands: Option<tokio::sync::mpsc::Sender<peer::PeerCommand>>,
    peer_pending_sends: std::collections::HashMap<u64, String>,
    peer_next_request_id: u64,
    identity_key_copied: bool,
    mls_group_id: String,
    mls_key_package: String,
    mls_invite_key_package: String,
    mls_commit: String,
    mls_received_commit: String,
    mls_update_proposal: String,
    mls_received_update_proposal: String,
    mls_update_proposal_epoch: Option<u64>,
    mls_update_proposal_group: Option<Vec<u8>>,
    mls_welcome: String,
    mls_ratchet_tree: String,
    mls_status: String,
    mls_quarantine_reason: Option<String>,
    mls_groups: Vec<storage::StoredMlsGroup>,
    mls_groups_error: Option<String>,
    mls_message_draft: String,
    mls_history: Vec<storage::StoredMlsMessage>,
    mls_history_group: Option<Vec<u8>>,
    mls_pending_commits: Vec<storage::StoredMlsCommit>,
    mls_pending_proposals: Vec<storage::StoredMlsProposal>,
    mls_pending_peer_key_package: Option<PendingPeerKeyPackage>,
    mls_pending_peer_welcome: Option<PendingPeerWelcome>,
    mls_commit_recipients: Vec<storage::MlsCommitRecipientStatus>,
    mls_fanout_running: bool,
    mls_event_fanout_running: bool,
    mls_pending_events: std::collections::HashMap<u64, ([u8; 16], [u8; 32])>,
    delegated_copy_sends: std::collections::HashMap<u64, [u8; 16]>,
    mls_sending_commits: std::collections::HashMap<u64, [u8; 16]>,
    mls_sending_proposals: std::collections::HashSet<u64>,
    mls_sending_key_packages: std::collections::HashSet<u64>,
    mls_sending_welcomes: std::collections::HashMap<u64, [u8; 16]>,
    mls_next_request_id: u64,
}

#[derive(Debug, Clone)]
enum ProfileStatus {
    Loading,
    Empty,
    Saved,
    Saving,
    Failed,
}

#[derive(Debug, Clone)]
enum IdentityStatus {
    Loading,
    Missing,
    Creating,
    Ready([u8; 32]),
    Failed,
}

#[derive(Debug, Clone)]
enum PeerListenStatus {
    Idle,
    Starting {
        port: u16,
    },
    Listening {
        port: u16,
        addresses: Vec<std::net::SocketAddr>,
    },
    Connected,
    Disconnected(String),
    Unauthorized(String),
    Failed(String),
}

#[derive(Debug, Clone)]
enum PeerSendStatus {
    Idle,
    Connecting,
    AwaitingAck,
    Sent,
    Failed(String),
}

#[derive(Debug, Clone)]
struct PeerTranscriptEntry {
    direction: PeerMessageDirection,
    text: String,
    persisted: bool,
    sequence: Option<i64>,
    transport_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerMessageDirection {
    Sent,
    Received,
}

#[derive(Debug, Clone)]
enum PeerListenEvent {
    Bound {
        addresses: Vec<std::net::SocketAddr>,
    },
    SessionCommands(tokio::sync::mpsc::Sender<peer::PeerCommand>),
    Session(peer::PeerEvent),
    Failed(String),
}

impl Default for Slouching {
    fn default() -> Self {
        Self {
            backend: BackendConnection::Connecting,
            transport: TransportState::Connecting(1),
            transport_handle: None,
            transport_generation: 1,
            screen: Screen::Home,
            invite: String::new(),
            name: String::new(),
            familiar: "Sapo Mago",
            show_gallery: false,
            settings_tab: 1,
            share_tab: 0,
            selected_source: 0,
            draft: String::new(),
            texture: true,
            note: None,
            capture_dir: None,
            capture_index: 0,
            capture_once: false,
            profile_status: ProfileStatus::Loading,
            identity_status: IdentityStatus::Loading,
            delegated_mls_storage: None,
            delegated_mls_storage_error: None,
            peer_public_key: String::new(),
            peer_verification_loaded_for: None,
            peer_key_verified: false,
            peer_verification_status: "Compare a chave completa por um canal independente."
                .to_owned(),
            active_peer_device: None,
            helper_listener_active: false,
            peer_listener_port: None,
            peer_listener_addresses: Vec::new(),
            peer_routes: Vec::new(),
            peer_routes_error: None,
            peer_listen_port: "45873".to_owned(),
            peer_address: String::new(),
            peer_relay_url: String::new(),
            peer_relay_token: String::new(),
            peer_relay_config: storage::PeerRelayConfig::default(),
            peer_relay_config_status: "Relay opcional desativado".to_owned(),
            peer_relay_config_loaded: false,
            peer_relay_config_dirty: false,
            peer_draft: String::new(),
            peer_listen_status: PeerListenStatus::Idle,
            peer_send_status: PeerSendStatus::Idle,
            peer_transcript: Vec::new(),
            peer_history_loaded_for: None,
            peer_history_generation: 0,
            peer_history_clear_confirmation: false,
            peer_history_clearing: false,
            peer_listener_handle: None,
            peer_listener_generation: 0,
            peer_session_commands: None,
            peer_pending_sends: std::collections::HashMap::new(),
            peer_next_request_id: 1,
            identity_key_copied: false,
            mls_group_id: String::new(),
            mls_key_package: String::new(),
            mls_invite_key_package: String::new(),
            mls_commit: String::new(),
            mls_received_commit: String::new(),
            mls_update_proposal: String::new(),
            mls_received_update_proposal: String::new(),
            mls_update_proposal_epoch: None,
            mls_update_proposal_group: None,
            mls_welcome: String::new(),
            mls_ratchet_tree: String::new(),
            mls_status: "Crie uma identidade do dispositivo para começar.".to_owned(),
            mls_quarantine_reason: None,
            mls_groups: Vec::new(),
            mls_groups_error: None,
            mls_message_draft: String::new(),
            mls_history: Vec::new(),
            mls_history_group: None,
            mls_pending_commits: Vec::new(),
            mls_pending_proposals: Vec::new(),
            mls_pending_peer_key_package: None,
            mls_pending_peer_welcome: None,
            mls_commit_recipients: Vec::new(),
            mls_fanout_running: false,
            mls_event_fanout_running: false,
            mls_pending_events: std::collections::HashMap::new(),
            delegated_copy_sends: std::collections::HashMap::new(),
            mls_sending_commits: std::collections::HashMap::new(),
            mls_sending_proposals: std::collections::HashSet::new(),
            mls_sending_key_packages: std::collections::HashSet::new(),
            mls_sending_welcomes: std::collections::HashMap::new(),
            mls_next_request_id: 1,
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    RefreshBackend,
    BackendFetched(Result<BackendStatus, FetchError>),
    TransportEvent(u64, TransportEvent),
    Navigate(Screen),
    InviteChanged(String),
    NameChanged(String),
    ChooseFamiliar(&'static str),
    ToggleGallery,
    SettingsTab(u8),
    ShareTab(u8),
    SelectSource(u8),
    DraftChanged(String),
    ToggleTexture,
    PreviewAction(&'static str),
    DismissNote,
    Capture,
    Captured(iced::window::Screenshot),
    ProfileLoaded(Result<Option<storage::LocalProfile>, String>),
    SaveProfile,
    ProfileSaved(storage::LocalProfile, Result<(), String>),
    IdentityLoaded(Result<Option<[u8; 32]>, String>),
    CreateIdentity,
    IdentityCreated(Result<[u8; 32], String>),
    DelegatedMlsStorageLoaded(Result<storage::DelegatedMlsStorageStatus, String>),
    SetDelegatedMlsStorage(bool),
    DelegatedMlsStorageSaved(bool, Result<storage::DelegatedMlsStorageStatus, String>),
    DelegatedCopyStored(
        u64,
        [u8; 16],
        Result<storage::DelegatedCopyStoreResult, String>,
    ),
    DelegatedCopiesLoaded(Result<Vec<storage::StoredDelegatedMlsCopy>, String>),
    DelegatedCopyReceiptProcessed(u64, Result<storage::ProcessedMlsApplicationEvent, String>),
    DelegatedCopyAcknowledged(u64, Result<bool, String>),
    CopyDeviceKey,
    CopyPeerListenAddress(String),
    PeerPublicKeyChanged(String),
    PeerVerificationLoaded(String, Result<bool, String>),
    TogglePeerVerification,
    PeerVerificationSaved(String, bool, Result<(), String>),
    PeerHistoryLoaded(
        u64,
        String,
        Result<Vec<storage::StoredDirectMessage>, String>,
    ),
    RequestClearPeerHistory,
    ConfirmClearPeerHistory,
    CancelClearPeerHistory,
    PeerHistoryCleared(String, Result<usize, String>),
    PeerListenPortChanged(String),
    PeerAddressChanged(String),
    PeerRelayUrlChanged(String),
    PeerRelayTokenChanged(String),
    SavePeerRelayConfig,
    DiscardPeerRelayConfig,
    PeerRelayConfigLoaded(Result<storage::PeerRelayConfig, String>),
    PeerRelayConfigSaved(storage::PeerRelayConfig, Result<(), String>),
    PeerDraftChanged(String),
    StartPeerListener,
    StopPeerListener,
    PeerListenEvent(u64, PeerListenEvent),
    PeerRoutesLoaded(Result<Vec<storage::StoredPeerRoute>, String>),
    PeerRouteSaved(Result<Vec<storage::StoredPeerRoute>, String>),
    PeerInboundStored(u64, String, Result<storage::StoredDirectMessage, String>),
    PeerOutboundStored(u64, String, Result<storage::StoredDirectMessage, String>),
    SendPeerText,
    PeerCommandSent(Result<(), String>),
    MlsGroupIdChanged(String),
    SelectMlsGroup(Vec<u8>),
    RefreshMlsGroups,
    MlsGroupsLoaded(Result<Vec<storage::StoredMlsGroup>, String>),
    MlsKeyPackageChanged(String),
    MlsInviteKeyPackageChanged(String),
    MlsCommitChanged(String),
    MlsReceivedCommitChanged(String),
    MlsUpdateProposalChanged(String),
    MlsReceivedUpdateProposalChanged(String),
    CreateMlsUpdateProposal,
    MlsUpdateProposalCreated(Result<storage::PreparedMlsUpdateProposal, String>),
    SendMlsUpdateProposal,
    MlsUpdateProposalPeerCommandSent(u64, Result<(), String>),
    MlsUpdateProposalInboundProcessed(
        u64,
        peer::MlsProposalEnvelope,
        Result<storage::ProcessedMlsProposal, String>,
    ),
    ApplyMlsUpdateProposal,
    MlsUpdateProposalProcessed(Result<storage::ProcessedMlsProposal, String>),
    CommitMlsProposals,
    SetMlsProposalApproval([u8; 16], bool),
    MlsProposalCommitCreated(Result<storage::StoredMlsCommit, String>),
    ApplyMlsCommit,
    MlsCommitProcessed(Result<storage::ProcessedMlsCommit, String>),
    DistributeMlsCommit,
    DistributeMlsCommitsToAll,
    MlsCommitFanoutFinished(Vec<u8>, Result<MlsCommitFanoutReport, String>),
    DistributeMlsEventsToAll,
    MlsEventFanoutFinished(Vec<u8>, Result<MlsEventFanoutReport, String>),
    MlsCommitsReadyToSend(Vec<u8>, Result<Vec<storage::StoredMlsCommit>, String>),
    MlsCommitPeerCommandSent(u64, Result<(), String>),
    MlsCommitDelivered(u64, Result<(), String>),
    MlsWelcomesReadyToSend(
        Vec<u8>,
        [u8; 32],
        Result<Vec<storage::StoredMlsWelcome>, String>,
    ),
    MlsWelcomePeerCommandSent(u64, Result<(), String>),
    MlsWelcomeDelivered(u64, Result<(), String>),
    MlsCommitRequestedReady(
        Vec<u8>,
        u64,
        Result<Option<storage::StoredMlsCommit>, String>,
    ),
    MlsCommitInboundProcessed(
        u64,
        peer::MlsCommitEnvelope,
        Result<storage::ProcessedMlsCommit, String>,
    ),
    MlsWelcomeChanged(String),
    MlsRatchetTreeChanged(String),
    CreateMlsGroup,
    MlsGroupCreated(Result<storage::CreatedMlsGroup, String>),
    PrepareMlsKeyPackage,
    MlsKeyPackagePrepared(Result<storage::PreparedMlsKeyPackage, String>),
    AdmitMlsMember,
    MlsMemberAdded(Result<storage::AddedMlsMember, String>),
    JoinMlsGroup,
    MlsGroupJoined(Result<storage::JoinedMlsGroup, String>),
    CopyMlsValue(String),
    MlsMessageDraftChanged(String),
    MlsHistoryLoaded(Vec<u8>, Result<Vec<storage::StoredMlsMessage>, String>),
    MlsQuarantineLoaded(Vec<u8>, Result<Option<String>, String>),
    MlsCommitsLoaded(Vec<u8>, Result<Vec<storage::StoredMlsCommit>, String>),
    MlsCommitRecipientsLoaded(
        Vec<u8>,
        Result<Vec<storage::MlsCommitRecipientStatus>, String>,
    ),
    MlsPendingProposalsLoaded(Vec<u8>, Result<Vec<storage::StoredMlsProposal>, String>),
    MlsProposalApprovalSaved([u8; 16], bool, Result<(), String>),
    SendMlsKeyPackage,
    MlsKeyPackageCommandSent(u64, Result<(), String>),
    JoinMlsGroupFromPeer(u64, Result<storage::JoinedMlsGroup, String>),
    RetryQueuedMlsEvents,
    MlsOutboxLoaded(
        Vec<u8>,
        [u8; 32],
        Result<Vec<storage::StoredOutboundEvent>, String>,
    ),
    SendMlsApplication,
    MlsApplicationCreated(Result<storage::PreparedMlsApplicationEvent, String>),
    MlsApplicationRecipientReady(
        storage::PreparedMlsApplicationEvent,
        [u8; 32],
        Result<Vec<storage::StoredOutboundEvent>, String>,
    ),
    MlsPeerCommandSent(u64, Result<(), String>),
    MlsInboundProcessed(
        u64,
        peer::MlsEventEnvelope,
        Result<storage::ProcessedMlsApplicationEvent, String>,
    ),
    MlsOutboundHeld(u64, [u8; 16], Result<(), String>),
}

fn update(state: &mut Slouching, message: Message) -> Task<Message> {
    match message {
        Message::RefreshBackend => {
            state.backend = BackendConnection::Connecting;
            state.transport = TransportState::Connecting(1);
            if let Some(handle) = state.transport_handle.take() {
                handle.abort();
            }
            state.transport_generation = state.transport_generation.saturating_add(1);
            let (transport, handle) = transport_task(state.transport_generation);
            state.transport_handle = Some(handle);
            return Task::batch([
                Task::perform(fetch_backend_status(), Message::BackendFetched),
                transport,
            ]);
        }
        Message::BackendFetched(result) => {
            state.backend = match result {
                Ok(status) => BackendConnection::Connected(status),
                Err(FetchError::Unavailable(reason)) => BackendConnection::Unavailable(reason),
                Err(FetchError::ContractMismatch(reason)) => {
                    BackendConnection::ContractMismatch(reason)
                }
            };
        }
        Message::TransportEvent(generation, event) if generation == state.transport_generation => {
            state.transport = match event {
                TransportEvent::Connecting(attempt) => TransportState::Connecting(attempt),
                TransportEvent::Connected(hello) => TransportState::Active {
                    hello,
                    heartbeats: 0,
                },
                TransportEvent::Heartbeat => match &state.transport {
                    TransportState::Active { hello, heartbeats } => TransportState::Active {
                        hello: hello.clone(),
                        heartbeats: heartbeats + 1,
                    },
                    previous => previous.clone(),
                },
                TransportEvent::Disconnected {
                    reason,
                    retry_seconds,
                } => TransportState::Disconnected {
                    reason,
                    retry_seconds,
                },
                TransportEvent::ProtocolError(reason) => TransportState::ProtocolError(reason),
            };
        }
        Message::TransportEvent(_, _) => {}
        Message::DelegatedMlsStorageLoaded(result) => match result {
            Ok(status) => {
                state.delegated_mls_storage = Some(status);
                state.delegated_mls_storage_error = None;
            }
            Err(error) => state.delegated_mls_storage_error = Some(error),
        },
        Message::SetDelegatedMlsStorage(enabled) => {
            let quota = state
                .delegated_mls_storage
                .as_ref()
                .map_or(64 * 1024 * 1024, |s| s.quota_bytes);
            state.delegated_mls_storage_error = None;
            return Task::perform(
                set_delegated_mls_storage_task(enabled, quota),
                move |result| Message::DelegatedMlsStorageSaved(enabled, result),
            );
        }
        Message::DelegatedMlsStorageSaved(enabled, result) => match result {
            Ok(status) => {
                state.delegated_mls_storage = Some(status);
                state.delegated_mls_storage_error = None;
            }
            Err(error) => {
                state.delegated_mls_storage_error = Some(error);
                if let Some(status) = &mut state.delegated_mls_storage {
                    status.enabled = !enabled;
                }
            }
        },
        Message::DelegatedCopyStored(sequence, event_id, result) => match result {
            Ok(_) => {
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::AcceptInbound { sequence });
                }
                state.mls_status = format!(
                    "Cópia MLS {} guardada neste peer até o destinatário buscar ou o prazo vencer.",
                    hex_encode_bytes(&event_id[..4])
                );
            }
            Err(error) => {
                state.mls_status = format!("Cópia MLS não retida; ACK não enviado: {error}");
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                        sequence,
                        reason: error,
                    });
                }
            }
        },
        Message::DelegatedCopiesLoaded(result) => match result {
            Ok(copies) => {
                let Some(commands) = state.peer_session_commands.as_ref() else {
                    return Task::none();
                };
                let commands = commands.clone();
                let mut sends = Vec::new();
                for copy in copies {
                    let request_id = state.mls_next_request_id;
                    state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
                    let grant = copy.grant;
                    let event_id = grant.event_id;
                    let event = encrypted_event_to_peer(&grant, copy.ciphertext);
                    state.delegated_copy_sends.insert(request_id, event_id);
                    sends.push(peer::PeerCommand::SendDelegatedMlsCopy {
                        request_id,
                        grant: Box::new(delegated_copy_grant_to_peer(grant)),
                        event: Box::new(event),
                    });
                }
                return Task::perform(
                    async move {
                        for command in sends {
                            commands
                                .send(command)
                                .await
                                .map_err(|error| error.to_string())?;
                        }
                        Ok::<(), String>(())
                    },
                    |result| match result {
                        Ok(()) => Message::PeerCommandSent(Ok(())),
                        Err(error) => Message::PeerCommandSent(Err(error)),
                    },
                );
            }
            Err(error) => state.mls_status = format!("Falha ao buscar cópias MLS: {error}"),
        },
        Message::DelegatedCopyReceiptProcessed(sequence, result) => match result {
            Ok(_) => {
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::AcceptInbound { sequence });
                }
                state.mls_status =
                    "Cópia MLS delegada entregue e persistida no grupo local.".into();
            }
            Err(error) => {
                state.mls_status = format!("Cópia delegada não aplicada; ACK não enviado: {error}");
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                        sequence,
                        reason: error,
                    });
                }
            }
        },
        Message::DelegatedCopyAcknowledged(request_id, result) => {
            state.delegated_copy_sends.remove(&request_id);
            if let Err(error) = result {
                state.mls_status = format!("Falha ao remover cópia já entregue: {error}");
            }
        }
        Message::Navigate(screen) => {
            state.screen = screen;
            state.show_gallery = false;
            state.note = None;
        }
        Message::InviteChanged(value) => state.invite = value,
        Message::NameChanged(value) => state.name = value,
        Message::ChooseFamiliar(value) => state.familiar = value,
        Message::ToggleGallery => state.show_gallery = !state.show_gallery,
        Message::SettingsTab(value) => state.settings_tab = value,
        Message::ShareTab(value) => {
            state.share_tab = value;
            state.selected_source = 0;
        }
        Message::SelectSource(value) => state.selected_source = value,
        Message::DraftChanged(value) => state.draft = value,
        Message::ToggleTexture => state.texture = !state.texture,
        Message::PreviewAction(note) => state.note = Some(note),
        Message::DismissNote => state.note = None,
        Message::Capture => {
            return iced::window::latest()
                .and_then(iced::window::screenshot)
                .map(Message::Captured);
        }
        Message::Captured(screenshot) => {
            if let Some(dir) = &state.capture_dir {
                let path = dir.join(format!("{}.png", state.screen.slug()));
                if let Err(error) = image_codec::save_buffer(
                    &path,
                    &screenshot.rgba,
                    screenshot.size.width,
                    screenshot.size.height,
                    image_codec::ColorType::Rgba8,
                ) {
                    eprintln!("Screenshot failed: {error}");
                    return iced::exit();
                }
                println!(
                    "Captured {} ({} × {})",
                    path.display(),
                    screenshot.size.width,
                    screenshot.size.height
                );
                if state.capture_once {
                    return iced::exit();
                }
                state.capture_index += 1;
                if state.capture_index == Screen::ALL.len() {
                    return iced::exit();
                }
                state.screen = Screen::ALL[state.capture_index];
                return capture_after(Duration::from_millis(600));
            }
        }
        Message::ProfileLoaded(result) => match result {
            Ok(Some(profile)) => {
                state.name = profile.display_name;
                state.familiar = storage::familiar_label(&profile.familiar);
                state.profile_status = ProfileStatus::Saved;
            }
            Ok(None) => state.profile_status = ProfileStatus::Empty,
            Err(_) => {
                state.profile_status = ProfileStatus::Failed;
            }
        },
        Message::SaveProfile => {
            let display_name = state.name.trim().to_owned();
            if display_name.is_empty() {
                state.note = Some("Escolha um nome antes de salvar o perfil local.");
                return Task::none();
            }
            if display_name.chars().count() > 40 {
                state.note = Some("O nome do perfil pode ter até 40 caracteres.");
                return Task::none();
            }
            let profile = storage::LocalProfile {
                display_name,
                familiar: storage::familiar_id(state.familiar).to_owned(),
            };
            state.profile_status = ProfileStatus::Saving;
            return Task::perform(save_profile_task(profile.clone()), move |result| {
                Message::ProfileSaved(profile, result)
            });
        }
        Message::ProfileSaved(profile, result) => match result {
            Ok(()) => {
                state.name = profile.display_name;
                state.familiar = storage::familiar_label(&profile.familiar);
                state.profile_status = ProfileStatus::Saved;
                state.note = Some("Perfil salvo no armazenamento local cifrado.");
            }
            Err(_) => {
                state.profile_status = ProfileStatus::Failed;
                state.note = Some("Não foi possível salvar o perfil local.");
            }
        },
        Message::IdentityLoaded(result) => match result {
            Ok(Some(public_key)) => {
                state.identity_status = IdentityStatus::Ready(public_key);
                return request_peer_history(state);
            }
            Ok(None) => state.identity_status = IdentityStatus::Missing,
            Err(_) => state.identity_status = IdentityStatus::Failed,
        },
        Message::CreateIdentity => {
            state.identity_status = IdentityStatus::Creating;
            return Task::perform(create_identity_task(), Message::IdentityCreated);
        }
        Message::IdentityCreated(result) => match result {
            Ok(public_key) => {
                state.identity_status = IdentityStatus::Ready(public_key);
                state.identity_key_copied = false;
                return request_peer_history(state);
            }
            Err(_) => {
                state.identity_status = IdentityStatus::Failed;
            }
        },
        Message::CopyDeviceKey => {
            if let IdentityStatus::Ready(public_key) = state.identity_status {
                state.identity_key_copied = true;
                return iced::clipboard::write(hex_encode_key(&public_key));
            }
        }
        Message::CopyPeerListenAddress(address) => {
            return iced::clipboard::write(address);
        }
        Message::PeerPublicKeyChanged(value) => {
            if state.peer_public_key != value {
                state.peer_public_key = value.clone();
                state.peer_verification_loaded_for = None;
                state.peer_key_verified = false;
                state.peer_verification_status =
                    "Compare a chave completa por um canal independente.".to_owned();
                state.peer_transcript.clear();
                state.peer_history_loaded_for = None;
                state.peer_history_generation = state.peer_history_generation.saturating_add(1);
                state.peer_history_clear_confirmation = false;
            }
            let history = request_peer_history(state);
            if let Ok(peer_id) = parse_peer_id(&value) {
                let key = hex_encode_key(peer_id.as_bytes());
                return Task::batch([
                    history,
                    Task::perform(
                        load_peer_verification_task(*peer_id.as_bytes()),
                        move |result| Message::PeerVerificationLoaded(key, result),
                    ),
                ]);
            }
            return history;
        }
        Message::PeerVerificationLoaded(peer_key, result) => {
            let current_key = parse_peer_id(&state.peer_public_key)
                .ok()
                .map(|peer| hex_encode_key(peer.as_bytes()));
            if current_key.as_deref() == Some(peer_key.as_str()) {
                match result {
                    Ok(verified) => {
                        state.peer_verification_loaded_for = Some(peer_key);
                        state.peer_key_verified = verified;
                        state.peer_verification_status = if verified {
                            "Chave conferida e marcada como verificada neste dispositivo."
                        } else {
                            "Ainda não verificada por um canal independente."
                        }
                        .to_owned();
                    }
                    Err(error) => {
                        state.peer_key_verified = false;
                        state.peer_verification_status =
                            format!("Não foi possível carregar a verificação: {error}");
                    }
                }
            }
        }
        Message::TogglePeerVerification => {
            let local_key = match &state.identity_status {
                IdentityStatus::Ready(local_key) => local_key,
                _ => {
                    state.peer_verification_status =
                        "Carregue a identidade local antes de verificar um peer.".to_owned();
                    return Task::none();
                }
            };
            let peer_id = match parse_peer_id(&state.peer_public_key) {
                Ok(peer_id) => peer_id,
                Err(error) => {
                    state.peer_verification_status = error;
                    return Task::none();
                }
            };
            let key = hex_encode_key(peer_id.as_bytes());
            if state.peer_verification_loaded_for.as_deref() != Some(key.as_str()) {
                state.peer_verification_status = "Aguarde a consulta da chave pinada.".to_owned();
                return Task::none();
            }
            if peer_is_local(&peer_id, local_key) {
                state.peer_verification_status =
                    "Não é possível verificar a própria chave como peer.".to_owned();
                return Task::none();
            }
            let verified = !state.peer_key_verified;
            state.peer_verification_status = if verified {
                "Salvando verificação local…".to_owned()
            } else {
                "Removendo verificação local…".to_owned()
            };
            return Task::perform(
                set_peer_verification_task(*peer_id.as_bytes(), verified),
                move |result| Message::PeerVerificationSaved(key, verified, result),
            );
        }
        Message::PeerVerificationSaved(peer_key, verified, result) => {
            let current_key = parse_peer_id(&state.peer_public_key)
                .ok()
                .map(|peer| hex_encode_key(peer.as_bytes()));
            if current_key.as_deref() == Some(peer_key.as_str()) {
                match result {
                    Ok(()) => {
                        state.peer_verification_loaded_for = Some(peer_key);
                        state.peer_key_verified = verified;
                        state.peer_verification_status = if verified {
                            "Chave conferida e marcada como verificada neste dispositivo."
                        } else {
                            "Verificação local removida para esta chave."
                        }
                        .to_owned();
                    }
                    Err(error) => {
                        state.peer_verification_status =
                            format!("Não foi possível salvar a verificação: {error}");
                    }
                }
            }
        }
        Message::PeerHistoryLoaded(generation, peer_key, result) => {
            if generation == state.peer_history_generation
                && state.peer_history_loaded_for.as_deref() == Some(peer_key.as_str())
                && state.peer_public_key == peer_key
            {
                match result {
                    Ok(messages) => {
                        let mut transcript: Vec<PeerTranscriptEntry> = messages
                            .into_iter()
                            .map(|message| PeerTranscriptEntry {
                                direction: match message.direction {
                                    storage::DirectMessageDirection::Sent => {
                                        PeerMessageDirection::Sent
                                    }
                                    storage::DirectMessageDirection::Received => {
                                        PeerMessageDirection::Received
                                    }
                                },
                                text: message.text,
                                persisted: true,
                                sequence: Some(message.sequence),
                                transport_id: None,
                            })
                            .collect();
                        for entry in std::mem::take(&mut state.peer_transcript) {
                            if !transcript
                                .iter()
                                .any(|loaded| loaded.sequence == entry.sequence)
                            {
                                transcript.push(entry);
                            }
                        }
                        transcript.sort_by_key(|entry| entry.sequence.unwrap_or(i64::MAX));
                        if transcript.len() > 200 {
                            transcript.drain(..transcript.len() - 200);
                        }
                        state.peer_transcript = transcript;
                    }
                    Err(error) => {
                        state.peer_send_status = PeerSendStatus::Failed(format!(
                            "Não foi possível carregar o histórico local: {error}"
                        ));
                    }
                }
            }
        }
        Message::RequestClearPeerHistory => {
            let can_clear = state.peer_history_loaded_for.as_deref()
                == Some(state.peer_public_key.as_str())
                && !state.peer_history_clearing
                && state.peer_listener_handle.is_none()
                && state.peer_pending_sends.is_empty();
            if can_clear {
                state.peer_history_clear_confirmation = true;
            }
        }
        Message::CancelClearPeerHistory => {
            state.peer_history_clear_confirmation = false;
        }
        Message::ConfirmClearPeerHistory => {
            if !state.peer_history_clear_confirmation
                || state.peer_listener_handle.is_some()
                || !state.peer_pending_sends.is_empty()
            {
                return Task::none();
            }
            let peer_key = state.peer_public_key.clone();
            let Ok(peer_id) = parse_peer_id(&peer_key) else {
                state.peer_history_clear_confirmation = false;
                return Task::none();
            };
            state.peer_history_clear_confirmation = false;
            state.peer_history_clearing = true;
            state.peer_history_generation = state.peer_history_generation.saturating_add(1);
            state.peer_history_loaded_for = None;
            let peer_device = *peer_id.as_bytes();
            return Task::perform(clear_direct_history_task(peer_device), move |result| {
                Message::PeerHistoryCleared(peer_key, result)
            });
        }
        Message::PeerHistoryCleared(peer_key, result) => {
            state.peer_history_clearing = false;
            if state.peer_public_key == peer_key {
                state.peer_history_loaded_for = Some(peer_key);
                match result {
                    Ok(_) => {
                        state.peer_transcript.clear();
                        state.note = Some("Histórico local deste peer apagado.");
                    }
                    Err(error) => {
                        state.peer_send_status = PeerSendStatus::Failed(format!(
                            "Não foi possível apagar o histórico local: {error}"
                        ));
                    }
                }
            }
        }
        Message::PeerListenPortChanged(value) => state.peer_listen_port = value,
        Message::PeerAddressChanged(value) => state.peer_address = value,
        Message::PeerRelayUrlChanged(value) => {
            state.peer_relay_url = value;
            state.peer_relay_config_dirty = true;
            state.peer_relay_config_status =
                "Relay editado; salve para aplicar à próxima conexão".to_owned();
        }
        Message::PeerRelayTokenChanged(value) => {
            state.peer_relay_token = value;
            state.peer_relay_config_dirty = true;
            state.peer_relay_config_status =
                "Relay editado; salve para aplicar à próxima conexão".to_owned();
        }
        Message::PeerRelayConfigLoaded(result) => match result {
            Ok(config) => {
                state.peer_relay_config_loaded = true;
                state.peer_relay_url = config.url.clone();
                state.peer_relay_token = config.token.clone();
                state.peer_relay_config = config.clone();
                state.peer_relay_config_dirty = false;
                state.peer_relay_config_status = if config.url.is_empty() {
                    "Relay opcional desativado".to_owned()
                } else {
                    "Relay do grupo carregado do perfil local".to_owned()
                };
            }
            Err(error) => state.peer_relay_config_status = error,
        },
        Message::SavePeerRelayConfig => {
            if state.peer_listener_handle.is_some() {
                state.peer_relay_config_status =
                    "Desconecte antes de alterar o relay usado por uma sessão.".to_owned();
                return Task::none();
            }
            let config = storage::PeerRelayConfig {
                url: state.peer_relay_url.trim().to_owned(),
                token: state.peer_relay_token.trim().to_owned(),
            };
            if let Err(error) = validate_peer_relay_config(&config) {
                state.peer_relay_config_status = error;
                return Task::none();
            }
            state.peer_relay_config_status = "Salvando relay no perfil local cifrado…".to_owned();
            return Task::perform(save_peer_relay_config_task(config.clone()), move |result| {
                Message::PeerRelayConfigSaved(config, result)
            });
        }
        Message::DiscardPeerRelayConfig => {
            state.peer_relay_url = state.peer_relay_config.url.clone();
            state.peer_relay_token = state.peer_relay_config.token.clone();
            state.peer_relay_config_dirty = false;
            state.peer_relay_config_status = if state.peer_relay_config.url.is_empty() {
                "Relay opcional desativado".to_owned()
            } else {
                "Relay salvo restaurado".to_owned()
            };
        }
        Message::PeerRelayConfigSaved(config, result) => match result {
            Ok(()) => {
                state.peer_relay_config_loaded = true;
                state.peer_relay_config = config.clone();
                state.peer_relay_url = config.url;
                state.peer_relay_token = config.token;
                state.peer_relay_config_dirty = false;
                state.peer_relay_config_status = if state.peer_relay_config.url.is_empty() {
                    "Relay opcional desativado e removido do perfil".to_owned()
                } else {
                    "Relay do grupo salvo no perfil local cifrado".to_owned()
                };
            }
            Err(error) => state.peer_relay_config_status = error,
        },
        Message::PeerRoutesLoaded(result) => match result {
            Ok(routes) => {
                state.peer_routes = routes;
                state.peer_routes_error = None;
            }
            Err(error) => state.peer_routes_error = Some(error),
        },
        Message::PeerRouteSaved(result) => match result {
            Ok(routes) => {
                state.peer_routes = routes;
                state.peer_routes_error = None;
            }
            Err(error) => state.peer_routes_error = Some(error),
        },
        Message::PeerDraftChanged(value) => state.peer_draft = value,
        Message::StartPeerListener => {
            if state.peer_listener_handle.is_some() {
                return Task::none();
            }
            if !state.peer_relay_config_loaded {
                state.peer_listen_status = PeerListenStatus::Failed(
                    "Aguarde o perfil local carregar a configuração de relay.".to_owned(),
                );
                return Task::none();
            }
            if state.peer_relay_config_dirty {
                state.peer_listen_status = PeerListenStatus::Failed(
                    "Salve ou descarte as alterações de relay antes de iniciar.".to_owned(),
                );
                return Task::none();
            }
            if !matches!(state.identity_status, IdentityStatus::Ready(_)) {
                state.peer_listen_status = PeerListenStatus::Failed(
                    "Crie ou carregue a identidade do dispositivo antes de escutar.".to_owned(),
                );
                return Task::none();
            }
            let port = match state.peer_listen_port.parse::<u16>() {
                Ok(port) if port != 0 => port,
                _ => {
                    state.peer_listen_status = PeerListenStatus::Failed(
                        "Informe uma porta UDP entre 1 e 65535.".to_owned(),
                    );
                    return Task::none();
                }
            };
            let relay = match peer_relay_from_config(&state.peer_relay_config) {
                Ok(relay) => relay,
                Err(error) => {
                    state.peer_listen_status = PeerListenStatus::Failed(error);
                    return Task::none();
                }
            };
            let helper_mode = state
                .delegated_mls_storage
                .is_some_and(|status| status.enabled);
            let expected_peer = if helper_mode {
                None
            } else {
                let peer = match parse_peer_id(&state.peer_public_key) {
                    Ok(peer) => peer,
                    Err(error) => {
                        state.peer_listen_status = PeerListenStatus::Failed(error);
                        return Task::none();
                    }
                };
                if let IdentityStatus::Ready(local_public_key) = state.identity_status
                    && peer_is_local(&peer, &local_public_key)
                {
                    state.peer_listen_status = PeerListenStatus::Failed(
                        "A chave do peer é a sua própria chave. Cole a chave do outro dispositivo."
                            .to_owned(),
                    );
                    return Task::none();
                }
                Some(peer)
            };
            state.peer_listener_generation = state.peer_listener_generation.saturating_add(1);
            let generation = state.peer_listener_generation;
            state.peer_listen_status = PeerListenStatus::Starting { port };
            state.helper_listener_active = helper_mode;
            state.peer_listener_port = Some(port);
            state.peer_listener_addresses.clear();
            let (task, handle) = peer_listener_task(generation, port, expected_peer, relay);
            state.peer_listener_handle = Some(handle);
            state.peer_session_commands = None;
            return task;
        }
        Message::StopPeerListener => {
            if state.helper_listener_active {
                if let Some(handle) = state.peer_listener_handle.take() {
                    handle.abort();
                }
                state.peer_session_commands = None;
                state.active_peer_device = None;
                state.helper_listener_active = false;
                state.peer_listener_port = None;
                state.peer_listener_addresses.clear();
                state.peer_listener_generation = state.peer_listener_generation.saturating_add(1);
                state.peer_listen_status = PeerListenStatus::Idle;
                return Task::none();
            }
            if matches!(
                state.peer_listen_status,
                PeerListenStatus::Connected
                    | PeerListenStatus::Listening { .. }
                    | PeerListenStatus::Unauthorized(_)
            ) {
                if let Some(commands) = state.peer_session_commands.take() {
                    let _ = commands.try_send(peer::PeerCommand::Disconnect);
                }
            } else if let Some(handle) = state.peer_listener_handle.take() {
                // While accept is pending, no session command receiver is active;
                // dropping this task closes the listener endpoint.
                handle.abort();
                state.peer_session_commands = None;
                state.peer_listener_generation = state.peer_listener_generation.saturating_add(1);
                state.peer_listen_status = PeerListenStatus::Idle;
            }
        }
        Message::PeerListenEvent(generation, event)
            if generation == state.peer_listener_generation =>
        {
            match event {
                PeerListenEvent::Bound { addresses } => {
                    let port = match state.peer_listen_status {
                        PeerListenStatus::Starting { port } => port,
                        PeerListenStatus::Listening { port, .. } => port,
                        _ => 0,
                    };
                    state.peer_listen_status = PeerListenStatus::Listening { port, addresses };
                    state.peer_listener_port = Some(port);
                    if let PeerListenStatus::Listening { addresses, .. } = &state.peer_listen_status
                    {
                        state.peer_listener_addresses = addresses.clone();
                    }
                }
                PeerListenEvent::SessionCommands(commands) => {
                    state.peer_session_commands = Some(commands);
                }
                PeerListenEvent::Session(peer::PeerEvent::Connected { peer_id }) => {
                    state.active_peer_device = Some(*peer_id.as_bytes());
                    if let Some(commands) = state.peer_session_commands.as_ref() {
                        let _ = commands.try_send(peer::PeerCommand::RequestDelegatedMlsCopies);
                    }
                    let initiated_connection =
                        matches!(state.peer_send_status, PeerSendStatus::Connecting);
                    let relay_configured = !state.peer_relay_config.url.trim().is_empty();
                    let relay_only_route =
                        initiated_connection && state.peer_address.trim().is_empty();
                    let remember_route = !state.helper_listener_active
                        && ((initiated_connection && !state.peer_address.trim().is_empty())
                            || relay_configured);
                    let route_task = if remember_route {
                        Task::perform(
                            save_peer_route_task(
                                *peer_id.as_bytes(),
                                state.peer_address.clone(),
                                relay_only_route || !initiated_connection,
                                !initiated_connection,
                            ),
                            Message::PeerRouteSaved,
                        )
                    } else {
                        Task::none()
                    };
                    apply_peer_event(state, peer::PeerEvent::Connected { peer_id });
                    let Some(group_id) = state.mls_history_group.clone() else {
                        return route_task;
                    };
                    if state.helper_listener_active && !active_peer_is_pinned(state) {
                        return route_task;
                    }
                    state.mls_status = "Sessão conectada; verificando Commits pendentes autorizados para este dispositivo…".to_owned();
                    let peer_device = *peer_id.as_bytes();
                    let commits_task = Task::perform(
                        load_mls_commits_for_peer_task(group_id.clone(), peer_device),
                        move |result| Message::MlsCommitsReadyToSend(group_id, result),
                    );
                    let welcome_group_id = state.mls_history_group.clone().unwrap_or_default();
                    let welcome_task = Task::perform(
                        load_mls_welcomes_for_peer_task(welcome_group_id.clone(), peer_device),
                        move |result| {
                            Message::MlsWelcomesReadyToSend(welcome_group_id, peer_device, result)
                        },
                    );
                    return Task::batch([route_task, commits_task, welcome_task]);
                }
                PeerListenEvent::Session(event) => match event {
                    peer::PeerEvent::Disconnected { reason } if state.helper_listener_active => {
                        state.active_peer_device = None;
                        state.peer_session_commands = None;
                        if let Some(port) = state.peer_listener_port {
                            state.peer_listen_status = PeerListenStatus::Listening {
                                port,
                                addresses: state.peer_listener_addresses.clone(),
                            };
                        } else {
                            state.peer_listen_status = PeerListenStatus::Failed(reason);
                        }
                    }
                    peer::PeerEvent::Received { sequence, text } => {
                        if !active_peer_is_pinned(state) {
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                                    sequence,
                                    reason: "direct text requires the manually pinned peer".into(),
                                });
                            }
                            return Task::none();
                        }
                        let Some(peer_device) = state.active_peer_device else {
                            state.peer_send_status = PeerSendStatus::Failed(
                                "Chave do peer inválida; mensagem recebida sem confirmação."
                                    .to_owned(),
                            );
                            return Task::none();
                        };
                        return Task::perform(
                            store_direct_message_task(
                                peer_device,
                                storage::DirectMessageDirection::Received,
                                text.clone(),
                            ),
                            move |result| Message::PeerInboundStored(sequence, text, result),
                        );
                    }
                    peer::PeerEvent::Acknowledged { request_id, text } => {
                        let Some(peer_device) = state
                            .active_peer_device
                            .filter(|_| active_peer_is_pinned(state))
                        else {
                            state.peer_pending_sends.remove(&request_id);
                            state.peer_send_status = PeerSendStatus::Failed(
                                "Peer confirmou a entrega, mas a chave do peer está inválida."
                                    .to_owned(),
                            );
                            return Task::none();
                        };
                        return Task::perform(
                            store_direct_message_task(
                                peer_device,
                                storage::DirectMessageDirection::Sent,
                                text.clone(),
                            ),
                            move |result| Message::PeerOutboundStored(request_id, text, result),
                        );
                    }
                    peer::PeerEvent::MlsEventReceived { sequence, event } => {
                        if !active_peer_is_pinned(state)
                            || Some(event.author_device) != state.active_peer_device
                        {
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                                    sequence,
                                    reason: "MLS event author must match the pinned session peer"
                                        .into(),
                                });
                            }
                            return Task::none();
                        }
                        let stored_event = storage::EncryptedEvent {
                            event_id: event.event_id,
                            author_device: event.author_device,
                            group_id: event.group_id.clone(),
                            epoch: event.epoch,
                            checkpoint: event.checkpoint.clone(),
                            expires_at_unix: event.expires_at_unix,
                            ciphertext: event.ciphertext.clone(),
                        };
                        return Task::perform(
                            process_inbound_mls_application_task(stored_event),
                            move |result| Message::MlsInboundProcessed(sequence, event, result),
                        );
                    }
                    peer::PeerEvent::DelegatedMlsCopyReceived {
                        sequence,
                        peer_id,
                        grant,
                        event,
                    } => {
                        let local_device = match state.identity_status {
                            IdentityStatus::Ready(key) => key,
                            _ => {
                                if let Some(commands) = state.peer_session_commands.as_ref() {
                                    let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                                        sequence,
                                        reason: "local device identity is unavailable".into(),
                                    });
                                }
                                return Task::none();
                            }
                        };
                        let stored_event = peer_event_to_encrypted(&event);
                        if grant.author_device == *peer_id.as_bytes() {
                            let grant_for_storage = peer_grant_to_storage(*grant);
                            return Task::perform(
                                store_delegated_copy_task(
                                    grant_for_storage,
                                    stored_event,
                                    *peer_id.as_bytes(),
                                ),
                                move |result| {
                                    Message::DelegatedCopyStored(sequence, event.event_id, result)
                                },
                            );
                        }
                        let grant_for_storage = peer_grant_to_storage(*grant);
                        return Task::perform(
                            process_delegated_copy_for_recipient_task(
                                grant_for_storage,
                                stored_event,
                                local_device,
                            ),
                            move |result| Message::DelegatedCopyReceiptProcessed(sequence, result),
                        );
                    }
                    peer::PeerEvent::DelegatedMlsCopiesRequested { peer_id } => {
                        return Task::perform(
                            load_delegated_copies_task(*peer_id.as_bytes()),
                            Message::DelegatedCopiesLoaded,
                        );
                    }
                    peer::PeerEvent::MlsCommitReceived { sequence, commit } => {
                        if !active_peer_is_pinned(state)
                            || Some(commit.author_device) != state.active_peer_device
                        {
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                                    sequence,
                                    reason: "MLS Commit author must match the pinned session peer"
                                        .into(),
                                });
                            }
                            return Task::none();
                        }
                        return Task::perform(
                            process_mls_commit_envelope_task(commit.clone()),
                            move |result| {
                                Message::MlsCommitInboundProcessed(sequence, commit, result)
                            },
                        );
                    }
                    peer::PeerEvent::MlsProposalReceived {
                        sequence,
                        peer_id,
                        proposal,
                    } => {
                        let pinned_peer = *peer_id.as_bytes();
                        if !active_peer_is_pinned(state) || proposal.author_device != pinned_peer {
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                                    sequence,
                                    reason: "MLS proposal author does not match pinned peer".into(),
                                });
                            }
                            state.mls_status =
                                "Proposta rejeitada: autor MLS diverge do peer fixado.".into();
                            return Task::none();
                        }
                        return Task::perform(
                            process_mls_proposal_from_peer_task(proposal.clone(), pinned_peer),
                            move |result| {
                                Message::MlsUpdateProposalInboundProcessed(
                                    sequence, proposal, result,
                                )
                            },
                        );
                    }
                    peer::PeerEvent::MlsKeyPackageReceived {
                        sequence,
                        peer_id,
                        key_package,
                    } => {
                        let pinned_peer = *peer_id.as_bytes();
                        let selected_group = hex_decode_bytes(&state.mls_group_id).ok();
                        let rejection = if !active_peer_is_pinned(state) {
                            Some("KeyPackage requires the manually pinned peer")
                        } else if key_package.invitee_device != pinned_peer {
                            Some("KeyPackage identity does not match the pinned peer")
                        } else if selected_group.as_deref() != Some(key_package.group_id.as_slice())
                        {
                            Some("open the matching MLS group before receiving its KeyPackage")
                        } else if state.mls_pending_peer_key_package.is_some() {
                            Some("another peer KeyPackage is already awaiting review")
                        } else {
                            None
                        };
                        if let Some(reason) = rejection {
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                                    sequence,
                                    reason: reason.to_owned(),
                                });
                            }
                            state.mls_status = format!("KeyPackage rejeitado: {reason}.");
                        } else {
                            state.mls_invite_key_package =
                                hex_encode_bytes(&key_package.key_package);
                            state.mls_pending_peer_key_package = Some((
                                sequence,
                                pinned_peer,
                                key_package.group_id,
                                key_package.key_package,
                            ));
                            state.mls_status = "KeyPackage do peer fixado recebido. Revise o grupo e clique em Validar e admitir membro para persistir o Commit.".into();
                        }
                    }
                    peer::PeerEvent::MlsWelcomeReceived {
                        sequence,
                        peer_id,
                        welcome,
                    } => {
                        let pinned_peer = *peer_id.as_bytes();
                        let rejection = if !active_peer_is_pinned(state) {
                            Some("Welcome requires the manually pinned committer")
                        } else if welcome.invitee_device
                            != match state.identity_status {
                                IdentityStatus::Ready(device) => device,
                                _ => [0; 32],
                            }
                        {
                            Some("Welcome is addressed to another device")
                        } else if state.mls_pending_peer_welcome.is_some() {
                            Some("another MLS Welcome is already awaiting admission")
                        } else {
                            None
                        };
                        if let Some(reason) = rejection {
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                                    sequence,
                                    reason: reason.to_owned(),
                                });
                            }
                            state.mls_status = format!("Welcome rejeitado: {reason}.");
                        } else {
                            state.mls_group_id = hex_encode_bytes(&welcome.group_id);
                            state.mls_welcome = hex_encode_bytes(&welcome.welcome);
                            state.mls_ratchet_tree = hex_encode_bytes(&welcome.ratchet_tree);
                            state.mls_pending_peer_welcome = Some((
                                sequence,
                                pinned_peer,
                                welcome.event_id,
                                welcome.group_id,
                                welcome.welcome,
                                welcome.ratchet_tree,
                            ));
                            state.mls_status = "Welcome recebido do committer fixado. Revise o convite e clique em Validar Welcome e entrar para salvar antes do ACK.".into();
                        }
                    }
                    peer::PeerEvent::MlsCommitRequested {
                        peer_id,
                        group_id,
                        predecessor_epoch,
                    } => {
                        if !active_peer_is_pinned(state)
                            || Some(*peer_id.as_bytes()) != state.active_peer_device
                        {
                            state.mls_status =
                                "Pedido de Commit recusado: peer não está fixado.".into();
                            return Task::none();
                        }
                        let peer_device = *peer_id.as_bytes();
                        return Task::perform(
                            load_authorized_mls_commit_task(
                                group_id.clone(),
                                predecessor_epoch,
                                peer_device,
                            ),
                            move |result| {
                                Message::MlsCommitRequestedReady(
                                    group_id,
                                    predecessor_epoch,
                                    result,
                                )
                            },
                        );
                    }
                    peer::PeerEvent::MlsCommitAcknowledged { request_id } => {
                        let Some(event_id) = state.mls_sending_commits.get(&request_id).copied()
                        else {
                            state.mls_status =
                                "ACK de Commit desconhecido; sessão encerrada.".to_owned();
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::Disconnect);
                            }
                            return Task::none();
                        };
                        let peer_device = match parse_peer_id(&state.peer_public_key) {
                            Ok(peer) => *peer.as_bytes(),
                            Err(error) => {
                                state.mls_status =
                                    format!("ACK recebido, mas peer inválido: {error}");
                                return Task::none();
                            }
                        };
                        return Task::perform(
                            mark_mls_commit_delivered_task(event_id, peer_device),
                            move |result| Message::MlsCommitDelivered(request_id, result),
                        );
                    }
                    peer::PeerEvent::MlsProposalAcknowledged { request_id } => {
                        if !state.mls_sending_proposals.remove(&request_id) {
                            state.mls_status =
                                "ACK de proposta desconhecida; sessão encerrada.".into();
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::Disconnect);
                            }
                            return Task::none();
                        }
                        state.mls_status = format!(
                            "Proposta de atualização MLS {request_id} foi persistida pelo committer."
                        );
                    }
                    peer::PeerEvent::MlsProposalRejected { request_id, reason } => {
                        state.mls_sending_proposals.remove(&request_id);
                        state.mls_status =
                            format!("Proposta MLS {request_id} rejeitada pelo peer: {reason}");
                    }
                    peer::PeerEvent::MlsProposalDeliveryUnknown { request_id } => {
                        state.mls_sending_proposals.remove(&request_id);
                        state.mls_status = format!(
                            "Entrega da proposta MLS {request_id} desconhecida; reenvie os mesmos bytes para evitar proposta duplicada."
                        );
                    }
                    peer::PeerEvent::MlsKeyPackageAcknowledged { request_id } => {
                        if !state.mls_sending_key_packages.remove(&request_id) {
                            state.mls_status =
                                "ACK de KeyPackage desconhecido; sessão encerrada.".into();
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::Disconnect);
                            }
                            return Task::none();
                        }
                        state.mls_status = "O committer autenticou e admitiu o KeyPackage; compartilhe Welcome e ratchet tree para concluir a entrada neste peer.".into();
                    }
                    peer::PeerEvent::MlsKeyPackageRejected { request_id, reason } => {
                        state.mls_sending_key_packages.remove(&request_id);
                        state.mls_status =
                            format!("KeyPackage {request_id} rejeitado pelo committer: {reason}");
                    }
                    peer::PeerEvent::MlsKeyPackageDeliveryUnknown { request_id } => {
                        state.mls_sending_key_packages.remove(&request_id);
                        state.mls_status = format!(
                            "Entrega do KeyPackage {request_id} desconhecida; envie novamente pelo mesmo peer."
                        );
                    }
                    peer::PeerEvent::MlsWelcomeAcknowledged { request_id } => {
                        if let Some(event_id) = state.mls_sending_welcomes.get(&request_id).copied()
                        {
                            return Task::perform(
                                mark_mls_welcome_delivered_task(event_id),
                                move |result| Message::MlsWelcomeDelivered(request_id, result),
                            );
                        }
                        state.mls_status = "ACK de Welcome desconhecido; sessão encerrada.".into();
                    }
                    peer::PeerEvent::MlsWelcomeRejected { request_id, reason } => {
                        state.mls_sending_welcomes.remove(&request_id);
                        state.mls_status = format!("Welcome {request_id} rejeitado: {reason}");
                    }
                    peer::PeerEvent::MlsWelcomeDeliveryUnknown { request_id } => {
                        state.mls_sending_welcomes.remove(&request_id);
                        state.mls_status = format!(
                            "Entrega do Welcome {request_id} desconhecida; confira o grupo no convidado antes de tentar novamente."
                        );
                    }
                    peer::PeerEvent::MlsCommitRejected { request_id, reason } => {
                        state.mls_sending_commits.remove(&request_id);
                        state.mls_status =
                            format!("Commit {request_id} não foi aplicado pelo peer: {reason}");
                    }
                    peer::PeerEvent::MlsCommitDeliveryUnknown { request_id } => {
                        state.mls_sending_commits.remove(&request_id);
                        state.mls_status = format!(
                            "Entrega do Commit {request_id} desconhecida; ele continua salvo para redelivery idempotente."
                        );
                    }
                    peer::PeerEvent::MlsEventAcknowledged { request_id } => {
                        let Some((event_id, peer_device)) =
                            state.mls_pending_events.get(&request_id).copied()
                        else {
                            state.mls_status =
                                "ACK de um evento MLS desconhecido; sessão encerrada.".to_owned();
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::Disconnect);
                            }
                            return Task::none();
                        };
                        return Task::perform(
                            update_mls_outbound_state_task(event_id, peer_device),
                            move |result| Message::MlsOutboundHeld(request_id, event_id, result),
                        );
                    }
                    peer::PeerEvent::DelegatedMlsCopyAcknowledged { request_id } => {
                        let Some(event_id) = state.delegated_copy_sends.get(&request_id).copied()
                        else {
                            // An author-to-helper store ACK does not correspond to a local held copy.
                            return Task::none();
                        };
                        let recipient = match parse_peer_id(&state.peer_public_key) {
                            Ok(peer) => *peer.as_bytes(),
                            Err(error) => {
                                state.mls_status = format!("Peer da cópia inválido: {error}");
                                return Task::none();
                            }
                        };
                        return Task::perform(
                            acknowledge_delegated_copy_task(event_id, recipient),
                            move |result| Message::DelegatedCopyAcknowledged(request_id, result),
                        );
                    }
                    peer::PeerEvent::DelegatedMlsCopyRejected { request_id, reason } => {
                        state.delegated_copy_sends.remove(&request_id);
                        state.mls_status = format!("Cópia MLS delegada recusada: {reason}");
                    }
                    peer::PeerEvent::DelegatedMlsCopyDeliveryUnknown { request_id } => {
                        state.delegated_copy_sends.remove(&request_id);
                        state.mls_status = "Entrega da cópia MLS desconhecida; ela permanece disponível para nova busca.".into();
                    }
                    peer::PeerEvent::MlsEventDeliveryUnknown { request_id } => {
                        state.mls_pending_events.remove(&request_id);
                        state.mls_status = format!(
                            "Entrega MLS {request_id} desconhecida; o ciphertext continua no outbox para reenvio."
                        );
                    }
                    peer::PeerEvent::MlsEventRejected { request_id, reason } => {
                        state.mls_pending_events.remove(&request_id);
                        state.mls_status = format!(
                            "Evento continua no outbox e não entrou na fila de transporte: {reason}"
                        );
                    }
                    event => apply_peer_event(state, event),
                },
                PeerListenEvent::Failed(error) => {
                    state.peer_listener_handle = None;
                    state.peer_session_commands = None;
                    if matches!(state.peer_send_status, PeerSendStatus::Connecting) {
                        state.peer_pending_sends.clear();
                        state.peer_send_status = PeerSendStatus::Failed(format!(
                            "Envio falhou: {error}. A mensagem não foi enviada."
                        ));
                    } else {
                        state.peer_listen_status = PeerListenStatus::Failed(error);
                    }
                }
            }
        }
        Message::PeerListenEvent(_, _) => {}
        Message::PeerInboundStored(sequence, text, result) => match result {
            Ok(stored) => {
                apply_peer_event(state, peer::PeerEvent::Received { sequence, text });
                if let Some(entry) = state.peer_transcript.iter_mut().rev().find(|entry| {
                    entry.direction == PeerMessageDirection::Received
                        && entry.transport_id == Some(sequence)
                }) {
                    entry.sequence = Some(stored.sequence);
                    entry.persisted = true;
                    entry.transport_id = None;
                }
            }
            Err(error) => {
                state.peer_send_status = PeerSendStatus::Failed(format!(
                    "Mensagem recebida, mas não foi salva localmente; ACK não enviado: {error}"
                ));
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::Disconnect);
                }
            }
        },
        Message::PeerOutboundStored(request_id, text, result) => match result {
            Ok(stored) => {
                apply_peer_event(state, peer::PeerEvent::Acknowledged { request_id, text });
                if let Some(entry) = state.peer_transcript.iter_mut().rev().find(|entry| {
                    entry.direction == PeerMessageDirection::Sent
                        && entry.transport_id == Some(request_id)
                }) {
                    entry.sequence = Some(stored.sequence);
                    entry.persisted = true;
                    entry.transport_id = None;
                }
            }
            Err(error) => {
                state.peer_pending_sends.remove(&request_id);
                state.peer_send_status = PeerSendStatus::Failed(format!(
                    "Peer confirmou a entrega, mas o histórico local falhou: {error}"
                ));
            }
        },
        Message::SendPeerText => {
            if !state.peer_relay_config_loaded {
                state.peer_send_status = PeerSendStatus::Failed(
                    "Aguarde o perfil local carregar a configuração de relay.".to_owned(),
                );
                return Task::none();
            }
            if state.peer_relay_config_dirty {
                state.peer_send_status = PeerSendStatus::Failed(
                    "Salve ou descarte as alterações de relay antes de conectar.".to_owned(),
                );
                return Task::none();
            }
            if !matches!(state.identity_status, IdentityStatus::Ready(_)) {
                state.peer_send_status = PeerSendStatus::Failed(
                    "Crie ou carregue a identidade do dispositivo antes de enviar.".to_owned(),
                );
                return Task::none();
            }
            let text = state.peer_draft.trim().to_owned();
            if text.is_empty() || text.len() > 16 * 1024 {
                state.peer_send_status = PeerSendStatus::Failed(
                    "A mensagem precisa ter entre 1 e 16 KiB em UTF-8.".to_owned(),
                );
                return Task::none();
            }
            if let Some(commands) = state.peer_session_commands.as_ref() {
                let request_id = state.peer_next_request_id;
                state.peer_next_request_id = state.peer_next_request_id.saturating_add(1);
                state.peer_pending_sends.insert(request_id, text.clone());
                state.peer_send_status = PeerSendStatus::AwaitingAck;
                let commands = commands.clone();
                return Task::perform(
                    async move {
                        commands
                            .send(peer::PeerCommand::Send { request_id, text })
                            .await
                            .map_err(|error| error.to_string())
                    },
                    Message::PeerCommandSent,
                );
            }
            let expected_peer = match parse_peer_id(&state.peer_public_key) {
                Ok(peer) => peer,
                Err(error) => {
                    state.peer_send_status = PeerSendStatus::Failed(error);
                    return Task::none();
                }
            };
            if let IdentityStatus::Ready(local_public_key) = state.identity_status
                && peer_is_local(&expected_peer, &local_public_key)
            {
                state.peer_send_status = PeerSendStatus::Failed(
                    "A chave do peer é a sua própria chave. Cole a chave do outro dispositivo."
                        .to_owned(),
                );
                return Task::none();
            }
            let address = if state.peer_address.trim().is_empty() {
                None
            } else {
                match state.peer_address.parse::<std::net::SocketAddr>() {
                    Ok(address) if !address.ip().is_unspecified() && address.port() != 0 => {
                        Some(address)
                    }
                    _ => {
                        state.peer_send_status = PeerSendStatus::Failed(
                            "Informe um IP alcançável com porta UDP válida.".to_owned(),
                        );
                        return Task::none();
                    }
                }
            };
            let relay = match peer_relay_from_config(&state.peer_relay_config) {
                Ok(relay) => relay,
                Err(error) => {
                    state.peer_send_status = PeerSendStatus::Failed(error);
                    return Task::none();
                }
            };
            if address.is_none() && relay.is_none() {
                state.peer_send_status = PeerSendStatus::Failed(
                    "Informe o endereço UDP do peer ou configure o relay operado pelo grupo."
                        .to_owned(),
                );
                return Task::none();
            }
            state.peer_send_status = PeerSendStatus::Connecting;
            let generation = state.peer_listener_generation.saturating_add(1);
            state.peer_listener_generation = generation;
            let request_id = state.peer_next_request_id;
            state.peer_next_request_id = state.peer_next_request_id.saturating_add(1);
            state.peer_pending_sends.insert(request_id, text.clone());
            let (task, handle) =
                peer_connect_task(generation, expected_peer, address, relay, request_id, text);
            state.peer_listener_handle = Some(handle);
            return task;
        }
        Message::PeerCommandSent(Ok(())) => {}
        Message::PeerCommandSent(Err(error)) => {
            state.peer_pending_sends.clear();
            state.peer_send_status =
                PeerSendStatus::Failed(format!("Não foi possível enviar na sessão: {error}"));
        }
        Message::MlsGroupIdChanged(value) => {
            state.mls_group_id = value;
            state.mls_history.clear();
            state.mls_history_group = None;
            state.mls_commit.clear();
            state.mls_pending_commits.clear();
            if let Ok(group_id) = hex_decode_bytes(&state.mls_group_id)
                && group_id.len() == 16
            {
                return load_mls_history(state, group_id);
            }
        }
        Message::SelectMlsGroup(group_id) => {
            if group_id.len() != 16 {
                state.mls_status = "ID de grupo local inválido.".to_owned();
                return Task::none();
            }
            state.mls_group_id = hex_encode_bytes(&group_id);
            state.mls_history.clear();
            state.mls_commit.clear();
            state.mls_pending_commits.clear();
            state.mls_pending_proposals.clear();
            return load_mls_history(state, group_id);
        }
        Message::RefreshMlsGroups => return load_mls_groups(),
        Message::MlsGroupsLoaded(result) => match result {
            Ok(groups) => {
                state.mls_groups = groups;
                state.mls_groups_error = None;
            }
            Err(error) => state.mls_groups_error = Some(error),
        },
        Message::MlsPendingProposalsLoaded(group_id, result) => {
            if state.mls_history_group.as_deref() == Some(group_id.as_slice()) {
                match result {
                    Ok(proposals) => state.mls_pending_proposals = proposals,
                    Err(error) => {
                        state.mls_status =
                            format!("Falha ao carregar propostas pendentes: {error}");
                        state.mls_pending_proposals.clear();
                    }
                }
            }
        }
        Message::MlsKeyPackageChanged(value) => state.mls_key_package = value,
        Message::MlsInviteKeyPackageChanged(value) => state.mls_invite_key_package = value,
        Message::MlsWelcomeChanged(value) => state.mls_welcome = value,
        Message::MlsRatchetTreeChanged(value) => state.mls_ratchet_tree = value,
        Message::CreateMlsGroup => {
            if !matches!(state.identity_status, IdentityStatus::Ready(_)) {
                state.mls_status = "Crie ou carregue a identidade do dispositivo primeiro.".into();
                return Task::none();
            }
            state.mls_status = "Criando grupo MLS local…".into();
            return Task::perform(create_mls_group_task(), Message::MlsGroupCreated);
        }
        Message::MlsGroupCreated(result) => match result {
            Ok(group) => {
                state.mls_group_id = hex_encode_bytes(&group.group_id);
                state.mls_status = format!(
                    "Grupo criado no epoch {}. Este dispositivo é o committer designado.",
                    group.epoch
                );
                let history = load_mls_history(state, group.group_id);
                return Task::batch([history, load_mls_groups()]);
            }
            Err(error) => state.mls_status = format!("Falha ao criar grupo: {error}"),
        },
        Message::PrepareMlsKeyPackage => {
            if !matches!(state.identity_status, IdentityStatus::Ready(_)) {
                state.mls_status = "Crie ou carregue a identidade do dispositivo primeiro.".into();
                return Task::none();
            }
            state.mls_status = "Preparando KeyPackage de uso único…".into();
            return Task::perform(
                create_mls_key_package_task(),
                Message::MlsKeyPackagePrepared,
            );
        }
        Message::MlsKeyPackagePrepared(result) => match result {
            Ok(package) => {
                state.mls_key_package = hex_encode_bytes(&package.public_bytes);
                state.mls_status = "KeyPackage público pronto. Compartilhe-o com o committer por um canal confiável.".into();
            }
            Err(error) => state.mls_status = format!("Falha ao preparar pacote: {error}"),
        },
        Message::SendMlsKeyPackage => {
            let Some(commands) = state.peer_session_commands.clone() else {
                state.mls_status =
                    "Conecte-se diretamente ao committer antes de enviar o KeyPackage.".into();
                return Task::none();
            };
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status = "Informe o ID do grupo MLS para este convite.".into();
                    return Task::none();
                }
            };
            let key_package = match hex_decode_bytes(&state.mls_key_package) {
                Ok(bytes) if !bytes.is_empty() => bytes,
                Ok(_) => {
                    state.mls_status = "Gere um KeyPackage antes de enviá-lo.".into();
                    return Task::none();
                }
                Err(error) => {
                    state.mls_status = format!("KeyPackage inválido: {error}");
                    return Task::none();
                }
            };
            let invitee_device = match state.identity_status {
                IdentityStatus::Ready(public_key) => public_key,
                _ => {
                    state.mls_status = "Carregue a identidade do dispositivo primeiro.".into();
                    return Task::none();
                }
            };
            let digest = blake3::hash(&key_package);
            let mut event_id = [0; 16];
            event_id.copy_from_slice(&digest.as_bytes()[..16]);
            let envelope = peer::MlsKeyPackageEnvelope {
                event_id,
                invitee_device,
                group_id,
                key_package,
            };
            let request_id = state.mls_next_request_id;
            state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
            state.mls_sending_key_packages.insert(request_id);
            state.mls_status = "Enviando KeyPackage público pela sessão fixada…".into();
            return Task::perform(
                async move {
                    commands
                        .send(peer::PeerCommand::SendMlsKeyPackage {
                            request_id,
                            key_package: envelope,
                        })
                        .await
                        .map_err(|error| error.to_string())
                },
                move |result| Message::MlsKeyPackageCommandSent(request_id, result),
            );
        }
        Message::MlsKeyPackageCommandSent(request_id, result) => match result {
            Ok(()) => {
                state.mls_status = format!(
                    "KeyPackage {request_id} enviado; aguardando o committer validar e admitir o membro."
                );
            }
            Err(error) => {
                state.mls_sending_key_packages.remove(&request_id);
                state.mls_status = format!("Falha ao enviar KeyPackage {request_id}: {error}");
            }
        },
        Message::AdmitMlsMember => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status =
                    "Grupo em quarentena; não é possível admitir membros.".to_owned();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(value) => value,
                Err(error) => {
                    state.mls_status = format!("ID do grupo inválido: {error}");
                    return Task::none();
                }
            };
            let package = match hex_decode_bytes(&state.mls_invite_key_package) {
                Ok(value) => value,
                Err(error) => {
                    state.mls_status = format!("KeyPackage inválido: {error}");
                    return Task::none();
                }
            };
            state.mls_status = "Validando pacote e criando Commit/Welcome…".into();
            if let Some((_, peer_device, expected_group, expected_package)) =
                state.mls_pending_peer_key_package.as_ref()
            {
                if &group_id != expected_group || &package != expected_package {
                    state.mls_status = "O KeyPackage recebido foi alterado; recarregue-o do peer antes de admitir.".into();
                    return Task::none();
                }
                let peer_device = *peer_device;
                return Task::perform(
                    admit_mls_member_from_peer_task(group_id, package, peer_device),
                    Message::MlsMemberAdded,
                );
            }
            return Task::perform(
                admit_mls_member_task(group_id, package),
                Message::MlsMemberAdded,
            );
        }
        Message::MlsMemberAdded(result) => {
            match result {
                Ok(admission) => {
                    let mut key_package_ack_error = None;
                    let mut welcome_delivery_request = None;
                    if let Some((sequence, peer_device, _, _)) =
                        state.mls_pending_peer_key_package.take()
                    {
                        if admission.invited_device != peer_device {
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                                    sequence,
                                    reason: "KeyPackage member does not match pinned peer".into(),
                                });
                            }
                            state.mls_status = "KeyPackage rejeitado: identidade do membro diverge do peer fixado.".into();
                            return Task::none();
                        }
                        if let Some(commands) = state.peer_session_commands.as_ref()
                            && let Err(error) =
                                commands.try_send(peer::PeerCommand::AcceptInbound { sequence })
                        {
                            key_package_ack_error = Some(error.to_string());
                        }
                        if key_package_ack_error.is_none()
                            && let Some(commands) = state.peer_session_commands.as_ref()
                        {
                            let event_id = storage::mls_welcome_event_id(
                                &admission.welcome,
                                &admission.ratchet_tree,
                            );
                            let request_id = state.mls_next_request_id;
                            state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
                            let envelope = peer::MlsWelcomeEnvelope {
                                event_id,
                                invitee_device: admission.invited_device,
                                group_id: admission.group_id.clone(),
                                welcome: admission.welcome.clone(),
                                ratchet_tree: admission.ratchet_tree.clone(),
                            };
                            match commands.try_send(peer::PeerCommand::SendMlsWelcome {
                                request_id,
                                welcome: envelope,
                            }) {
                                Ok(()) => {
                                    state.mls_sending_welcomes.insert(request_id, event_id);
                                    welcome_delivery_request = Some(request_id);
                                }
                                Err(error) => {
                                    key_package_ack_error =
                                        Some(format!("Welcome não pôde ser enfileirado: {error}"));
                                }
                            }
                        } else if key_package_ack_error.is_none() {
                            key_package_ack_error =
                                Some("a sessão direta com o convidado foi encerrada".into());
                        }
                    }
                    state.mls_commit = hex_encode_bytes(&admission.commit);
                    state.mls_welcome = hex_encode_bytes(&admission.welcome);
                    state.mls_ratchet_tree = hex_encode_bytes(&admission.ratchet_tree);
                    state.mls_status = if let Some(error) = key_package_ack_error {
                        format!(
                            "Convite salvo localmente, mas a entrega automática do Welcome falhou: {error}. O Welcome e o ratchet tree continuam disponíveis para cópia."
                        )
                    } else if let Some(request_id) = welcome_delivery_request {
                        format!(
                            "Commit salvo. Welcome {request_id} enviado ao convidado; aguardando ele validar e persistir a entrada."
                        )
                    } else {
                        format!(
                            "Commit {} salvo no outbox local; envie também aos membros MLS existentes. Envie Welcome e ratchet tree ao convidado (epoch {}).",
                            hex_encode_bytes(&admission.commit_event_id[..4]),
                            admission.epoch
                        )
                    };
                    let history = load_mls_history(state, admission.group_id);
                    return Task::batch([history, load_mls_groups()]);
                }
                Err(error) => {
                    if let Some((sequence, _, _, _)) = state.mls_pending_peer_key_package.take()
                        && let Some(commands) = state.peer_session_commands.as_ref()
                    {
                        let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                            sequence,
                            reason: error.clone(),
                        });
                    }
                    state.mls_status = format!("Falha ao admitir membro: {error}");
                }
            }
        }
        Message::JoinMlsGroup => {
            let welcome = match hex_decode_bytes(&state.mls_welcome) {
                Ok(value) => value,
                Err(error) => {
                    state.mls_status = format!("Welcome inválido: {error}");
                    return Task::none();
                }
            };
            let tree = match hex_decode_bytes(&state.mls_ratchet_tree) {
                Ok(value) => value,
                Err(error) => {
                    state.mls_status = format!("Ratchet tree inválida: {error}");
                    return Task::none();
                }
            };
            state.mls_status = "Validando Welcome com a chave privada local…".into();
            if let Some((
                sequence,
                peer_device,
                event_id,
                group_id,
                expected_welcome,
                expected_tree,
            )) = state.mls_pending_peer_welcome.as_ref()
            {
                if &welcome != expected_welcome
                    || &tree != expected_tree
                    || hex_decode_bytes(&state.mls_group_id).ok().as_ref() != Some(group_id)
                {
                    state.mls_status =
                        "O Welcome recebido foi alterado; receba novamente do committer fixado."
                            .into();
                    return Task::none();
                }
                let sequence = *sequence;
                return Task::perform(
                    join_mls_group_from_peer_task(
                        welcome,
                        tree,
                        *event_id,
                        *peer_device,
                        group_id
                            .as_slice()
                            .try_into()
                            .expect("group ID is 16 bytes"),
                    ),
                    move |result| Message::JoinMlsGroupFromPeer(sequence, result),
                );
            }
            return Task::perform(join_mls_group_task(welcome, tree), Message::MlsGroupJoined);
        }
        Message::MlsGroupJoined(result) => match result {
            Ok(group) => {
                state.mls_group_id = hex_encode_bytes(&group.group_id);
                state.mls_status = format!(
                    "Grupo ingressado no epoch {}. O grupo e as chaves estão no SQLCipher local.",
                    group.epoch
                );
                let history = load_mls_history(state, group.group_id);
                return Task::batch([history, load_mls_groups()]);
            }
            Err(error) => state.mls_status = format!("Falha ao ingressar no grupo: {error}"),
        },
        Message::JoinMlsGroupFromPeer(sequence, result) => match result {
            Ok(group) => {
                state.mls_status = match state.peer_session_commands.as_ref() {
                    Some(commands) => {
                        match commands.try_send(peer::PeerCommand::AcceptInbound { sequence }) {
                            Ok(()) => format!(
                                "Grupo ingressado no epoch {} e salvo no SQLCipher local; Welcome confirmado ao committer.",
                                group.epoch
                            ),
                            Err(error) => format!(
                                "Grupo ingressado e salvo, mas não foi possível confirmar o Welcome ao committer: {error}"
                            ),
                        }
                    }
                    None => format!(
                        "Grupo ingressado no epoch {} e salvo no SQLCipher local; a sessão encerrou antes do ACK do Welcome.",
                        group.epoch
                    ),
                };
                state.mls_pending_peer_welcome = None;
                state.mls_group_id = hex_encode_bytes(&group.group_id);
                let history = load_mls_history(state, group.group_id);
                return Task::batch([history, load_mls_groups()]);
            }
            Err(error) => {
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                        sequence,
                        reason: error.clone(),
                    });
                }
                state.mls_pending_peer_welcome = None;
                state.mls_status = format!("Falha ao validar Welcome do peer fixado: {error}");
            }
        },
        Message::CopyMlsValue(value) => return iced::clipboard::write(value),
        Message::MlsMessageDraftChanged(value) => state.mls_message_draft = value,
        Message::MlsCommitChanged(value) => state.mls_commit = value,
        Message::MlsReceivedCommitChanged(value) => state.mls_received_commit = value,
        Message::MlsUpdateProposalChanged(value) => {
            state.mls_update_proposal = value;
            state.mls_update_proposal_epoch = None;
            state.mls_update_proposal_group = None;
        }
        Message::MlsReceivedUpdateProposalChanged(value) => {
            state.mls_received_update_proposal = value
        }
        Message::CreateMlsUpdateProposal => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status = "Grupo em quarentena; atualização de membro bloqueada.".into();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status =
                        "Informe o ID do grupo MLS ingressado neste dispositivo.".into();
                    return Task::none();
                }
            };
            state.mls_status =
                "Criando proposta assinada para atualizar a chave deste membro…".into();
            return Task::perform(
                create_mls_update_proposal_task(group_id),
                Message::MlsUpdateProposalCreated,
            );
        }
        Message::MlsUpdateProposalCreated(result) => match result {
            Ok(proposal) => {
                state.mls_update_proposal = hex_encode_bytes(&proposal.proposal);
                state.mls_update_proposal_epoch = Some(proposal.epoch);
                state.mls_update_proposal_group = Some(proposal.group_id);
                state.mls_status = format!(
                    "Proposta de atualização pronta para o committer designado (epoch {}). Compartilhe pelo canal confiável.",
                    proposal.epoch
                );
            }
            Err(error) => state.mls_status = format!("Falha ao criar proposta MLS: {error}"),
        },
        Message::SendMlsUpdateProposal => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status = "Grupo em quarentena; envio de proposta bloqueado.".into();
                return Task::none();
            }
            let Some(commands) = state.peer_session_commands.clone() else {
                state.mls_status =
                    "Conecte-se ao committer pela sessão direta antes de enviar a proposta.".into();
                return Task::none();
            };
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status =
                        "Informe o ID do grupo MLS ingressado neste dispositivo.".into();
                    return Task::none();
                }
            };
            if state.mls_update_proposal_group.as_deref() != Some(group_id.as_slice()) {
                state.mls_status = "Gere novamente a proposta para o grupo selecionado.".into();
                return Task::none();
            }
            let Some(epoch) = state.mls_update_proposal_epoch else {
                state.mls_status =
                    "Gere uma proposta nesta sessão antes de enviá-la diretamente.".into();
                return Task::none();
            };
            let proposal = match hex_decode_bytes(&state.mls_update_proposal) {
                Ok(proposal) if !proposal.is_empty() => proposal,
                Ok(_) => {
                    state.mls_status = "A proposta MLS está vazia.".into();
                    return Task::none();
                }
                Err(error) => {
                    state.mls_status = format!("Proposta MLS inválida: {error}");
                    return Task::none();
                }
            };
            let author_device = match state.identity_status {
                IdentityStatus::Ready(public_key) => public_key,
                _ => {
                    state.mls_status =
                        "Carregue a identidade do dispositivo para enviar a proposta.".into();
                    return Task::none();
                }
            };
            let event_hash = blake3::hash(&proposal);
            let mut event_id = [0; 16];
            event_id.copy_from_slice(&event_hash.as_bytes()[..16]);
            let envelope = peer::MlsProposalEnvelope {
                event_id,
                author_device,
                group_id,
                epoch,
                proposal,
            };
            let request_id = state.mls_next_request_id;
            state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
            state.mls_sending_proposals.insert(request_id);
            state.mls_status =
                "Enviando proposta MLS pela sessão fixada; aguardando persistência do committer…"
                    .into();
            return Task::perform(
                async move {
                    commands
                        .send(peer::PeerCommand::SendMlsProposal {
                            request_id,
                            proposal: envelope,
                        })
                        .await
                        .map_err(|error| error.to_string())
                },
                move |result| Message::MlsUpdateProposalPeerCommandSent(request_id, result),
            );
        }
        Message::MlsUpdateProposalPeerCommandSent(request_id, Ok(())) => {
            state.mls_status = format!(
                "Proposta MLS {request_id} enviada ao peer; aguardando validação e persistência."
            );
        }
        Message::MlsUpdateProposalPeerCommandSent(request_id, Err(error)) => {
            state.mls_sending_proposals.remove(&request_id);
            state.mls_status = format!("Proposta permanece pronta para reenviar: {error}");
        }
        Message::ApplyMlsUpdateProposal => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status = "Grupo em quarentena; propostas MLS bloqueadas.".into();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status =
                        "Informe o ID do grupo MLS ingressado neste dispositivo.".into();
                    return Task::none();
                }
            };
            let proposal = match hex_decode_bytes(&state.mls_received_update_proposal) {
                Ok(proposal) => proposal,
                Err(error) => {
                    state.mls_status = format!("Proposta MLS inválida: {error}");
                    return Task::none();
                }
            };
            state.mls_status = "Autenticando a proposta do membro e guardando-a no grupo…".into();
            return Task::perform(
                process_mls_update_proposal_task(group_id, proposal),
                Message::MlsUpdateProposalProcessed,
            );
        }
        Message::MlsUpdateProposalProcessed(result) => match result {
            Ok(storage::ProcessedMlsProposal::Accepted { epoch }) => {
                state.mls_received_update_proposal.clear();
                state.mls_status = format!(
                    "Atualização autenticada e salva como proposta pendente no epoch {epoch}. O committer pode gerar o Commit."
                );
                if let Ok(group_id) = hex_decode_bytes(&state.mls_group_id)
                    && group_id.len() == 16
                {
                    return load_mls_history(state, group_id);
                }
            }
            Ok(storage::ProcessedMlsProposal::Duplicate { epoch }) => {
                state.mls_received_update_proposal.clear();
                state.mls_status = format!(
                    "Proposta já está salva no grupo no epoch {epoch}; redelivery não duplicou a operação."
                );
                if let Ok(group_id) = hex_decode_bytes(&state.mls_group_id)
                    && group_id.len() == 16
                {
                    return load_mls_history(state, group_id);
                }
            }
            Err(error) => state.mls_status = format!("Proposta MLS rejeitada: {error}"),
        },
        Message::MlsUpdateProposalInboundProcessed(sequence, proposal, result) => match result {
            Ok(processed) => {
                if let Some(commands) = state.peer_session_commands.as_ref()
                    && let Err(error) =
                        commands.try_send(peer::PeerCommand::AcceptInbound { sequence })
                {
                    state.mls_status =
                        format!("Proposta MLS foi salva, mas não foi possível enviar ACK: {error}");
                    return Task::none();
                }
                state.mls_group_id = hex_encode_bytes(&proposal.group_id);
                state.mls_status = match processed {
                    storage::ProcessedMlsProposal::Accepted { epoch } => format!(
                        "Proposta de self-update autenticada e salva no epoch {epoch}; ACK enviado ao membro."
                    ),
                    storage::ProcessedMlsProposal::Duplicate { epoch } => format!(
                        "Proposta MLS já estava salva no epoch {epoch}; ACK de redelivery enviado."
                    ),
                };
                return load_mls_history(state, proposal.group_id);
            }
            Err(error) => {
                if let Some(commands) = state.peer_session_commands.as_ref()
                    && let Err(send_error) = commands.try_send(peer::PeerCommand::RejectInbound {
                        sequence,
                        reason: error.clone(),
                    })
                {
                    state.mls_status = format!(
                        "Proposta rejeitada ({error}), mas a rejeição não pôde ser enviada: {send_error}"
                    );
                    return Task::none();
                }
                state.mls_status = format!("Proposta MLS rejeitada sem ACK: {error}");
            }
        },
        Message::CommitMlsProposals => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status = "Grupo em quarentena; geração de Commit bloqueada.".into();
                return Task::none();
            }
            let approved = state
                .mls_pending_proposals
                .iter()
                .filter(|proposal| proposal.approved)
                .map(|proposal| proposal.proposal_id)
                .collect::<Vec<_>>();
            if approved.is_empty() {
                state.mls_status = "Aprove ao menos uma proposta antes de criar o Commit.".into();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status =
                        "Informe o ID do grupo MLS ingressado neste dispositivo.".into();
                    return Task::none();
                }
            };
            state.mls_status = format!(
                "Criando Commit com {} proposta(s) aprovada(s)…",
                approved.len()
            );
            return Task::perform(
                commit_mls_proposals_task(group_id, approved),
                Message::MlsProposalCommitCreated,
            );
        }
        Message::SetMlsProposalApproval(proposal_id, approved) => {
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => return Task::none(),
            };
            state.mls_status = if approved {
                "Aprovando proposta MLS…"
            } else {
                "Rejeitando proposta MLS…"
            }
            .into();
            return Task::perform(
                set_mls_proposal_approval_task(group_id, proposal_id, approved),
                move |result| Message::MlsProposalApprovalSaved(proposal_id, approved, result),
            );
        }
        Message::MlsProposalApprovalSaved(proposal_id, approved, result) => match result {
            Ok(()) => {
                if let Some(proposal) = state
                    .mls_pending_proposals
                    .iter_mut()
                    .find(|proposal| proposal.proposal_id == proposal_id)
                {
                    proposal.approved = approved;
                }
                state.mls_status = if approved {
                    "Proposta aprovada para o próximo Commit."
                } else {
                    "Proposta rejeitada e excluída do próximo Commit."
                }
                .into();
            }
            Err(error) => {
                state.mls_status = format!("Falha ao salvar decisão da proposta: {error}")
            }
        },
        Message::MlsProposalCommitCreated(result) => match result {
            Ok(commit) => {
                state.mls_commit = hex_encode_bytes(&commit.commit);
                state.mls_status = format!(
                    "Commit MLS do epoch {} salvo no outbox para os membros anteriores. Distribua pela sessão direta.",
                    commit.epoch
                );
                let history = load_mls_history(state, commit.group_id);
                return Task::batch([history, load_mls_groups()]);
            }
            Err(error) => {
                state.mls_status = format!("Falha ao criar Commit das propostas: {error}")
            }
        },
        Message::DistributeMlsCommitsToAll => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status =
                    "Grupo em quarentena; fan-out de Commits está bloqueado.".to_owned();
                return Task::none();
            }
            if state.mls_fanout_running
                || state.peer_listener_handle.is_some()
                || !state.peer_pending_sends.is_empty()
                || !state.mls_sending_commits.is_empty()
            {
                state.mls_status = "Encerre a sessão/listener atual e aguarde as entregas em curso antes do fan-out.".into();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status = "Informe o ID do grupo MLS.".to_owned();
                    return Task::none();
                }
            };
            state.mls_fanout_running = true;
            state.mls_status =
                "Buscando rotas salvas e entregando Commits em ordem, com ACK por membro…".into();
            return Task::perform(fanout_mls_commits_task(group_id.clone()), move |result| {
                Message::MlsCommitFanoutFinished(group_id, result)
            });
        }
        Message::MlsCommitFanoutFinished(group_id, result) => {
            state.mls_fanout_running = false;
            match result {
                Ok(report) if report.failures.is_empty() => {
                    state.mls_status = format!(
                        "Fan-out concluído: {} Commit(s) confirmados por ACK em {} peer(s).",
                        report.commits_acked, report.recipients
                    );
                }
                Ok(report) => {
                    state.mls_status = format!(
                        "Fan-out parcial: {} Commit(s) confirmados em {} peer(s); {} peer(s) pendentes/sem rota. {}",
                        report.commits_acked,
                        report.recipients,
                        report.failures.len(),
                        report.failures.join(" · ")
                    );
                }
                Err(error) => state.mls_status = format!("Fan-out falhou: {error}"),
            }
            return load_mls_history(state, group_id);
        }
        Message::DistributeMlsEventsToAll => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status =
                    "Grupo em quarentena; fan-out de mensagens está bloqueado.".into();
                return Task::none();
            }
            if state.mls_event_fanout_running
                || state.mls_fanout_running
                || state.peer_listener_handle.is_some()
                || !state.peer_pending_sends.is_empty()
                || !state.mls_pending_events.is_empty()
            {
                state.mls_status = "Encerre a sessão/listener atual e aguarde envios antes do fan-out de mensagens.".into();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status = "Informe o ID do grupo MLS.".into();
                    return Task::none();
                }
            };
            state.mls_event_fanout_running = true;
            state.mls_status =
                "Distribuindo eventos MLS salvos aos membros com rotas pinadas…".into();
            return Task::perform(fanout_mls_events_task(group_id.clone()), move |result| {
                Message::MlsEventFanoutFinished(group_id, result)
            });
        }
        Message::MlsEventFanoutFinished(group_id, result) => {
            state.mls_event_fanout_running = false;
            match result {
                Ok(report) if report.failures.is_empty() => {
                    state.mls_status = format!(
                        "Fan-out MLS: {} evento(s) recebidos em {} peer(s), {} cópia(s) guardadas por ajudantes; {} expirado(s).",
                        report.events_acked,
                        report.recipients,
                        report.copies_held,
                        report.events_expired
                    );
                }
                Ok(report) => {
                    state.mls_status = format!(
                        "Fan-out MLS parcial: {} evento(s) recebidos em {} peer(s), {} cópia(s) guardadas; {} peer(s) pendente(s), {} expirado(s). {}",
                        report.events_acked,
                        report.recipients,
                        report.copies_held,
                        report.failures.len(),
                        report.events_expired,
                        report.failures.join(" · ")
                    );
                }
                Err(error) => state.mls_status = format!("Fan-out MLS falhou: {error}"),
            }
            return load_mls_history(state, group_id);
        }
        Message::DistributeMlsCommit => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status =
                    "Grupo em quarentena; distribuição de Commits bloqueada.".to_owned();
                return Task::none();
            }
            if !state.mls_sending_commits.is_empty() {
                state.mls_status =
                    "Aguardando a confirmação do Commit atual antes de avançar a cadeia."
                        .to_owned();
                return Task::none();
            }
            if state.peer_session_commands.is_none()
                || !matches!(state.peer_listen_status, PeerListenStatus::Connected)
            {
                state.mls_status =
                    "Conecte primeiro ao dispositivo que já é membro do grupo.".to_owned();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status = "Informe o ID do grupo MLS.".to_owned();
                    return Task::none();
                }
            };
            let peer_id = match parse_peer_id(&state.peer_public_key) {
                Ok(peer_id) => *peer_id.as_bytes(),
                Err(error) => {
                    state.mls_status = format!("Peer inválido: {error}");
                    return Task::none();
                }
            };
            state.mls_status = "Verificando se o peer é membro autenticado do grupo…".to_owned();
            return Task::perform(
                load_mls_commits_for_peer_task(group_id.clone(), peer_id),
                move |result| Message::MlsCommitsReadyToSend(group_id, result),
            );
        }
        Message::MlsCommitsReadyToSend(group_id, result) => {
            if !state.mls_sending_commits.is_empty() {
                state.mls_status =
                    "Aguardando o ACK do Commit em trânsito antes de enviar o próximo.".to_owned();
                return Task::none();
            }
            return match result {
                Ok(commits) => {
                    let Some(commands) = state.peer_session_commands.clone() else {
                        state.mls_status =
                            "Sessão encerrou; Commits continuam pendentes localmente.".to_owned();
                        return Task::none();
                    };
                    let available = peer::MAX_PENDING_MESSAGES.saturating_sub(
                        state.peer_pending_sends.len()
                            + state.mls_pending_events.len()
                            + state.mls_sending_commits.len(),
                    );
                    let mut sends = Vec::new();
                    for stored in commits.into_iter().take(available.min(1)) {
                        let request_id = state.mls_next_request_id;
                        state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
                        state
                            .mls_sending_commits
                            .insert(request_id, stored.event_id);
                        let envelope = peer::MlsCommitEnvelope {
                            event_id: stored.event_id,
                            author_device: stored.author_device,
                            group_id: stored.group_id,
                            predecessor_epoch: stored.predecessor_epoch,
                            epoch: stored.epoch,
                            commit: stored.commit,
                        };
                        let commands = commands.clone();
                        sends.push(Task::perform(
                            async move {
                                commands
                                    .send(peer::PeerCommand::SendMlsCommit {
                                        request_id,
                                        commit: envelope,
                                    })
                                    .await
                                    .map_err(|error| error.to_string())
                            },
                            move |result| Message::MlsCommitPeerCommandSent(request_id, result),
                        ));
                    }
                    state
                        .mls_pending_commits
                        .retain(|commit| commit.group_id != group_id);
                    if sends.is_empty() {
                        state.mls_status = "Nenhum Commit pendente para este grupo, ou a janela de envio está cheia.".to_owned();
                        Task::none()
                    } else {
                        state.mls_status = format!(
                            "Enviando {} Commit(s) ao membro conectado; aguardando aplicação e ACK…",
                            sends.len()
                        );
                        Task::batch(sends)
                    }
                }
                Err(error) => {
                    state.mls_status = format!("Commit não distribuído: {error}");
                    Task::none()
                }
            };
        }
        Message::MlsCommitPeerCommandSent(request_id, Ok(())) => {
            state.mls_status = format!(
                "Commit {request_id} enviado; aguardando autenticação e aplicação pelo membro."
            );
        }
        Message::MlsCommitPeerCommandSent(request_id, Err(error)) => {
            state.mls_sending_commits.remove(&request_id);
            state.mls_status = format!("Commit permanece pendente localmente: {error}");
        }
        Message::MlsWelcomesReadyToSend(group_id, peer_device, result) => {
            return match result {
                Ok(welcomes) => {
                    let Some(commands) = state.peer_session_commands.clone() else {
                        return Task::none();
                    };
                    let mut tasks = Vec::new();
                    for stored in welcomes.into_iter().take(peer::MAX_PENDING_MESSAGES) {
                        let request_id = state.mls_next_request_id;
                        state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
                        state
                            .mls_sending_welcomes
                            .insert(request_id, stored.event_id);
                        let envelope = peer::MlsWelcomeEnvelope {
                            event_id: stored.event_id,
                            invitee_device: stored.invitee_device,
                            group_id: stored.group_id,
                            welcome: stored.welcome,
                            ratchet_tree: stored.ratchet_tree,
                        };
                        let commands = commands.clone();
                        tasks.push(Task::perform(
                            async move {
                                commands
                                    .send(peer::PeerCommand::SendMlsWelcome {
                                        request_id,
                                        welcome: envelope,
                                    })
                                    .await
                                    .map_err(|error| error.to_string())
                            },
                            move |result| Message::MlsWelcomePeerCommandSent(request_id, result),
                        ));
                    }
                    if tasks.is_empty() {
                        state.mls_status = format!(
                            "Nenhum Welcome pendente para {}…",
                            hex_encode_bytes(&peer_device[..4])
                        );
                        Task::none()
                    } else {
                        state.mls_status = format!(
                            "Reenviando {} Welcome(s) persistido(s) ao peer pinado…",
                            tasks.len()
                        );
                        Task::batch(tasks)
                    }
                }
                Err(error) => {
                    state.mls_status = format!(
                        "Falha ao carregar Welcome pendente para o grupo {}: {error}",
                        hex_encode_bytes(&group_id[..group_id.len().min(4)])
                    );
                    Task::none()
                }
            };
        }
        Message::MlsWelcomePeerCommandSent(request_id, Ok(())) => {
            state.mls_status = format!(
                "Welcome {request_id} enviado; aguardando ACK após persistência do grupo pelo convidado."
            );
        }
        Message::MlsWelcomePeerCommandSent(request_id, Err(error)) => {
            state.mls_sending_welcomes.remove(&request_id);
            state.mls_status = format!("Welcome permanece na fila local para retry: {error}");
        }
        Message::MlsWelcomeDelivered(request_id, Ok(())) => {
            state.mls_sending_welcomes.remove(&request_id);
            state.mls_status =
                format!("Welcome {request_id} confirmado e marcado como entregue no outbox local.");
        }
        Message::MlsWelcomeDelivered(request_id, Err(error)) => {
            state.mls_sending_welcomes.remove(&request_id);
            state.mls_status = format!(
                "Peer confirmou Welcome {request_id}, mas o ACK local não persistiu: {error}; o retry é idempotente."
            );
        }
        Message::MlsCommitRequestedReady(_group_id, predecessor_epoch, result) => match result {
            Ok(Some(stored)) => {
                let Some(commands) = state.peer_session_commands.clone() else {
                    state.mls_status =
                        "Solicitação recebida sem sessão ativa; Commit permanece salvo.".to_owned();
                    return Task::none();
                };
                let request_id = state.mls_next_request_id;
                state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
                state
                    .mls_sending_commits
                    .insert(request_id, stored.event_id);
                let envelope = peer::MlsCommitEnvelope {
                    event_id: stored.event_id,
                    author_device: stored.author_device,
                    group_id: stored.group_id,
                    predecessor_epoch: stored.predecessor_epoch,
                    epoch: stored.epoch,
                    commit: stored.commit,
                };
                state.mls_status =
                    format!("Enviando predecessor epoch {predecessor_epoch} solicitado pelo peer.");
                return Task::perform(
                    async move {
                        commands
                            .send(peer::PeerCommand::SendMlsCommit {
                                request_id,
                                commit: envelope,
                            })
                            .await
                            .map_err(|error| error.to_string())
                    },
                    move |result| Message::MlsCommitPeerCommandSent(request_id, result),
                );
            }
            Ok(None) => {
                state.mls_status = format!(
                    "Peer pediu predecessor epoch {predecessor_epoch}, mas não há Commit elegível para esse dispositivo e grupo."
                );
            }
            Err(error) => {
                state.mls_status = format!("Falha ao buscar predecessor solicitado: {error}")
            }
        },
        Message::MlsCommitDelivered(request_id, Ok(())) => {
            state.mls_sending_commits.remove(&request_id);
            state.mls_status =
                format!("Commit {request_id} aplicado pelo membro; ACK salvo localmente.");
            if let Ok(group_id) = hex_decode_bytes(&state.mls_group_id)
                && group_id.len() == 16
            {
                let history = load_mls_history(state, group_id.clone());
                if matches!(state.peer_listen_status, PeerListenStatus::Connected)
                    && let Ok(peer) = parse_peer_id(&state.peer_public_key)
                {
                    let peer_device = *peer.as_bytes();
                    return Task::batch([
                        history,
                        Task::perform(
                            load_mls_commits_for_peer_task(group_id.clone(), peer_device),
                            move |result| Message::MlsCommitsReadyToSend(group_id, result),
                        ),
                    ]);
                }
                return history;
            }
        }
        Message::MlsCommitDelivered(request_id, Err(error)) => {
            state.mls_sending_commits.remove(&request_id);
            state.mls_status = format!(
                "Peer aplicou o Commit {request_id}, mas o ACK local não persistiu: {error}. A redelivery é segura."
            );
        }
        Message::MlsCommitInboundProcessed(sequence, envelope, result) => match result {
            Ok(processed) => {
                if let storage::ProcessedMlsCommit::EquivocationDetected { predecessor_epoch } =
                    &processed
                {
                    state.mls_quarantine_reason = Some(format!(
                        "Commits assinados diferentes para o predecessor epoch {predecessor_epoch}."
                    ));
                    if let Some(commands) = state.peer_session_commands.as_ref() {
                        let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                            sequence,
                            reason: "authenticated committer equivocation; group quarantined"
                                .to_owned(),
                        });
                    }
                    state.mls_status = format!(
                        "ALERTA DE SEGURANÇA: Commits assinados diferentes no predecessor epoch {predecessor_epoch}. Grupo em quarentena; envio MLS pausado."
                    );
                    return load_mls_groups();
                }
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::AcceptInbound { sequence });
                }
                state.mls_status = match processed {
                    storage::ProcessedMlsCommit::Applied { epoch } => format!(
                        "Commit recebido, autenticado e aplicado; epoch {epoch}. ACK enviado ao committer."
                    ),
                    storage::ProcessedMlsCommit::Duplicate { epoch } => {
                        format!("Commit já aplicado; epoch {epoch}. ACK de redelivery enviado.")
                    }
                    storage::ProcessedMlsCommit::EquivocationDetected { .. } => unreachable!(),
                };
                let history = load_mls_history(state, envelope.group_id);
                return Task::batch([history, load_mls_groups()]);
            }
            Err(error) => {
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    if let Err(send_error) = commands.try_send(peer::PeerCommand::RejectInbound {
                        sequence,
                        reason: error.clone(),
                    }) {
                        state.mls_status = format!(
                            "Commit fora de ordem; não foi possível confirmar a rejeição antes da recuperação: {send_error}"
                        );
                        return Task::none();
                    }
                    let missing = missing_predecessor_from_error(&error)
                        .filter(|expected| *expected < envelope.predecessor_epoch);
                    if let Some(predecessor_epoch) = missing {
                        match commands.try_send(peer::PeerCommand::RequestMlsCommit {
                            group_id: envelope.group_id.clone(),
                            predecessor_epoch,
                        }) {
                            Ok(()) => {
                                state.mls_status = format!(
                                    "Commit fora de ordem; solicitando predecessor epoch {predecessor_epoch} ao committer."
                                );
                            }
                            Err(send_error) => {
                                state.mls_status = format!(
                                    "Commit fora de ordem; não foi possível solicitar o predecessor: {send_error}"
                                );
                            }
                        }
                    } else {
                        state.mls_status =
                            format!("Commit recebido foi rejeitado; grupo local intacto: {error}");
                    }
                } else {
                    state.mls_status =
                        format!("Commit recebido foi rejeitado; grupo local intacto: {error}");
                }
            }
        },
        Message::ApplyMlsCommit => {
            if state.mls_quarantine_reason.is_some() {
                state.mls_status =
                    "Grupo em quarentena; aplicação manual de Commits bloqueada.".to_owned();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status =
                        "Informe o ID do grupo MLS ingressado neste dispositivo.".to_owned();
                    return Task::none();
                }
            };
            let commit = match hex_decode_bytes(&state.mls_received_commit) {
                Ok(commit) => commit,
                Err(error) => {
                    state.mls_status = format!("Commit recebido inválido: {error}");
                    return Task::none();
                }
            };
            state.mls_status = "Autenticando o Commit e avançando o epoch local…".to_owned();
            return Task::perform(
                process_mls_commit_task(group_id, commit),
                Message::MlsCommitProcessed,
            );
        }
        Message::MlsCommitProcessed(Ok(result)) => {
            state.mls_received_commit.clear();
            state.mls_status = match result {
                storage::ProcessedMlsCommit::Applied { epoch } => {
                    format!("Commit autenticado e aplicado; grupo agora está no epoch {epoch}.")
                }
                storage::ProcessedMlsCommit::Duplicate { epoch } => {
                    format!("Commit já aplicado anteriormente; grupo permanece no epoch {epoch}.")
                }
                storage::ProcessedMlsCommit::EquivocationDetected { predecessor_epoch } => {
                    state.mls_quarantine_reason = Some(format!(
                        "Commits assinados diferentes para o predecessor epoch {predecessor_epoch}."
                    ));
                    format!(
                        "ALERTA DE SEGURANÇA: Commits conflitantes autenticados no epoch {predecessor_epoch}; grupo em quarentena."
                    )
                }
            };
            let groups = load_mls_groups();
            if let Ok(group_id) = hex_decode_bytes(&state.mls_group_id)
                && group_id.len() == 16
            {
                return Task::batch([load_mls_history(state, group_id), groups]);
            }
            return groups;
        }
        Message::MlsCommitProcessed(Err(error)) => {
            state.mls_status = format!("Commit MLS rejeitado sem avançar o grupo: {error}");
        }
        Message::MlsHistoryLoaded(group_id, result) => {
            if state.mls_history_group.as_deref() == Some(group_id.as_slice()) {
                match result {
                    Ok(messages) => state.mls_history = messages,
                    Err(error) => {
                        state.mls_status =
                            format!("Não foi possível carregar histórico MLS: {error}");
                    }
                }
            }
        }
        Message::MlsQuarantineLoaded(group_id, result) => {
            if state.mls_history_group.as_deref() == Some(group_id.as_slice()) {
                match result {
                    Ok(reason) => state.mls_quarantine_reason = reason,
                    Err(error) => {
                        state.mls_status =
                            format!("Não foi possível verificar a quarentena MLS: {error}");
                    }
                }
            }
        }
        Message::MlsCommitsLoaded(group_id, result) => {
            if state.mls_history_group.as_deref() == Some(group_id.as_slice()) {
                match result {
                    Ok(commits) => {
                        state.mls_commit = commits
                            .last()
                            .map(|commit| hex_encode_bytes(&commit.commit))
                            .unwrap_or_default();
                        state.mls_pending_commits = commits;
                    }
                    Err(error) => {
                        state.mls_status =
                            format!("Não foi possível ler Commits pendentes: {error}");
                    }
                }
            }
        }
        Message::MlsCommitRecipientsLoaded(group_id, result) => {
            if state.mls_history_group.as_deref() == Some(group_id.as_slice()) {
                match result {
                    Ok(recipients) => state.mls_commit_recipients = recipients,
                    Err(error) => {
                        state.mls_status =
                            format!("Não foi possível carregar confirmações de Commit: {error}");
                    }
                }
            }
        }
        Message::RetryQueuedMlsEvents => {
            if !matches!(state.peer_listen_status, PeerListenStatus::Connected) {
                state.mls_status =
                    "Conecte a sessão direta antes de reenviar eventos MLS pendentes.".to_owned();
                return Task::none();
            }
            let Ok(group_id) = hex_decode_bytes(&state.mls_group_id) else {
                state.mls_status =
                    "Informe o ID do grupo MLS para procurar eventos pendentes.".to_owned();
                return Task::none();
            };
            let peer_device = match parse_peer_id(&state.peer_public_key) {
                Ok(peer) => *peer.as_bytes(),
                Err(error) => {
                    state.mls_status = format!("Peer pin inválido para retry: {error}");
                    return Task::none();
                }
            };
            state.mls_status =
                "Consultando outbox local para reenviar eventos pendentes…".to_owned();
            return Task::perform(
                load_mls_events_for_peer_task(group_id.clone(), peer_device),
                move |result| Message::MlsOutboxLoaded(group_id, peer_device, result),
            );
        }
        Message::MlsOutboxLoaded(group_id, peer_device, result) => {
            if hex_decode_bytes(&state.mls_group_id).ok().as_deref() != Some(group_id.as_slice())
                || parse_peer_id(&state.peer_public_key)
                    .ok()
                    .is_none_or(|peer| *peer.as_bytes() != peer_device)
            {
                return Task::none();
            }
            return match result {
                Ok(events) => {
                    let Some(commands) = state.peer_session_commands.clone() else {
                        state.mls_status =
                            "Sessão encerrada; os eventos seguem no outbox.".to_owned();
                        return Task::none();
                    };
                    let mut sends = Vec::new();
                    let available_slots = peer::MAX_PENDING_MESSAGES.saturating_sub(
                        state.peer_pending_sends.len() + state.mls_pending_events.len(),
                    );
                    let pending_event_ids: std::collections::HashSet<_> = state
                        .mls_pending_events
                        .values()
                        .map(|(event_id, _)| *event_id)
                        .collect();
                    for stored in events
                        .into_iter()
                        .filter(|stored| !pending_event_ids.contains(&stored.event.event_id))
                        .take(available_slots)
                    {
                        let request_id = state.mls_next_request_id;
                        state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
                        state
                            .mls_pending_events
                            .insert(request_id, (stored.event.event_id, peer_device));
                        let event = peer::MlsEventEnvelope {
                            event_id: stored.event.event_id,
                            author_device: stored.event.author_device,
                            group_id: stored.event.group_id,
                            epoch: stored.event.epoch,
                            checkpoint: stored.event.checkpoint,
                            expires_at_unix: stored.event.expires_at_unix,
                            ciphertext: stored.event.ciphertext,
                        };
                        let commands = commands.clone();
                        sends.push(Task::perform(
                            async move {
                                commands
                                    .send(peer::PeerCommand::SendMlsEvent { request_id, event })
                                    .await
                                    .map_err(|error| error.to_string())
                            },
                            move |result| Message::MlsPeerCommandSent(request_id, result),
                        ));
                    }
                    if sends.is_empty() {
                        state.mls_status = "Nenhuma mensagem MLS pendente neste grupo.".to_owned();
                        Task::none()
                    } else {
                        state.mls_status =
                            format!("Reenviando {} evento(s) MLS salvo(s)…", sends.len());
                        Task::batch(sends)
                    }
                }
                Err(error) => {
                    state.mls_status = format!("Falha ao consultar o outbox MLS: {error}");
                    Task::none()
                }
            };
        }
        Message::SendMlsApplication => {
            if state.peer_session_commands.is_none()
                || !matches!(state.peer_listen_status, PeerListenStatus::Connected)
            {
                state.mls_status =
                    "Conecte ao dispositivo do grupo na tela Texto direto · LAN/VPN antes de enviar."
                        .to_owned();
                return Task::none();
            }
            let group_id = match hex_decode_bytes(&state.mls_group_id) {
                Ok(group_id) if group_id.len() == 16 => group_id,
                _ => {
                    state.mls_status =
                        "Informe o ID de um grupo MLS ingressado neste dispositivo.".to_owned();
                    return Task::none();
                }
            };
            let text = state.mls_message_draft.trim().to_owned();
            if text.is_empty() || text.len() > 16 * 1024 {
                state.mls_status =
                    "A mensagem MLS precisa ter entre 1 e 16 KiB em UTF-8.".to_owned();
                return Task::none();
            }
            state.mls_status = "Cifrando com OpenMLS e salvando no outbox local…".to_owned();
            return Task::perform(
                create_mls_application_task(group_id, text),
                Message::MlsApplicationCreated,
            );
        }
        Message::MlsApplicationCreated(result) => match result {
            Ok(prepared) => {
                let peer_device = match parse_peer_id(&state.peer_public_key) {
                    Ok(peer) => *peer.as_bytes(),
                    Err(error) => {
                        state.mls_status = format!(
                            "Mensagem cifrada e salva; peer pin inválido para envio: {error}"
                        );
                        return load_mls_history(state, prepared.event.group_id);
                    }
                };
                state.mls_message_draft.clear();
                state.mls_status =
                    "Mensagem cifrada e salva; verificando se o peer é membro deste grupo…".into();
                return Task::perform(
                    load_mls_events_for_peer_task(prepared.event.group_id.clone(), peer_device),
                    move |result| {
                        Message::MlsApplicationRecipientReady(prepared, peer_device, result)
                    },
                );
            }
            Err(error) => {
                state.mls_status = format!("Falha ao cifrar/salvar mensagem MLS: {error}")
            }
        },
        Message::MlsApplicationRecipientReady(prepared, peer_device, result) => {
            if parse_peer_id(&state.peer_public_key)
                .ok()
                .is_none_or(|peer| *peer.as_bytes() != peer_device)
            {
                return Task::none();
            }
            let is_recipient = match result {
                Ok(events) => events
                    .iter()
                    .any(|stored| stored.event.event_id == prepared.event.event_id),
                Err(error) => {
                    state.mls_status =
                        format!("Mensagem salva; não foi possível conferir o peer: {error}");
                    return load_mls_history(state, prepared.event.group_id);
                }
            };
            if !is_recipient {
                state.mls_status = "Mensagem MLS salva no outbox, mas o peer pinado não consta no snapshot de membros deste epoch.".into();
                return load_mls_history(state, prepared.event.group_id);
            }
            let Some(commands) = state.peer_session_commands.clone() else {
                state.mls_status =
                    "Mensagem salva no outbox. Conecte ao membro pinado e reenvie pendentes."
                        .into();
                return load_mls_history(state, prepared.event.group_id);
            };
            let request_id = state.mls_next_request_id;
            state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
            state
                .mls_pending_events
                .insert(request_id, (prepared.event.event_id, peer_device));
            let event = peer::MlsEventEnvelope {
                event_id: prepared.event.event_id,
                author_device: prepared.event.author_device,
                group_id: prepared.event.group_id.clone(),
                epoch: prepared.event.epoch,
                checkpoint: prepared.event.checkpoint,
                expires_at_unix: prepared.event.expires_at_unix,
                ciphertext: prepared.event.ciphertext,
            };
            state.mls_status = "Evento cifrado e salvo; enviando ao membro autenticado…".into();
            let history_group_id = event.group_id.clone();
            return Task::batch([
                Task::perform(
                    async move {
                        commands
                            .send(peer::PeerCommand::SendMlsEvent { request_id, event })
                            .await
                            .map_err(|error| error.to_string())
                    },
                    move |result| Message::MlsPeerCommandSent(request_id, result),
                ),
                Task::perform(
                    load_mls_history_task(history_group_id.clone()),
                    move |result| Message::MlsHistoryLoaded(history_group_id, result),
                ),
            ]);
        }
        Message::MlsPeerCommandSent(request_id, Ok(())) => {
            state.mls_status = format!("Evento MLS {request_id} enviado; aguardando ACK do peer.");
        }
        Message::MlsPeerCommandSent(request_id, Err(error)) => {
            state.mls_pending_events.remove(&request_id);
            state.mls_status = format!("Evento salvo no outbox; falha ao iniciar envio: {error}");
        }
        Message::MlsInboundProcessed(sequence, event, result) => match result {
            Ok(processed) => {
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::AcceptInbound { sequence });
                }
                state.mls_status = match processed {
                    storage::ProcessedMlsApplicationEvent::Received(_) => {
                        format!(
                            "Mensagem MLS de {} recebida, autenticada e salva.",
                            hex_encode_bytes(&event.author_device[..4])
                        )
                    }
                    storage::ProcessedMlsApplicationEvent::Duplicate => {
                        "Reenvio MLS idêntico já salvo; ACK confirmado sem reaplicar o ratchet."
                            .to_owned()
                    }
                };
                return load_mls_history(state, event.group_id);
            }
            Err(error) => {
                state.mls_status = format!("Evento MLS recusado; ACK não enviado: {error}");
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::Disconnect);
                }
            }
        },
        Message::MlsOutboundHeld(request_id, event_id, result) => {
            state.mls_pending_events.remove(&request_id);
            match result {
                Ok(()) => {
                    state.mls_status = format!(
                        "Peer confirmou que reteve o evento MLS {}.",
                        hex_encode_bytes(&event_id[..4])
                    );
                }
                Err(error) => {
                    state.mls_status =
                        format!("Peer confirmou o evento, mas o estado local falhou: {error}")
                }
            }
        }
    }
    Task::none()
}

async fn fetch_backend_status() -> Result<BackendStatus, FetchError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|error| FetchError::Unavailable(error.to_string()))?;
    let response = client
        .get(STATUS_URL)
        .send()
        .await
        .map_err(|error| FetchError::Unavailable(error.to_string()))?;
    if !response.status().is_success() {
        return Err(FetchError::Unavailable(format!(
            "HTTP {} from local backend",
            response.status()
        )));
    }
    let body = response
        .text()
        .await
        .map_err(|error| FetchError::ContractMismatch(error.to_string()))?;
    parse_status(&body)
}

fn parse_status(body: &str) -> Result<BackendStatus, FetchError> {
    let status: BackendStatus = serde_json::from_str(body)
        .map_err(|error| FetchError::ContractMismatch(error.to_string()))?;
    if status.contract_version != CONTRACT_VERSION || status.backend != "elixir_scaffold" {
        return Err(FetchError::ContractMismatch(format!(
            "Expected Elixir status contract v{CONTRACT_VERSION}; got {} v{}",
            status.backend, status.contract_version
        )));
    }
    Ok(status)
}

async fn connect_transport() -> Result<(WsStream, protocol::ServerHello), HandshakeError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (mut socket, _) = connect_async(WS_URL)
            .await
            .map_err(|error| HandshakeError::Unavailable(error.to_string()))?;
        let frame = protocol::ClientFrame {
            payload: Some(protocol::client_frame::Payload::Hello(
                protocol::ClientHello {
                    protocol_version: CONTRACT_VERSION,
                },
            )),
        };
        socket
            .send(WsMessage::Binary(frame.encode_to_vec().into()))
            .await
            .map_err(|error| HandshakeError::Unavailable(error.to_string()))?;
        let reply = socket
            .next()
            .await
            .ok_or_else(|| HandshakeError::Protocol("backend closed before reply".into()))?
            .map_err(|error| HandshakeError::Unavailable(error.to_string()))?;
        let WsMessage::Binary(bytes) = reply else {
            return Err(HandshakeError::Protocol(
                "expected binary ServerFrame".into(),
            ));
        };
        let hello = decode_server_hello(&bytes)?;
        Ok((socket, hello))
    })
    .await
    .map_err(|_| HandshakeError::Unavailable("WebSocket handshake timed out".into()))?
}

fn transport_task(generation: u64) -> (Task<Message>, Handle) {
    Task::run(transport_events(), move |event| {
        Message::TransportEvent(generation, event)
    })
    .abortable()
}

fn transport_events() -> impl futures_util::Stream<Item = TransportEvent> + Send + 'static {
    async_stream::stream! {
        let mut attempt = 1u32;
        loop {
            yield TransportEvent::Connecting(attempt);
            let failure = match connect_transport().await {
                Ok((mut socket, hello)) => {
                    yield TransportEvent::Connected(hello);
                    attempt = 1;
                    loop {
                        match heartbeat_cycle(&mut socket).await {
                            Ok(()) => yield TransportEvent::Heartbeat,
                            Err(reason) => break reason,
                        }
                    }
                }
                Err(HandshakeError::Protocol(reason)) => {
                    yield TransportEvent::ProtocolError(reason);
                    break;
                }
                Err(HandshakeError::Unavailable(reason)) => reason,
            };
            let retry_seconds = retry_delay_seconds(attempt);
            yield TransportEvent::Disconnected { reason: failure, retry_seconds };
            tokio::time::sleep(Duration::from_secs(retry_seconds)).await;
            attempt = attempt.saturating_add(1);
        }
    }
}

fn retry_delay_seconds(attempt: u32) -> u64 {
    1u64 << attempt.saturating_sub(1).min(3)
}

async fn heartbeat_cycle(socket: &mut WsStream) -> Result<(), String> {
    tokio::time::sleep(HEARTBEAT_INTERVAL).await;
    socket
        .send(WsMessage::Ping(PING_PAYLOAD.to_vec().into()))
        .await
        .map_err(|error| error.to_string())?;
    tokio::time::timeout(HEARTBEAT_TIMEOUT, async {
        loop {
            match socket.next().await {
                Some(Ok(WsMessage::Pong(payload))) if payload.as_ref() == PING_PAYLOAD => {
                    return Ok(());
                }
                Some(Ok(WsMessage::Close(frame))) => {
                    return Err(format!("backend closed transport: {frame:?}"));
                }
                Some(Err(error)) => return Err(error.to_string()),
                None => return Err("backend closed transport".into()),
                Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => {}
                Some(Ok(other)) => {
                    return Err(format!("unexpected frame after handshake: {other:?}"));
                }
            }
        }
    })
    .await
    .map_err(|_| "heartbeat Pong timed out".to_string())?
}

fn decode_server_hello(bytes: &[u8]) -> Result<protocol::ServerHello, HandshakeError> {
    let frame = protocol::ServerFrame::decode(bytes)
        .map_err(|error| HandshakeError::Protocol(error.to_string()))?;
    match frame.payload {
        Some(protocol::server_frame::Payload::Hello(hello))
            if hello.protocol_version == CONTRACT_VERSION && hello.server_role == "elixir" =>
        {
            Ok(hello)
        }
        Some(protocol::server_frame::Payload::Hello(hello)) => {
            Err(HandshakeError::Protocol(format!(
                "expected Elixir protocol v{CONTRACT_VERSION}; got {} v{}",
                hello.server_role, hello.protocol_version
            )))
        }
        Some(protocol::server_frame::Payload::VersionError(error)) => {
            Err(HandshakeError::Protocol(format!(
                "server supports protocol v{}",
                error.supported_version
            )))
        }
        None => Err(HandshakeError::Protocol("empty ServerFrame".into())),
    }
}

fn boot() -> (Slouching, Task<Message>) {
    let mut state = Slouching::default();
    let args: Vec<String> = std::env::args().collect();
    let capture_peer_verification = args.iter().any(|arg| arg == "--capture-peer-verification");
    if let Some(pos) = args.iter().position(|s| s == "--screen")
        && let Some(name) = args.get(pos + 1)
        && let Some(screen) = Screen::ALL.into_iter().find(|s| s.slug() == name)
    {
        state.screen = screen;
    }
    if let Some(pos) = args.iter().position(|s| s == "--capture-screen")
        && let Some(name) = args.get(pos + 1)
        && let Some(screen) = Screen::ALL.into_iter().find(|s| s.slug() == name)
    {
        state.screen = screen;
        state.capture_once = true;
    }
    if let Some(pos) = args.iter().position(|s| s == "--settings-tab")
        && let Some(value) = args.get(pos + 1).and_then(|value| value.parse::<u8>().ok())
    {
        state.settings_tab = value.min(7);
    }
    if args.iter().any(|arg| arg == "--capture-peer-addresses") {
        state.screen = Screen::Chat;
        let addresses = ["192.168.1.20:45873", "100.64.0.20:45873"]
            .into_iter()
            .map(|address| address.parse().expect("valid capture address"))
            .collect::<Vec<std::net::SocketAddr>>();
        state.peer_listen_port = "45873".to_owned();
        state.peer_listener_port = Some(45873);
        state.peer_listener_addresses = addresses.clone();
        state.peer_listen_status = PeerListenStatus::Listening {
            port: 45873,
            addresses,
        };
    }
    if args.iter().any(|arg| arg == "--capture-mls-review") {
        state.screen = Screen::Mls;
        state.mls_group_id = "5f8d4d2a7c314e6a9b0f123456789abc".to_owned();
        state.mls_history_group = hex_decode_bytes(&state.mls_group_id).ok();
        state.mls_pending_proposals = vec![
            storage::StoredMlsProposal {
                proposal_id: [0x4a; 16],
                epoch: 12,
                author_device: [0x72; 32],
                approved: false,
                rejected: false,
            },
            storage::StoredMlsProposal {
                proposal_id: [0x9c; 16],
                epoch: 12,
                author_device: [0x31; 32],
                approved: true,
                rejected: false,
            },
            storage::StoredMlsProposal {
                proposal_id: [0xe1; 16],
                epoch: 12,
                author_device: [0xb4; 32],
                approved: false,
                rejected: true,
            },
        ];
    }
    if capture_peer_verification {
        let peer_key = [0x22; 32];
        state.screen = Screen::Verify;
        state.identity_status = IdentityStatus::Ready([0x11; 32]);
        state.peer_public_key = hex_encode_key(&peer_key);
        state.peer_verification_loaded_for = Some(state.peer_public_key.clone());
        state.peer_key_verified = true;
        state.peer_verification_status =
            "Chave conferida e marcada como verificada neste dispositivo.".to_owned();
    }
    if let Some(pos) = args.iter().position(|s| s == "--capture-dir")
        && let Some(path) = args.get(pos + 1)
    {
        let dir = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&dir).expect("create screenshot directory");
        state.capture_dir = Some(dir);
        if !state.capture_once {
            state.screen = Screen::ALL[0];
        }
    }
    let capture = if state.capture_dir.is_some() {
        let delay = std::env::var("SLOUCHING_CAPTURE_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(6));
        capture_after(delay)
    } else {
        Task::none()
    };
    let (transport, handle) = transport_task(state.transport_generation);
    state.transport_handle = Some(handle);
    (
        state,
        Task::batch([
            Task::perform(fetch_backend_status(), Message::BackendFetched),
            Task::perform(load_profile_task(), Message::ProfileLoaded),
            if capture_peer_verification {
                Task::none()
            } else {
                Task::perform(load_identity_task(), Message::IdentityLoaded)
            },
            Task::perform(
                load_peer_relay_config_task(),
                Message::PeerRelayConfigLoaded,
            ),
            Task::perform(
                load_delegated_mls_storage_task(),
                Message::DelegatedMlsStorageLoaded,
            ),
            load_mls_groups(),
            Task::perform(load_peer_routes_task(), Message::PeerRoutesLoaded),
            transport,
            capture,
        ]),
    )
}

async fn load_profile_task() -> Result<Option<storage::LocalProfile>, String> {
    tokio::task::spawn_blocking(storage::load_profile)
        .await
        .map_err(|error| format!("local profile task failed: {error}"))?
}

async fn load_peer_relay_config_task() -> Result<storage::PeerRelayConfig, String> {
    tokio::task::spawn_blocking(storage::load_peer_relay_config)
        .await
        .map_err(|error| format!("local relay-settings load failed: {error}"))?
}

async fn save_peer_relay_config_task(config: storage::PeerRelayConfig) -> Result<(), String> {
    tokio::task::spawn_blocking(move || storage::save_peer_relay_config(&config))
        .await
        .map_err(|error| format!("local relay-settings save failed: {error}"))?
}

async fn load_delegated_mls_storage_task() -> Result<storage::DelegatedMlsStorageStatus, String> {
    tokio::task::spawn_blocking(storage::load_delegated_mls_storage_status)
        .await
        .map_err(|error| format!("delegated MLS storage task failed: {error}"))?
}

async fn set_delegated_mls_storage_task(
    enabled: bool,
    quota_bytes: i64,
) -> Result<storage::DelegatedMlsStorageStatus, String> {
    tokio::task::spawn_blocking(move || {
        storage::set_delegated_mls_storage_policy(enabled, quota_bytes)?;
        storage::load_delegated_mls_storage_status()
    })
    .await
    .map_err(|error| format!("delegated MLS storage update task failed: {error}"))?
}

fn peer_grant_to_storage(grant: peer::DelegatedMlsCopyGrant) -> storage::DelegatedMlsCopyGrant {
    storage::DelegatedMlsCopyGrant {
        event_id: grant.event_id,
        author_device: grant.author_device,
        recipient_device: grant.recipient_device,
        group_id: grant.group_id,
        epoch: grant.epoch,
        expires_at_unix: grant.expires_at_unix,
        checkpoint: grant.checkpoint,
        ciphertext_digest: grant.ciphertext_digest,
        signature: grant.signature,
    }
}

fn delegated_copy_grant_to_peer(
    grant: storage::DelegatedMlsCopyGrant,
) -> peer::DelegatedMlsCopyGrant {
    peer::DelegatedMlsCopyGrant {
        event_id: grant.event_id,
        author_device: grant.author_device,
        recipient_device: grant.recipient_device,
        group_id: grant.group_id,
        epoch: grant.epoch,
        expires_at_unix: grant.expires_at_unix,
        checkpoint: grant.checkpoint,
        ciphertext_digest: grant.ciphertext_digest,
        signature: grant.signature,
    }
}

fn peer_event_to_encrypted(event: &peer::MlsEventEnvelope) -> storage::EncryptedEvent {
    storage::EncryptedEvent {
        event_id: event.event_id,
        author_device: event.author_device,
        group_id: event.group_id.clone(),
        epoch: event.epoch,
        checkpoint: event.checkpoint.clone(),
        expires_at_unix: event.expires_at_unix,
        ciphertext: event.ciphertext.clone(),
    }
}

fn encrypted_event_to_peer(
    grant: &storage::DelegatedMlsCopyGrant,
    ciphertext: Vec<u8>,
) -> peer::MlsEventEnvelope {
    peer::MlsEventEnvelope {
        event_id: grant.event_id,
        author_device: grant.author_device,
        group_id: grant.group_id.to_vec(),
        epoch: grant.epoch,
        checkpoint: grant.checkpoint.clone(),
        expires_at_unix: grant.expires_at_unix,
        ciphertext,
    }
}

async fn store_delegated_copy_task(
    grant: storage::DelegatedMlsCopyGrant,
    event: storage::EncryptedEvent,
    authenticated_author: [u8; 32],
) -> Result<storage::DelegatedCopyStoreResult, String> {
    tokio::task::spawn_blocking(move || {
        storage::store_delegated_mls_copy(&grant, &event, authenticated_author)
    })
    .await
    .map_err(|error| format!("delegated copy storage task failed: {error}"))?
}

async fn process_delegated_copy_for_recipient_task(
    grant: storage::DelegatedMlsCopyGrant,
    event: storage::EncryptedEvent,
    recipient_device: [u8; 32],
) -> Result<storage::ProcessedMlsApplicationEvent, String> {
    tokio::task::spawn_blocking(move || {
        storage::verify_delegated_mls_copy(&grant, &event, recipient_device)?;
        storage::process_inbound_mls_application_event(&event)
    })
    .await
    .map_err(|error| format!("delegated copy recipient task failed: {error}"))?
}

async fn load_delegated_copies_task(
    recipient_device: [u8; 32],
) -> Result<Vec<storage::StoredDelegatedMlsCopy>, String> {
    tokio::task::spawn_blocking(move || {
        storage::list_delegated_mls_copies_for_device(recipient_device, peer::MAX_PENDING_MESSAGES)
    })
    .await
    .map_err(|error| format!("delegated copy fetch task failed: {error}"))?
}

async fn acknowledge_delegated_copy_task(
    event_id: [u8; 16],
    recipient_device: [u8; 32],
) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || {
        storage::acknowledge_delegated_mls_copy(event_id, recipient_device)
    })
    .await
    .map_err(|error| format!("delegated copy acknowledgement task failed: {error}"))?
}

fn load_mls_groups() -> Task<Message> {
    Task::perform(load_mls_groups_task(), Message::MlsGroupsLoaded)
}

async fn load_mls_groups_task() -> Result<Vec<storage::StoredMlsGroup>, String> {
    tokio::task::spawn_blocking(storage::list_mls_groups)
        .await
        .map_err(|error| format!("MLS group list task failed: {error}"))?
}

async fn load_direct_history_task(
    peer_device: [u8; 32],
) -> Result<Vec<storage::StoredDirectMessage>, String> {
    tokio::task::spawn_blocking(move || storage::list_direct_messages(peer_device, 200))
        .await
        .map_err(|error| format!("direct history task failed: {error}"))?
}

async fn load_peer_verification_task(device_public_key: [u8; 32]) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || storage::peer_key_is_verified(device_public_key))
        .await
        .map_err(|error| format!("peer verification query task failed: {error}"))?
}

async fn set_peer_verification_task(
    device_public_key: [u8; 32],
    verified: bool,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || storage::set_peer_key_verified(device_public_key, verified))
        .await
        .map_err(|error| format!("peer verification save task failed: {error}"))?
}

async fn clear_direct_history_task(peer_device: [u8; 32]) -> Result<usize, String> {
    tokio::task::spawn_blocking(move || storage::clear_direct_history(peer_device))
        .await
        .map_err(|error| format!("direct history deletion task failed: {error}"))?
}

async fn store_direct_message_task(
    peer_device: [u8; 32],
    direction: storage::DirectMessageDirection,
    text: String,
) -> Result<storage::StoredDirectMessage, String> {
    tokio::task::spawn_blocking(move || {
        storage::store_direct_message(peer_device, direction, &text)
    })
    .await
    .map_err(|error| format!("direct history task failed: {error}"))?
}

async fn load_peer_routes_task() -> Result<Vec<storage::StoredPeerRoute>, String> {
    tokio::task::spawn_blocking(storage::list_peer_routes)
        .await
        .map_err(|error| format!("peer route load task failed: {error}"))?
}

async fn save_peer_route_task(
    peer_device: [u8; 32],
    address: String,
    relay_only: bool,
    only_if_missing: bool,
) -> Result<Vec<storage::StoredPeerRoute>, String> {
    tokio::task::spawn_blocking(move || {
        if relay_only && only_if_missing {
            storage::ensure_peer_relay_route(peer_device)?;
        } else if relay_only {
            storage::save_peer_relay_route(peer_device)?;
        } else {
            storage::save_peer_route(peer_device, &address)?;
        }
        storage::list_peer_routes()
    })
    .await
    .map_err(|error| format!("peer route persistence task failed: {error}"))?
}

async fn save_profile_task(profile: storage::LocalProfile) -> Result<(), String> {
    tokio::task::spawn_blocking(move || storage::save_profile(&profile))
        .await
        .map_err(|error| format!("local profile task failed: {error}"))?
}

async fn load_identity_task() -> Result<Option<[u8; 32]>, String> {
    tokio::task::spawn_blocking(storage::load_identity_public_key)
        .await
        .map_err(|error| format!("device identity task failed: {error}"))?
}

async fn create_identity_task() -> Result<[u8; 32], String> {
    tokio::task::spawn_blocking(storage::create_or_load_identity_public_key)
        .await
        .map_err(|error| format!("device identity task failed: {error}"))?
}

async fn create_mls_group_task() -> Result<storage::CreatedMlsGroup, String> {
    tokio::task::spawn_blocking(|| {
        storage::create_mls_group(
            openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        )
    })
    .await
    .map_err(|error| format!("MLS group task failed: {error}"))?
}

async fn create_mls_key_package_task() -> Result<storage::PreparedMlsKeyPackage, String> {
    tokio::task::spawn_blocking(|| {
        storage::create_mls_key_package(
            openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        )
    })
    .await
    .map_err(|error| format!("MLS KeyPackage task failed: {error}"))?
}

async fn admit_mls_member_task(
    group_id: Vec<u8>,
    package: Vec<u8>,
) -> Result<storage::AddedMlsMember, String> {
    tokio::task::spawn_blocking(move || storage::add_mls_group_member(&group_id, &package))
        .await
        .map_err(|error| format!("MLS member admission task failed: {error}"))?
}

async fn admit_mls_member_from_peer_task(
    group_id: Vec<u8>,
    package: Vec<u8>,
    pinned_peer_device: [u8; 32],
) -> Result<storage::AddedMlsMember, String> {
    tokio::task::spawn_blocking(move || {
        storage::add_mls_group_member_from_peer(&group_id, &package, pinned_peer_device)
    })
    .await
    .map_err(|error| format!("pinned MLS member admission task failed: {error}"))?
}

async fn create_mls_update_proposal_task(
    group_id: Vec<u8>,
) -> Result<storage::PreparedMlsUpdateProposal, String> {
    tokio::task::spawn_blocking(move || storage::create_mls_self_update_proposal(&group_id))
        .await
        .map_err(|error| format!("MLS update proposal task failed: {error}"))?
}

async fn process_mls_update_proposal_task(
    group_id: Vec<u8>,
    proposal: Vec<u8>,
) -> Result<storage::ProcessedMlsProposal, String> {
    tokio::task::spawn_blocking(move || {
        storage::process_mls_self_update_proposal(&group_id, &proposal)
    })
    .await
    .map_err(|error| format!("MLS proposal processing task failed: {error}"))?
}

async fn process_mls_proposal_from_peer_task(
    proposal: peer::MlsProposalEnvelope,
    pinned_peer_device: [u8; 32],
) -> Result<storage::ProcessedMlsProposal, String> {
    tokio::task::spawn_blocking(move || {
        storage::process_mls_self_update_proposal_from_peer(&proposal, pinned_peer_device)
    })
    .await
    .map_err(|error| format!("MLS peer proposal task failed: {error}"))?
}

async fn commit_mls_proposals_task(
    group_id: Vec<u8>,
    proposal_ids: Vec<[u8; 16]>,
) -> Result<storage::StoredMlsCommit, String> {
    tokio::task::spawn_blocking(move || {
        storage::commit_approved_mls_proposals(&group_id, &proposal_ids)
    })
    .await
    .map_err(|error| format!("MLS proposal Commit task failed: {error}"))?
}

async fn set_mls_proposal_approval_task(
    group_id: Vec<u8>,
    proposal_id: [u8; 16],
    approved: bool,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        storage::set_mls_proposal_approval(&group_id, proposal_id, approved)
    })
    .await
    .map_err(|error| format!("MLS proposal decision task failed: {error}"))?
}

async fn join_mls_group_task(
    welcome: Vec<u8>,
    tree: Vec<u8>,
) -> Result<storage::JoinedMlsGroup, String> {
    tokio::task::spawn_blocking(move || storage::join_mls_group_from_welcome(&welcome, &tree))
        .await
        .map_err(|error| format!("MLS Welcome task failed: {error}"))?
}

async fn join_mls_group_from_peer_task(
    welcome: Vec<u8>,
    tree: Vec<u8>,
    event_id: [u8; 16],
    expected_committer_device: [u8; 32],
    expected_group_id: [u8; 16],
) -> Result<storage::JoinedMlsGroup, String> {
    tokio::task::spawn_blocking(move || {
        storage::join_mls_group_from_pinned_peer_event(
            event_id,
            &welcome,
            &tree,
            expected_committer_device,
            expected_group_id,
        )
    })
    .await
    .map_err(|error| format!("MLS peer Welcome task failed: {error}"))?
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn load_mls_history(state: &mut Slouching, group_id: Vec<u8>) -> Task<Message> {
    state.mls_history_group = Some(group_id.clone());
    state.mls_quarantine_reason = None;
    let history_group_id = group_id.clone();
    let quarantine_group_id = group_id.clone();
    let commits_group_id = group_id.clone();
    let commits_message_group_id = group_id.clone();
    let proposals_group_id = group_id.clone();
    let recipients_group_id = group_id.clone();
    let recipients_message_group_id = recipients_group_id.clone();
    Task::batch([
        Task::perform(load_mls_history_task(group_id.clone()), move |result| {
            Message::MlsHistoryLoaded(history_group_id, result)
        }),
        Task::perform(
            load_mls_quarantine_task(quarantine_group_id.clone()),
            move |result| Message::MlsQuarantineLoaded(quarantine_group_id, result),
        ),
        Task::perform(load_mls_commits_task(commits_group_id), move |result| {
            Message::MlsCommitsLoaded(commits_message_group_id, result)
        }),
        Task::perform(
            load_mls_commit_recipient_status_task(recipients_group_id),
            move |result| Message::MlsCommitRecipientsLoaded(recipients_message_group_id, result),
        ),
        Task::perform(
            load_pending_mls_proposals_task(proposals_group_id),
            move |result| Message::MlsPendingProposalsLoaded(group_id, result),
        ),
    ])
}

async fn load_mls_quarantine_task(group_id: Vec<u8>) -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(move || storage::load_mls_group_quarantine(&group_id))
        .await
        .map_err(|error| format!("MLS quarantine query task failed: {error}"))?
}

async fn load_mls_history_task(
    group_id: Vec<u8>,
) -> Result<Vec<storage::StoredMlsMessage>, String> {
    tokio::task::spawn_blocking(move || storage::list_mls_messages(&group_id, 200))
        .await
        .map_err(|error| format!("MLS history task failed: {error}"))?
}

async fn load_pending_mls_proposals_task(
    group_id: Vec<u8>,
) -> Result<Vec<storage::StoredMlsProposal>, String> {
    tokio::task::spawn_blocking(move || storage::list_pending_mls_proposals(&group_id))
        .await
        .map_err(|error| format!("MLS pending proposal query failed: {error}"))?
}

async fn load_mls_commits_task(group_id: Vec<u8>) -> Result<Vec<storage::StoredMlsCommit>, String> {
    tokio::task::spawn_blocking(move || storage::list_queued_mls_commits(&group_id, 100))
        .await
        .map_err(|error| format!("MLS Commit outbox task failed: {error}"))?
}

async fn load_mls_commit_recipient_status_task(
    group_id: Vec<u8>,
) -> Result<Vec<storage::MlsCommitRecipientStatus>, String> {
    tokio::task::spawn_blocking(move || storage::list_mls_commit_recipient_status(&group_id, 200))
        .await
        .map_err(|error| format!("MLS Commit recipient status task failed: {error}"))?
}

async fn load_mls_welcomes_for_peer_task(
    group_id: Vec<u8>,
    peer_device: [u8; 32],
) -> Result<Vec<storage::StoredMlsWelcome>, String> {
    tokio::task::spawn_blocking(move || {
        storage::list_queued_mls_welcomes_for_peer(&group_id, peer_device)
    })
    .await
    .map_err(|error| format!("MLS Welcome outbox task failed: {error}"))?
}

async fn mark_mls_welcome_delivered_task(event_id: [u8; 16]) -> Result<(), String> {
    tokio::task::spawn_blocking(move || storage::mark_mls_welcome_delivered(event_id))
        .await
        .map_err(|error| format!("MLS Welcome ACK persistence task failed: {error}"))?
}

async fn load_mls_commits_for_peer_task(
    group_id: Vec<u8>,
    peer_device: [u8; 32],
) -> Result<Vec<storage::StoredMlsCommit>, String> {
    tokio::task::spawn_blocking(move || {
        storage::list_queued_mls_commits_for_peer(&group_id, &peer_device, 100)
    })
    .await
    .map_err(|error| format!("MLS Commit peer check failed: {error}"))?
}

async fn fanout_mls_commits_task(group_id: Vec<u8>) -> Result<MlsCommitFanoutReport, String> {
    let recipient_group_id = group_id.clone();
    let (statuses, routes) = tokio::task::spawn_blocking(move || {
        Ok::<_, String>((
            storage::list_queued_mls_commit_recipients(&recipient_group_id)?,
            storage::list_peer_routes()?,
        ))
    })
    .await
    .map_err(|error| format!("MLS fan-out preparation task failed: {error}"))??;
    let relay_config = load_peer_relay_config_task().await?;
    let relay = peer_relay_from_config(&relay_config)?;
    let route_by_device = routes
        .into_iter()
        .map(|route| (route.device_public_key, route))
        .collect::<std::collections::HashMap<_, _>>();
    let mut recipients = statuses;
    recipients.sort_unstable();
    recipients.dedup();

    let mut report = MlsCommitFanoutReport {
        recipients: recipients.len(),
        commits_acked: 0,
        failures: Vec::new(),
    };
    for peer_device in recipients {
        let Some(route) = route_by_device.get(&peer_device) else {
            report.failures.push(format!(
                "{}… sem rota salva",
                hex_encode_bytes(&peer_device[..4])
            ));
            continue;
        };
        let address = match peer_route_socket(route) {
            Ok(address) => address,
            Err(error) => {
                report
                    .failures
                    .push(format!("{}…: {error}", hex_encode_bytes(&peer_device[..4])));
                continue;
            }
        };
        loop {
            let commits = match load_mls_commits_for_peer_task(group_id.clone(), peer_device).await
            {
                Ok(commits) => commits,
                Err(error) => {
                    report
                        .failures
                        .push(format!("{}…: {error}", hex_encode_bytes(&peer_device[..4])));
                    break;
                }
            };
            if commits.is_empty() {
                break;
            }
            let has_more = commits.len() == 100;
            let outcome =
                fanout_mls_commits_to_peer(peer_device, address, relay.clone(), commits).await;
            report.commits_acked += outcome.commits_acked;
            if let Some(error) = outcome.failure {
                report
                    .failures
                    .push(format!("{}…: {error}", hex_encode_bytes(&peer_device[..4])));
                break;
            }
            if !has_more {
                break;
            }
        }
    }
    Ok(report)
}

async fn fanout_mls_commits_to_peer(
    peer_device: [u8; 32],
    address: Option<std::net::SocketAddr>,
    relay: Option<peer::ParticipantRelay>,
    commits: Vec<storage::StoredMlsCommit>,
) -> MlsCommitFanoutPeerOutcome {
    let mut outcome = MlsCommitFanoutPeerOutcome::default();
    let endpoint = match parse_peer_id(&hex_encode_bytes(&peer_device)) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            outcome.failure = Some(format!("invalid pinned peer key: {error}"));
            return outcome;
        }
    };
    let local_identity = match load_peer_secret_key_task().await {
        Ok(identity) => identity,
        Err(error) => {
            outcome.failure = Some(error);
            return outcome;
        }
    };
    let session =
        match peer::connect_peer_with_relay(local_identity, endpoint, address, relay).await {
            Ok(session) => session,
            Err(error) => {
                outcome.failure = Some(error);
                return outcome;
            }
        };
    let (commands, receiver) = tokio::sync::mpsc::channel(8);
    let mut events = Box::pin(session.run(receiver));
    match tokio::time::timeout(Duration::from_secs(8), events.next()).await {
        Ok(Some(peer::PeerEvent::Connected { peer_id })) if *peer_id.as_bytes() == peer_device => {}
        Ok(Some(event)) => {
            outcome.failure = Some(format!("unexpected session start event: {event:?}"));
            return outcome;
        }
        Ok(None) => {
            outcome.failure = Some("session ended before connect event".to_owned());
            return outcome;
        }
        Err(_) => {
            outcome.failure = Some("timed out waiting for connected peer".to_owned());
            return outcome;
        }
    }

    for (index, stored) in commits.into_iter().enumerate() {
        let request_id = index as u64 + 1;
        let envelope = peer::MlsCommitEnvelope {
            event_id: stored.event_id,
            author_device: stored.author_device,
            group_id: stored.group_id,
            predecessor_epoch: stored.predecessor_epoch,
            epoch: stored.epoch,
            commit: stored.commit,
        };
        if let Err(error) = commands
            .send(peer::PeerCommand::SendMlsCommit {
                request_id,
                commit: envelope,
            })
            .await
        {
            outcome.failure = Some(format!("could not queue Commit: {error}"));
            break;
        }
        let acknowledged = loop {
            match tokio::time::timeout(Duration::from_secs(30), events.next()).await {
                Ok(Some(peer::PeerEvent::MlsCommitAcknowledged {
                    request_id: acknowledged_id,
                })) if acknowledged_id == request_id => break true,
                Ok(Some(peer::PeerEvent::MlsCommitRejected {
                    request_id: rejected_id,
                    reason,
                })) if rejected_id == request_id => {
                    outcome.failure = Some(format!("Commit rejected: {reason}"));
                    break false;
                }
                Ok(Some(peer::PeerEvent::MlsCommitDeliveryUnknown {
                    request_id: unknown_id,
                })) if unknown_id == request_id => {
                    outcome.failure = Some("Commit delivery is unknown".to_owned());
                    break false;
                }
                Ok(Some(peer::PeerEvent::Disconnected { reason })) => {
                    outcome.failure = Some(format!("peer disconnected: {reason}"));
                    break false;
                }
                Ok(Some(peer::PeerEvent::Connected { .. })) => continue,
                Ok(Some(peer::PeerEvent::DelegatedMlsCopiesRequested { .. })) => continue,
                Ok(Some(peer::PeerEvent::DelegatedMlsCopyReceived { sequence, .. })) => {
                    let _ = commands
                        .send(peer::PeerCommand::RejectInbound {
                            sequence,
                            reason: "background Commit fan-out does not consume delegated copies"
                                .into(),
                        })
                        .await;
                    continue;
                }
                Ok(Some(event)) => {
                    outcome.failure = Some(format!(
                        "unexpected event during Commit delivery: {event:?}"
                    ));
                    break false;
                }
                Ok(None) => {
                    outcome.failure = Some("session ended before Commit ACK".to_owned());
                    break false;
                }
                Err(_) => {
                    outcome.failure = Some("timed out waiting for Commit ACK".to_owned());
                    break false;
                }
            }
        };
        if !acknowledged {
            break;
        }
        let event_id = stored.event_id;
        if let Err(error) = tokio::task::spawn_blocking(move || {
            storage::mark_mls_commit_delivered(event_id, peer_device)
        })
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result)
        {
            outcome.failure = Some(format!(
                "peer ACKed but local recipient ledger could not be updated: {error}"
            ));
            break;
        }
        outcome.commits_acked += 1;
    }

    let _ = commands.send(peer::PeerCommand::Disconnect).await;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(event) = events.next().await {
            if matches!(event, peer::PeerEvent::Disconnected { .. }) {
                break;
            }
        }
    })
    .await;
    outcome
}

async fn fanout_mls_events_task(group_id: Vec<u8>) -> Result<MlsEventFanoutReport, String> {
    let route_group_id = group_id.clone();
    let (events_expired, recipients, routes) = tokio::task::spawn_blocking(move || {
        let events_expired = storage::expire_queued_mls_events(&route_group_id)?;
        Ok::<_, String>((
            events_expired,
            storage::list_queued_mls_event_recipients(&route_group_id)?,
            storage::list_peer_routes()?,
        ))
    })
    .await
    .map_err(|error| format!("MLS event fan-out preparation failed: {error}"))??;
    let relay_config = load_peer_relay_config_task().await?;
    let relay = peer_relay_from_config(&relay_config)?;
    let route_by_device = routes
        .into_iter()
        .map(|route| (route.device_public_key, route))
        .collect::<std::collections::HashMap<_, _>>();
    let mut report = MlsEventFanoutReport {
        recipients: recipients.len(),
        events_acked: 0,
        copies_held: 0,
        events_expired,
        failures: Vec::new(),
    };
    for peer_device in recipients.iter().copied() {
        let Some(route) = route_by_device.get(&peer_device) else {
            let pending = load_all_mls_events_for_peer_task(group_id.clone(), peer_device).await?;
            if !pending.is_empty() {
                let (held, failure) = fanout_mls_copies_to_helpers(
                    peer_device,
                    &pending,
                    &recipients,
                    &route_by_device,
                    relay.clone(),
                )
                .await;
                report.copies_held += held;
                if let Some(reason) = failure {
                    report.failures.push(format!(
                        "{}… sem rota direta; cópia: {reason}",
                        hex_encode_bytes(&peer_device[..4])
                    ));
                }
            }
            continue;
        };
        let address = match peer_route_socket(route) {
            Ok(address) => address,
            Err(error) => {
                report
                    .failures
                    .push(format!("{}…: {error}", hex_encode_bytes(&peer_device[..4])));
                continue;
            }
        };
        let commits = load_mls_commits_for_peer_task(group_id.clone(), peer_device).await?;
        if !commits.is_empty() {
            report.failures.push(format!(
                "{}… requer {} Commit(s) antes das mensagens",
                hex_encode_bytes(&peer_device[..4]),
                commits.len()
            ));
            continue;
        }
        loop {
            let events = match load_mls_events_for_peer_task(group_id.clone(), peer_device).await {
                Ok(events) => events,
                Err(error) => {
                    report
                        .failures
                        .push(format!("{}…: {error}", hex_encode_bytes(&peer_device[..4])));
                    break;
                }
            };
            if events.is_empty() {
                break;
            }
            let has_more = events.len() == 16;
            let outcome =
                fanout_mls_events_to_peer(peer_device, address, relay.clone(), events).await;
            report.events_acked += outcome.0;
            if let Some(error) = outcome.1 {
                let events_for_copy =
                    load_all_mls_events_for_peer_task(group_id.clone(), peer_device).await?;
                let (held, copy_failure) = fanout_mls_copies_to_helpers(
                    peer_device,
                    &events_for_copy,
                    &recipients,
                    &route_by_device,
                    relay.clone(),
                )
                .await;
                report.copies_held += held;
                if held == 0 {
                    report.failures.push(format!(
                        "{}…: {error}; cópia: {}",
                        hex_encode_bytes(&peer_device[..4]),
                        copy_failure.unwrap_or_else(|| "nenhum ajudante aceitou".to_owned())
                    ));
                    break;
                }
                if let Some(copy_failure) = copy_failure {
                    report.failures.push(format!(
                        "{}…: {} evento(s) direto(s) falharam; cópia parcial: {copy_failure}",
                        hex_encode_bytes(&peer_device[..4]),
                        held
                    ));
                }
                break;
            }
            if !has_more {
                break;
            }
        }
    }
    Ok(report)
}

async fn fanout_mls_copies_to_helpers(
    target_device: [u8; 32],
    events: &[storage::StoredOutboundEvent],
    group_members: &[[u8; 32]],
    routes: &std::collections::HashMap<[u8; 32], storage::StoredPeerRoute>,
    relay: Option<peer::ParticipantRelay>,
) -> (usize, Option<String>) {
    let mut last_failure = None;
    for helper_device in group_members.iter().copied() {
        if helper_device == target_device
            || events
                .first()
                .is_some_and(|event| event.event.author_device == helper_device)
        {
            continue;
        }
        let Some(route) = routes.get(&helper_device) else {
            continue;
        };
        let address = match peer_route_socket(route) {
            Ok(address) => address,
            Err(error) => {
                last_failure = Some(error);
                continue;
            }
        };
        let (stored, failure) = fanout_mls_copies_to_helper(
            helper_device,
            address,
            relay.clone(),
            target_device,
            events,
        )
        .await;
        if stored == events.len() {
            return (stored, None);
        }
        last_failure =
            failure.or_else(|| Some(format!("helper stored {stored}/{} copies", events.len())));
        if stored > 0 {
            return (stored, last_failure);
        }
    }
    (
        0,
        Some(last_failure.unwrap_or_else(|| "no reachable opted-in group helper".to_owned())),
    )
}

async fn fanout_mls_copies_to_helper(
    helper_device: [u8; 32],
    address: Option<std::net::SocketAddr>,
    relay: Option<peer::ParticipantRelay>,
    target_device: [u8; 32],
    events: &[storage::StoredOutboundEvent],
) -> (usize, Option<String>) {
    let endpoint = match parse_peer_id(&hex_encode_bytes(&helper_device)) {
        Ok(endpoint) => endpoint,
        Err(error) => return (0, Some(format!("invalid helper identity: {error}"))),
    };
    let identity = match load_peer_secret_key_task().await {
        Ok(identity) => identity,
        Err(error) => return (0, Some(error)),
    };
    let session = match peer::connect_peer_with_relay(identity, endpoint, address, relay).await {
        Ok(session) => session,
        Err(error) => return (0, Some(error)),
    };
    let (commands, receiver) = tokio::sync::mpsc::channel(8);
    let mut stream = Box::pin(session.run(receiver));
    match tokio::time::timeout(Duration::from_secs(8), stream.next()).await {
        Ok(Some(peer::PeerEvent::Connected { peer_id }))
            if *peer_id.as_bytes() == helper_device => {}
        Ok(Some(event)) => {
            return (
                0,
                Some(format!("unexpected helper session event: {event:?}")),
            );
        }
        Ok(None) => return (0, Some("helper session ended before connect".to_owned())),
        Err(_) => return (0, Some("timed out connecting to helper".to_owned())),
    }
    let mut stored = 0;
    let mut failure = None;
    for (index, queued) in events.iter().enumerate() {
        let event = peer_event_from_encrypted(&queued.event);
        let event_for_signing = queued.event.clone();
        let grant = match tokio::task::spawn_blocking(move || {
            storage::sign_delegated_mls_copy_grant(&event_for_signing, target_device)
        })
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result)
        {
            Ok(grant) => grant,
            Err(error) => {
                failure = Some(format!("could not authorize copy: {error}"));
                break;
            }
        };
        let request_id = index as u64 + 1;
        if let Err(error) = commands
            .send(peer::PeerCommand::SendDelegatedMlsCopy {
                request_id,
                grant: Box::new(delegated_copy_grant_to_peer(grant)),
                event: Box::new(event),
            })
            .await
        {
            failure = Some(format!("could not queue delegated copy: {error}"));
            break;
        }
        let accepted = loop {
            match tokio::time::timeout(Duration::from_secs(30), stream.next()).await {
                Ok(Some(peer::PeerEvent::DelegatedMlsCopyAcknowledged { request_id: ack }))
                    if ack == request_id =>
                {
                    break true;
                }
                Ok(Some(peer::PeerEvent::DelegatedMlsCopyRejected {
                    request_id: rejected,
                    reason,
                })) if rejected == request_id => {
                    failure = Some(format!("helper declined storage: {reason}"));
                    break false;
                }
                Ok(Some(peer::PeerEvent::DelegatedMlsCopyDeliveryUnknown {
                    request_id: unknown,
                })) if unknown == request_id => {
                    failure = Some("helper storage acknowledgement is unknown".to_owned());
                    break false;
                }
                Ok(Some(peer::PeerEvent::Disconnected { reason })) => {
                    failure = Some(format!("helper disconnected: {reason}"));
                    break false;
                }
                Ok(Some(peer::PeerEvent::Connected { .. })) => continue,
                Ok(Some(peer::PeerEvent::DelegatedMlsCopiesRequested { .. })) => continue,
                Ok(Some(peer::PeerEvent::DelegatedMlsCopyReceived { sequence, .. })) => {
                    let _ = commands
                        .send(peer::PeerCommand::RejectInbound {
                            sequence,
                            reason: "background helper fan-out does not consume inbound copies"
                                .into(),
                        })
                        .await;
                    continue;
                }
                Ok(Some(other)) => {
                    failure = Some(format!("unexpected event during helper storage: {other:?}"));
                    break false;
                }
                Ok(None) => {
                    failure = Some("helper session ended before copy ACK".to_owned());
                    break false;
                }
                Err(_) => {
                    failure = Some("timed out waiting for helper storage ACK".to_owned());
                    break false;
                }
            }
        };
        if !accepted {
            break;
        }
        stored += 1;
    }
    let _ = commands.send(peer::PeerCommand::Disconnect).await;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(event) = stream.next().await {
            if matches!(event, peer::PeerEvent::Disconnected { .. }) {
                break;
            }
        }
    })
    .await;
    (stored, failure)
}

fn peer_event_from_encrypted(event: &storage::EncryptedEvent) -> peer::MlsEventEnvelope {
    peer::MlsEventEnvelope {
        event_id: event.event_id,
        author_device: event.author_device,
        group_id: event.group_id.clone(),
        epoch: event.epoch,
        checkpoint: event.checkpoint.clone(),
        expires_at_unix: event.expires_at_unix,
        ciphertext: event.ciphertext.clone(),
    }
}

async fn fanout_mls_events_to_peer(
    peer_device: [u8; 32],
    address: Option<std::net::SocketAddr>,
    relay: Option<peer::ParticipantRelay>,
    events_to_send: Vec<storage::StoredOutboundEvent>,
) -> (usize, Option<String>) {
    let mut acked = 0;
    let mut failure = None;
    let endpoint = match parse_peer_id(&hex_encode_bytes(&peer_device)) {
        Ok(endpoint) => endpoint,
        Err(error) => return (acked, Some(format!("invalid pinned peer key: {error}"))),
    };
    let local_identity = match load_peer_secret_key_task().await {
        Ok(identity) => identity,
        Err(error) => return (acked, Some(error)),
    };
    let session =
        match peer::connect_peer_with_relay(local_identity, endpoint, address, relay).await {
            Ok(session) => session,
            Err(error) => return (acked, Some(error)),
        };
    let (commands, receiver) = tokio::sync::mpsc::channel(8);
    let mut stream = Box::pin(session.run(receiver));
    match tokio::time::timeout(Duration::from_secs(8), stream.next()).await {
        Ok(Some(peer::PeerEvent::Connected { peer_id })) if *peer_id.as_bytes() == peer_device => {}
        Ok(Some(event)) => {
            return (
                acked,
                Some(format!("unexpected session start event: {event:?}")),
            );
        }
        Ok(None) => return (acked, Some("session ended before connect event".to_owned())),
        Err(_) => {
            return (
                acked,
                Some("timed out waiting for connected peer".to_owned()),
            );
        }
    }
    for (index, stored) in events_to_send.into_iter().enumerate() {
        let request_id = index as u64 + 1;
        let event = peer::MlsEventEnvelope {
            event_id: stored.event.event_id,
            author_device: stored.event.author_device,
            group_id: stored.event.group_id,
            epoch: stored.event.epoch,
            checkpoint: stored.event.checkpoint,
            expires_at_unix: stored.event.expires_at_unix,
            ciphertext: stored.event.ciphertext,
        };
        if let Err(error) = commands
            .send(peer::PeerCommand::SendMlsEvent { request_id, event })
            .await
        {
            failure = Some(format!("could not queue MLS event: {error}"));
            break;
        }
        let delivered = loop {
            match tokio::time::timeout(Duration::from_secs(30), stream.next()).await {
                Ok(Some(peer::PeerEvent::MlsEventAcknowledged { request_id: ack }))
                    if ack == request_id =>
                {
                    break true;
                }
                Ok(Some(peer::PeerEvent::MlsEventRejected {
                    request_id: rejected,
                    reason,
                })) if rejected == request_id => {
                    failure = Some(format!("MLS event rejected: {reason}"));
                    break false;
                }
                Ok(Some(peer::PeerEvent::MlsEventDeliveryUnknown {
                    request_id: unknown,
                })) if unknown == request_id => {
                    failure = Some("MLS event delivery is unknown".to_owned());
                    break false;
                }
                Ok(Some(peer::PeerEvent::Disconnected { reason })) => {
                    failure = Some(format!("peer disconnected: {reason}"));
                    break false;
                }
                Ok(Some(peer::PeerEvent::Connected { .. })) => continue,
                Ok(Some(peer::PeerEvent::DelegatedMlsCopiesRequested { .. })) => continue,
                Ok(Some(peer::PeerEvent::DelegatedMlsCopyReceived { sequence, .. })) => {
                    let _ = commands
                        .send(peer::PeerCommand::RejectInbound {
                            sequence,
                            reason: "background event fan-out does not consume delegated copies"
                                .into(),
                        })
                        .await;
                    continue;
                }
                Ok(Some(other)) => {
                    failure = Some(format!("unexpected event during MLS delivery: {other:?}"));
                    break false;
                }
                Ok(None) => {
                    failure = Some("session ended before MLS event ACK".to_owned());
                    break false;
                }
                Err(_) => {
                    failure = Some("timed out waiting for MLS event ACK".to_owned());
                    break false;
                }
            }
        };
        if !delivered {
            break;
        }
        let event_id = stored.event.event_id;
        if let Err(error) = tokio::task::spawn_blocking(move || {
            storage::mark_mls_event_delivered_to_peer(event_id, peer_device)
        })
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result)
        {
            failure = Some(format!(
                "peer ACKed but local recipient ledger failed: {error}"
            ));
            break;
        }
        acked += 1;
    }
    let _ = commands.send(peer::PeerCommand::Disconnect).await;
    let _ = tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(event) = stream.next().await {
            if matches!(event, peer::PeerEvent::Disconnected { .. }) {
                break;
            }
        }
    })
    .await;
    (acked, failure)
}

async fn load_authorized_mls_commit_task(
    group_id: Vec<u8>,
    predecessor_epoch: u64,
    peer_device: [u8; 32],
) -> Result<Option<storage::StoredMlsCommit>, String> {
    tokio::task::spawn_blocking(move || {
        storage::load_authorized_mls_commit_for_peer(&group_id, predecessor_epoch, &peer_device)
    })
    .await
    .map_err(|error| format!("MLS predecessor lookup task failed: {error}"))?
}

async fn mark_mls_commit_delivered_task(
    event_id: [u8; 16],
    peer_device: [u8; 32],
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || storage::mark_mls_commit_delivered(event_id, peer_device))
        .await
        .map_err(|error| format!("MLS Commit delivery ledger task failed: {error}"))?
}

async fn load_mls_events_for_peer_task(
    group_id: Vec<u8>,
    peer_device: [u8; 32],
) -> Result<Vec<storage::StoredOutboundEvent>, String> {
    tokio::task::spawn_blocking(move || {
        storage::list_queued_mls_events_for_peer(&group_id, peer_device, 16)
    })
    .await
    .map_err(|error| format!("MLS peer outbox task failed: {error}"))?
}

async fn load_all_mls_events_for_peer_task(
    group_id: Vec<u8>,
    peer_device: [u8; 32],
) -> Result<Vec<storage::StoredOutboundEvent>, String> {
    tokio::task::spawn_blocking(move || {
        storage::list_queued_mls_events_for_peer(&group_id, peer_device, 500)
    })
    .await
    .map_err(|error| format!("MLS helper-copy outbox task failed: {error}"))?
}

async fn create_mls_application_task(
    group_id: Vec<u8>,
    text: String,
) -> Result<storage::PreparedMlsApplicationEvent, String> {
    let expires_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock is invalid: {error}"))?
        .as_secs()
        .saturating_add(30 * 24 * 60 * 60) as i64;
    tokio::task::spawn_blocking(move || {
        storage::create_mls_application_event(&group_id, text.as_bytes(), expires_at_unix)
    })
    .await
    .map_err(|error| format!("MLS application encryption task failed: {error}"))?
}

async fn process_inbound_mls_application_task(
    event: storage::EncryptedEvent,
) -> Result<storage::ProcessedMlsApplicationEvent, String> {
    tokio::task::spawn_blocking(move || storage::process_inbound_mls_application_event(&event))
        .await
        .map_err(|error| format!("MLS inbound processing task failed: {error}"))?
}

async fn update_mls_outbound_state_task(
    event_id: [u8; 16],
    peer_device: [u8; 32],
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        storage::mark_mls_event_delivered_to_peer(event_id, peer_device)
    })
    .await
    .map_err(|error| format!("MLS delivery state task failed: {error}"))?
}

async fn process_mls_commit_task(
    group_id: Vec<u8>,
    commit: Vec<u8>,
) -> Result<storage::ProcessedMlsCommit, String> {
    tokio::task::spawn_blocking(move || storage::process_inbound_mls_commit(&group_id, &commit))
        .await
        .map_err(|error| format!("MLS Commit task failed: {error}"))?
}

async fn process_mls_commit_envelope_task(
    envelope: peer::MlsCommitEnvelope,
) -> Result<storage::ProcessedMlsCommit, String> {
    tokio::task::spawn_blocking(move || storage::process_inbound_mls_commit_envelope(&envelope))
        .await
        .map_err(|error| format!("MLS Commit authentication task failed: {error}"))?
}

fn hex_decode_bytes(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() > 256 * 1024 {
        return Err("cole bytes hexadecimais completos".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            let high = digit(pair[0]).ok_or_else(|| "contém caractere que não é hex".to_owned())?;
            let low = digit(pair[1]).ok_or_else(|| "contém caractere que não é hex".to_owned())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn missing_predecessor_from_error(error: &str) -> Option<u64> {
    error
        .strip_prefix("MLS Commit is out of order: expected predecessor epoch ")?
        .split_once(',')?
        .0
        .parse()
        .ok()
}

fn peer_listener_task(
    generation: u64,
    port: u16,
    expected_peer: Option<iroh::EndpointId>,
    relay: Option<peer::ParticipantRelay>,
) -> (Task<Message>, Handle) {
    let events = async_stream::stream! {
        let local_identity = match load_peer_secret_key_task().await {
            Ok(identity) => identity,
            Err(error) => {
                yield PeerListenEvent::Failed(error);
                return;
            }
        };
        let bind_address = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        let listener_result = if let Some(expected_peer) = expected_peer {
            peer::bind_listener_with_relay(local_identity, bind_address, expected_peer, relay).await
        } else {
            peer::bind_helper_listener_with_relay(local_identity, bind_address, relay).await
        };
        let listener = match listener_result {
            Ok(listener) => listener,
            Err(error) => {
                yield PeerListenEvent::Failed(error);
                return;
            }
        };
        let addresses = listener.direct_addresses();
        yield PeerListenEvent::Bound { addresses };
        loop {
            match listener.accept_session().await {
                Ok(session) => {
                    let (commands, command_rx) = tokio::sync::mpsc::channel(32);
                    yield PeerListenEvent::SessionCommands(commands);
                    let mut events = Box::pin(session.run(command_rx));
                    while let Some(event) = events.next().await {
                        let disconnected = matches!(event, peer::PeerEvent::Disconnected { .. });
                        yield PeerListenEvent::Session(event);
                        if disconnected { break; }
                    }
                    if expected_peer.is_some() {
                        return;
                    }
                }
                Err(peer::PeerAcceptError::Unauthorized(peer_id)) => {
                    yield PeerListenEvent::Session(peer::PeerEvent::Unauthorized { peer_id });
                }
                Err(peer::PeerAcceptError::Failed(error)) => {
                    yield PeerListenEvent::Failed(error);
                    return;
                }
            }
        }
    };
    Task::run(events, move |event| {
        Message::PeerListenEvent(generation, event)
    })
    .abortable()
}

fn peer_connect_task(
    generation: u64,
    expected_peer: iroh::EndpointId,
    address: Option<std::net::SocketAddr>,
    relay: Option<peer::ParticipantRelay>,
    request_id: u64,
    first_text: String,
) -> (Task<Message>, Handle) {
    let events = async_stream::stream! {
        let local_identity = match load_peer_secret_key_task().await {
            Ok(identity) => identity,
            Err(error) => { yield PeerListenEvent::Failed(error); return; }
        };
        match peer::connect_peer_with_relay(local_identity, expected_peer, address, relay).await {
            Ok(session) => {
                let (commands, command_rx) = tokio::sync::mpsc::channel(32);
                if let Err(error) = commands.send(peer::PeerCommand::Send { request_id, text: first_text }).await {
                    yield PeerListenEvent::Failed(format!("could not queue initial message: {error}"));
                    return;
                }
                yield PeerListenEvent::SessionCommands(commands);
                let mut events = Box::pin(session.run(command_rx));
                while let Some(event) = events.next().await {
                    let disconnected = matches!(event, peer::PeerEvent::Disconnected { .. });
                    yield PeerListenEvent::Session(event);
                    if disconnected { break; }
                }
            }
            Err(error) => yield PeerListenEvent::Failed(error),
        }
    };
    Task::run(events, move |event| {
        Message::PeerListenEvent(generation, event)
    })
    .abortable()
}

fn apply_peer_event(state: &mut Slouching, event: peer::PeerEvent) {
    match event {
        peer::PeerEvent::Connected { .. } => {
            state.peer_listen_status = PeerListenStatus::Connected;
            if matches!(state.peer_send_status, PeerSendStatus::Connecting) {
                state.peer_send_status = PeerSendStatus::Idle;
            }
        }
        peer::PeerEvent::Received { sequence, text } => {
            state.peer_transcript.push(PeerTranscriptEntry {
                direction: PeerMessageDirection::Received,
                text,
                persisted: false,
                sequence: None,
                transport_id: Some(sequence),
            });
            if let Some(commands) = state.peer_session_commands.as_ref() {
                let _ = commands.try_send(peer::PeerCommand::AcceptInbound { sequence });
            }
        }
        peer::PeerEvent::Acknowledged { request_id, text } => {
            if state.peer_pending_sends.remove(&request_id).is_some() {
                let draft_matches_sent_text = state.peer_draft.trim() == text;
                state.peer_transcript.push(PeerTranscriptEntry {
                    direction: PeerMessageDirection::Sent,
                    text,
                    persisted: false,
                    sequence: None,
                    transport_id: Some(request_id),
                });
                if draft_matches_sent_text {
                    state.peer_draft.clear();
                }
            }
            state.peer_send_status = if state.peer_pending_sends.is_empty() {
                PeerSendStatus::Sent
            } else {
                PeerSendStatus::AwaitingAck
            };
        }
        peer::PeerEvent::Rejected { request_id, reason } => {
            state.peer_pending_sends.remove(&request_id);
            state.peer_send_status = PeerSendStatus::Failed(reason);
        }
        peer::PeerEvent::DeliveryUnknown { request_id, text } => {
            state.peer_pending_sends.remove(&request_id);
            state.peer_send_status =
                PeerSendStatus::Failed(format!("Entrega não confirmada: {text}"));
        }
        peer::PeerEvent::MlsEventReceived { .. } => {}
        peer::PeerEvent::MlsCommitReceived { .. } => {}
        peer::PeerEvent::MlsProposalReceived { .. } => {}
        peer::PeerEvent::MlsKeyPackageReceived { .. } => {}
        peer::PeerEvent::MlsWelcomeReceived { .. } => {}
        peer::PeerEvent::DelegatedMlsCopyReceived { .. }
        | peer::PeerEvent::DelegatedMlsCopiesRequested { .. } => {}
        peer::PeerEvent::MlsCommitRequested { .. } => {}
        peer::PeerEvent::MlsEventAcknowledged { request_id } => {
            state.peer_send_status = PeerSendStatus::Failed(format!(
                "ACK do evento MLS {request_id} não está conectado ao estado de entrega."
            ));
        }
        peer::PeerEvent::MlsEventRejected { request_id, reason } => {
            state.mls_pending_events.remove(&request_id);
            state.mls_status = format!("Evento MLS {request_id} continua no outbox: {reason}");
        }
        peer::PeerEvent::MlsEventDeliveryUnknown { request_id } => {
            state.peer_send_status = PeerSendStatus::Failed(format!(
                "Entrega do evento MLS {request_id} não confirmada."
            ));
        }
        peer::PeerEvent::MlsCommitAcknowledged { .. }
        | peer::PeerEvent::MlsCommitRejected { .. }
        | peer::PeerEvent::MlsCommitDeliveryUnknown { .. }
        | peer::PeerEvent::MlsProposalAcknowledged { .. }
        | peer::PeerEvent::MlsProposalRejected { .. }
        | peer::PeerEvent::MlsProposalDeliveryUnknown { .. }
        | peer::PeerEvent::MlsKeyPackageAcknowledged { .. }
        | peer::PeerEvent::MlsKeyPackageRejected { .. }
        | peer::PeerEvent::MlsKeyPackageDeliveryUnknown { .. }
        | peer::PeerEvent::MlsWelcomeAcknowledged { .. }
        | peer::PeerEvent::MlsWelcomeRejected { .. }
        | peer::PeerEvent::MlsWelcomeDeliveryUnknown { .. }
        | peer::PeerEvent::DelegatedMlsCopyAcknowledged { .. }
        | peer::PeerEvent::DelegatedMlsCopyRejected { .. }
        | peer::PeerEvent::DelegatedMlsCopyDeliveryUnknown { .. } => {}
        peer::PeerEvent::Unauthorized { .. } => {
            state.peer_listen_status = PeerListenStatus::Unauthorized(
                "peer não corresponde à chave pública fixada".to_owned(),
            );
        }
        peer::PeerEvent::Disconnected { reason } => {
            state.peer_listen_status = PeerListenStatus::Disconnected(reason);
            state.peer_session_commands = None;
            state.peer_listener_handle = None;
            state.active_peer_device = None;
            if !state.peer_pending_sends.is_empty() {
                state.peer_pending_sends.clear();
                state.peer_send_status = PeerSendStatus::Failed(
                    "Conexão encerrada antes da confirmação; entrega desconhecida.".to_owned(),
                );
            }
        }
    }
}

fn active_peer_is_pinned(state: &Slouching) -> bool {
    let Ok(peer) = parse_peer_id(&state.peer_public_key) else {
        return false;
    };
    state.active_peer_device == Some(*peer.as_bytes())
}

async fn load_peer_secret_key_task() -> Result<iroh::SecretKey, String> {
    tokio::task::spawn_blocking(storage::load_device_peer_secret_key)
        .await
        .map_err(|error| format!("device identity task failed: {error}"))?
}

fn view(state: &Slouching) -> Element<'_, Message> {
    ui::view(state)
}

fn request_peer_history(state: &mut Slouching) -> Task<Message> {
    let peer_key = state.peer_public_key.clone();
    if peer_key.is_empty()
        || state.peer_history_loaded_for.as_deref() == Some(peer_key.as_str())
        || !matches!(state.identity_status, IdentityStatus::Ready(_))
    {
        return Task::none();
    }
    let Ok(peer_id) = parse_peer_id(&peer_key) else {
        return Task::none();
    };
    if matches!(state.identity_status, IdentityStatus::Ready(local) if peer_is_local(&peer_id, &local))
    {
        return Task::none();
    }
    state.peer_history_loaded_for = Some(peer_key.clone());
    state.peer_history_generation = state.peer_history_generation.saturating_add(1);
    let generation = state.peer_history_generation;
    let peer_device = *peer_id.as_bytes();
    Task::perform(load_direct_history_task(peer_device), move |result| {
        Message::PeerHistoryLoaded(generation, peer_key, result)
    })
}

fn capture_after(delay: Duration) -> Task<Message> {
    Task::perform(
        async move {
            tokio::time::sleep(delay).await;
        },
        |_| Message::Capture,
    )
}

fn main() -> iced::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg == "--lan-listen" || arg == "--lan-send")
    {
        if let Err(error) = run_lan_command(&args) {
            eprintln!("direct peer error: {error}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let size = std::env::var("SLOUCHING_WINDOW_SIZE")
        .ok()
        .and_then(|s| {
            s.split_once('x')
                .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        })
        .unwrap_or((1100.0, 720.0));
    let mut window = iced::window::Settings {
        size: size.into(),
        min_size: Some((800.0, 560.0).into()),
        position: iced::window::Position::Centered,
        ..Default::default()
    };
    #[cfg(target_os = "linux")]
    {
        window.platform_specific.application_id = "com.slouching.desktop".into();
    }
    iced::application(boot, update, view)
        .title("slouching · native client")
        .theme(Theme::Dark)
        .default_font(ui::MONO)
        .font(include_bytes!("../assets/fonts/bricolagegrotesque.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/jetbrainsmono.ttf").as_slice())
        .window(window)
        .run()
}

fn run_lan_command(args: &[String]) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start peer runtime: {error}"))?;
    match args.first().map(String::as_str) {
        Some("--lan-listen") if args.len() == 4 && args[2] == "--expect-peer" => {
            let port = args[1]
                .parse::<u16>()
                .map_err(|error| format!("invalid listen port: {error}"))?;
            let expected_peer = parse_peer_id(&args[3])?;
            let local_identity = storage::load_device_peer_secret_key()?;
            let listener = runtime.block_on(peer::bind_listener(
                local_identity,
                std::net::SocketAddr::from(([0, 0, 0, 0], port)),
                expected_peer,
            ))?;
            println!("Device identity: {}", hex_encode_key(listener.id().as_bytes()));
            println!("Listening on 0.0.0.0:{port} (direct UDP peer transport)");
            for address in listener
                .direct_addresses()
                .into_iter()
                .filter(|address| !address.ip().is_unspecified())
            {
                println!("Direct endpoint address: {address}");
            }
            std::io::Write::flush(&mut std::io::stdout())
                .map_err(|error| format!("could not flush listener status: {error}"))?;
            let text = runtime.block_on(listener.receive_once())?;
            println!("Pinned peer text: {text}");
            Ok(())
        }
        Some("--lan-send")
            if args.len() == 6 && args[2] == "--expect-peer" && args[4] == "--text" =>
        {
            let address = args[1]
                .parse::<std::net::SocketAddr>()
                .map_err(|error| format!("invalid peer socket address: {error}"))?;
            let expected_peer = parse_peer_id(&args[3])?;
            let local_identity = storage::load_device_peer_secret_key()?;
            println!(
                "Device identity: {}",
                hex_encode_key(local_identity.public().as_bytes())
            );
            let acknowledgement = runtime.block_on(peer::send_once(
                local_identity,
                expected_peer,
                address,
                &args[5],
            ))?;
            println!("Peer acknowledgement: {acknowledgement}");
            Ok(())
        }
        _ => Err("usage: --lan-listen <port> --expect-peer <device-public-key-hex> | --lan-send <ip:port> --expect-peer <device-public-key-hex> --text <text>".to_owned()),
    }
}

fn validate_peer_relay_config(config: &storage::PeerRelayConfig) -> Result<(), String> {
    if config.url.is_empty() {
        return if config.token.is_empty() {
            Ok(())
        } else {
            Err("remova o token ou informe a URL do relay do grupo".to_owned())
        };
    }
    let relay_url = config
        .url
        .parse::<iroh::RelayUrl>()
        .map_err(|error| format!("URL do relay inválida: {error}"))?;
    let local_http = relay_url.scheme() == "http"
        && relay_url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    if relay_url.scheme() != "https" && !local_http {
        return Err("relay remoto exige HTTPS; HTTP só é permitido em localhost".to_owned());
    }
    if config.token.len() < 16 {
        return Err("use um token compartilhado com pelo menos 16 caracteres".to_owned());
    }
    Ok(())
}

fn peer_relay_from_config(
    config: &storage::PeerRelayConfig,
) -> Result<Option<peer::ParticipantRelay>, String> {
    validate_peer_relay_config(config)?;
    if config.url.is_empty() {
        return Ok(None);
    }
    let url = config
        .url
        .parse::<iroh::RelayUrl>()
        .map_err(|error| format!("URL do relay inválida: {error}"))?;
    Ok(Some(peer::ParticipantRelay {
        url,
        access_token: config.token.clone(),
    }))
}

fn peer_route_socket(
    route: &storage::StoredPeerRoute,
) -> Result<Option<std::net::SocketAddr>, String> {
    if route.relay_only {
        return Ok(None);
    }
    let address = route
        .address
        .parse::<std::net::SocketAddr>()
        .map_err(|_| "saved peer route is not an IP address and UDP port".to_owned())?;
    if address.ip().is_unspecified() || address.port() == 0 {
        return Err("saved peer route must use a reachable IP and nonzero port".to_owned());
    }
    Ok(Some(address))
}

fn parse_peer_id(value: &str) -> Result<iroh::EndpointId, String> {
    let bytes = hex_decode_key(value)?;
    iroh::EndpointId::from_bytes(&bytes)
        .map_err(|error| format!("invalid peer identity key: {error}"))
}

fn peer_is_local(peer_id: &iroh::EndpointId, local_public_key: &[u8; 32]) -> bool {
    peer_id.as_bytes() == local_public_key
}

fn hex_decode_key(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("device public key must be exactly 64 hexadecimal characters".to_owned());
    }
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| "device public key must be hexadecimal".to_owned())?;
    }
    Ok(key)
}

fn hex_encode_key(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_relay_requires_tls_and_a_shared_token() {
        let valid = storage::PeerRelayConfig {
            url: "https://relay.crew.example".to_owned(),
            token: "crew-shared-token-0123456789".to_owned(),
        };
        assert!(validate_peer_relay_config(&valid).is_ok());
        assert!(peer_relay_from_config(&valid).unwrap().is_some());

        let no_token = storage::PeerRelayConfig {
            token: "short".to_owned(),
            ..valid.clone()
        };
        assert!(validate_peer_relay_config(&no_token).is_err());

        let insecure_remote = storage::PeerRelayConfig {
            url: "http://relay.crew.example".to_owned(),
            ..valid
        };
        assert!(validate_peer_relay_config(&insecure_remote).is_err());

        let local_development = storage::PeerRelayConfig {
            url: "http://127.0.0.1:3340".to_owned(),
            token: "local-development-token-0123456789".to_owned(),
        };
        assert!(validate_peer_relay_config(&local_development).is_ok());
    }

    #[test]
    fn saved_relay_routes_do_not_require_a_direct_socket() {
        let direct = storage::StoredPeerRoute {
            device_public_key: [0x51; 32],
            address: "192.168.1.42:45873".to_owned(),
            relay_only: false,
        };
        assert_eq!(
            peer_route_socket(&direct).unwrap(),
            Some("192.168.1.42:45873".parse().unwrap())
        );

        let relay_only = storage::StoredPeerRoute {
            device_public_key: [0x52; 32],
            address: "via group relay".to_owned(),
            relay_only: true,
        };
        assert_eq!(peer_route_socket(&relay_only).unwrap(), None);
    }

    #[test]
    fn parses_only_the_expected_predecessor_from_order_errors() {
        assert_eq!(
            missing_predecessor_from_error(
                "MLS Commit is out of order: expected predecessor epoch 4, received 7"
            ),
            Some(4)
        );
        assert_eq!(
            missing_predecessor_from_error(
                "MLS Commit is out of order: expected predecessor epoch x, received 7"
            ),
            None
        );
        assert_eq!(missing_predecessor_from_error("invalid Commit"), None);
    }

    #[test]
    fn mls_artifact_hex_encoding_round_trips_and_rejects_malformed_input() {
        let bytes = [0, 1, 0x7f, 0x80, 0xfe, 0xff];
        let encoded = hex_encode_bytes(&bytes);
        assert_eq!(encoded, "00017f80feff");
        assert_eq!(hex_decode_bytes(&encoded).unwrap(), bytes);
        assert_eq!(hex_decode_bytes("A0b1").unwrap(), [0xa0, 0xb1]);
        assert!(hex_decode_bytes("abc").is_err());
        assert!(hex_decode_bytes("0x").is_err());
        assert!(hex_decode_bytes(&"00".repeat(128 * 1024 + 1)).is_err());
    }

    #[test]
    fn detects_when_the_peer_pin_is_the_local_device_key() {
        let local = iroh::SecretKey::from_bytes(&[0x41; 32]).public();
        let remote = iroh::SecretKey::from_bytes(&[0x42; 32]).public();
        assert!(peer_is_local(&local, local.as_bytes()));
        assert!(!peer_is_local(&remote, local.as_bytes()));
    }

    #[test]
    fn accepts_only_elixir_status_contract_v1() {
        let valid = r#"{"contract_version":1,"backend":"elixir_scaffold","identity":"not_implemented","messaging":"not_implemented","calls":"not_implemented","peer_connections":0}"#;
        assert!(parse_status(valid).is_ok());
        assert!(matches!(
            parse_status(&valid.replace("\"elixir_scaffold\"", "\"rust_scaffold\"")),
            Err(FetchError::ContractMismatch(_))
        ));
        assert!(matches!(
            parse_status(&valid.replace("\"contract_version\":1", "\"contract_version\":2")),
            Err(FetchError::ContractMismatch(_))
        ));
        assert!(matches!(
            parse_status(&valid.replace("\"not_implemented\"", "\"ready\"")),
            Err(FetchError::ContractMismatch(_))
        ));
    }

    #[test]
    fn validates_binary_server_hello_and_version_error() {
        let hello = protocol::ServerFrame {
            payload: Some(protocol::server_frame::Payload::Hello(
                protocol::ServerHello {
                    protocol_version: CONTRACT_VERSION,
                    server_role: "elixir".into(),
                    identity_available: false,
                    messaging_available: false,
                    calls_available: false,
                },
            )),
        };
        assert!(decode_server_hello(&hello.encode_to_vec()).is_ok());
        let mismatch = protocol::ServerFrame {
            payload: Some(protocol::server_frame::Payload::VersionError(
                protocol::VersionError {
                    supported_version: CONTRACT_VERSION,
                },
            )),
        };
        assert!(matches!(
            decode_server_hello(&mismatch.encode_to_vec()),
            Err(HandshakeError::Protocol(_))
        ));
        assert!(matches!(
            decode_server_hello(b"not protobuf"),
            Err(HandshakeError::Protocol(_))
        ));
    }

    #[test]
    fn peer_transcript_records_inbound_before_ack_and_outbound_only_after_ack() {
        let mut state = Slouching::default();
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        state.peer_session_commands = Some(commands);
        state.peer_pending_sends.insert(7, "outgoing".to_owned());
        apply_peer_event(
            &mut state,
            peer::PeerEvent::Received {
                sequence: 3,
                text: "incoming".to_owned(),
            },
        );
        assert!(matches!(
            state.peer_transcript.as_slice(),
            [PeerTranscriptEntry { direction: PeerMessageDirection::Received, text, .. }] if text == "incoming"
        ));
        assert!(matches!(
            command_rx.try_recv(),
            Ok(peer::PeerCommand::AcceptInbound { sequence: 3 })
        ));

        apply_peer_event(
            &mut state,
            peer::PeerEvent::Acknowledged {
                request_id: 7,
                text: "outgoing".to_owned(),
            },
        );
        assert!(matches!(state.peer_send_status, PeerSendStatus::Sent));
        assert!(matches!(
            state.peer_transcript.as_slice(),
            [
                PeerTranscriptEntry { direction: PeerMessageDirection::Received, text: incoming, .. },
                PeerTranscriptEntry { direction: PeerMessageDirection::Sent, text: outgoing, .. }
            ] if incoming == "incoming" && outgoing == "outgoing"
        ));

        state.peer_pending_sends.insert(8, "unknown".to_owned());
        apply_peer_event(
            &mut state,
            peer::PeerEvent::DeliveryUnknown {
                request_id: 8,
                text: "unknown".to_owned(),
            },
        );
        assert_eq!(state.peer_transcript.len(), 2);
        assert!(matches!(state.peer_send_status, PeerSendStatus::Failed(_)));
        state.peer_listener_generation = 2;
        let _ = update(
            &mut state,
            Message::PeerListenEvent(
                1,
                PeerListenEvent::Session(peer::PeerEvent::Received {
                    sequence: 4,
                    text: "stale".to_owned(),
                }),
            ),
        );
        assert_eq!(state.peer_transcript.len(), 2);
        let _ = update(
            &mut state,
            Message::PeerListenEvent(
                2,
                PeerListenEvent::Session(peer::PeerEvent::Received {
                    sequence: 5,
                    text: "current".to_owned(),
                }),
            ),
        );
        assert_eq!(state.peer_transcript.len(), 2);
    }

    #[test]
    fn peer_send_and_listen_require_a_local_device_identity() {
        let mut state = Slouching::default();
        let _ = update(&mut state, Message::StartPeerListener);
        let _ = update(&mut state, Message::SendPeerText);
        assert!(matches!(
            state.peer_listen_status,
            PeerListenStatus::Failed(_)
        ));
        assert!(matches!(state.peer_send_status, PeerSendStatus::Failed(_)));
        assert!(state.peer_listener_handle.is_none());
        assert!(state.peer_transcript.is_empty());
    }
}
