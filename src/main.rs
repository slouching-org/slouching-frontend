use futures_util::{SinkExt, StreamExt};
use iced::{Element, Task, Theme, task::Handle};

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
            Self::Chat => "Texto direto · LAN",
            Self::Mls => "Grupo MLS · local",
            Self::Incoming => "Chamada recebida",
            Self::Verify => "Verificar selo",
            Self::Home => "Início",
            Self::Call => "Chamada em grupo",
        }
    }
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
    peer_public_key: String,
    peer_listen_port: String,
    peer_address: String,
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
    mls_welcome: String,
    mls_ratchet_tree: String,
    mls_status: String,
    mls_message_draft: String,
    mls_history: Vec<storage::StoredMlsMessage>,
    mls_history_group: Option<Vec<u8>>,
    mls_pending_commits: Vec<storage::StoredMlsCommit>,
    mls_pending_events: std::collections::HashMap<u64, [u8; 16]>,
    mls_sending_commits: std::collections::HashMap<u64, [u8; 16]>,
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
            peer_public_key: String::new(),
            peer_listen_port: "45873".to_owned(),
            peer_address: String::new(),
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
            mls_welcome: String::new(),
            mls_ratchet_tree: String::new(),
            mls_status: "Crie uma identidade do dispositivo para começar.".to_owned(),
            mls_message_draft: String::new(),
            mls_history: Vec::new(),
            mls_history_group: None,
            mls_pending_commits: Vec::new(),
            mls_pending_events: std::collections::HashMap::new(),
            mls_sending_commits: std::collections::HashMap::new(),
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
    CopyDeviceKey,
    CopyPeerListenAddress(String),
    PeerPublicKeyChanged(String),
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
    PeerDraftChanged(String),
    StartPeerListener,
    StopPeerListener,
    PeerListenEvent(u64, PeerListenEvent),
    PeerInboundStored(u64, String, Result<storage::StoredDirectMessage, String>),
    PeerOutboundStored(u64, String, Result<storage::StoredDirectMessage, String>),
    SendPeerText,
    PeerCommandSent(Result<(), String>),
    MlsGroupIdChanged(String),
    MlsKeyPackageChanged(String),
    MlsInviteKeyPackageChanged(String),
    MlsCommitChanged(String),
    MlsReceivedCommitChanged(String),
    ApplyMlsCommit,
    MlsCommitProcessed(Result<storage::ProcessedMlsCommit, String>),
    DistributeMlsCommit,
    MlsCommitsReadyToSend(Vec<u8>, Result<Vec<storage::StoredMlsCommit>, String>),
    MlsCommitPeerCommandSent(u64, Result<(), String>),
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
    MlsCommitsLoaded(Vec<u8>, Result<Vec<storage::StoredMlsCommit>, String>),
    RetryQueuedMlsEvents,
    MlsOutboxLoaded(Vec<u8>, Result<Vec<storage::StoredOutboundEvent>, String>),
    SendMlsApplication,
    MlsApplicationCreated(Result<storage::PreparedMlsApplicationEvent, String>),
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
                state.peer_transcript.clear();
                state.peer_history_loaded_for = None;
                state.peer_history_generation = state.peer_history_generation.saturating_add(1);
                state.peer_history_clear_confirmation = false;
            }
            return request_peer_history(state);
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
        Message::PeerDraftChanged(value) => state.peer_draft = value,
        Message::StartPeerListener => {
            if state.peer_listener_handle.is_some() {
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
            let expected_peer = match parse_peer_id(&state.peer_public_key) {
                Ok(peer) => peer,
                Err(error) => {
                    state.peer_listen_status = PeerListenStatus::Failed(error);
                    return Task::none();
                }
            };
            if let IdentityStatus::Ready(local_public_key) = state.identity_status
                && peer_is_local(&expected_peer, &local_public_key)
            {
                state.peer_listen_status = PeerListenStatus::Failed(
                    "A chave do peer é a sua própria chave. Cole a chave do outro dispositivo."
                        .to_owned(),
                );
                return Task::none();
            }
            state.peer_listener_generation = state.peer_listener_generation.saturating_add(1);
            let generation = state.peer_listener_generation;
            state.peer_listen_status = PeerListenStatus::Starting { port };
            let (task, handle) = peer_listener_task(generation, port, expected_peer);
            state.peer_listener_handle = Some(handle);
            state.peer_session_commands = None;
            return task;
        }
        Message::StopPeerListener => {
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
                }
                PeerListenEvent::SessionCommands(commands) => {
                    state.peer_session_commands = Some(commands);
                }
                PeerListenEvent::Session(event) => match event {
                    peer::PeerEvent::Received { sequence, text } => {
                        let Ok(peer_id) = parse_peer_id(&state.peer_public_key) else {
                            state.peer_send_status = PeerSendStatus::Failed(
                                "Chave do peer inválida; mensagem recebida sem confirmação."
                                    .to_owned(),
                            );
                            return Task::none();
                        };
                        let peer_device = *peer_id.as_bytes();
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
                        let Ok(peer_id) = parse_peer_id(&state.peer_public_key) else {
                            state.peer_pending_sends.remove(&request_id);
                            state.peer_send_status = PeerSendStatus::Failed(
                                "Peer confirmou a entrega, mas a chave do peer está inválida."
                                    .to_owned(),
                            );
                            return Task::none();
                        };
                        let peer_device = *peer_id.as_bytes();
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
                    peer::PeerEvent::MlsCommitReceived { sequence, commit } => {
                        return Task::perform(
                            process_mls_commit_envelope_task(commit.clone()),
                            move |result| {
                                Message::MlsCommitInboundProcessed(sequence, commit, result)
                            },
                        );
                    }
                    peer::PeerEvent::MlsCommitAcknowledged { request_id } => {
                        if state.mls_sending_commits.remove(&request_id).is_some() {
                            state.mls_status = format!(
                                "Membro autenticou e aplicou o Commit {request_id}; epoch atualizado."
                            );
                        } else {
                            state.mls_status =
                                "ACK de Commit desconhecido; sessão encerrada.".to_owned();
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::Disconnect);
                            }
                        }
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
                        let Some(event_id) = state.mls_pending_events.get(&request_id).copied()
                        else {
                            state.mls_status =
                                "ACK de um evento MLS desconhecido; sessão encerrada.".to_owned();
                            if let Some(commands) = state.peer_session_commands.as_ref() {
                                let _ = commands.try_send(peer::PeerCommand::Disconnect);
                            }
                            return Task::none();
                        };
                        return Task::perform(
                            update_mls_outbound_state_task(event_id),
                            move |result| Message::MlsOutboundHeld(request_id, event_id, result),
                        );
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
            let address = match state.peer_address.parse::<std::net::SocketAddr>() {
                Ok(address) if !address.ip().is_unspecified() && address.port() != 0 => address,
                _ => {
                    state.peer_send_status = PeerSendStatus::Failed("Informe o IP LAN e a porta UDP do outro dispositivo, por exemplo 192.168.1.20:45873.".to_owned());
                    return Task::none();
                }
            };
            state.peer_send_status = PeerSendStatus::Connecting;
            let generation = state.peer_listener_generation.saturating_add(1);
            state.peer_listener_generation = generation;
            let request_id = state.peer_next_request_id;
            state.peer_next_request_id = state.peer_next_request_id.saturating_add(1);
            state.peer_pending_sends.insert(request_id, text.clone());
            let (task, handle) =
                peer_connect_task(generation, expected_peer, address, request_id, text);
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
                return load_mls_history(state, group.group_id);
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
        Message::AdmitMlsMember => {
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
            return Task::perform(
                admit_mls_member_task(group_id, package),
                Message::MlsMemberAdded,
            );
        }
        Message::MlsMemberAdded(result) => match result {
            Ok(admission) => {
                state.mls_commit = hex_encode_bytes(&admission.commit);
                state.mls_welcome = hex_encode_bytes(&admission.welcome);
                state.mls_ratchet_tree = hex_encode_bytes(&admission.ratchet_tree);
                state.mls_status = format!(
                    "Commit {} salvo no outbox local; envie também aos membros MLS existentes. Envie Welcome e ratchet tree ao convidado (epoch {}).",
                    hex_encode_bytes(&admission.commit_event_id[..4]),
                    admission.epoch
                );
                return load_mls_history(state, admission.group_id);
            }
            Err(error) => state.mls_status = format!("Falha ao admitir membro: {error}"),
        },
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
            return Task::perform(join_mls_group_task(welcome, tree), Message::MlsGroupJoined);
        }
        Message::MlsGroupJoined(result) => match result {
            Ok(group) => {
                state.mls_group_id = hex_encode_bytes(&group.group_id);
                state.mls_status = format!(
                    "Grupo ingressado no epoch {}. O grupo e as chaves estão no SQLCipher local.",
                    group.epoch
                );
                return load_mls_history(state, group.group_id);
            }
            Err(error) => state.mls_status = format!("Falha ao ingressar no grupo: {error}"),
        },
        Message::CopyMlsValue(value) => return iced::clipboard::write(value),
        Message::MlsMessageDraftChanged(value) => state.mls_message_draft = value,
        Message::MlsCommitChanged(value) => state.mls_commit = value,
        Message::MlsReceivedCommitChanged(value) => state.mls_received_commit = value,
        Message::DistributeMlsCommit => {
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
        Message::MlsCommitInboundProcessed(sequence, envelope, result) => match result {
            Ok(processed) => {
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
                };
                return load_mls_history(state, envelope.group_id);
            }
            Err(error) => {
                state.mls_status =
                    format!("Commit recebido foi rejeitado; grupo local intacto: {error}");
                if let Some(commands) = state.peer_session_commands.as_ref() {
                    let _ = commands.try_send(peer::PeerCommand::RejectInbound {
                        sequence,
                        reason: error,
                    });
                }
            }
        },
        Message::ApplyMlsCommit => {
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
            };
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
            state.mls_status =
                "Consultando outbox local para reenviar eventos pendentes…".to_owned();
            return Task::perform(load_mls_outbox_task(), move |result| {
                Message::MlsOutboxLoaded(group_id, result)
            });
        }
        Message::MlsOutboxLoaded(group_id, result) => {
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
                    let pending_event_ids: std::collections::HashSet<_> =
                        state.mls_pending_events.values().copied().collect();
                    for stored in events
                        .into_iter()
                        .filter(|stored| {
                            stored.state == storage::OutboundDeliveryState::Queued
                                && stored.event.group_id == group_id
                                && !pending_event_ids.contains(&stored.event.event_id)
                        })
                        .take(available_slots)
                    {
                        let request_id = state.mls_next_request_id;
                        state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
                        state
                            .mls_pending_events
                            .insert(request_id, stored.event.event_id);
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
                    "Conecte ao dispositivo do grupo na tela Texto direto · LAN antes de enviar."
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
                let request_id = state.mls_next_request_id;
                state.mls_next_request_id = state.mls_next_request_id.saturating_add(1);
                state
                    .mls_pending_events
                    .insert(request_id, prepared.event.event_id);
                let event = peer::MlsEventEnvelope {
                    event_id: prepared.event.event_id,
                    author_device: prepared.event.author_device,
                    group_id: prepared.event.group_id.clone(),
                    epoch: prepared.event.epoch,
                    checkpoint: prepared.event.checkpoint,
                    expires_at_unix: prepared.event.expires_at_unix,
                    ciphertext: prepared.event.ciphertext,
                };
                state.mls_message_draft.clear();
                state.mls_status =
                    "Evento cifrado e salvo localmente; enviando pela sessão QUIC…".to_owned();
                let Some(commands) = state.peer_session_commands.clone() else {
                    state.mls_pending_events.remove(&request_id);
                    state.mls_status =
                        "Evento salvo no outbox local. Conecte ao peer e reenvie pendentes."
                            .to_owned();
                    return load_mls_history(state, event.group_id);
                };
                let group_id = event.group_id.clone();
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
                    Task::perform(load_mls_history_task(group_id.clone()), move |result| {
                        Message::MlsHistoryLoaded(group_id, result)
                    }),
                ]);
            }
            Err(error) => {
                state.mls_status = format!("Falha ao cifrar/salvar mensagem MLS: {error}")
            }
        },
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
            Task::perform(load_identity_task(), Message::IdentityLoaded),
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

async fn load_direct_history_task(
    peer_device: [u8; 32],
) -> Result<Vec<storage::StoredDirectMessage>, String> {
    tokio::task::spawn_blocking(move || storage::list_direct_messages(peer_device, 200))
        .await
        .map_err(|error| format!("direct history task failed: {error}"))?
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

async fn join_mls_group_task(
    welcome: Vec<u8>,
    tree: Vec<u8>,
) -> Result<storage::JoinedMlsGroup, String> {
    tokio::task::spawn_blocking(move || storage::join_mls_group_from_welcome(&welcome, &tree))
        .await
        .map_err(|error| format!("MLS Welcome task failed: {error}"))?
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
    let history_group_id = group_id.clone();
    Task::batch([
        Task::perform(load_mls_history_task(group_id.clone()), move |result| {
            Message::MlsHistoryLoaded(history_group_id, result)
        }),
        Task::perform(load_mls_commits_task(group_id.clone()), move |result| {
            Message::MlsCommitsLoaded(group_id, result)
        }),
    ])
}

async fn load_mls_history_task(
    group_id: Vec<u8>,
) -> Result<Vec<storage::StoredMlsMessage>, String> {
    tokio::task::spawn_blocking(move || storage::list_mls_messages(&group_id, 200))
        .await
        .map_err(|error| format!("MLS history task failed: {error}"))?
}

async fn load_mls_commits_task(group_id: Vec<u8>) -> Result<Vec<storage::StoredMlsCommit>, String> {
    tokio::task::spawn_blocking(move || storage::list_queued_mls_commits(&group_id, 100))
        .await
        .map_err(|error| format!("MLS Commit outbox task failed: {error}"))?
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

async fn load_mls_outbox_task() -> Result<Vec<storage::StoredOutboundEvent>, String> {
    tokio::task::spawn_blocking(|| storage::list_outbound_events(0, 500))
        .await
        .map_err(|error| format!("MLS outbox task failed: {error}"))?
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

async fn update_mls_outbound_state_task(event_id: [u8; 16]) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        storage::update_outbound_delivery_state(
            event_id,
            storage::OutboundDeliveryState::HeldByPeer,
        )
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

fn peer_listener_task(
    generation: u64,
    port: u16,
    expected_peer: iroh::EndpointId,
) -> (Task<Message>, Handle) {
    let events = async_stream::stream! {
        let local_identity = match load_peer_secret_key_task().await {
            Ok(identity) => identity,
            Err(error) => {
                yield PeerListenEvent::Failed(error);
                return;
            }
        };
        let listener = match peer::bind_listener(
            local_identity,
            std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            expected_peer,
        ).await {
            Ok(listener) => listener,
            Err(error) => {
                yield PeerListenEvent::Failed(error);
                return;
            }
        };
        let addresses = listener.direct_addresses();
        yield PeerListenEvent::Bound { addresses };
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(32);
        yield PeerListenEvent::SessionCommands(commands);
        loop {
            let accepted = tokio::select! {
                result = listener.accept_session() => Some(result),
                command = command_rx.recv() => {
                    if matches!(command, Some(peer::PeerCommand::Disconnect) | None) {
                        listener.close().await;
                        yield PeerListenEvent::Session(peer::PeerEvent::Disconnected { reason: "listener stopped".to_owned() });
                        return;
                    }
                    None
                }
            };
            let Some(accepted) = accepted else { continue; };
            match accepted {
                Ok(session) => {
                    let mut events = Box::pin(session.run(command_rx));
                    while let Some(event) = events.next().await {
                        let disconnected = matches!(event, peer::PeerEvent::Disconnected { .. });
                        yield PeerListenEvent::Session(event);
                        if disconnected { break; }
                    }
                    return;
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
    address: std::net::SocketAddr,
    request_id: u64,
    first_text: String,
) -> (Task<Message>, Handle) {
    let events = async_stream::stream! {
        let local_identity = match load_peer_secret_key_task().await {
            Ok(identity) => identity,
            Err(error) => { yield PeerListenEvent::Failed(error); return; }
        };
        match peer::connect_peer(local_identity, expected_peer, address).await {
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
        | peer::PeerEvent::MlsCommitDeliveryUnknown { .. } => {}
        peer::PeerEvent::Unauthorized { .. } => {
            state.peer_listen_status = PeerListenStatus::Unauthorized(
                "peer não corresponde à chave pública fixada".to_owned(),
            );
        }
        peer::PeerEvent::Disconnected { reason } => {
            state.peer_listen_status = PeerListenStatus::Disconnected(reason);
            state.peer_session_commands = None;
            state.peer_listener_handle = None;
            if !state.peer_pending_sends.is_empty() {
                state.peer_pending_sends.clear();
                state.peer_send_status = PeerSendStatus::Failed(
                    "Conexão encerrada antes da confirmação; entrega desconhecida.".to_owned(),
                );
            }
        }
    }
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
            eprintln!("LAN peer error: {error}");
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
            println!("Listening on 0.0.0.0:{port} (direct LAN only)");
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
