use futures_util::{SinkExt, StreamExt};
use iced::{Element, Task, Theme, task::Handle};

mod storage;
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
    Incoming,
    Verify,
    #[default]
    Home,
    Call,
}

impl Screen {
    const ALL: [Self; 11] = [
        Self::Components,
        Self::Familiar,
        Self::Settings,
        Self::Lobby,
        Self::Connecting,
        Self::Share,
        Self::Chat,
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
            Self::Chat => "Conversa pessoal",
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
            Ok(Some(public_key)) => state.identity_status = IdentityStatus::Ready(public_key),
            Ok(None) => state.identity_status = IdentityStatus::Missing,
            Err(_) => state.identity_status = IdentityStatus::Failed,
        },
        Message::CreateIdentity => {
            state.identity_status = IdentityStatus::Creating;
            return Task::perform(create_identity_task(), Message::IdentityCreated);
        }
        Message::IdentityCreated(result) => match result {
            Ok(public_key) => state.identity_status = IdentityStatus::Ready(public_key),
            Err(_) => {
                state.identity_status = IdentityStatus::Failed;
                state.note = Some("Não foi possível criar a chave no cofre do sistema.");
            }
        },
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

fn view(state: &Slouching) -> Element<'_, Message> {
    ui::view(state)
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
        .title("slouching · native design preview")
        .theme(Theme::Dark)
        .default_font(ui::MONO)
        .font(include_bytes!("../assets/fonts/bricolagegrotesque.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/jetbrainsmono.ttf").as_slice())
        .window(window)
        .run()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
