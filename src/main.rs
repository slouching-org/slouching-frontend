use futures_util::{SinkExt, StreamExt};
use iced::widget::{button, column, container, image, row, text, text_input};
use iced::{Color, Element, Fill, Length, Task, Theme, task::Handle};
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

#[derive(Debug, Clone, Copy, Default)]
enum Screen {
    #[default]
    Home,
    Familiar,
    Call,
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
            familiar: "Wizard",
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
        Message::Navigate(screen) => state.screen = screen,
        Message::InviteChanged(value) => state.invite = value,
        Message::NameChanged(value) => state.name = value,
        Message::ChooseFamiliar(value) => state.familiar = value,
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
    let (transport, handle) = transport_task(state.transport_generation);
    state.transport_handle = Some(handle);
    (
        state,
        Task::batch([
            Task::perform(fetch_backend_status(), Message::BackendFetched),
            transport,
        ]),
    )
}

fn view(state: &Slouching) -> Element<'_, Message> {
    let navigation = row![
        button("Home").on_press(Message::Navigate(Screen::Home)),
        button("Familiar").on_press(Message::Navigate(Screen::Familiar)),
        button("Call preview").on_press(Message::Navigate(Screen::Call)),
    ]
    .spacing(12);

    let page = match state.screen {
        Screen::Home => home(state),
        Screen::Familiar => familiar(state),
        Screen::Call => call(),
    };

    container(
        column![
            navigation,
            backend_status_view(&state.backend),
            transport_status_view(&state.transport),
            page,
        ]
        .spacing(20),
    )
    .padding(24)
    .width(Fill)
    .height(Fill)
    .into()
}

fn transport_status_view(transport: &TransportState) -> Element<'_, Message> {
    let label = match transport {
        TransportState::Connecting(attempt) => {
            format!("Local WebSocket transport: connecting (attempt {attempt})…")
        }
        TransportState::Disconnected {
            reason,
            retry_seconds,
        } => {
            format!("Local WebSocket transport disconnected: {reason} · retry in {retry_seconds} s")
        }
        TransportState::ProtocolError(reason) => format!("WebSocket protocol error: {reason}"),
        TransportState::Active { hello, heartbeats } => format!(
            "Local WebSocket transport active · protocol v{} · Pong acknowledgements: {} · identity: {} · messaging: {} · calls: {}",
            hello.protocol_version,
            heartbeats,
            availability_label(hello.identity_available),
            availability_label(hello.messaging_available),
            availability_label(hello.calls_available),
        ),
    };
    text(label).color(Color::from_rgb8(180, 140, 255)).into()
}

fn availability_label(available: bool) -> &'static str {
    if available {
        "available"
    } else {
        "unavailable"
    }
}

fn backend_status_view(backend: &BackendConnection) -> Element<'_, Message> {
    let status = match backend {
        BackendConnection::Connecting => "Connecting to local Elixir backend…".to_string(),
        BackendConnection::Unavailable(reason) => format!("Local backend unavailable: {reason}"),
        BackendConnection::ContractMismatch(reason) => {
            format!("Status contract mismatch: {reason}")
        }
        BackendConnection::Connected(snapshot) => format!(
            "Local Elixir backend responding · contract v{} · Identity: {} · Messaging: {} · Calls: {} · Peer connections: {}",
            snapshot.contract_version,
            capability_label(snapshot.identity),
            capability_label(snapshot.messaging),
            capability_label(snapshot.calls),
            snapshot.peer_connections
        ),
    };
    column![
        row![
            text(status).color(Color::from_rgb8(242, 223, 138)),
            button("Refresh backend").on_press(Message::RefreshBackend),
        ]
        .spacing(12),
        text("Local diagnostic only · no secure peer connection or chat is active")
            .size(13)
            .color(Color::from_rgb8(180, 140, 255)),
    ]
    .spacing(5)
    .into()
}

fn capability_label(capability: CapabilityStatus) -> &'static str {
    match capability {
        CapabilityStatus::NotImplemented => "not implemented",
    }
}

fn home(state: &Slouching) -> Element<'_, Message> {
    let logo = image(image::Handle::from_bytes(
        include_bytes!("../prototypes/web/brand/05-two-wizards-primary-logo.png").to_vec(),
    ))
    .width(Length::Fixed(80.0))
    .height(Length::Fixed(80.0));
    let scenery = image(image::Handle::from_bytes(
        include_bytes!("../prototypes/web/art/bg-home.jpg").to_vec(),
    ))
    .width(Length::Fill)
    .height(Length::Fixed(350.0));

    column![
        row![
            logo,
            text("slouching")
                .size(68)
                .color(Color::from_rgb8(242, 223, 138)),
        ]
        .spacing(16),
        text("P2P voice & video for you and your crew")
            .size(17)
            .color(Color::from_rgb8(236, 230, 255)),
        row![button("Join a call"), button("Create a call")].spacing(12),
        text_input("slouch:// invitation · preview only", &state.invite)
            .on_input(Message::InviteChanged),
        text("Call actions are unavailable in this scaffold.")
            .color(Color::from_rgb8(180, 140, 255)),
        scenery,
    ]
    .spacing(15)
    .into()
}

fn familiar(state: &Slouching) -> Element<'_, Message> {
    column![
        text("Who sits by the campfire?")
            .size(38)
            .color(Color::from_rgb8(242, 223, 138)),
        text("Choose a preview name and familiar. No cryptographic identity is created."),
        text_input("Your name", &state.name).on_input(Message::NameChanged),
        row![
            button("Wizard").on_press(Message::ChooseFamiliar("Wizard")),
            button("Frog").on_press(Message::ChooseFamiliar("Frog")),
            button("Orb").on_press(Message::ChooseFamiliar("Orb")),
        ]
        .spacing(12),
        text(format!("Selected familiar: {}", state.familiar)),
    ]
    .spacing(18)
    .into()
}

fn call() -> Element<'static, Message> {
    let art = image(image::Handle::from_bytes(
        include_bytes!("../prototypes/web/art/scene-orb.jpg").to_vec(),
    ))
    .width(Length::Fill)
    .height(Length::Fixed(390.0));

    column![
        text("THE MOSSY STUMP · CALL PREVIEW")
            .size(28)
            .color(Color::from_rgb8(242, 223, 138)),
        text("Illustrative art. No participant or video stream is connected.")
            .color(Color::from_rgb8(180, 140, 255)),
        art,
        row![
            button("Microphone"),
            button("Camera"),
            button("Share screen"),
            button("Leave preview").on_press(Message::Navigate(Screen::Home)),
        ]
        .spacing(12),
        text("Device controls are disabled in this preview.")
            .color(Color::from_rgb8(180, 140, 255)),
    ]
    .spacing(16)
    .into()
}

fn main() -> iced::Result {
    iced::application(boot, update, view)
        .theme(Theme::Dark)
        .window_size((1000.0, 800.0))
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
