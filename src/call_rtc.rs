//! WebRTC peer-connection lifecycle and SDP/ICE handling for direct calls.
//!
//! Signaling is carried by the pinned peer session. This module gathers host
//! ICE candidates into SDP for the initial offer/answer exchange and can apply
//! later trickled candidates. Media tracks are added by the call media layer.

use bytes::{Bytes, BytesMut};
use media::Sample;
use rtc::{
    media_stream::MediaStreamTrack,
    peer_connection::configuration::media_engine::MIME_TYPE_OPUS,
    rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
    },
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit, RTCDataChannelState},
    media_stream::{
        track_local::{TrackLocal, static_sample::TrackLocalStaticSample},
        track_remote::{TrackRemote, TrackRemoteEvent},
    },
    peer_connection::{
        MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
        RTCConfigurationBuilder, RTCIceGatheringState, RTCPeerConnectionState, Registry,
        register_default_interceptors,
    },
    runtime::{Runtime, TokioRuntime},
};

const ICE_GATHERING_TIMEOUT: Duration = Duration::from_secs(10);
const OPUS_PAYLOAD_TYPE: u8 = 111;
const OPUS_FRAME_DURATION: Duration = Duration::from_millis(20);
const CALL_DATA_CHANNEL: &str = "slouching-call-v1";

#[derive(Clone)]
struct CallEvents {
    gathering_complete: watch::Sender<bool>,
    connection_state: watch::Sender<String>,
    incoming_tracks: mpsc::UnboundedSender<Arc<dyn TrackRemote>>,
    incoming_data_channels: mpsc::UnboundedSender<Arc<dyn DataChannel>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for CallEvents {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.gathering_complete.send_replace(true);
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        self.connection_state.send_replace(format!("{state:?}"));
    }

    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        let _ = self.incoming_tracks.send(track);
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        let _ = self.incoming_data_channels.send(channel);
    }
}

struct CallAudioState {
    encoder: AsyncMutex<crate::call_audio::CallAudioEncoder>,
    decoder: AsyncMutex<crate::call_audio::CallAudioDecoderSet>,
    track: Arc<TrackLocalStaticSample>,
    ssrc: u32,
    input_device_id: String,
    microphone_muted: AtomicBool,
    sink: Arc<dyn crate::call_audio::AudioSink>,
}

#[derive(Clone)]
struct CallDataChannelContext {
    active_channel: Arc<AsyncMutex<Option<Arc<dyn DataChannel>>>>,
    screen_decoder: Arc<AsyncMutex<Option<crate::call_video::CallVideoDecoder>>>,
    chat_decoder: Arc<AsyncMutex<Option<crate::call_chat::CallChatReceiver>>>,
    remote_screen_frame: watch::Sender<Option<Arc<crate::call_video::DecodedVideoFrame>>>,
    screen_share_status: watch::Sender<String>,
    received_screen_frames: mpsc::UnboundedSender<Vec<u8>>,
    chat_messages: tokio::sync::broadcast::Sender<String>,
}

impl CallAudioState {
    async fn send_audio_frame(&self, pcm: &[f32]) -> Result<(), String> {
        if self.microphone_muted.load(Ordering::Acquire) {
            return Ok(());
        }
        let protected = self
            .encoder
            .lock()
            .await
            .encode_and_protect(pcm)
            .map_err(|error| error.to_string())?;
        let now = Instant::now();
        let sample = Sample {
            data: Bytes::from(protected),
            timestamp: now,
            duration: OPUS_FRAME_DURATION,
            ..Sample::new(now)
        };
        self.track
            .write_sample(self.ssrc, OPUS_PAYLOAD_TYPE, &sample, &[])
            .await
            .map_err(|error| error.to_string())
    }
}

/// Owns one WebRTC peer connection. Create exactly one instance per remote
/// member in a mesh call.
pub struct CallRtcSession {
    peer_connection: Box<dyn PeerConnection>,
    gathering_complete: watch::Receiver<bool>,
    connection_state: watch::Receiver<String>,
    audio_status: watch::Sender<String>,
    incoming_tracks: Mutex<Option<mpsc::UnboundedReceiver<Arc<dyn TrackRemote>>>>,
    incoming_data_channels: Mutex<Option<mpsc::UnboundedReceiver<Arc<dyn DataChannel>>>>,
    screen_data_channel: Arc<AsyncMutex<Option<Arc<dyn DataChannel>>>>,
    received_screen_frames: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
    received_screen_frames_tx: mpsc::UnboundedSender<Vec<u8>>,
    screen_video_encoder: AsyncMutex<Option<crate::call_video::CallVideoEncoder>>,
    screen_video_decoder: Arc<AsyncMutex<Option<crate::call_video::CallVideoDecoder>>>,
    screen_share_active: Arc<AtomicBool>,
    wayland_capture_stop: Arc<AtomicBool>,
    camera_capture_stop: Arc<AtomicBool>,
    screen_share_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    remote_screen_frame: watch::Sender<Option<Arc<crate::call_video::DecodedVideoFrame>>>,
    screen_share_status: watch::Sender<String>,
    call_chat_sender: AsyncMutex<Option<crate::call_chat::CallChatSender>>,
    call_chat_receiver: Arc<AsyncMutex<Option<crate::call_chat::CallChatReceiver>>>,
    call_chat_messages: tokio::sync::broadcast::Sender<String>,
    audio: Option<Arc<CallAudioState>>,
    audio_started: AtomicBool,
    audio_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    data_channel_created: AtomicBool,
}

impl CallRtcSession {
    pub async fn new() -> Result<Self, String> {
        let (gathering_tx, gathering_complete) = watch::channel(false);
        let (state_tx, connection_state) = watch::channel("New".to_owned());
        let (incoming_track_tx, incoming_tracks) = mpsc::unbounded_channel();
        let (incoming_data_channel_tx, incoming_data_channels) = mpsc::unbounded_channel();
        let (received_screen_frames_tx, received_screen_frames) = mpsc::unbounded_channel();
        let (call_chat_messages, _) = tokio::sync::broadcast::channel(128);
        let (remote_screen_frame, _) = watch::channel(None);
        let (screen_share_status, _) =
            watch::channel("Compartilhamento de vídeo parado.".to_owned());
        let (audio_status, _) = watch::channel("Áudio ainda não conectado.".to_owned());
        let handler = Arc::new(CallEvents {
            gathering_complete: gathering_tx,
            connection_state: state_tx,
            incoming_tracks: incoming_track_tx,
            incoming_data_channels: incoming_data_channel_tx,
        });
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|error| format!("could not register WebRTC codecs: {error}"))?;
        let interceptor_registry =
            register_default_interceptors(Registry::new(), &mut media_engine)
                .map_err(|error| format!("could not configure WebRTC interceptors: {error}"))?;
        let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
        let peer_connection = PeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(interceptor_registry)
            .with_handler(handler)
            .with_runtime(runtime)
            .with_udp_addrs(vec!["0.0.0.0:0".to_owned()])
            .with_data_channel_send_buffer_limit(128 * 1024)
            .build()
            .await
            .map_err(|error| format!("could not create WebRTC peer connection: {error}"))?;

        let session = Self {
            peer_connection: Box::new(peer_connection),
            gathering_complete,
            connection_state,
            audio_status,
            incoming_tracks: Mutex::new(Some(incoming_tracks)),
            incoming_data_channels: Mutex::new(Some(incoming_data_channels)),
            screen_data_channel: Arc::new(AsyncMutex::new(None)),
            received_screen_frames: Mutex::new(Some(received_screen_frames)),
            received_screen_frames_tx,
            screen_video_encoder: AsyncMutex::new(None),
            screen_video_decoder: Arc::new(AsyncMutex::new(None)),
            screen_share_active: Arc::new(AtomicBool::new(false)),
            wayland_capture_stop: Arc::new(AtomicBool::new(true)),
            camera_capture_stop: Arc::new(AtomicBool::new(true)),
            screen_share_task: Mutex::new(None),
            remote_screen_frame,
            screen_share_status,
            call_chat_sender: AsyncMutex::new(None),
            call_chat_receiver: Arc::new(AsyncMutex::new(None)),
            call_chat_messages,
            audio: None,
            audio_started: AtomicBool::new(false),
            audio_tasks: Mutex::new(Vec::new()),
            data_channel_created: AtomicBool::new(false),
        };
        session.start_screen_data_receiver();
        Ok(session)
    }

    /// Build an audio-capable peer connection using the current call MLS group.
    /// The microphone and output devices are opened only after ICE/DTLS connects.
    pub async fn new_for_call_group(
        group_id: [u8; 16],
        remote_device: [u8; 32],
        input_device_id: String,
        output_device_id: String,
    ) -> Result<Self, String> {
        let (encoder, decoder, video_encoder, video_decoder, chat_sender, chat_receiver) =
            tokio::task::spawn_blocking(move || {
                Ok::<_, String>((
                    crate::call_audio::CallAudioEncoder::for_call_group(&group_id)?,
                    crate::call_audio::CallAudioDecoderSet::for_call_group(&group_id)?,
                    crate::call_video::CallVideoEncoder::for_call_group(&group_id)?,
                    crate::call_video::CallVideoDecoder::for_call_group_member(
                        &group_id,
                        &remote_device,
                    )?,
                    crate::call_chat::CallChatSender::for_call_group(&group_id)?,
                    crate::call_chat::CallChatReceiver::for_call_group_member(
                        &group_id,
                        &remote_device,
                    )?,
                ))
            })
            .await
            .map_err(|error| format!("call media context task failed: {error}"))??;
        let sink = Arc::new(crate::audio::AudioPlayback::open(&output_device_id)?);
        let session = Self::new_with_audio_codecs(encoder, decoder, input_device_id, sink).await?;
        *session.screen_video_encoder.lock().await = Some(video_encoder);
        *session.screen_video_decoder.lock().await = Some(video_decoder);
        *session.call_chat_sender.lock().await = Some(chat_sender);
        *session.call_chat_receiver.lock().await = Some(chat_receiver);
        Ok(session)
    }

    async fn new_with_audio_codecs(
        encoder: crate::call_audio::CallAudioEncoder,
        decoder: crate::call_audio::CallAudioDecoderSet,
        input_device_id: String,
        sink: Arc<dyn crate::call_audio::AudioSink>,
    ) -> Result<Self, String> {
        let mut session = Self::new().await?;
        let ssrc = random_ssrc()?;
        let codec = RTCRtpCodec {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48_000,
            channels: 2,
            ..Default::default()
        };
        let track = Arc::new(
            TrackLocalStaticSample::new(
                Instant::now(),
                MediaStreamTrack::new(
                    "slouching-call".to_owned(),
                    format!("slouching-audio-{ssrc:08x}"),
                    "Slouching microphone".to_owned(),
                    RtpCodecKind::Audio,
                    vec![RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            ssrc: Some(ssrc),
                            ..Default::default()
                        },
                        codec,
                        ..Default::default()
                    }],
                ),
            )
            .map_err(|error| format!("could not create Opus RTP track: {error}"))?,
        );
        session
            .peer_connection
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal>)
            .await
            .map_err(|error| format!("could not add protected Opus RTP track: {error}"))?;
        session.audio = Some(Arc::new(CallAudioState {
            encoder: AsyncMutex::new(encoder),
            decoder: AsyncMutex::new(decoder),
            track,
            ssrc,
            input_device_id,
            microphone_muted: AtomicBool::new(false),
            sink,
        }));
        session.start_audio_receiver();
        session
            .audio_status
            .send_replace("Opus/SFrame track ready; aguardando conexão ICE/DTLS.".to_owned());
        Ok(session)
    }

    /// Create an offer and return the completed SDP, including gathered host
    /// candidates. No STUN or TURN server is contacted by default.
    pub async fn create_offer(&self) -> Result<Vec<u8>, String> {
        if !self.data_channel_created.swap(true, Ordering::AcqRel) {
            let screen_channel = self
                .peer_connection
                .create_data_channel(
                    CALL_DATA_CHANNEL,
                    Some(RTCDataChannelInit {
                        ordered: true,
                        ..Default::default()
                    }),
                )
                .await
                .map_err(|error| {
                    self.data_channel_created.store(false, Ordering::Release);
                    format!("could not create screen-sharing data channel: {error}")
                })?;
            spawn_screen_data_channel_receiver(
                Arc::clone(&screen_channel),
                self.data_channel_context(),
            );
        }
        let offer = self
            .peer_connection
            .create_offer(None)
            .await
            .map_err(|error| format!("could not create WebRTC offer: {error}"))?;
        self.peer_connection
            .set_local_description(offer)
            .await
            .map_err(|error| format!("could not set local WebRTC offer: {error}"))?;
        self.wait_for_ice_gathering().await?;
        let description = self
            .peer_connection
            .local_description()
            .await
            .ok_or_else(|| "WebRTC did not produce a local offer".to_owned())?;
        serde_json::to_vec(&description)
            .map_err(|error| format!("could not serialize WebRTC offer: {error}"))
    }

    /// Apply a remote offer and return the completed SDP answer.
    pub async fn accept_offer(&self, offer: &[u8]) -> Result<Vec<u8>, String> {
        let offer = serde_json::from_slice(offer)
            .map_err(|error| format!("WebRTC offer is invalid JSON: {error}"))?;
        self.peer_connection
            .set_remote_description(offer)
            .await
            .map_err(|error| format!("could not apply remote WebRTC offer: {error}"))?;
        let answer = self
            .peer_connection
            .create_answer(None)
            .await
            .map_err(|error| format!("could not create WebRTC answer: {error}"))?;
        self.peer_connection
            .set_local_description(answer)
            .await
            .map_err(|error| format!("could not set local WebRTC answer: {error}"))?;
        self.wait_for_ice_gathering().await?;
        let description = self
            .peer_connection
            .local_description()
            .await
            .ok_or_else(|| "WebRTC did not produce a local answer".to_owned())?;
        serde_json::to_vec(&description)
            .map_err(|error| format!("could not serialize WebRTC answer: {error}"))
    }

    /// Apply the answer to the offer created by this peer.
    pub async fn accept_answer(&self, answer: &[u8]) -> Result<(), String> {
        let answer = serde_json::from_slice(answer)
            .map_err(|error| format!("WebRTC answer is invalid JSON: {error}"))?;
        self.peer_connection
            .set_remote_description(answer)
            .await
            .map_err(|error| format!("could not apply remote WebRTC answer: {error}"))
    }

    /// Apply an ICE candidate received through the pinned call-signaling path.
    pub async fn add_ice_candidate(&self, candidate: &[u8]) -> Result<(), String> {
        let candidate = serde_json::from_slice(candidate)
            .map_err(|error| format!("WebRTC ICE candidate is invalid JSON: {error}"))?;
        self.peer_connection
            .add_ice_candidate(candidate)
            .await
            .map_err(|error| format!("could not apply remote WebRTC ICE candidate: {error}"))
    }

    pub fn connection_state(&self) -> watch::Receiver<String> {
        self.connection_state.clone()
    }

    pub fn audio_status(&self) -> watch::Receiver<String> {
        self.audio_status.subscribe()
    }

    /// Take the single-consumer stream of complete, reassembled protected
    /// screen access units received on this peer connection.
    pub fn take_received_screen_frames(&self) -> Option<mpsc::UnboundedReceiver<Vec<u8>>> {
        self.received_screen_frames
            .lock()
            .ok()
            .and_then(|mut frames| frames.take())
    }

    pub fn remote_screen_frame(
        &self,
    ) -> watch::Receiver<Option<Arc<crate::call_video::DecodedVideoFrame>>> {
        self.remote_screen_frame.subscribe()
    }

    pub fn screen_share_status(&self) -> watch::Receiver<String> {
        self.screen_share_status.subscribe()
    }

    pub fn subscribe_call_chat(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.call_chat_messages.subscribe()
    }

    pub async fn send_call_chat(&self, text: &str) -> Result<(), String> {
        let channel = self
            .screen_data_channel
            .lock()
            .await
            .clone()
            .ok_or_else(|| "call chat channel is not ready".to_owned())?;
        if channel
            .ready_state()
            .await
            .map_err(|error| error.to_string())?
            != RTCDataChannelState::Open
        {
            return Err("call chat channel is not connected".to_owned());
        }
        let ciphertext = self
            .call_chat_sender
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| "call chat MLS protection is not available".to_owned())?
            .encrypt(text)?;
        let frame = crate::call_chat::frame_ciphertext(&ciphertext)?;
        channel
            .send(BytesMut::from(frame.as_slice()))
            .await
            .map_err(|error| format!("could not send protected call message: {error}"))
    }

    pub fn is_video_sharing(&self) -> bool {
        self.screen_share_active.load(Ordering::Acquire)
    }

    pub async fn start_screen_sharing(self: &Arc<Self>, monitor_id: u32) -> Result<(), String> {
        self.start_desktop_video_sharing(
            crate::screen_capture::VideoSource::Monitor(monitor_id),
            "tela",
        )
        .await
    }

    pub async fn start_window_sharing(self: &Arc<Self>, window_id: u32) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        if crate::screen_capture::uses_wayland_window_portal() {
            return self.start_wayland_window_sharing().await;
        }
        self.start_desktop_video_sharing(
            crate::screen_capture::VideoSource::Window(window_id),
            "janela",
        )
        .await
    }

    #[cfg(target_os = "linux")]
    async fn start_wayland_window_sharing(self: &Arc<Self>) -> Result<(), String> {
        if self.screen_video_encoder.lock().await.is_none() {
            return Err("esta chamada não tem um codec de vídeo associado ao grupo MLS".to_owned());
        }
        let channel = self
            .screen_data_channel
            .lock()
            .await
            .clone()
            .ok_or_else(|| "o canal de vídeo ainda não foi negociado com o peer".to_owned())?;
        if channel
            .ready_state()
            .await
            .map_err(|error| error.to_string())?
            != RTCDataChannelState::Open
        {
            return Err("aguarde WebRTC antes de escolher uma janela".to_owned());
        }
        if self.screen_share_active.swap(true, Ordering::AcqRel) {
            return Err("já existe um compartilhamento de vídeo nesta chamada".to_owned());
        }
        self.screen_share_status
            .send_replace("Aguardando a seleção da janela pelo portal do desktop…".to_owned());
        let capture_stop = Arc::clone(&self.wayland_capture_stop);
        capture_stop.store(false, Ordering::Release);
        let mut capture =
            match crate::wayland_capture::WaylandWindowCapture::start(capture_stop).await {
                Ok(capture) => capture,
                Err(error) => {
                    self.screen_share_active.store(false, Ordering::Release);
                    self.screen_share_status.send_replace(error.clone());
                    return Err(error);
                }
            };
        self.screen_share_status
            .send_replace("Janela selecionada; transmissão protegida iniciada.".to_owned());
        let session = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut frame_id = 0_u32;
            let mut interval = tokio::time::interval(Duration::from_millis(200));
            loop {
                interval.tick().await;
                let captured =
                    match tokio::time::timeout(Duration::from_millis(200), capture.recv()).await {
                        Ok(Some(Ok(frame))) => frame,
                        Ok(Some(Err(error))) => {
                            session
                                .screen_share_status
                                .send_replace(format!("Captura Wayland da janela falhou: {error}"));
                            session.send_video_stop_signal().await;
                            break;
                        }
                        Ok(None) => {
                            session
                                .screen_share_status
                                .send_replace("O portal encerrou a captura da janela.".to_owned());
                            session.send_video_stop_signal().await;
                            break;
                        }
                        Err(_) => continue,
                    };
                let protected = {
                    let mut encoder = session.screen_video_encoder.lock().await;
                    let Some(encoder) = encoder.as_mut() else {
                        break;
                    };
                    encoder.encode_and_protect(captured.width, captured.height, captured.rgba)
                };
                let protected = match protected {
                    Ok(frame) => frame,
                    Err(error) => {
                        session.screen_share_status.send_replace(format!(
                            "Quadro Wayland H.264/SFrame não enviado: {error}"
                        ));
                        continue;
                    }
                };
                match session
                    .send_protected_video_frame(frame_id, &protected)
                    .await
                {
                    Ok(()) => {
                        session.screen_share_status.send_replace(format!(
                            "Janela Wayland compartilhada · quadro {frame_id} · H.264/SFrame."
                        ));
                        frame_id = frame_id.wrapping_add(1);
                    }
                    Err(error) if error.contains("peer is behind") => {
                        frame_id = frame_id.wrapping_add(1);
                    }
                    Err(error) => {
                        session
                            .screen_share_status
                            .send_replace(format!("Compartilhamento interrompido: {error}"));
                        break;
                    }
                }
            }
            capture.stop().await;
            session.screen_share_active.store(false, Ordering::Release);
        });
        if let Ok(mut active_task) = self.screen_share_task.lock() {
            *active_task = Some(task);
        }
        Ok(())
    }

    async fn start_desktop_video_sharing(
        self: &Arc<Self>,
        source: crate::screen_capture::VideoSource,
        source_name: &'static str,
    ) -> Result<(), String> {
        if self.screen_video_encoder.lock().await.is_none() {
            return Err("esta chamada não tem um codec de vídeo associado ao grupo MLS".to_owned());
        }
        let channel = self
            .screen_data_channel
            .lock()
            .await
            .clone()
            .ok_or_else(|| "o canal de vídeo ainda não foi negociado com o peer".to_owned())?;
        if channel
            .ready_state()
            .await
            .map_err(|error| error.to_string())?
            != RTCDataChannelState::Open
        {
            return Err(format!(
                "aguarde WebRTC antes de compartilhar {source_name}"
            ));
        }
        if self.screen_share_active.swap(true, Ordering::AcqRel) {
            return Err("já existe um compartilhamento de vídeo nesta chamada".to_owned());
        }
        self.screen_share_status.send_replace(format!(
            "Capturando {source_name} local a 5 quadros por segundo; vídeo protegido por SFrame."
        ));
        let session = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut frame_id = 0_u32;
            let mut interval = tokio::time::interval(Duration::from_millis(200));
            loop {
                interval.tick().await;
                let captured = tokio::task::spawn_blocking(move || {
                    crate::screen_capture::capture_video_source(source)
                })
                .await;
                let captured = match captured {
                    Ok(Ok(frame)) => frame,
                    Ok(Err(error)) => {
                        session
                            .screen_share_status
                            .send_replace(format!("Captura de {source_name} falhou: {error}"));
                        session.send_video_stop_signal().await;
                        break;
                    }
                    Err(error) => {
                        session
                            .screen_share_status
                            .send_replace(format!("Tarefa de captura falhou: {error}"));
                        session.send_video_stop_signal().await;
                        break;
                    }
                };
                let protected = {
                    let mut encoder = session.screen_video_encoder.lock().await;
                    let Some(encoder) = encoder.as_mut() else {
                        break;
                    };
                    encoder.encode_and_protect(captured.width, captured.height, captured.rgba)
                };
                let protected = match protected {
                    Ok(frame) => frame,
                    Err(error) => {
                        session
                            .screen_share_status
                            .send_replace(format!("Quadro H.264/SFrame não enviado: {error}"));
                        continue;
                    }
                };
                match session
                    .send_protected_video_frame(frame_id, &protected)
                    .await
                {
                    Ok(()) => {
                        session.screen_share_status.send_replace(format!(
                            "{source_name} compartilhada · quadro {frame_id} · H.264/SFrame."
                        ));
                        frame_id = frame_id.wrapping_add(1);
                    }
                    Err(error) if error.contains("peer is behind") => {
                        frame_id = frame_id.wrapping_add(1);
                    }
                    Err(error) => {
                        session
                            .screen_share_status
                            .send_replace(format!("Compartilhamento interrompido: {error}"));
                        break;
                    }
                }
            }
            session.screen_share_active.store(false, Ordering::Release);
        });
        if let Ok(mut active_task) = self.screen_share_task.lock() {
            *active_task = Some(task);
        }
        Ok(())
    }

    /// Capture a selected camera and send bounded H.264/SFrame frames over the
    /// same reliable channel used for call video. Camera opening waits for the
    /// OS permission/device result before this action reports success.
    pub async fn start_camera_sharing(
        self: &Arc<Self>,
        camera_index: nokhwa::utils::CameraIndex,
    ) -> Result<(), String> {
        if self.screen_video_encoder.lock().await.is_none() {
            return Err("esta chamada não tem um codec de vídeo associado ao grupo MLS".to_owned());
        }
        let channel = self
            .screen_data_channel
            .lock()
            .await
            .clone()
            .ok_or_else(|| "o canal de vídeo ainda não foi negociado com o peer".to_owned())?;
        if channel
            .ready_state()
            .await
            .map_err(|error| error.to_string())?
            != RTCDataChannelState::Open
        {
            return Err("aguarde a conexão WebRTC antes de compartilhar a câmera".to_owned());
        }
        if self.screen_share_active.swap(true, Ordering::AcqRel) {
            return Err("já existe um compartilhamento de vídeo nesta chamada".to_owned());
        }
        let stop = Arc::clone(&self.camera_capture_stop);
        stop.store(false, Ordering::Release);
        let mut frames = match crate::camera_capture::stream(camera_index, Arc::clone(&stop)).await
        {
            Ok(frames) => frames,
            Err(error) => {
                stop.store(true, Ordering::Release);
                self.screen_share_active.store(false, Ordering::Release);
                return Err(error);
            }
        };
        self.screen_share_status.send_replace(
            "Câmera ativa · captura local e proteção SFrame do grupo da chamada.".to_owned(),
        );
        let session = Arc::clone(self);
        let task = tokio::spawn(async move {
            let mut frame_id = 0_u32;
            while let Some(frame) = frames.recv().await {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => {
                        session
                            .screen_share_status
                            .send_replace(format!("Captura da câmera falhou: {error}"));
                        break;
                    }
                };
                let protected = {
                    let mut encoder = session.screen_video_encoder.lock().await;
                    let Some(encoder) = encoder.as_mut() else {
                        break;
                    };
                    encoder.encode_and_protect(frame.width, frame.height, frame.rgba)
                };
                let protected = match protected {
                    Ok(frame) => frame,
                    Err(error) => {
                        session.screen_share_status.send_replace(format!(
                            "Quadro de câmera H.264/SFrame rejeitado: {error}"
                        ));
                        continue;
                    }
                };
                match session
                    .send_protected_video_frame(frame_id, &protected)
                    .await
                {
                    Ok(()) => {
                        session.screen_share_status.send_replace(format!(
                            "Câmera compartilhada · quadro {frame_id} · H.264/SFrame."
                        ));
                        frame_id = frame_id.wrapping_add(1);
                    }
                    Err(error) if error.contains("peer is behind") => {
                        frame_id = frame_id.wrapping_add(1);
                    }
                    Err(error) => {
                        session
                            .screen_share_status
                            .send_replace(format!("Compartilhamento interrompido: {error}"));
                        break;
                    }
                }
            }
            stop.store(true, Ordering::Release);
            session.screen_share_active.store(false, Ordering::Release);
        });
        if let Ok(mut active_task) = self.screen_share_task.lock() {
            *active_task = Some(task);
        }
        Ok(())
    }

    pub async fn stop_video_sharing(&self) {
        self.wayland_capture_stop.store(true, Ordering::Release);
        self.camera_capture_stop.store(true, Ordering::Release);
        if let Ok(mut task) = self.screen_share_task.lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
        self.send_video_stop_signal().await;
        self.screen_share_active.store(false, Ordering::Release);
        self.screen_share_status
            .send_replace("Compartilhamento de vídeo parado.".to_owned());
    }

    async fn send_video_stop_signal(&self) {
        if let Some(channel) = self.screen_data_channel.lock().await.clone()
            && channel
                .ready_state()
                .await
                .is_ok_and(|state| state == RTCDataChannelState::Open)
        {
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                channel.send(BytesMut::from(
                    crate::video_transport::stop_sharing_message(),
                )),
            )
            .await;
        }
    }

    /// Send one already SFrame-protected H.264 access unit over the bounded
    /// bounded call-video data channel.
    pub async fn send_protected_video_frame(
        &self,
        frame_id: u32,
        protected_frame: &[u8],
    ) -> Result<(), String> {
        let channel = self
            .screen_data_channel
            .lock()
            .await
            .clone()
            .ok_or_else(|| "video channel is not available on this call".to_owned())?;
        let state = channel
            .ready_state()
            .await
            .map_err(|error| format!("could not read video channel state: {error}"))?;
        if state != RTCDataChannelState::Open {
            return Err(format!("video channel is not open: {state:?}"));
        }
        let fragments = crate::video_transport::fragment_frame(frame_id, protected_frame)?;
        for fragment in fragments {
            let outstanding = channel
                .outstanding_bytes()
                .await
                .map_err(|error| format!("could not read video send queue: {error}"))?;
            if outstanding > 96 * 1024 {
                return Err("screen-sharing frame skipped because the peer is behind".to_owned());
            }
            channel
                .try_send(BytesMut::from(fragment.as_slice()))
                .await
                .map_err(|error| format!("could not queue protected video fragment: {error}"))?;
        }
        Ok(())
    }

    fn start_screen_data_receiver(&self) {
        let receiver = self
            .incoming_data_channels
            .lock()
            .ok()
            .and_then(|mut channels| channels.take());
        let Some(mut receiver) = receiver else {
            return;
        };
        let data_channel_context = self.data_channel_context();
        let task = tokio::spawn(async move {
            while let Some(channel) = receiver.recv().await {
                if channel.label().await.ok().as_deref() == Some(CALL_DATA_CHANNEL) {
                    spawn_screen_data_channel_receiver(channel, data_channel_context.clone());
                }
            }
        });
        if let Ok(mut tasks) = self.audio_tasks.lock() {
            tasks.push(task);
        }
    }

    fn data_channel_context(&self) -> CallDataChannelContext {
        CallDataChannelContext {
            active_channel: Arc::clone(&self.screen_data_channel),
            screen_decoder: Arc::clone(&self.screen_video_decoder),
            chat_decoder: Arc::clone(&self.call_chat_receiver),
            remote_screen_frame: self.remote_screen_frame.clone(),
            screen_share_status: self.screen_share_status.clone(),
            received_screen_frames: self.received_screen_frames_tx.clone(),
            chat_messages: self.call_chat_messages.clone(),
        }
    }

    pub fn set_microphone_muted(&self, muted: bool) {
        if let Some(audio) = self.audio.as_ref() {
            audio.microphone_muted.store(muted, Ordering::Release);
            self.audio_status.send_replace(if muted {
                "Microfone silenciado localmente.".to_owned()
            } else {
                "Microfone ativo · Opus/SFrame · enviando áudio protegido.".to_owned()
            });
        }
    }

    /// Open the selected microphone once the peer connection is established.
    pub async fn start_microphone(&self) -> Result<(), String> {
        let Some(audio) = self.audio.as_ref().cloned() else {
            return Ok(());
        };
        if self.audio_started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let input_device_id = audio.input_device_id.clone();
        let capture = match tokio::task::spawn_blocking(move || {
            crate::audio::AudioCapture::open(&input_device_id)
        })
        .await
        .map_err(|error| format!("microphone startup task failed: {error}"))?
        {
            Ok(capture) => capture,
            Err(error) => {
                self.audio_started.store(false, Ordering::Release);
                self.audio_status
                    .send_replace(format!("Microfone indisponível: {error}"));
                return Err(error);
            }
        };
        let sample_rate = capture.sample_rate();
        let audio_status = self.audio_status.clone();
        let track_audio = Arc::clone(&audio);
        let capture_task = tokio::spawn(async move {
            let mut capture = capture;
            let mut frames = match crate::call_audio::VoiceFrameAssembler::new(sample_rate) {
                Ok(frames) => frames,
                Err(error) => {
                    audio_status.send_replace(format!("Falha na captura de áudio: {error}"));
                    return;
                }
            };
            loop {
                match tokio::time::timeout(Duration::from_millis(250), capture.next_chunk()).await {
                    Ok(Some(chunk)) => match frames.push(&chunk) {
                        Ok(frames) => {
                            for pcm in frames {
                                if let Err(error) = track_audio.send_audio_frame(&pcm).await {
                                    audio_status.send_replace(format!(
                                        "Falha ao proteger/enviar áudio RTP: {error}"
                                    ));
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            audio_status
                                .send_replace(format!("Falha no formato do microfone: {error}"));
                            return;
                        }
                    },
                    Ok(None) => {
                        audio_status.send_replace("Captura do microfone foi encerrada.".to_owned());
                        return;
                    }
                    Err(_) => {
                        if let Some(error) = capture.error() {
                            audio_status.send_replace(format!("Falha do microfone: {error}"));
                            return;
                        }
                    }
                }
            }
        });
        if let Ok(mut tasks) = self.audio_tasks.lock() {
            tasks.push(capture_task);
        }
        self.audio_status
            .send_replace(if audio.microphone_muted.load(Ordering::Acquire) {
                "Microfone silenciado localmente; captura não enviada.".to_owned()
            } else {
                "Microfone ativo · Opus/SFrame · enviando áudio protegido.".to_owned()
            });
        Ok(())
    }

    fn start_audio_receiver(&self) {
        let receiver = self
            .incoming_tracks
            .lock()
            .ok()
            .and_then(|mut tracks| tracks.take());
        let (Some(mut receiver), Some(audio)) = (receiver, self.audio.as_ref().cloned()) else {
            return;
        };
        let audio_status = self.audio_status.clone();
        let task = tokio::spawn(async move {
            let mut track_tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = receiver.recv() => match incoming {
                        Some(track) => {
                            let audio = Arc::clone(&audio);
                            let audio_status = audio_status.clone();
                            track_tasks.spawn(async move {
                                while let Some(event) = track.poll().await {
                                    match event {
                                        TrackRemoteEvent::OnRtpPacket(packet) => {
                                            match audio.decoder.lock().await.unprotect_and_decode(&packet.payload) {
                                                Ok(pcm) => audio.sink.push_mono(&pcm),
                                                Err(error) => {
                                                    audio_status.send_replace(format!("Quadro SFrame de áudio rejeitado: {error}"));
                                                }
                                            }
                                        }
                                        TrackRemoteEvent::OnEnded | TrackRemoteEvent::OnEnding => break,
                                        TrackRemoteEvent::OnError => {
                                            audio_status.send_replace("Track de áudio remoto reportou erro.".to_owned());
                                            break;
                                        }
                                        _ => {}
                                    }
                                }
                            });
                        }
                        None => break,
                    },
                    Some(_) = track_tasks.join_next(), if !track_tasks.is_empty() => {}
                }
            }
        });
        if let Ok(mut tasks) = self.audio_tasks.lock() {
            tasks.push(task);
        }
    }

    pub async fn close(&self) -> Result<(), String> {
        self.stop_video_sharing().await;
        if let Ok(mut tasks) = self.audio_tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        self.audio_status
            .send_replace("Áudio encerrado.".to_owned());
        self.peer_connection
            .close()
            .await
            .map_err(|error| format!("could not close WebRTC peer connection: {error}"))
    }

    async fn wait_for_ice_gathering(&self) -> Result<(), String> {
        let mut gathering_complete = self.gathering_complete.clone();
        tokio::time::timeout(ICE_GATHERING_TIMEOUT, async move {
            while !*gathering_complete.borrow() {
                gathering_complete
                    .changed()
                    .await
                    .map_err(|_| "WebRTC ICE gathering event stream ended".to_owned())?;
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "timed out gathering WebRTC ICE candidates".to_owned())??;
        Ok(())
    }
}

fn spawn_screen_data_channel_receiver(
    channel: Arc<dyn DataChannel>,
    context: CallDataChannelContext,
) {
    tokio::spawn(async move {
        *context.active_channel.lock().await = Some(Arc::clone(&channel));
        let mut reassembler = crate::video_transport::VideoFrameReassembler::default();
        while let Some(event) = channel.poll().await {
            match event {
                DataChannelEvent::OnMessage(message) if !message.is_string => {
                    if let Some(ciphertext) = crate::call_chat::ciphertext_from_frame(&message.data)
                    {
                        let decoded = {
                            let mut decoder = context.chat_decoder.lock().await;
                            decoder
                                .as_mut()
                                .ok_or_else(|| {
                                    "call chat MLS protection is not available".to_owned()
                                })
                                .and_then(|decoder| decoder.decrypt(ciphertext))
                        };
                        if let Ok(text) = decoded {
                            let _ = context.chat_messages.send(text);
                        }
                    } else if crate::video_transport::is_stop_sharing_message(&message.data) {
                        reassembler.clear();
                        context.remote_screen_frame.send_replace(None);
                    } else if let Ok(Some(frame)) = reassembler.push(&message.data) {
                        let decoded = {
                            let mut decoder = context.screen_decoder.lock().await;
                            match decoder.as_mut() {
                                Some(decoder) => decoder.unprotect_and_decode(&frame).map(Some),
                                None => Ok(None),
                            }
                        };
                        match decoded {
                            Ok(Some(Some(frame))) => {
                                context
                                    .remote_screen_frame
                                    .send_replace(Some(Arc::new(frame)));
                            }
                            Ok(None) | Ok(Some(None)) => {
                                let _ = context.received_screen_frames.send(frame);
                            }
                            Err(error) => {
                                context
                                    .screen_share_status
                                    .send_replace(format!("Quadro remoto rejeitado: {error}"));
                            }
                        }
                    }
                }
                DataChannelEvent::OnClose => break,
                _ => {}
            }
        }
        let mut active = context.active_channel.lock().await;
        if active
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &channel))
        {
            *active = None;
        }
    });
}

fn random_ssrc() -> Result<u32, String> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes).map_err(|error| format!("could not create audio SSRC: {error}"))?;
    let ssrc = u32::from_be_bytes(bytes);
    Ok(if ssrc == 0 { 1 } else { ssrc })
}

impl std::fmt::Debug for CallRtcSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallRtcSession")
            .field("connection_state", &*self.connection_state.borrow())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, timeout};

    struct TestSink(mpsc::UnboundedSender<Vec<f32>>);

    impl crate::call_audio::AudioSink for TestSink {
        fn push_mono(&self, samples: &[f32]) {
            let _ = self.0.send(samples.to_vec());
        }
    }

    #[tokio::test]
    async fn loopback_peers_negotiate_webrtc_over_gathered_host_candidates() {
        let caller = CallRtcSession::new().await.unwrap();
        let callee = CallRtcSession::new().await.unwrap();
        let offer = caller.create_offer().await.unwrap();
        assert!(String::from_utf8_lossy(&offer).contains("a=candidate:"));
        let answer = callee.accept_offer(&offer).await.unwrap();
        caller.accept_answer(&answer).await.unwrap();

        for state in [caller.connection_state(), callee.connection_state()] {
            let mut state = state;
            timeout(Duration::from_secs(10), async {
                loop {
                    if state.borrow().as_str() == "Connected" {
                        break;
                    }
                    state.changed().await.unwrap();
                }
            })
            .await
            .expect("loopback WebRTC ICE and DTLS should connect");
        }
        caller.close().await.unwrap();
        callee.close().await.unwrap();
        sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn protected_opus_audio_crosses_webrtc_loopback_and_reaches_sink() {
        const EXPORTER_KEY: &[u8] = b"0123456789abcdef";
        let (caller_sink_tx, _caller_sink_rx) = mpsc::unbounded_channel();
        let (callee_sink_tx, mut callee_sink_rx) = mpsc::unbounded_channel();
        let caller = CallRtcSession::new_with_audio_codecs(
            crate::call_audio::CallAudioEncoder::new(
                crate::media::MediaFrameSender::new(3, 0, EXPORTER_KEY).unwrap(),
            )
            .unwrap(),
            crate::call_audio::CallAudioDecoderSet::new(vec![
                crate::call_audio::CallAudioDecoder::new(
                    crate::media::MediaFrameReceiver::new(3, 1, EXPORTER_KEY).unwrap(),
                )
                .unwrap(),
            ])
            .unwrap(),
            String::new(),
            Arc::new(TestSink(caller_sink_tx)),
        )
        .await
        .unwrap();
        let callee = CallRtcSession::new_with_audio_codecs(
            crate::call_audio::CallAudioEncoder::new(
                crate::media::MediaFrameSender::new(3, 1, EXPORTER_KEY).unwrap(),
            )
            .unwrap(),
            crate::call_audio::CallAudioDecoderSet::new(vec![
                crate::call_audio::CallAudioDecoder::new(
                    crate::media::MediaFrameReceiver::new(3, 0, EXPORTER_KEY).unwrap(),
                )
                .unwrap(),
            ])
            .unwrap(),
            String::new(),
            Arc::new(TestSink(callee_sink_tx)),
        )
        .await
        .unwrap();

        let offer = caller.create_offer().await.unwrap();
        let answer = callee.accept_offer(&offer).await.unwrap();
        caller.accept_answer(&answer).await.unwrap();
        for state in [caller.connection_state(), callee.connection_state()] {
            let mut state = state;
            timeout(Duration::from_secs(10), async {
                loop {
                    if state.borrow().as_str() == "Connected" {
                        break;
                    }
                    state.changed().await.unwrap();
                }
            })
            .await
            .expect("audio loopback should connect over WebRTC");
        }

        let frame = (0..crate::call_audio::FRAME_SAMPLES)
            .map(|sample| {
                (sample as f32 * 440.0 * std::f32::consts::TAU
                    / crate::call_audio::SAMPLE_RATE_HZ as f32)
                    .sin()
                    * 0.2
            })
            .collect::<Vec<_>>();
        caller.set_microphone_muted(true);
        caller
            .audio
            .as_ref()
            .unwrap()
            .send_audio_frame(&frame)
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), callee_sink_rx.recv())
                .await
                .is_err()
        );
        caller.set_microphone_muted(false);
        caller
            .audio
            .as_ref()
            .unwrap()
            .send_audio_frame(&frame)
            .await
            .unwrap();
        let received = timeout(Duration::from_secs(5), callee_sink_rx.recv())
            .await
            .expect("callee should receive an RTP frame")
            .expect("callee audio sink should remain open");
        assert_eq!(received.len(), crate::call_audio::FRAME_SAMPLES);
        assert!(received.iter().any(|sample| sample.abs() > 0.01));

        caller.close().await.unwrap();
        callee.close().await.unwrap();
    }

    #[tokio::test]
    async fn call_data_channel_reassembles_bounded_video_fragments() {
        let caller = Arc::new(CallRtcSession::new().await.unwrap());
        let callee = Arc::new(CallRtcSession::new().await.unwrap());
        let offer = caller.create_offer().await.unwrap();
        let answer = callee.accept_offer(&offer).await.unwrap();
        caller.accept_answer(&answer).await.unwrap();
        let mut received = callee.take_received_screen_frames().unwrap();
        let frame = (0..(12 * 1024 * 2 + 37))
            .map(|index| (index % 239) as u8)
            .collect::<Vec<_>>();

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match caller.send_protected_video_frame(7, &frame).await {
                    Ok(()) => break,
                    Err(error) if error.contains("not open") || error.contains("not available") => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("could not send test video fragments: {error}"),
                }
            }
        })
        .await
        .expect("screen data channel should open after WebRTC negotiation");
        let received = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("screen frame should arrive")
            .expect("screen data channel should remain open");
        assert_eq!(received, frame);
        let mut remote_video = callee.remote_screen_frame();
        callee.remote_screen_frame.send_replace(Some(Arc::new(
            crate::call_video::DecodedVideoFrame {
                width: 1,
                height: 1,
                rgba: vec![0, 0, 0, 255],
            },
        )));
        remote_video.changed().await.unwrap();
        assert!(remote_video.borrow().is_some());
        caller.stop_video_sharing().await;
        tokio::time::timeout(Duration::from_secs(5), remote_video.changed())
            .await
            .expect("stop-sharing signal should reach the remote peer")
            .expect("remote video watch should stay active");
        assert!(remote_video.borrow().is_none());
        caller.close().await.unwrap();
        callee.close().await.unwrap();
    }

    #[tokio::test]
    async fn protected_h264_screen_frame_crosses_data_channel_and_decodes_remotely() {
        let caller = Arc::new(CallRtcSession::new().await.unwrap());
        let callee = Arc::new(CallRtcSession::new().await.unwrap());
        let offer = caller.create_offer().await.unwrap();
        let answer = callee.accept_offer(&offer).await.unwrap();
        caller.accept_answer(&answer).await.unwrap();
        let (caller_encoder, callee_decoder) =
            crate::call_video::test_encoder_decoder_pair().unwrap();
        let (callee_encoder, caller_decoder) =
            crate::call_video::test_encoder_decoder_pair().unwrap();
        *caller.screen_video_encoder.lock().await = Some(caller_encoder);
        *callee.screen_video_decoder.lock().await = Some(callee_decoder);
        *callee.screen_video_encoder.lock().await = Some(callee_encoder);
        *caller.screen_video_decoder.lock().await = Some(caller_decoder);
        let pixels = vec![96_u8; 320 * 240 * 4];
        let protected = caller
            .screen_video_encoder
            .lock()
            .await
            .as_mut()
            .unwrap()
            .encode_and_protect(320, 240, pixels)
            .unwrap();
        let mut remote_frame = callee.remote_screen_frame();

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match caller.send_protected_video_frame(1, &protected).await {
                    Ok(()) => break,
                    Err(error) if error.contains("not open") || error.contains("not available") => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("could not send protected screen frame: {error}"),
                }
            }
        })
        .await
        .expect("screen data channel should open after WebRTC negotiation");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                remote_frame.changed().await.unwrap();
                if remote_frame.borrow().is_some() {
                    break;
                }
            }
        })
        .await
        .expect("authenticated screen frame should be rendered remotely");
        let decoded = remote_frame.borrow().clone().unwrap();
        assert_eq!((decoded.width, decoded.height), (320, 240));
        assert_eq!(decoded.rgba.len(), 320 * 240 * 4);

        let mut caller_remote_frame = caller.remote_screen_frame();
        let reverse_frame = callee
            .screen_video_encoder
            .lock()
            .await
            .as_mut()
            .unwrap()
            .encode_and_protect(320, 240, vec![32_u8; 320 * 240 * 4])
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match callee.send_protected_video_frame(2, &reverse_frame).await {
                    Ok(()) => break,
                    Err(error) if error.contains("not open") || error.contains("not available") => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("could not send reverse screen frame: {error}"),
                }
            }
        })
        .await
        .expect("answer peer should be able to send over the negotiated channel");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                caller_remote_frame.changed().await.unwrap();
                if caller_remote_frame.borrow().is_some() {
                    break;
                }
            }
        })
        .await
        .expect("offer peer should receive and decode the reverse screen frame");
        let reverse_decoded = caller_remote_frame.borrow().clone().unwrap();
        assert_eq!((reverse_decoded.width, reverse_decoded.height), (320, 240));

        caller.close().await.unwrap();
        callee.close().await.unwrap();
    }

    #[tokio::test]
    async fn ephemeral_call_chat_is_sframe_protected_over_reliable_data_channel() {
        let caller = Arc::new(CallRtcSession::new().await.unwrap());
        let callee = Arc::new(CallRtcSession::new().await.unwrap());
        let offer = caller.create_offer().await.unwrap();
        let answer = callee.accept_offer(&offer).await.unwrap();
        caller.accept_answer(&answer).await.unwrap();
        let (caller_sender, caller_receiver) = crate::call_chat::test_sender_receiver().unwrap();
        let (callee_sender, callee_receiver) = crate::call_chat::test_sender_receiver().unwrap();
        *caller.call_chat_sender.lock().await = Some(caller_sender);
        *caller.call_chat_receiver.lock().await = Some(caller_receiver);
        *callee.call_chat_sender.lock().await = Some(callee_sender);
        *callee.call_chat_receiver.lock().await = Some(callee_receiver);
        let mut caller_incoming = caller.subscribe_call_chat();
        let mut callee_incoming = callee.subscribe_call_chat();

        for (sender, receiver, text) in [
            (
                Arc::clone(&caller),
                &mut callee_incoming,
                "mensagem da pessoa que iniciou",
            ),
            (
                Arc::clone(&callee),
                &mut caller_incoming,
                "resposta da pessoa que aceitou",
            ),
        ] {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match sender.send_call_chat(text).await {
                        Ok(()) => break,
                        Err(error)
                            if error.contains("not ready") || error.contains("not connected") =>
                        {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(error) => panic!("could not send protected call chat: {error}"),
                    }
                }
            })
            .await
            .expect("call chat DataChannel should open after negotiation");
            let received = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
                .await
                .expect("call chat message should arrive")
                .expect("call chat channel should remain open");
            assert_eq!(received, text);
        }

        caller.close().await.unwrap();
        callee.close().await.unwrap();
    }
}
