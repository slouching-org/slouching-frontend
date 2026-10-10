//! WebRTC peer-connection lifecycle and SDP/ICE handling for direct calls.
//!
//! Signaling is carried by the pinned peer session. This module gathers host
//! ICE candidates into SDP for the initial offer/answer exchange and can apply
//! later trickled candidates. Media tracks are added by the call media layer.

use bytes::Bytes;
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

#[derive(Clone)]
struct CallEvents {
    gathering_complete: watch::Sender<bool>,
    connection_state: watch::Sender<String>,
    incoming_tracks: mpsc::UnboundedSender<Arc<dyn TrackRemote>>,
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
}

struct CallAudioState {
    encoder: AsyncMutex<crate::call_audio::CallAudioEncoder>,
    decoder: AsyncMutex<crate::call_audio::CallAudioDecoder>,
    track: Arc<TrackLocalStaticSample>,
    ssrc: u32,
    input_device_id: String,
    microphone_muted: AtomicBool,
    sink: Arc<dyn crate::call_audio::AudioSink>,
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
        let (audio_status, _) = watch::channel("Áudio ainda não conectado.".to_owned());
        let handler = Arc::new(CallEvents {
            gathering_complete: gathering_tx,
            connection_state: state_tx,
            incoming_tracks: incoming_track_tx,
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
            .build()
            .await
            .map_err(|error| format!("could not create WebRTC peer connection: {error}"))?;

        Ok(Self {
            peer_connection: Box::new(peer_connection),
            gathering_complete,
            connection_state,
            audio_status,
            incoming_tracks: Mutex::new(Some(incoming_tracks)),
            audio: None,
            audio_started: AtomicBool::new(false),
            audio_tasks: Mutex::new(Vec::new()),
            data_channel_created: AtomicBool::new(false),
        })
    }

    /// Build an audio-capable peer connection using the current call MLS group.
    /// The microphone and output devices are opened only after ICE/DTLS connects.
    pub async fn new_for_call_group(
        group_id: [u8; 16],
        remote_device: [u8; 32],
        input_device_id: String,
        output_device_id: String,
    ) -> Result<Self, String> {
        let (encoder, decoder) = tokio::task::spawn_blocking(move || {
            Ok::<_, String>((
                crate::call_audio::CallAudioEncoder::for_call_group(&group_id)?,
                crate::call_audio::CallAudioDecoder::for_call_group_member(
                    &group_id,
                    &remote_device,
                )?,
            ))
        })
        .await
        .map_err(|error| format!("call media context task failed: {error}"))??;
        let sink = Arc::new(crate::audio::AudioPlayback::open(&output_device_id)?);
        Self::new_with_audio_codecs(encoder, decoder, input_device_id, sink).await
    }

    async fn new_with_audio_codecs(
        encoder: crate::call_audio::CallAudioEncoder,
        decoder: crate::call_audio::CallAudioDecoder,
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
            self.peer_connection
                .create_data_channel("slouching-call-control", None)
                .await
                .map_err(|error| {
                    self.data_channel_created.store(false, Ordering::Release);
                    format!("could not create WebRTC call control channel: {error}")
                })?;
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
            crate::call_audio::CallAudioDecoder::new(
                crate::media::MediaFrameReceiver::new(3, 1, EXPORTER_KEY).unwrap(),
            )
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
            crate::call_audio::CallAudioDecoder::new(
                crate::media::MediaFrameReceiver::new(3, 0, EXPORTER_KEY).unwrap(),
            )
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
}
