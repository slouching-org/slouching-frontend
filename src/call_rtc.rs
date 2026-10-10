//! WebRTC peer-connection lifecycle and SDP/ICE handling for direct calls.
//!
//! Signaling is carried by the pinned peer session. This module gathers host
//! ICE candidates into SDP for the initial offer/answer exchange and can apply
//! later trickled candidates. Media tracks are added by the call media layer.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::watch;
use webrtc::{
    peer_connection::{
        MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
        RTCConfigurationBuilder, RTCIceGatheringState, RTCPeerConnectionState, Registry,
        register_default_interceptors,
    },
    runtime::{Runtime, TokioRuntime},
};

const ICE_GATHERING_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct CallEvents {
    gathering_complete: watch::Sender<bool>,
    connection_state: watch::Sender<String>,
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
}

/// Owns one WebRTC peer connection. Create exactly one instance per remote
/// member in a mesh call.
pub struct CallRtcSession {
    peer_connection: Box<dyn PeerConnection>,
    gathering_complete: watch::Receiver<bool>,
    connection_state: watch::Receiver<String>,
    data_channel_created: AtomicBool,
}

impl CallRtcSession {
    pub async fn new() -> Result<Self, String> {
        let (gathering_tx, gathering_complete) = watch::channel(false);
        let (state_tx, connection_state) = watch::channel("New".to_owned());
        let handler = Arc::new(CallEvents {
            gathering_complete: gathering_tx,
            connection_state: state_tx,
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
            data_channel_created: AtomicBool::new(false),
        })
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

    pub async fn close(&self) -> Result<(), String> {
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
}
