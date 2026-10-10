//! Opus voice frames protected with the call group's SFrame keys.
//!
//! This codec boundary is intentionally independent from CPAL and WebRTC I/O.
//! Each microphone frame is encoded before SFrame protection; received SFrame
//! payloads are authenticated before Opus decoding.

use crate::media::{MediaFrameReceiver, MediaFrameSender};
use opus::{Application, Channels};

pub const SAMPLE_RATE_HZ: u32 = 48_000;
pub const FRAME_SAMPLES: usize = 960;
const MAX_OPUS_PACKET_BYTES: usize = 4_000;
const MAX_OPUS_FRAME_SAMPLES: usize = 5_760;

pub struct CallAudioEncoder {
    encoder: opus::Encoder,
    protector: MediaFrameSender,
}

impl CallAudioEncoder {
    pub fn for_call_group(group_id: &[u8]) -> Result<Self, String> {
        Self::new(MediaFrameSender::from_call_group(group_id)?)
    }

    pub(crate) fn new(protector: MediaFrameSender) -> Result<Self, String> {
        let encoder = opus::Encoder::new(SAMPLE_RATE_HZ, Channels::Mono, Application::Voip)
            .map_err(|error| format!("could not create Opus voice encoder: {error}"))?;
        Ok(Self { encoder, protector })
    }

    /// Encode one 20 ms mono frame at 48 kHz, then authenticate and encrypt it.
    pub fn encode_and_protect(&mut self, pcm: &[f32]) -> Result<Vec<u8>, String> {
        if pcm.len() != FRAME_SAMPLES {
            return Err(format!(
                "Opus voice input must contain exactly {FRAME_SAMPLES} mono samples"
            ));
        }
        if pcm.iter().any(|sample| !sample.is_finite()) {
            return Err("Opus voice input contains a non-finite sample".to_owned());
        }
        let mut packet = vec![0; MAX_OPUS_PACKET_BYTES];
        let encoded = self
            .encoder
            .encode_float(pcm, &mut packet)
            .map_err(|error| format!("could not encode Opus voice frame: {error}"))?;
        packet.truncate(encoded);
        self.protector.encrypt(&packet)
    }
}

pub struct CallAudioDecoder {
    decoder: opus::Decoder,
    unprotector: MediaFrameReceiver,
}

impl CallAudioDecoder {
    pub fn for_call_group_member(
        group_id: &[u8],
        sender_device_public_key: &[u8; 32],
    ) -> Result<Self, String> {
        Self::new(MediaFrameReceiver::for_call_group_member(
            group_id,
            sender_device_public_key,
        )?)
    }

    pub(crate) fn new(unprotector: MediaFrameReceiver) -> Result<Self, String> {
        let decoder = opus::Decoder::new(SAMPLE_RATE_HZ, Channels::Mono)
            .map_err(|error| format!("could not create Opus voice decoder: {error}"))?;
        Ok(Self {
            decoder,
            unprotector,
        })
    }

    /// Authenticate/decrypt one SFrame, then decode its Opus voice packet.
    pub fn unprotect_and_decode(&mut self, protected: &[u8]) -> Result<Vec<f32>, String> {
        let packet = self.unprotector.decrypt(protected)?;
        let mut pcm = vec![0.0; MAX_OPUS_FRAME_SAMPLES];
        let decoded = self
            .decoder
            .decode_float(&packet, &mut pcm, false)
            .map_err(|error| format!("could not decode Opus voice frame: {error}"))?;
        pcm.truncate(decoded);
        Ok(pcm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MLS_EXPORTER_KEY: &[u8] = b"0123456789abcdef";

    #[test]
    fn opus_voice_round_trip_is_sframe_protected() {
        let sender = MediaFrameSender::new(4, 2, TEST_MLS_EXPORTER_KEY).unwrap();
        let receiver = MediaFrameReceiver::new(4, 2, TEST_MLS_EXPORTER_KEY).unwrap();
        let mut encoder = CallAudioEncoder::new(sender).unwrap();
        let mut decoder = CallAudioDecoder::new(receiver).unwrap();
        let pcm = (0..FRAME_SAMPLES)
            .map(|index| {
                (index as f32 * 440.0 * std::f32::consts::TAU / SAMPLE_RATE_HZ as f32).sin() * 0.2
            })
            .collect::<Vec<_>>();

        let protected = encoder.encode_and_protect(&pcm).unwrap();
        assert_ne!(
            protected,
            pcm.iter()
                .flat_map(|sample| sample.to_le_bytes())
                .collect::<Vec<_>>()
        );
        let decoded = decoder.unprotect_and_decode(&protected).unwrap();
        assert_eq!(decoded.len(), FRAME_SAMPLES);
        assert!(decoded.iter().any(|sample| sample.abs() > 0.01));
        assert!(decoder.unprotect_and_decode(&protected).is_err());
    }

    #[test]
    fn voice_encoder_rejects_wrong_frame_size_and_non_finite_samples() {
        let sender = MediaFrameSender::new(4, 2, TEST_MLS_EXPORTER_KEY).unwrap();
        let mut encoder = CallAudioEncoder::new(sender).unwrap();
        assert!(
            encoder
                .encode_and_protect(&[0.0; FRAME_SAMPLES - 1])
                .is_err()
        );
        let mut invalid = [0.0; FRAME_SAMPLES];
        invalid[0] = f32::NAN;
        assert!(encoder.encode_and_protect(&invalid).is_err());
    }
}
