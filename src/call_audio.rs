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

pub trait AudioSink: Send + Sync + 'static {
    fn push_mono(&self, samples: &[f32]);
}

pub struct CallAudioEncoder {
    encoder: opus::Encoder,
    protector: MediaFrameSender,
}

/// Incrementally converts CPAL mono chunks to the 48 kHz, 20 ms frames Opus
/// expects. Linear interpolation is used to match the device's default rate.
pub struct VoiceFrameAssembler {
    input_rate: u32,
    next_input_position: f64,
    input: Vec<f32>,
    pending: Vec<f32>,
}

impl VoiceFrameAssembler {
    pub fn new(input_rate: u32) -> Result<Self, String> {
        if input_rate == 0 {
            return Err("microphone sample rate must be greater than zero".to_owned());
        }
        Ok(Self {
            input_rate,
            next_input_position: 0.0,
            input: Vec::new(),
            pending: Vec::with_capacity(FRAME_SAMPLES * 2),
        })
    }

    pub fn push(&mut self, mono_samples: &[f32]) -> Result<Vec<Vec<f32>>, String> {
        if mono_samples.iter().any(|sample| !sample.is_finite()) {
            return Err("microphone chunk contains a non-finite sample".to_owned());
        }
        self.input.extend_from_slice(mono_samples);
        let step = self.input_rate as f64 / SAMPLE_RATE_HZ as f64;
        while self.next_input_position + 1.0 < self.input.len() as f64 {
            let left_index = self.next_input_position.floor() as usize;
            let fraction = (self.next_input_position - left_index as f64) as f32;
            let left = self.input[left_index];
            let right = self.input[left_index + 1];
            self.pending.push(left + (right - left) * fraction);
            self.next_input_position += step;
        }
        let consumed = self.next_input_position.floor() as usize;
        if consumed > 0 {
            self.input.drain(..consumed);
            self.next_input_position -= consumed as f64;
        }

        let complete_frames = self.pending.len() / FRAME_SAMPLES;
        let mut frames = Vec::with_capacity(complete_frames);
        for _ in 0..complete_frames {
            frames.push(self.pending.drain(..FRAME_SAMPLES).collect());
        }
        Ok(frames)
    }
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

/// Receives protected audio from every other member of a call MLS group.
/// Each sender needs an independent replay window and stateful Opus decoder.
pub struct CallAudioDecoderSet {
    decoders: Vec<CallAudioDecoder>,
}

impl CallAudioDecoderSet {
    pub(crate) fn for_call_group(group_id: &[u8]) -> Result<Self, String> {
        let context = crate::storage::load_call_media_context(group_id)?;
        let decoders = context
            .members
            .iter()
            .filter(|member| member.index != context.local_member_index)
            .map(|member| {
                CallAudioDecoder::new(MediaFrameReceiver::new(
                    context.epoch,
                    member.index,
                    context.base_key.as_slice(),
                )?)
            })
            .collect::<Result<Vec<_>, String>>()?;
        if decoders.is_empty() {
            return Err("call MLS group has no remote audio members".to_owned());
        }
        Ok(Self { decoders })
    }

    #[cfg(test)]
    pub(crate) fn new(decoders: Vec<CallAudioDecoder>) -> Result<Self, String> {
        if decoders.is_empty() {
            return Err("call audio decoder set cannot be empty".to_owned());
        }
        Ok(Self { decoders })
    }

    /// The SFrame member index selects the decoder, preserving per-speaker
    /// replay protection and Opus state while rejecting unknown senders.
    pub fn unprotect_and_decode(&mut self, protected: &[u8]) -> Result<Vec<f32>, String> {
        let mut last_error = None;
        for decoder in &mut self.decoders {
            match decoder.unprotect_and_decode(protected) {
                Ok(pcm) => return Ok(pcm),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| "call has no remote audio decoder".to_owned()))
    }
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
    fn decoder_set_receives_multiple_members_with_independent_replay_windows() {
        let mut sender_a =
            CallAudioEncoder::new(MediaFrameSender::new(4, 2, TEST_MLS_EXPORTER_KEY).unwrap())
                .unwrap();
        let mut sender_b =
            CallAudioEncoder::new(MediaFrameSender::new(4, 3, TEST_MLS_EXPORTER_KEY).unwrap())
                .unwrap();
        let mut receivers = CallAudioDecoderSet::new(vec![
            CallAudioDecoder::new(MediaFrameReceiver::new(4, 2, TEST_MLS_EXPORTER_KEY).unwrap())
                .unwrap(),
            CallAudioDecoder::new(MediaFrameReceiver::new(4, 3, TEST_MLS_EXPORTER_KEY).unwrap())
                .unwrap(),
        ])
        .unwrap();
        let pcm = [0.1; FRAME_SAMPLES];
        let frame_a = sender_a.encode_and_protect(&pcm).unwrap();
        let frame_b = sender_b.encode_and_protect(&pcm).unwrap();

        assert_eq!(
            receivers.unprotect_and_decode(&frame_a).unwrap().len(),
            FRAME_SAMPLES
        );
        assert!(receivers.unprotect_and_decode(&frame_a).is_err());
        assert_eq!(
            receivers.unprotect_and_decode(&frame_b).unwrap().len(),
            FRAME_SAMPLES
        );
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

    #[test]
    fn frame_assembler_resamples_and_handles_callback_boundaries() {
        let mut assembler = VoiceFrameAssembler::new(44_100).unwrap();
        let mut frames = Vec::new();
        for _ in 0..3 {
            frames.extend(assembler.push(&[0.25; 441]).unwrap());
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), FRAME_SAMPLES);
        assert!(
            frames[0]
                .iter()
                .all(|sample| (*sample - 0.25).abs() < 0.001)
        );
    }

    #[test]
    fn frame_assembler_rejects_invalid_sample_rates_and_nan_audio() {
        assert!(VoiceFrameAssembler::new(0).is_err());
        let mut assembler = VoiceFrameAssembler::new(48_000).unwrap();
        assert!(assembler.push(&[f32::NAN]).is_err());
    }
}
