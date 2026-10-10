//! H.264 screen frames with per-frame SFrame protection from the call MLS group.
//!
//! This codec boundary does not own screen capture, WebRTC transport, or UI
//! rendering. Screen frames are bounded to keep the protected envelope usable
//! for real-time delivery and to avoid doing codec work on the Iced thread.

use crate::media::{MediaFrameReceiver, MediaFrameSender};
use openh264::{
    OpenH264API,
    decoder::Decoder,
    encoder::{BitRate, Encoder, EncoderConfig, FrameRate, UsageType},
    formats::{RgbaSliceU8, YUVBuffer, YUVSource},
};

const MAX_WIDTH: u32 = 960;
const MAX_HEIGHT: u32 = 540;
const MAX_INPUT_PIXELS: usize = 7_680 * 4_320;

#[derive(Debug, Clone)]
pub struct DecodedVideoFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

pub struct CallVideoEncoder {
    encoder: Encoder,
    protector: MediaFrameSender,
}

impl CallVideoEncoder {
    pub fn for_call_group(group_id: &[u8]) -> Result<Self, String> {
        Self::new(MediaFrameSender::from_call_group(group_id)?)
    }

    fn new(protector: MediaFrameSender) -> Result<Self, String> {
        let encoder = Encoder::with_api_config(
            OpenH264API::from_source(),
            EncoderConfig::new()
                .usage_type(UsageType::ScreenContentRealTime)
                .bitrate(BitRate::from_bps(300_000))
                .max_frame_rate(FrameRate::from_hz(5.0))
                .skip_frames(true),
        )
        .map_err(|error| format!("could not create H.264 screen encoder: {error}"))?;
        Ok(Self { encoder, protector })
    }

    /// Encode one RGBA screen image and protect the complete H.264 access unit.
    pub fn encode_and_protect(
        &mut self,
        width: u32,
        height: u32,
        rgba: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        validate_image(width, height, &rgba)?;
        let image = image_codec::RgbaImage::from_raw(width, height, rgba)
            .ok_or_else(|| "screen image buffer does not match its dimensions".to_owned())?;
        let (width, height, scaled) = scale_to_limit(image);
        let source = RgbaSliceU8::new(&scaled, (width as usize, height as usize));
        let yuv = YUVBuffer::from_rgb_source(source);
        let encoded = self
            .encoder
            .encode(&yuv)
            .map_err(|error| format!("could not encode H.264 screen frame: {error}"))?
            .to_vec();
        if encoded.is_empty() {
            return Err("H.264 encoder did not produce a complete screen frame".to_owned());
        }
        self.protector.encrypt(&encoded)
    }
}

pub struct CallVideoDecoder {
    decoder: Decoder,
    unprotector: MediaFrameReceiver,
}

impl CallVideoDecoder {
    pub fn for_call_group_member(
        group_id: &[u8],
        sender_device_public_key: &[u8; 32],
    ) -> Result<Self, String> {
        Self::new(MediaFrameReceiver::for_call_group_member(
            group_id,
            sender_device_public_key,
        )?)
    }

    fn new(unprotector: MediaFrameReceiver) -> Result<Self, String> {
        let decoder = Decoder::new()
            .map_err(|error| format!("could not create H.264 screen decoder: {error}"))?;
        Ok(Self {
            decoder,
            unprotector,
        })
    }

    /// Authenticate/decrypt one access unit before decoding the H.264 bytes.
    pub fn unprotect_and_decode(
        &mut self,
        protected: &[u8],
    ) -> Result<Option<DecodedVideoFrame>, String> {
        let encoded = self.unprotector.decrypt(protected)?;
        let Some(decoded) = self
            .decoder
            .decode(&encoded)
            .map_err(|error| format!("could not decode H.264 screen frame: {error}"))?
        else {
            return Ok(None);
        };
        let (width, height) = decoded.dimensions();
        let mut rgba = vec![0; width * height * 4];
        decoded.write_rgba8(&mut rgba);
        Ok(Some(DecodedVideoFrame {
            width: width as u32,
            height: height as u32,
            rgba,
        }))
    }
}

fn validate_image(width: u32, height: u32, rgba: &[u8]) -> Result<(), String> {
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| "screen image dimensions overflow".to_owned())?;
    if width < 2 || height < 2 || pixels > MAX_INPUT_PIXELS {
        return Err("screen image dimensions are outside the supported bounds".to_owned());
    }
    if rgba.len() != pixels.saturating_mul(4) {
        return Err("screen image buffer does not match its dimensions".to_owned());
    }
    Ok(())
}

fn scale_to_limit(image: image_codec::RgbaImage) -> (u32, u32, Vec<u8>) {
    let width = image.width();
    let height = image.height();
    let scale = (MAX_WIDTH as f32 / width as f32)
        .min(MAX_HEIGHT as f32 / height as f32)
        .min(1.0);
    let mut target_width = ((width as f32 * scale).floor() as u32).max(2) & !1;
    let mut target_height = ((height as f32 * scale).floor() as u32).max(2) & !1;
    target_width = target_width.min(MAX_WIDTH);
    target_height = target_height.min(MAX_HEIGHT);
    if target_width == width && target_height == height {
        return (width, height, image.into_raw());
    }
    let resized = image_codec::imageops::resize(
        &image,
        target_width,
        target_height,
        image_codec::imageops::FilterType::Triangle,
    );
    (target_width, target_height, resized.into_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MLS_EXPORTER_KEY: &[u8] = b"0123456789abcdef";

    #[test]
    fn h264_screen_access_unit_is_sframe_protected_and_decodes_after_authentication() {
        let mut rgba = vec![0_u8; 320 * 240 * 4];
        for y in 0..240 {
            for x in 0..320 {
                let offset = (y * 320 + x) * 4;
                rgba[offset] = (x % 256) as u8;
                rgba[offset + 1] = (y % 256) as u8;
                rgba[offset + 2] = 80;
                rgba[offset + 3] = 255;
            }
        }
        let mut encoder =
            CallVideoEncoder::new(MediaFrameSender::new(9, 1, TEST_MLS_EXPORTER_KEY).unwrap())
                .unwrap();
        let mut decoder =
            CallVideoDecoder::new(MediaFrameReceiver::new(9, 1, TEST_MLS_EXPORTER_KEY).unwrap())
                .unwrap();
        let original = rgba.clone();
        let protected = encoder.encode_and_protect(320, 240, rgba).unwrap();
        assert_ne!(protected, original);
        let decoded = decoder
            .unprotect_and_decode(&protected)
            .unwrap()
            .expect("first H.264 access unit should decode");
        assert_eq!((decoded.width, decoded.height), (320, 240));
        assert_eq!(decoded.rgba.len(), 320 * 240 * 4);
        assert!(decoder.unprotect_and_decode(&protected).is_err());

        let mut tampered_receiver =
            CallVideoDecoder::new(MediaFrameReceiver::new(9, 1, TEST_MLS_EXPORTER_KEY).unwrap())
                .unwrap();
        let mut tampered = protected;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(tampered_receiver.unprotect_and_decode(&tampered).is_err());
    }

    #[test]
    fn video_input_rejects_mismatched_and_oversized_buffers() {
        let mut encoder =
            CallVideoEncoder::new(MediaFrameSender::new(9, 1, TEST_MLS_EXPORTER_KEY).unwrap())
                .unwrap();
        assert!(encoder.encode_and_protect(4, 4, vec![0; 4]).is_err());
        assert!(validate_image(20_000, 20_000, &[]).is_err());
    }
}
