//! SFrame protection for encoded call-media frames.
//!
//! The caller must supply key material exported from the call's MLS group. Do
//! not use conversation-group secrets or device identity keys here. Networking,
//! capture, playback, and MLS call-group management are wired in later slices.

use sframe::{
    CipherSuite,
    frame::validation::{ReplayAttackProtection, Tolerance},
    frame::{EncryptedFrameView, MediaFrame, MonotonicCounter},
    header::KeyId,
    key::{DecryptionKey, EncryptionKey},
    mls::{MlsKeyId, MlsKeyIdBitRange},
};
use zeroize::Zeroizing;

const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm128Sha256;
const MAX_ENCODED_FRAME_BYTES: usize = 64 * 1024;
const MAX_SFRAME_OVERHEAD_BYTES: usize = 64;
const REPLAY_WINDOW_FRAMES: usize = 128;

fn make_mls_key_id(context_id: u64, epoch: u64, member_index: u64) -> Result<MlsKeyId, String> {
    let bit_range = MlsKeyIdBitRange::try_new(16, 8)
        .map_err(|error| format!("invalid SFrame MLS key ID format: {error}"))?;
    MlsKeyId::try_new(context_id, epoch, member_index, bit_range)
        .map_err(|error| format!("call epoch/member does not fit the SFrame key ID: {error}"))
}

fn validate_exporter_key(mls_exported_key: &[u8]) -> Result<(), String> {
    if mls_exported_key.len() != CIPHER_SUITE.key_len() {
        return Err(format!(
            "call MLS exporter must provide exactly {} bytes for the selected SFrame suite",
            CIPHER_SUITE.key_len()
        ));
    }
    Ok(())
}

pub struct MediaFrameSender {
    key: EncryptionKey,
    key_id: MlsKeyId,
    counter: MonotonicCounter,
}

impl MediaFrameSender {
    pub fn new(epoch: u64, member_index: u64, mls_exported_key: &[u8]) -> Result<Self, String> {
        validate_exporter_key(mls_exported_key)?;
        Self::with_context_id(epoch, member_index, random_context_id()?, mls_exported_key)
    }

    fn with_context_id(
        epoch: u64,
        member_index: u64,
        context_id: u64,
        mls_exported_key: &[u8],
    ) -> Result<Self, String> {
        validate_exporter_key(mls_exported_key)?;
        let key_id = make_mls_key_id(context_id, epoch, member_index)?;
        let key = EncryptionKey::derive_from(CIPHER_SUITE, key_id, mls_exported_key)
            .map_err(|error| format!("could not derive SFrame sender key: {error}"))?;
        Ok(Self {
            key,
            key_id,
            counter: MonotonicCounter::default(),
        })
    }

    pub fn key_id(&self) -> KeyId {
        KeyId::from(self.key_id)
    }

    pub fn context_id(&self) -> u64 {
        self.key_id.context_id()
    }

    pub fn encrypt(&mut self, encoded_frame: &[u8]) -> Result<Vec<u8>, String> {
        if encoded_frame.is_empty() || encoded_frame.len() > MAX_ENCODED_FRAME_BYTES {
            return Err("encoded media frame is empty or exceeds 64 KiB".to_owned());
        }
        let frame = MediaFrame::try_new(&mut self.counter, encoded_frame)
            .map_err(|error| format!("could not assign SFrame counter: {error}"))?;
        let encrypted = frame
            .encrypt(&self.key)
            .map_err(|error| format!("could not encrypt SFrame: {error}"))?;
        Ok(encrypted.as_ref().to_vec())
    }
}

pub struct MediaFrameReceiver {
    epoch: u64,
    member_index: u64,
    exporter_key: Option<Zeroizing<Vec<u8>>>,
    key_id: Option<KeyId>,
    key: Option<DecryptionKey>,
    replay_protection: Option<ReplayAttackProtection>,
}

impl MediaFrameReceiver {
    pub fn new(epoch: u64, member_index: u64, mls_exported_key: &[u8]) -> Result<Self, String> {
        validate_exporter_key(mls_exported_key)?;
        Ok(Self {
            epoch,
            member_index,
            exporter_key: Some(Zeroizing::new(mls_exported_key.to_vec())),
            key_id: None,
            key: None,
            replay_protection: None,
        })
    }

    pub fn decrypt(&mut self, encrypted_frame: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted_frame.len() > MAX_ENCODED_FRAME_BYTES + MAX_SFRAME_OVERHEAD_BYTES {
            return Err("encrypted media frame exceeds 64 KiB".to_owned());
        }
        let frame = EncryptedFrameView::try_new(encrypted_frame)
            .map_err(|error| format!("invalid SFrame header: {error}"))?;
        let key_id = frame.header().key_id();
        let bit_range = MlsKeyIdBitRange::try_new(16, 8)
            .map_err(|error| format!("invalid SFrame MLS key ID format: {error}"))?;
        let mls_key_id = MlsKeyId::from_key_id(key_id, bit_range);
        if mls_key_id.epoch_lsb() != (self.epoch & 0xffff)
            || mls_key_id.member_index() != self.member_index
        {
            return Err("SFrame key ID does not match the pinned MLS member and epoch".to_owned());
        }
        if self.key_id.is_some_and(|expected| expected != key_id) {
            return Err("SFrame sender context changed during this call session".to_owned());
        }

        if self.key.is_none() {
            let exporter_key = self
                .exporter_key
                .as_ref()
                .ok_or_else(|| "SFrame receiver exporter key was already cleared".to_owned())?;
            let key = DecryptionKey::derive_from(CIPHER_SUITE, key_id, exporter_key.as_slice())
                .map_err(|error| format!("could not derive SFrame receiver key: {error}"))?;
            let mut replay_protection =
                ReplayAttackProtection::new(key_id, Tolerance::new(REPLAY_WINDOW_FRAMES));
            let plaintext = frame
                .validated_decrypt(&key, &mut replay_protection)
                .map_err(|error| format!("SFrame authentication failed: {error}"))?;
            let payload = plaintext.payload().to_vec();
            self.exporter_key = None;
            self.key_id = Some(key_id);
            self.key = Some(key);
            self.replay_protection = Some(replay_protection);
            return Ok(payload);
        }

        let key = self
            .key
            .as_ref()
            .ok_or_else(|| "SFrame receiver key is unavailable".to_owned())?;
        let replay_protection = self
            .replay_protection
            .as_mut()
            .ok_or_else(|| "SFrame replay protection is unavailable".to_owned())?;
        let plaintext = frame
            .validated_decrypt(key, replay_protection)
            .map_err(|error| format!("SFrame rejected: {error}"))?;
        Ok(plaintext.payload().to_vec())
    }
}

fn random_context_id() -> Result<u64, String> {
    // The 16 epoch and 8 member bits leave 39 random bits for session uniqueness.
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("could not create a unique SFrame session context: {error}"))?;
    let random = u64::from_be_bytes(bytes);
    Ok(random & ((1_u64 << (MlsKeyIdBitRange::MAX - 16 - 8)) - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MLS_EXPORTER_KEY: &[u8] = b"0123456789abcdef";

    #[test]
    fn sframe_round_trip_encrypts_and_rejects_replayed_frames() {
        let mut sender =
            MediaFrameSender::with_context_id(7, 3, 99, TEST_MLS_EXPORTER_KEY).unwrap();
        let mut receiver = MediaFrameReceiver::new(7, 3, TEST_MLS_EXPORTER_KEY).unwrap();
        let encoded_opus_frame = [0x42, 0x19, 0xa7, 0x00, 0xff];

        let encrypted = sender.encrypt(&encoded_opus_frame).unwrap();
        assert_ne!(encrypted, encoded_opus_frame);
        assert_eq!(receiver.decrypt(&encrypted).unwrap(), encoded_opus_frame);
        assert!(receiver.decrypt(&encrypted).is_err());
    }

    #[test]
    fn sframe_rejects_wrong_key_id_and_wrong_mls_exporter_secret() {
        let mut sender =
            MediaFrameSender::with_context_id(7, 3, 99, TEST_MLS_EXPORTER_KEY).unwrap();
        let encrypted = sender.encrypt(b"encoded audio").unwrap();
        let mut wrong_sender = MediaFrameReceiver::new(7, 4, TEST_MLS_EXPORTER_KEY).unwrap();
        let mut wrong_group = MediaFrameReceiver::new(7, 3, b"differentkey1234").unwrap();

        assert!(wrong_sender.decrypt(&encrypted).is_err());
        assert!(wrong_group.decrypt(&encrypted).is_err());
    }

    #[test]
    fn sframe_rejects_empty_and_oversized_media_frames() {
        let mut sender =
            MediaFrameSender::with_context_id(7, 3, 99, TEST_MLS_EXPORTER_KEY).unwrap();
        assert!(sender.encrypt(&[]).is_err());
        assert!(
            sender
                .encrypt(&vec![0; MAX_ENCODED_FRAME_BYTES + 1])
                .is_err()
        );

        let mut receiver = MediaFrameReceiver::new(7, 3, TEST_MLS_EXPORTER_KEY).unwrap();
        assert!(
            receiver
                .decrypt(&vec![0; MAX_ENCODED_FRAME_BYTES + 33])
                .is_err()
        );
    }

    #[test]
    fn sframe_key_id_binds_epoch_and_member_and_bounds_member_count() {
        let member_a = make_mls_key_id(99, 12, 1).unwrap();
        let member_b = make_mls_key_id(99, 12, 2).unwrap();
        let next_epoch = make_mls_key_id(99, 13, 1).unwrap();
        let next_context = make_mls_key_id(100, 12, 1).unwrap();
        assert_ne!(KeyId::from(member_a), KeyId::from(member_b));
        assert_ne!(KeyId::from(member_a), KeyId::from(next_epoch));
        assert_ne!(KeyId::from(member_a), KeyId::from(next_context));
        assert!(make_mls_key_id(0, 12, 256).is_err());
    }

    #[test]
    fn sframe_rejects_wrong_exporter_key_length() {
        assert!(MediaFrameSender::new(1, 0, b"too short").is_err());
        assert!(MediaFrameReceiver::new(1, 0, b"too short").is_err());
    }

    #[test]
    fn sender_uses_a_fresh_context_for_each_new_instance() {
        let first = MediaFrameSender::new(7, 3, TEST_MLS_EXPORTER_KEY).unwrap();
        let second = MediaFrameSender::new(7, 3, TEST_MLS_EXPORTER_KEY).unwrap();
        assert_ne!(first.key_id(), second.key_id());
    }

    #[test]
    fn receiver_rejects_a_new_sender_context_mid_session() {
        let mut first_sender =
            MediaFrameSender::with_context_id(7, 3, 99, TEST_MLS_EXPORTER_KEY).unwrap();
        let mut replacement_sender =
            MediaFrameSender::with_context_id(7, 3, 100, TEST_MLS_EXPORTER_KEY).unwrap();
        let mut receiver = MediaFrameReceiver::new(7, 3, TEST_MLS_EXPORTER_KEY).unwrap();

        let first_frame = first_sender.encrypt(b"first frame").unwrap();
        assert_eq!(receiver.decrypt(&first_frame).unwrap(), b"first frame");
        let replaced_frame = replacement_sender.encrypt(b"replacement frame").unwrap();
        assert!(receiver.decrypt(&replaced_frame).is_err());
    }
}
