//! Ephemeral end-to-end protected room chat carried by the call DataChannel.

use crate::media::{MediaFrameReceiver, MediaFrameSender};

const MAX_ROOM_MESSAGE_BYTES: usize = 4096;
const WIRE_MARKER: &[u8; 4] = b"SLCT";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomMessage {
    pub local: bool,
    pub text: String,
}

pub fn frame_ciphertext(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_ROOM_MESSAGE_BYTES + 64 {
        return Err("protected call message is outside its byte limit".to_owned());
    }
    let mut frame = Vec::with_capacity(WIRE_MARKER.len() + ciphertext.len());
    frame.extend_from_slice(WIRE_MARKER);
    frame.extend_from_slice(ciphertext);
    Ok(frame)
}

pub fn ciphertext_from_frame(frame: &[u8]) -> Option<&[u8]> {
    frame
        .strip_prefix(WIRE_MARKER)
        .filter(|ciphertext| !ciphertext.is_empty())
}

pub struct CallChatSender {
    protector: MediaFrameSender,
}

impl CallChatSender {
    pub fn for_call_group(group_id: &[u8]) -> Result<Self, String> {
        Ok(Self {
            protector: MediaFrameSender::from_call_group(group_id)?,
        })
    }

    pub fn encrypt(&mut self, message: &str) -> Result<Vec<u8>, String> {
        let bytes = message.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_ROOM_MESSAGE_BYTES {
            return Err("call message must contain 1 to 4096 UTF-8 bytes".to_owned());
        }
        self.protector.encrypt(bytes)
    }
}

pub struct CallChatReceiver {
    unprotector: MediaFrameReceiver,
}

impl CallChatReceiver {
    pub fn for_call_group_member(
        group_id: &[u8],
        sender_device_public_key: &[u8; 32],
    ) -> Result<Self, String> {
        Ok(Self {
            unprotector: MediaFrameReceiver::for_call_group_member(
                group_id,
                sender_device_public_key,
            )?,
        })
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<String, String> {
        let plaintext = self.unprotector.decrypt(ciphertext)?;
        if plaintext.is_empty() || plaintext.len() > MAX_ROOM_MESSAGE_BYTES {
            return Err("decrypted call message is outside the 1 to 4096 byte limit".to_owned());
        }
        String::from_utf8(plaintext).map_err(|_| "decrypted call message is not UTF-8".to_owned())
    }
}

#[cfg(test)]
pub(crate) fn test_sender_receiver() -> Result<(CallChatSender, CallChatReceiver), String> {
    Ok((
        CallChatSender {
            protector: MediaFrameSender::new(9, 1, b"0123456789abcdef")?,
        },
        CallChatReceiver {
            unprotector: MediaFrameReceiver::new(9, 1, b"0123456789abcdef")?,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_chat_is_encrypted_authenticated_and_replay_protected() {
        let (mut sender, mut receiver) = test_sender_receiver().unwrap();
        let ciphertext = sender.encrypt("mensagem só desta chamada").unwrap();
        assert!(
            !ciphertext
                .windows("mensagem só desta chamada".len())
                .any(|window| window == "mensagem só desta chamada".as_bytes())
        );
        assert_eq!(
            receiver.decrypt(&ciphertext).unwrap(),
            "mensagem só desta chamada"
        );
        assert!(receiver.decrypt(&ciphertext).is_err());

        let (mut sender, mut receiver) = test_sender_receiver().unwrap();
        let mut tampered = sender.encrypt("não altere").unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(receiver.decrypt(&tampered).is_err());
    }

    #[test]
    fn room_chat_rejects_empty_and_oversized_messages() {
        let (mut sender, _) = test_sender_receiver().unwrap();
        assert!(sender.encrypt("").is_err());
        assert!(
            sender
                .encrypt(&"x".repeat(MAX_ROOM_MESSAGE_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn wire_frame_marks_only_bounded_ciphertext_as_room_chat() {
        let frame = frame_ciphertext(b"protected").unwrap();
        assert_eq!(ciphertext_from_frame(&frame), Some(b"protected".as_slice()));
        assert!(ciphertext_from_frame(b"SLCT").is_none());
        assert!(ciphertext_from_frame(b"SLVFprotected").is_none());
        assert!(frame_ciphertext(&[]).is_err());
        assert!(frame_ciphertext(&vec![0; MAX_ROOM_MESSAGE_BYTES + 65]).is_err());
    }
}
