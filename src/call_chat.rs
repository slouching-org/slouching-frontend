//! Ephemeral end-to-end protected room chat carried by the call DataChannel.

use crate::media::{MediaFrameReceiver, MediaFrameSender};
use std::collections::HashMap;

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
    epoch: u64,
    unprotectors: HashMap<u64, MediaFrameReceiver>,
}

impl CallChatReceiver {
    pub fn for_call_group_member(
        group_id: &[u8],
        sender_device_public_key: &[u8; 32],
    ) -> Result<Self, String> {
        Self::for_call_group_members(group_id, std::slice::from_ref(sender_device_public_key))
    }

    pub fn for_call_group_members(
        group_id: &[u8],
        sender_device_public_keys: &[[u8; 32]],
    ) -> Result<Self, String> {
        let context = crate::storage::load_call_media_context(group_id)?;
        let mut unprotectors = HashMap::with_capacity(sender_device_public_keys.len());
        for device_key in sender_device_public_keys {
            let member = context
                .members
                .iter()
                .find(|member| &member.device_public_key == device_key)
                .ok_or_else(|| "SFrame sender is not a member of this call MLS group".to_owned())?;
            if member.index == context.local_member_index
                || unprotectors.contains_key(&member.index)
            {
                return Err("call chat sender list contains a duplicate or local member".to_owned());
            }
            unprotectors.insert(
                member.index,
                MediaFrameReceiver::new(context.epoch, member.index, context.base_key.as_slice())?,
            );
        }
        if unprotectors.is_empty() {
            return Err("call chat requires at least one remote member".to_owned());
        }
        Ok(Self {
            epoch: context.epoch,
            unprotectors,
        })
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<String, String> {
        let member_index = MediaFrameReceiver::sender_member_index(self.epoch, ciphertext)?;
        let receiver = self
            .unprotectors
            .get_mut(&member_index)
            .ok_or_else(|| "call chat sender is not a remote call MLS member".to_owned())?;
        let plaintext = receiver.decrypt(ciphertext)?;
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
            epoch: 9,
            unprotectors: HashMap::from([(1, MediaFrameReceiver::new(9, 1, b"0123456789abcdef")?)]),
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
    fn room_chat_selects_independent_receivers_for_each_remote_member() {
        let mut sender_a = CallChatSender {
            protector: MediaFrameSender::new(9, 2, b"0123456789abcdef").unwrap(),
        };
        let mut sender_b = CallChatSender {
            protector: MediaFrameSender::new(9, 3, b"0123456789abcdef").unwrap(),
        };
        let mut unauthorized_sender = CallChatSender {
            protector: MediaFrameSender::new(9, 4, b"0123456789abcdef").unwrap(),
        };
        let mut receiver = CallChatReceiver {
            epoch: 9,
            unprotectors: HashMap::from([
                (
                    2,
                    MediaFrameReceiver::new(9, 2, b"0123456789abcdef").unwrap(),
                ),
                (
                    3,
                    MediaFrameReceiver::new(9, 3, b"0123456789abcdef").unwrap(),
                ),
            ]),
        };
        let message_a = sender_a.encrypt("fala A").unwrap();
        let message_b = sender_b.encrypt("fala B").unwrap();
        let unauthorized = unauthorized_sender.encrypt("fora do roster").unwrap();

        assert_eq!(receiver.decrypt(&message_a).unwrap(), "fala A");
        assert_eq!(receiver.decrypt(&message_b).unwrap(), "fala B");
        assert!(receiver.decrypt(&message_a).is_err());
        assert!(receiver.decrypt(&unauthorized).is_err());
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
