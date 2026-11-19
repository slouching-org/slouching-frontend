//! Full, symmetric fingerprints for comparing two pinned device identities.

const DOMAIN: &[u8] = b"slouching-device-pair-fingerprint-v1\0";
/// Derives a full 256-bit comparison fingerprint from both public device keys.
/// The result is identical on both devices and reveals no private key material.
pub fn derive(local_device: &[u8; 32], peer_device: &[u8; 32]) -> String {
    let (first, second) = if local_device <= peer_device {
        (local_device, peer_device)
    } else {
        (peer_device, local_device)
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(first);
    hasher.update(second);
    hex::encode(hasher.finalize().as_bytes())
}

/// Formats a fingerprint as four short groups per line for live comparison.
pub fn display(fingerprint: &str) -> String {
    let mut formatted = String::with_capacity(fingerprint.len());
    for (index, character) in fingerprint.chars().enumerate() {
        if index > 0 {
            if index % 16 == 0 {
                formatted.push('\n');
            } else if index % 4 == 0 {
                formatted.push(' ');
            }
        }
        formatted.push(character);
    }
    formatted
}

#[cfg(test)]
mod tests {
    use super::{derive, display};

    #[test]
    fn minimized_utf8_fingerprint_formats_without_splitting_a_character() {
        let input = "@$[\u{0380}";
        assert_eq!(input.len(), 5);
        assert_eq!(display(input), input);
        assert_eq!(display("abcédefghijklmnopq"), "abcé defg hijk lmno\npq");
    }

    #[test]
    fn fingerprint_display_preserves_ascii_grouping() {
        assert_eq!(display(""), "");
        assert_eq!(display("0123456789abcdef0123"), "0123 4567 89ab cdef\n0123");
    }

    #[test]
    fn fingerprint_is_symmetric_and_full_length() {
        let first = [0x11; 32];
        let second = [0x22; 32];
        let from_first = derive(&first, &second);
        assert_eq!(from_first, derive(&second, &first));
        assert_eq!(from_first.len(), 64);
        assert!(from_first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(display(&from_first).lines().count(), 4);
    }

    #[test]
    fn fingerprint_binds_both_device_keys() {
        let first = [0x11; 32];
        let second = [0x22; 32];
        let third = [0x33; 32];
        assert_ne!(derive(&first, &second), derive(&first, &third));
        assert_ne!(derive(&first, &second), derive(&second, &third));
    }
}
