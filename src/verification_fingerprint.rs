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
    fingerprint
        .as_bytes()
        .chunks(16)
        .map(|line| {
            line.chunks(4)
                .map(|group| std::str::from_utf8(group).expect("hex fingerprint is ASCII"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{derive, display};

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
