//! Short, symmetric safety codes for comparing two pinned device identities.

const DOMAIN: &[u8] = b"slouching-device-safety-code-v1\0";
const DECIMAL_SPACE: u64 = 1_000_000_000_000;

/// Derives a 12-digit comparison code from both device keys. The result is
/// identical on both devices and reveals no private key material.
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
    let digest = hasher.finalize();
    let prefix: [u8; 8] = digest.as_bytes()[..8]
        .try_into()
        .expect("eight-byte BLAKE3 prefix");
    let value = u64::from_be_bytes(prefix) % DECIMAL_SPACE;
    format!("{value:012}")
}

#[cfg(test)]
mod tests {
    use super::derive;

    #[test]
    fn safety_code_is_symmetric_and_twelve_digits() {
        let first = [0x11; 32];
        let second = [0x22; 32];
        let from_first = derive(&first, &second);
        assert_eq!(from_first, derive(&second, &first));
        assert_eq!(from_first.len(), 12);
        assert!(from_first.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn safety_code_binds_both_device_keys() {
        let first = [0x11; 32];
        let second = [0x22; 32];
        let third = [0x33; 32];
        assert_ne!(derive(&first, &second), derive(&first, &third));
        assert_ne!(derive(&first, &second), derive(&second, &third));
    }
}
