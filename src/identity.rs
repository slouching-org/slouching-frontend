use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const DOMAIN: &[u8] = b"slouching/device-identity/mls-signing-key-binding";
pub const BINDING_VERSION: u16 = 1;

/// Proof that a device identity authorized one MLS signing key and scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsSigningKeyBinding {
    pub version: u16,
    pub device_public_key: [u8; 32],
    /// MLS SignatureScheme code point (the ciphersuite's signature scheme).
    pub signature_scheme: u16,
    pub mls_signing_public_key: Vec<u8>,
    pub signature: [u8; 64],
}

impl MlsSigningKeyBinding {
    pub(crate) fn sign(
        device_identity: &SigningKey,
        signature_scheme: u16,
        mls_signing_public_key: &[u8],
    ) -> Option<Self> {
        let mls_key_len = u32::try_from(mls_signing_public_key.len()).ok()?;
        if mls_signing_public_key.is_empty() {
            return None;
        }
        let device_public_key = device_identity.verifying_key().to_bytes();
        let payload = binding_payload(
            BINDING_VERSION,
            &device_public_key,
            signature_scheme,
            mls_signing_public_key,
            mls_key_len,
        );
        let signature = device_identity.sign(&payload).to_bytes();
        Some(Self {
            version: BINDING_VERSION,
            device_public_key,
            signature_scheme,
            mls_signing_public_key: mls_signing_public_key.to_vec(),
            signature,
        })
    }

    /// Verify both the expected long-term device key and its signed MLS-key binding.
    pub fn verify(&self, expected_device: &[u8; 32]) -> bool {
        if self.version != BINDING_VERSION
            || &self.device_public_key != expected_device
            || self.mls_signing_public_key.is_empty()
        {
            return false;
        }
        let Ok(mls_key_len) = u32::try_from(self.mls_signing_public_key.len()) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&self.device_public_key) else {
            return false;
        };
        let payload = binding_payload(
            self.version,
            &self.device_public_key,
            self.signature_scheme,
            &self.mls_signing_public_key,
            mls_key_len,
        );
        verifying_key
            .verify_strict(&payload, &Signature::from_bytes(&self.signature))
            .is_ok()
    }
}

fn binding_payload(
    version: u16,
    device_public_key: &[u8; 32],
    signature_scheme: u16,
    mls_signing_public_key: &[u8],
    mls_key_len: u32,
) -> Vec<u8> {
    let mut payload =
        Vec::with_capacity(DOMAIN.len() + 2 + 32 + 2 + 4 + mls_signing_public_key.len());
    payload.extend_from_slice(DOMAIN);
    payload.extend_from_slice(&version.to_be_bytes());
    payload.extend_from_slice(device_public_key);
    payload.extend_from_slice(&signature_scheme.to_be_bytes());
    payload.extend_from_slice(&mls_key_len.to_be_bytes());
    payload.extend_from_slice(mls_signing_public_key);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_verifies_and_rejects_tampering_or_another_device() {
        let device = SigningKey::from_bytes(&[7; 32]);
        let other_device = SigningKey::from_bytes(&[8; 32]);
        let binding = MlsSigningKeyBinding::sign(&device, 0x0807, &[3; 32]).unwrap();
        let device_public = device.verifying_key().to_bytes();
        assert!(binding.verify(&device_public));

        let mut changed_key = binding.clone();
        changed_key.mls_signing_public_key[0] ^= 1;
        assert!(!changed_key.verify(&device_public));

        let mut changed_scheme = binding.clone();
        changed_scheme.signature_scheme ^= 1;
        assert!(!changed_scheme.verify(&device_public));

        let mut changed_version = binding.clone();
        changed_version.version += 1;
        assert!(!changed_version.verify(&device_public));

        assert!(!binding.verify(&other_device.verifying_key().to_bytes()));
    }
}
