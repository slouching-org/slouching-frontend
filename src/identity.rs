use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const DOMAIN: &[u8] = b"slouching/device-identity/mls-signing-key-binding";
const CONTACT_PAIRING_IDENTITY_DOMAIN: &[u8] = b"slouching/contact-pairing/device-identity/v1\0";
const SERIALIZED_BINDING_MAGIC: &[u8; 4] = b"SLMB";
const MAX_SERIALIZED_MLS_KEY_BYTES: usize = 16 * 1024;
pub const BINDING_VERSION: u16 = 1;

/// Public device key signed for one fresh, confirmed contact-pairing transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactIdentityProof {
    pub device_key: [u8; 32],
    pub signature: [u8; 64],
}

impl ContactIdentityProof {
    pub fn sign(identity: &SigningKey, transcript_hash: &[u8; 32]) -> Self {
        let device_key = identity.verifying_key().to_bytes();
        let signature = identity.sign(&contact_pairing_identity_payload(
            &device_key,
            transcript_hash,
        ));
        Self {
            device_key,
            signature: signature.to_bytes(),
        }
    }

    #[allow(dead_code)]
    pub fn verify(&self, transcript_hash: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.device_key) else {
            return false;
        };
        key.verify_strict(
            &contact_pairing_identity_payload(&self.device_key, transcript_hash),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

fn contact_pairing_identity_payload(device_key: &[u8; 32], transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(CONTACT_PAIRING_IDENTITY_DOMAIN.len() + 64);
    payload.extend_from_slice(CONTACT_PAIRING_IDENTITY_DOMAIN);
    payload.extend_from_slice(transcript_hash);
    payload.extend_from_slice(device_key);
    payload
}

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

    /// Verify that this device authorized the MLS key actually carried by a credential.
    pub fn verifies_mls_credential(
        &self,
        expected_device: &[u8; 32],
        signature_scheme: u16,
        mls_signing_public_key: &[u8],
    ) -> bool {
        self.signature_scheme == signature_scheme
            && self.mls_signing_public_key == mls_signing_public_key
            && self.verify(expected_device)
    }

    /// Encode a bounded, versioned representation for an MLS BasicCredential.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let mls_key_len = u32::try_from(self.mls_signing_public_key.len()).ok()?;
        if self.mls_signing_public_key.is_empty()
            || self.mls_signing_public_key.len() > MAX_SERIALIZED_MLS_KEY_BYTES
        {
            return None;
        }
        let mut encoded = Vec::with_capacity(
            SERIALIZED_BINDING_MAGIC.len()
                + 2
                + 2
                + 32
                + 4
                + self.mls_signing_public_key.len()
                + 64,
        );
        encoded.extend_from_slice(SERIALIZED_BINDING_MAGIC);
        encoded.extend_from_slice(&self.version.to_be_bytes());
        encoded.extend_from_slice(&self.signature_scheme.to_be_bytes());
        encoded.extend_from_slice(&self.device_public_key);
        encoded.extend_from_slice(&mls_key_len.to_be_bytes());
        encoded.extend_from_slice(&self.mls_signing_public_key);
        encoded.extend_from_slice(&self.signature);
        Some(encoded)
    }

    /// Decode the canonical credential representation, rejecting trailing or oversized data.
    pub fn from_bytes(encoded: &[u8]) -> Option<Self> {
        const FIXED_LEN: usize = 4 + 2 + 2 + 32 + 4 + 64;
        if encoded.len() < FIXED_LEN || &encoded[..4] != SERIALIZED_BINDING_MAGIC {
            return None;
        }
        let version = u16::from_be_bytes(encoded[4..6].try_into().ok()?);
        if version != BINDING_VERSION {
            return None;
        }
        let signature_scheme = u16::from_be_bytes(encoded[6..8].try_into().ok()?);
        let device_public_key = encoded[8..40].try_into().ok()?;
        let mls_key_len =
            usize::try_from(u32::from_be_bytes(encoded[40..44].try_into().ok()?)).ok()?;
        if mls_key_len == 0 || mls_key_len > MAX_SERIALIZED_MLS_KEY_BYTES {
            return None;
        }
        let expected_len = FIXED_LEN.checked_add(mls_key_len)?;
        if encoded.len() != expected_len {
            return None;
        }
        let mls_key_end = 44 + mls_key_len;
        let mls_signing_public_key = encoded[44..mls_key_end].to_vec();
        let signature = encoded[mls_key_end..].try_into().ok()?;
        Some(Self {
            version,
            device_public_key,
            signature_scheme,
            mls_signing_public_key,
            signature,
        })
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

    #[test]
    fn binding_credential_encoding_is_bounded_canonical_and_verifiable() {
        let device = SigningKey::from_bytes(&[0x37; 32]);
        let binding = MlsSigningKeyBinding::sign(&device, 0x0807, &[0x51; 32]).unwrap();
        let encoded = binding.to_bytes().expect("binding should encode");
        assert_eq!(
            MlsSigningKeyBinding::from_bytes(&encoded),
            Some(binding.clone())
        );
        assert!(binding.verify(&device.verifying_key().to_bytes()));
        assert!(binding.verifies_mls_credential(
            &device.verifying_key().to_bytes(),
            0x0807,
            &[0x51; 32]
        ));
        assert!(!binding.verifies_mls_credential(
            &device.verifying_key().to_bytes(),
            0x0808,
            &[0x51; 32]
        ));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(MlsSigningKeyBinding::from_bytes(&trailing).is_none());

        let mut wrong_version = encoded;
        wrong_version[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert!(MlsSigningKeyBinding::from_bytes(&wrong_version).is_none());
    }
}
