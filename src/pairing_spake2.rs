//! Experimental cryptographic building blocks for the future contact-pairing flow.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::{Zeroize, Zeroizing};

pub use crate::identity::ContactIdentityProof;

const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_SYMBOLS: usize = 20;
const CODE_BYTES: usize = 13;
const SPAKE2_MESSAGE_BYTES: usize = 33;
const PAIRING_ID: &[u8] = b"slouching/contact-pairing/v1";
const KEY_DOMAIN: &[u8] = b"slouching/contact-pairing/session-key/v1\0";
const CONFIRM_DOMAIN: &[u8] = b"slouching/contact-pairing/key-confirmation/v1\0";
const IDENTITY_AAD_DOMAIN: &[u8] = b"slouching/contact-pairing/encrypted-identity/v1\0";
const IDENTITY_MAGIC: &[u8; 4] = b"SLPI";
const IDENTITY_ENVELOPE_BYTES: usize = 128;
const IDENTITY_PLAINTEXT_BYTES: usize = 100;

/// A one-time code with 100 bits of entropy, formatted in four-character groups.
pub struct PairingCode(Zeroizing<String>);

impl PairingCode {
    /// Generate a code from the operating system cryptographic random source.
    pub fn generate() -> Result<Self, String> {
        let mut random = [0_u8; CODE_BYTES];
        getrandom::fill(&mut random)
            .map_err(|error| format!("could not generate a pairing code: {error}"))?;

        // Encode exactly 100 random bits as 20 Crockford Base32 symbols.
        let mut encoded = String::with_capacity(CODE_SYMBOLS + 4);
        for symbol in 0..CODE_SYMBOLS {
            let bit_offset = symbol * 5;
            let byte_offset = bit_offset / 8;
            let shift = bit_offset % 8;
            let window = (u16::from(random[byte_offset]) << 8)
                | u16::from(*random.get(byte_offset + 1).unwrap_or(&0));
            let value = ((window >> (11 - shift)) & 0x1f) as usize;
            if symbol > 0 && symbol % 5 == 0 {
                encoded.push('-');
            }
            encoded.push(CODE_ALPHABET[value] as char);
        }
        random.zeroize();
        Ok(Self(Zeroizing::new(encoded)))
    }

    /// Parse a displayed code, accepting ASCII lowercase and optional hyphens.
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.len() > 64 {
            return Err("pairing code exceeds the input limit".to_owned());
        }
        let normalized: String = value
            .bytes()
            .filter(|byte| *byte != b'-' && !byte.is_ascii_whitespace())
            .map(|byte| byte.to_ascii_uppercase() as char)
            .collect();
        if normalized.len() != CODE_SYMBOLS
            || !normalized.bytes().all(|byte| CODE_ALPHABET.contains(&byte))
        {
            return Err("pairing code must contain 20 Crockford Base32 symbols".to_owned());
        }
        let formatted = normalized
            .as_bytes()
            .chunks(5)
            .map(|part| std::str::from_utf8(part).expect("validated ASCII code"))
            .collect::<Vec<_>>()
            .join("-");
        Ok(Self(Zeroizing::new(formatted)))
    }

    /// Return the grouped code suitable for display or explicit copy.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    fn password(&self) -> Password {
        let compact: String = self
            .0
            .chars()
            .filter(|character| *character != '-')
            .collect();
        Password::new(compact.as_bytes())
    }
}

/// One side of an in-memory SPAKE2 exchange. It is single-use.
pub struct PairingExchange {
    state: Spake2<Ed25519Group>,
    local_message: Vec<u8>,
}

/// SPAKE2 output that cannot derive application keys until confirmed by the peer.
pub struct PairingSession {
    key: Zeroizing<[u8; 32]>,
    confirmation: [u8; 32],
    transcript_hash: [u8; 32],
}

/// Key material available only after the peer proves it derived the same secret.
pub struct ConfirmedPairingSession {
    key: Zeroizing<[u8; 32]>,
    transcript_hash: [u8; 32],
}

impl PairingSession {
    /// The tag the other participant must return over the rendezvous channel.
    pub fn confirmation_tag(&self) -> [u8; 32] {
        self.confirmation
    }

    /// Require the peer's matching confirmation tag before releasing key use.
    pub fn confirm(self, peer_tag: &[u8]) -> Result<ConfirmedPairingSession, String> {
        if peer_tag.len() != self.confirmation.len() {
            return Err("peer key confirmation has an invalid size".to_owned());
        }
        let matches = self
            .confirmation
            .iter()
            .zip(peer_tag)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0;
        if !matches {
            return Err("peer did not confirm the pairing code".to_owned());
        }
        Ok(ConfirmedPairingSession {
            key: self.key,
            transcript_hash: self.transcript_hash,
        })
    }
}

impl ConfirmedPairingSession {
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }

    /// Encrypt the signed device proof so the rendezvous sees only opaque bytes.
    pub fn seal_identity_proof(
        &self,
        proof: &ContactIdentityProof,
    ) -> Result<[u8; IDENTITY_ENVELOPE_BYTES], String> {
        if !proof.verify(&self.transcript_hash) {
            return Err("device identity proof does not match this pairing transcript".to_owned());
        }
        let mut plaintext = Zeroizing::new([0_u8; IDENTITY_PLAINTEXT_BYTES]);
        plaintext[..4].copy_from_slice(IDENTITY_MAGIC);
        plaintext[4..36].copy_from_slice(&proof.device_key);
        plaintext[36..].copy_from_slice(&proof.signature);

        let key = Zeroizing::new(self.derive_key(b"contact-identity-envelope")?);
        let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| "could not initialize the identity envelope cipher".to_owned())?;
        let mut nonce_bytes = [0_u8; 12];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|error| format!("could not generate an identity envelope nonce: {error}"))?;
        let aad = identity_aad(&self.transcript_hash);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| "could not encrypt the device identity proof".to_owned())?;
        if ciphertext.len() != IDENTITY_ENVELOPE_BYTES - nonce_bytes.len() {
            return Err("encrypted identity proof has an unexpected size".to_owned());
        }
        let mut envelope = [0_u8; IDENTITY_ENVELOPE_BYTES];
        envelope[..nonce_bytes.len()].copy_from_slice(&nonce_bytes);
        envelope[nonce_bytes.len()..].copy_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Decrypt and verify the device proof for this transcript.
    pub fn open_identity_proof(&self, envelope: &[u8]) -> Result<ContactIdentityProof, String> {
        if envelope.len() != IDENTITY_ENVELOPE_BYTES {
            return Err("encrypted device identity has an invalid size".to_owned());
        }
        let key = Zeroizing::new(self.derive_key(b"contact-identity-envelope")?);
        let cipher = ChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| "could not initialize the identity envelope cipher".to_owned())?;
        let aad = identity_aad(&self.transcript_hash);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&envelope[..12]),
                    Payload {
                        msg: &envelope[12..],
                        aad: &aad,
                    },
                )
                .map_err(|_| "encrypted device identity failed authentication".to_owned())?,
        );
        if plaintext.len() != IDENTITY_PLAINTEXT_BYTES || &plaintext[..4] != IDENTITY_MAGIC {
            return Err("encrypted device identity has an unsupported format".to_owned());
        }
        let proof = ContactIdentityProof {
            device_key: plaintext[4..36]
                .try_into()
                .map_err(|_| "device identity key has an invalid size".to_owned())?,
            signature: plaintext[36..]
                .try_into()
                .map_err(|_| "device identity signature has an invalid size".to_owned())?,
        };
        if !proof.verify(&self.transcript_hash) {
            return Err("device identity signature is invalid for this pairing".to_owned());
        }
        Ok(proof)
    }

    /// Derive a purpose-specific key after successful key confirmation.
    pub fn derive_key(&self, purpose: &[u8]) -> Result<[u8; 32], String> {
        if purpose.is_empty() || purpose.len() > 128 {
            return Err("key purpose must contain 1 to 128 bytes".to_owned());
        }
        let mut context = Vec::with_capacity(KEY_DOMAIN.len() + purpose.len());
        context.extend_from_slice(KEY_DOMAIN);
        context.extend_from_slice(purpose);
        let key = blake3::keyed_hash(&self.key, &context);
        Ok(*key.as_bytes())
    }
}

impl PairingExchange {
    /// Start SPAKE2 and return the bounded message to send to the other side.
    pub fn start(code: &PairingCode) -> Self {
        let (state, local_message) =
            Spake2::<Ed25519Group>::start_symmetric(&code.password(), &Identity::new(PAIRING_ID));
        Self {
            state,
            local_message,
        }
    }

    pub fn outbound_message(&self) -> &[u8] {
        &self.local_message
    }

    /// Finish with the peer message and bind the result to both exchanged messages.
    pub fn finish(self, peer_message: &[u8]) -> Result<PairingSession, String> {
        if peer_message.len() != SPAKE2_MESSAGE_BYTES
            || self.local_message.len() != SPAKE2_MESSAGE_BYTES
        {
            return Err("invalid SPAKE2 message size".to_owned());
        }
        let mut spake_key = Zeroizing::new(
            self.state
                .finish(peer_message)
                .map_err(|error| format!("invalid SPAKE2 message: {error:?}"))?,
        );
        if spake_key.len() != 32 {
            return Err("SPAKE2 returned an unexpected key length".to_owned());
        }

        let (first, second) = if self.local_message.as_slice() <= peer_message {
            (self.local_message.as_slice(), peer_message)
        } else {
            (peer_message, self.local_message.as_slice())
        };
        let mut transcript = blake3::Hasher::new_derive_key("slouching SPAKE2 transcript v1");
        transcript.update(PAIRING_ID);
        transcript.update(first);
        transcript.update(second);

        let mut session_key = Zeroizing::new([0_u8; 32]);
        let transcript_hash = *transcript.finalize().as_bytes();
        let mut key_context = Vec::with_capacity(KEY_DOMAIN.len() + 32);
        key_context.extend_from_slice(KEY_DOMAIN);
        key_context.extend_from_slice(&transcript_hash);
        let key_hash = blake3::keyed_hash(
            spake_key
                .as_slice()
                .try_into()
                .map_err(|_| "SPAKE2 returned an unexpected key length".to_owned())?,
            &key_context,
        );
        session_key.copy_from_slice(key_hash.as_bytes());
        spake_key.zeroize();

        let mut confirmation_context = Vec::with_capacity(CONFIRM_DOMAIN.len() + 32);
        confirmation_context.extend_from_slice(CONFIRM_DOMAIN);
        confirmation_context.extend_from_slice(&transcript_hash);
        let confirmation = *blake3::keyed_hash(&session_key, &confirmation_context).as_bytes();

        Ok(PairingSession {
            key: session_key,
            confirmation,
            transcript_hash,
        })
    }
}

fn identity_aad(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(IDENTITY_AAD_DOMAIN.len() + transcript_hash.len());
    aad.extend_from_slice(IDENTITY_AAD_DOMAIN);
    aad.extend_from_slice(transcript_hash);
    aad
}

#[cfg(test)]
mod tests {
    use super::{PairingCode, PairingExchange};
    use ed25519_dalek::SigningKey;

    #[test]
    fn generated_codes_have_100_bits_and_parse_case_insensitively() {
        let code = PairingCode::generate().unwrap();
        assert_eq!(code.expose().len(), 23);
        assert_eq!(code.expose().matches('-').count(), 3);
        let parsed = PairingCode::parse(&code.expose().to_lowercase()).unwrap();
        assert!(parsed.expose() == code.expose());
    }

    #[test]
    fn parser_rejects_short_ambiguous_and_malformed_codes() {
        for value in ["1234", "O1234-I5678-L9012-U3456", "12345-12345-12345-1234!"] {
            assert!(PairingCode::parse(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn matching_codes_confirm_the_same_transcript_and_derive_equal_keys() {
        let code = PairingCode::parse("01234-56789-ABCDE-FGHJK").unwrap();
        let first = PairingExchange::start(&code);
        let second = PairingExchange::start(&code);
        let first_message = first.outbound_message().to_vec();
        let second_message = second.outbound_message().to_vec();
        let first = first.finish(&second_message).unwrap();
        let second = second.finish(&first_message).unwrap();

        let first_tag = first.confirmation_tag();
        let second_tag = second.confirmation_tag();
        let first = first.confirm(&second_tag).unwrap();
        let second = second.confirm(&first_tag).unwrap();
        assert_eq!(
            first.derive_key(b"contact-identity").unwrap(),
            second.derive_key(b"contact-identity").unwrap()
        );
        assert_ne!(
            first.derive_key(b"contact-identity").unwrap(),
            first.derive_key(b"other-purpose").unwrap()
        );
    }

    #[test]
    fn wrong_codes_do_not_confirm_even_when_spake2_finishes() {
        let first_code = PairingCode::parse("01234-56789-ABCDE-FGHJK").unwrap();
        let wrong_code = PairingCode::parse("11234-56789-ABCDE-FGHJK").unwrap();
        let first = PairingExchange::start(&first_code);
        let second = PairingExchange::start(&wrong_code);
        let first_message = first.outbound_message().to_vec();
        let second_message = second.outbound_message().to_vec();
        let first = first.finish(&second_message).unwrap();
        let second = second.finish(&first_message).unwrap();

        let first_tag = first.confirmation_tag();
        let second_tag = second.confirmation_tag();
        assert!(first.confirm(&second_tag).is_err());
        assert!(second.confirm(&first_tag).is_err());
    }

    #[test]
    fn confirmation_is_bound_to_a_fresh_exchange() {
        let code = PairingCode::parse("01234-56789-ABCDE-FGHJK").unwrap();
        let make_session = || {
            let first = PairingExchange::start(&code);
            let second = PairingExchange::start(&code);
            let first_message = first.outbound_message().to_vec();
            let second_message = second.outbound_message().to_vec();
            (
                first.finish(&second_message).unwrap(),
                second.finish(&first_message).unwrap(),
            )
        };
        let (old_first, old_second) = make_session();
        let (new_first, new_second) = make_session();
        let (fresh_first, _) = make_session();
        assert!(fresh_first.confirm(&old_second.confirmation_tag()).is_err());
        assert_ne!(
            old_first
                .confirm(&old_second.confirmation_tag())
                .unwrap()
                .derive_key(b"contact-identity")
                .unwrap(),
            new_first
                .confirm(&new_second.confirmation_tag())
                .unwrap()
                .derive_key(b"contact-identity")
                .unwrap()
        );
    }

    #[test]
    fn malformed_peer_message_is_rejected() {
        let code = PairingCode::parse("01234-56789-ABCDE-FGHJK").unwrap();
        assert!(PairingExchange::start(&code).finish(b"short").is_err());
    }

    #[test]
    fn signed_device_identity_is_encrypted_and_bound_to_the_confirmed_transcript() {
        let code = PairingCode::parse("01234-56789-ABCDE-FGHJK").unwrap();
        let first = PairingExchange::start(&code);
        let second = PairingExchange::start(&code);
        let first_message = first.outbound_message().to_vec();
        let second_message = second.outbound_message().to_vec();
        let first = first.finish(&second_message).unwrap();
        let second = second.finish(&first_message).unwrap();
        let first_tag = first.confirmation_tag();
        let second_tag = second.confirmation_tag();
        let first = first.confirm(&second_tag).unwrap();
        let second = second.confirm(&first_tag).unwrap();
        assert_eq!(first.transcript_hash(), second.transcript_hash());

        let first_identity = SigningKey::from_bytes(&[0x41; 32]);
        let second_identity = SigningKey::from_bytes(&[0x42; 32]);
        let first_proof =
            super::ContactIdentityProof::sign(&first_identity, &first.transcript_hash());
        let second_proof =
            super::ContactIdentityProof::sign(&second_identity, &second.transcript_hash());
        let first_envelope = first.seal_identity_proof(&first_proof).unwrap();
        let second_envelope = second.seal_identity_proof(&second_proof).unwrap();
        assert_eq!(first_envelope.len(), 128);
        assert_eq!(
            first.open_identity_proof(&second_envelope).unwrap(),
            second_proof
        );
        assert_eq!(
            second.open_identity_proof(&first_envelope).unwrap(),
            first_proof
        );

        let mut tampered = second_envelope;
        tampered[20] ^= 1;
        assert!(first.open_identity_proof(&tampered).is_err());

        let unrelated = SigningKey::from_bytes(&[0x43; 32]);
        let unrelated_proof = super::ContactIdentityProof::sign(&unrelated, &[0xff; 32]);
        assert!(first.seal_identity_proof(&unrelated_proof).is_err());
    }
}
