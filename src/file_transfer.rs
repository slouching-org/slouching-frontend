//! File-transfer primitives for direct, recipient-authenticated peer sessions.
//!
//! The content key and transfer ID are random for each file. Chunk nonces are
//! derived from that transfer ID and the monotonically increasing chunk index;
//! authenticated data binds the ciphertext to the transfer, total size, index,
//! and chunk length. Public addressing must use the ciphertext digest only.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;
pub const FILE_CHUNK_PLAINTEXT_BYTES: usize = 48 * 1024;
const FILE_CHUNK_TAG_BYTES: usize = 16;
const FILE_AAD_PREFIX: &[u8] = b"SLCH-FILE-CHUNK-v1";
const FILE_OFFER_MAGIC: &[u8; 4] = b"SLFO";
const FILE_OFFER_VERSION: u16 = 1;
const FILE_OFFER_FIXED_BYTES: usize = 4 + 2 + 16 + 32 + 8 + 4 + 2;

/// Metadata and per-file key sent only inside the pinned QUIC session.
#[derive(PartialEq, Eq)]
pub struct FileOffer {
    pub transfer_id: [u8; 16],
    pub content_key: [u8; 32],
    pub total_bytes: u64,
    pub chunk_count: u32,
    pub filename: String,
}

impl std::fmt::Debug for FileOffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileOffer")
            .field("transfer_id", &self.transfer_id)
            .field("content_key", &"[redacted]")
            .field("total_bytes", &self.total_bytes)
            .field("chunk_count", &self.chunk_count)
            .field("filename", &self.filename)
            .finish()
    }
}

impl Drop for FileOffer {
    fn drop(&mut self) {
        self.content_key.zeroize();
    }
}

impl FileOffer {
    pub fn from_secrets(
        secrets: &FileTransferSecrets,
        total_bytes: u64,
        filename: String,
    ) -> Result<Self, String> {
        validate_filename(&filename)?;
        Ok(Self {
            transfer_id: *secrets.transfer_id(),
            content_key: *secrets.content_key(),
            total_bytes,
            chunk_count: chunk_count(total_bytes)?,
            filename,
        })
    }

    /// Encode only for transmission inside a pinned, authenticated QUIC session.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        validate_filename(&self.filename)?;
        let expected_chunks = chunk_count(self.total_bytes)?;
        if expected_chunks != self.chunk_count {
            return Err("file offer chunk count does not match its declared size".to_owned());
        }
        let filename = self.filename.as_bytes();
        let filename_len = u16::try_from(filename.len())
            .map_err(|_| "file name is too long to encode".to_owned())?;
        let mut encoded = Vec::with_capacity(FILE_OFFER_FIXED_BYTES + filename.len());
        encoded.extend_from_slice(FILE_OFFER_MAGIC);
        encoded.extend_from_slice(&FILE_OFFER_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.transfer_id);
        encoded.extend_from_slice(&self.content_key);
        encoded.extend_from_slice(&self.total_bytes.to_be_bytes());
        encoded.extend_from_slice(&self.chunk_count.to_be_bytes());
        encoded.extend_from_slice(&filename_len.to_be_bytes());
        encoded.extend_from_slice(filename);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.len() < FILE_OFFER_FIXED_BYTES {
            return Err("file offer is truncated".to_owned());
        }
        if &encoded[..4] != FILE_OFFER_MAGIC {
            return Err("invalid file offer magic".to_owned());
        }
        let version = u16::from_be_bytes([encoded[4], encoded[5]]);
        if version != FILE_OFFER_VERSION {
            return Err(format!("unsupported file offer version: {version}"));
        }
        let mut transfer_id = [0; 16];
        transfer_id.copy_from_slice(&encoded[6..22]);
        let mut content_key = Zeroizing::new([0; 32]);
        content_key.copy_from_slice(&encoded[22..54]);
        let total_bytes = u64::from_be_bytes(encoded[54..62].try_into().unwrap());
        let declared_chunk_count = u32::from_be_bytes(encoded[62..66].try_into().unwrap());
        let filename_len = u16::from_be_bytes([encoded[66], encoded[67]]) as usize;
        if encoded.len() != FILE_OFFER_FIXED_BYTES + filename_len {
            return Err("file offer filename length does not match its frame".to_owned());
        }
        let filename = std::str::from_utf8(&encoded[FILE_OFFER_FIXED_BYTES..])
            .map_err(|_| "file offer filename is not valid UTF-8".to_owned())?
            .to_owned();
        validate_filename(&filename)?;
        let expected_chunks = chunk_count(total_bytes)?;
        if declared_chunk_count != expected_chunks {
            return Err("file offer chunk count does not match its declared size".to_owned());
        }
        if transfer_id.iter().all(|byte| *byte == 0) || content_key.iter().all(|byte| *byte == 0) {
            return Err("file offer contains an invalid zero identifier or key".to_owned());
        }
        Ok(Self {
            transfer_id,
            content_key: *content_key,
            total_bytes,
            chunk_count: declared_chunk_count,
            filename,
        })
    }
}

#[derive(PartialEq, Eq)]
pub struct FileTransferSecrets {
    transfer_id: [u8; 16],
    content_key: [u8; 32],
}

impl std::fmt::Debug for FileTransferSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileTransferSecrets")
            .field("transfer_id", &self.transfer_id)
            .field("content_key", &"[redacted]")
            .finish()
    }
}

impl Drop for FileTransferSecrets {
    fn drop(&mut self) {
        self.content_key.zeroize();
    }
}

impl FileTransferSecrets {
    pub fn generate() -> Result<Self, String> {
        let mut transfer_id = [0; 16];
        let mut content_key = [0; 32];
        getrandom::fill(&mut transfer_id)
            .map_err(|error| format!("could not generate file transfer ID: {error}"))?;
        getrandom::fill(&mut content_key)
            .map_err(|error| format!("could not generate file content key: {error}"))?;
        Ok(Self {
            transfer_id,
            content_key,
        })
    }

    pub fn from_parts(transfer_id: [u8; 16], content_key: [u8; 32]) -> Self {
        Self {
            transfer_id,
            content_key,
        }
    }

    pub fn transfer_id(&self) -> &[u8; 16] {
        &self.transfer_id
    }

    /// The caller may serialize this only inside the authenticated QUIC session.
    pub fn content_key(&self) -> &[u8; 32] {
        &self.content_key
    }
}

pub fn chunk_count(total_bytes: u64) -> Result<u32, String> {
    if total_bytes > MAX_FILE_BYTES {
        return Err(format!(
            "file exceeds the {} MiB transfer limit",
            MAX_FILE_BYTES / (1024 * 1024)
        ));
    }
    let chunk_size = FILE_CHUNK_PLAINTEXT_BYTES as u64;
    let count = total_bytes.div_ceil(chunk_size);
    u32::try_from(count).map_err(|_| "file has too many chunks".to_owned())
}

pub fn expected_plaintext_chunk_len(total_bytes: u64, index: u32) -> Result<usize, String> {
    let count = chunk_count(total_bytes)?;
    if index >= count {
        return Err("file chunk index is outside the declared transfer".to_owned());
    }
    let chunk_size = FILE_CHUNK_PLAINTEXT_BYTES as u64;
    let preceding_bytes = u64::from(index)
        .checked_mul(chunk_size)
        .ok_or_else(|| "file chunk offset overflow".to_owned())?;
    let remaining = total_bytes
        .checked_sub(preceding_bytes)
        .ok_or_else(|| "file chunk offset exceeds total size".to_owned())?;
    usize::try_from(remaining.min(chunk_size))
        .map_err(|_| "file chunk length does not fit this platform".to_owned())
}

pub fn encrypt_chunk(
    transfer_id: &[u8; 16],
    content_key: &[u8; 32],
    total_bytes: u64,
    index: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let expected_len = expected_plaintext_chunk_len(total_bytes, index)?;
    if plaintext.len() != expected_len {
        return Err("file chunk length does not match its declared index".to_owned());
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(content_key));
    cipher
        .encrypt(
            XNonce::from_slice(&chunk_nonce(transfer_id, index)),
            Payload {
                msg: plaintext,
                aad: &chunk_aad(transfer_id, total_bytes, index, plaintext.len()),
            },
        )
        .map_err(|_| "could not encrypt file chunk".to_owned())
}

pub fn decrypt_chunk(
    transfer_id: &[u8; 16],
    content_key: &[u8; 32],
    total_bytes: u64,
    index: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let expected_len = expected_plaintext_chunk_len(total_bytes, index)?;
    if ciphertext.len() != expected_len + FILE_CHUNK_TAG_BYTES {
        return Err("ciphertext length does not match the declared file chunk".to_owned());
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(content_key));
    cipher
        .decrypt(
            XNonce::from_slice(&chunk_nonce(transfer_id, index)),
            Payload {
                msg: ciphertext,
                aad: &chunk_aad(transfer_id, total_bytes, index, expected_len),
            },
        )
        .map_err(|_| "file chunk authentication failed".to_owned())
}

/// BLAKE3 digest of transmitted ciphertext, suitable for content-addressing.
pub fn ciphertext_digest(ciphertext_chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for chunk in ciphertext_chunks {
        hasher.update(chunk);
    }
    *hasher.finalize().as_bytes()
}

pub fn validate_filename(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 255 || name == "." || name == ".." {
        return Err("file name must contain 1–255 UTF-8 bytes and cannot be a dot path".to_owned());
    }
    if name
        .chars()
        .any(|character| character == '/' || character == '\\' || character.is_control())
    {
        return Err("file name cannot contain a path separator or control character".to_owned());
    }
    Ok(())
}

fn chunk_nonce(transfer_id: &[u8; 16], index: u32) -> [u8; 24] {
    let mut nonce = [0; 24];
    nonce[..16].copy_from_slice(transfer_id);
    nonce[16..].copy_from_slice(&u64::from(index).to_be_bytes());
    nonce
}

fn chunk_aad(
    transfer_id: &[u8; 16],
    total_bytes: u64,
    index: u32,
    plaintext_len: usize,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FILE_AAD_PREFIX.len() + 16 + 8 + 4 + 4);
    aad.extend_from_slice(FILE_AAD_PREFIX);
    aad.extend_from_slice(transfer_id);
    aad.extend_from_slice(&total_bytes.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&(plaintext_len as u32).to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_chunks_round_trip_and_bind_transfer_size_and_index() {
        let secrets = FileTransferSecrets::from_parts([0x31; 16], [0x52; 32]);
        let total_bytes = FILE_CHUNK_PLAINTEXT_BYTES as u64 + 7;
        let first = vec![0xa5; FILE_CHUNK_PLAINTEXT_BYTES];
        let last = b"partial";
        let first_ciphertext = encrypt_chunk(
            secrets.transfer_id(),
            secrets.content_key(),
            total_bytes,
            0,
            &first,
        )
        .unwrap();
        let last_ciphertext = encrypt_chunk(
            secrets.transfer_id(),
            secrets.content_key(),
            total_bytes,
            1,
            last,
        )
        .unwrap();

        assert_eq!(
            decrypt_chunk(
                secrets.transfer_id(),
                secrets.content_key(),
                total_bytes,
                0,
                &first_ciphertext,
            )
            .unwrap(),
            first
        );
        assert_eq!(
            decrypt_chunk(
                secrets.transfer_id(),
                secrets.content_key(),
                total_bytes,
                1,
                &last_ciphertext,
            )
            .unwrap(),
            last
        );
        assert!(
            decrypt_chunk(
                secrets.transfer_id(),
                secrets.content_key(),
                total_bytes,
                0,
                &last_ciphertext,
            )
            .is_err()
        );
        assert!(
            decrypt_chunk(
                secrets.transfer_id(),
                secrets.content_key(),
                total_bytes + 1,
                1,
                &last_ciphertext,
            )
            .is_err()
        );
    }

    #[test]
    fn file_chunks_reject_tampering_wrong_keys_and_wrong_lengths() {
        let secrets = FileTransferSecrets::from_parts([0x41; 16], [0x62; 32]);
        let plaintext = b"crew-only attachment";
        let mut ciphertext = encrypt_chunk(
            secrets.transfer_id(),
            secrets.content_key(),
            plaintext.len() as u64,
            0,
            plaintext,
        )
        .unwrap();
        ciphertext[0] ^= 0x80;
        assert!(
            decrypt_chunk(
                secrets.transfer_id(),
                secrets.content_key(),
                plaintext.len() as u64,
                0,
                &ciphertext,
            )
            .is_err()
        );

        let ciphertext = encrypt_chunk(
            secrets.transfer_id(),
            secrets.content_key(),
            plaintext.len() as u64,
            0,
            plaintext,
        )
        .unwrap();
        assert!(
            decrypt_chunk(
                secrets.transfer_id(),
                &[0x63; 32],
                plaintext.len() as u64,
                0,
                &ciphertext,
            )
            .is_err()
        );
        assert!(
            encrypt_chunk(
                secrets.transfer_id(),
                secrets.content_key(),
                plaintext.len() as u64,
                0,
                b"short",
            )
            .is_err()
        );
    }

    #[test]
    fn file_chunk_bounds_handle_empty_exact_and_partial_files() {
        assert_eq!(chunk_count(0).unwrap(), 0);
        assert_eq!(
            expected_plaintext_chunk_len(0, 0).unwrap_err(),
            "file chunk index is outside the declared transfer"
        );
        assert_eq!(chunk_count(FILE_CHUNK_PLAINTEXT_BYTES as u64).unwrap(), 1);
        assert_eq!(
            expected_plaintext_chunk_len(FILE_CHUNK_PLAINTEXT_BYTES as u64, 0).unwrap(),
            FILE_CHUNK_PLAINTEXT_BYTES
        );
        assert_eq!(
            expected_plaintext_chunk_len(FILE_CHUNK_PLAINTEXT_BYTES as u64 + 1, 1).unwrap(),
            1
        );
        assert!(chunk_count(MAX_FILE_BYTES + 1).is_err());
    }

    #[test]
    fn filenames_cannot_select_a_path_or_smuggle_control_characters() {
        assert!(validate_filename("field-notes.txt").is_ok());
        assert!(validate_filename("reunião.pdf").is_ok());
        assert!(validate_filename("").is_err());
        assert!(validate_filename("..").is_err());
        assert!(validate_filename("../private.txt").is_err());
        assert!(validate_filename("folder\\private.txt").is_err());
        assert!(validate_filename("safe\nname.txt").is_err());
    }

    #[test]
    fn content_digest_is_over_ciphertext_bytes() {
        assert_ne!(
            ciphertext_digest(&[b"encrypted"]),
            *blake3::hash(b"plaintext").as_bytes()
        );
        assert_eq!(
            ciphertext_digest(&[b"chunk-a", b"chunk-b"]),
            ciphertext_digest(&[b"chunk-achunk-b"])
        );
    }

    #[test]
    fn file_offer_round_trips_and_redacts_its_content_key() {
        let secrets = FileTransferSecrets::from_parts([0x31; 16], [0x52; 32]);
        let offer = FileOffer::from_secrets(
            &secrets,
            FILE_CHUNK_PLAINTEXT_BYTES as u64 + 9,
            "crew notes.txt".to_owned(),
        )
        .unwrap();
        let encoded = offer.encode().unwrap();
        let decoded = FileOffer::decode(&encoded).unwrap();
        assert_eq!(decoded.transfer_id, [0x31; 16]);
        assert_eq!(decoded.content_key, [0x52; 32]);
        assert_eq!(decoded.total_bytes, FILE_CHUNK_PLAINTEXT_BYTES as u64 + 9);
        assert_eq!(decoded.chunk_count, 2);
        assert_eq!(decoded.filename, "crew notes.txt");
        assert!(!format!("{decoded:?}").contains(&"52".repeat(32)));
    }

    #[test]
    fn file_offer_rejects_bad_lengths_versions_keys_and_chunk_counts() {
        let offer = FileOffer {
            transfer_id: [0x31; 16],
            content_key: [0x52; 32],
            total_bytes: 1,
            chunk_count: 1,
            filename: "safe.txt".to_owned(),
        };
        let encoded = offer.encode().unwrap();
        assert!(FileOffer::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(FileOffer::decode(&[encoded.as_slice(), b"extra"].concat()).is_err());

        let mut invalid_version = encoded.clone();
        invalid_version[5] = 2;
        assert!(
            FileOffer::decode(&invalid_version)
                .unwrap_err()
                .contains("version")
        );

        let mut invalid_count = encoded.clone();
        invalid_count[65] = 2;
        assert!(
            FileOffer::decode(&invalid_count)
                .unwrap_err()
                .contains("chunk count")
        );

        let mut invalid_key = encoded;
        invalid_key[22..54].fill(0);
        assert!(
            FileOffer::decode(&invalid_key)
                .unwrap_err()
                .contains("zero")
        );
    }

    #[test]
    fn file_offer_builder_checks_size_and_filename() {
        let secrets = FileTransferSecrets::from_parts([0x31; 16], [0x52; 32]);
        assert!(FileOffer::from_secrets(&secrets, MAX_FILE_BYTES + 1, "too-big".into()).is_err());
        assert!(FileOffer::from_secrets(&secrets, 12, "../escape".into()).is_err());
    }
}
