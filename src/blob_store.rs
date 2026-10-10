//! Persistent storage and authorized serving for encrypted file blobs.
//!
//! Only ciphertext enters the iroh-blobs store. The content key stays in the
//! returned offer and must be persisted by the caller in the encrypted profile.

use crate::file_transfer::{
    FileOffer, FileTransferSecrets, IncomingFileWriter, MAX_FILE_BYTES, chunk_count, encrypt_chunk,
    expected_plaintext_chunk_len, validate_filename,
};
use bytes::Bytes;
use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use iroh_blobs::{BlobsProtocol, Hash, api::Store, store::fs::FsStore};
use std::{
    collections::HashSet,
    path::Path,
    sync::{Arc, RwLock},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
pub struct StoredEncryptedFile {
    pub offer: FileOffer,
    pub ciphertext_hash: [u8; 32],
}

impl StoredEncryptedFile {
    pub fn blob_hash(&self) -> Hash {
        Hash::from_bytes(self.ciphertext_hash)
    }
}

/// Durable local ciphertext store. Imports encrypt each bounded chunk before
/// handing it to iroh-blobs; plaintext is never stored in the blob database.
#[derive(Clone, Debug)]
pub struct EncryptedBlobStore {
    store: FsStore,
    root: std::path::PathBuf,
}

struct TemporaryCiphertextFile(std::path::PathBuf);

impl Drop for TemporaryCiphertextFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl EncryptedBlobStore {
    /// Open the per-user encrypted blob database used by the desktop app.
    pub async fn open_default() -> Result<Self, String> {
        let project = directories::ProjectDirs::from("org", "slouching", "Slouching")
            .ok_or_else(|| "could not resolve the Slouching data directory".to_owned())?;
        Self::open(project.data_dir().join("encrypted-blobs")).await
    }

    pub async fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref();
        std::fs::create_dir_all(root)
            .map_err(|error| format!("could not create encrypted blob directory: {error}"))?;
        restrict_directory_permissions(root)?;
        let mut options = iroh_blobs::store::fs::options::Options::new(root);
        options.gc = Some(iroh_blobs::store::GcConfig {
            interval: std::time::Duration::from_secs(30 * 60),
            add_protected: None,
        });
        let store = FsStore::load_with_opts(root.join("blobs.db"), options)
            .await
            .map_err(|error| format!("could not open encrypted blob store: {error}"))?;
        Ok(Self {
            store,
            root: root.to_path_buf(),
        })
    }

    pub fn protocol(
        &self,
        authorized_peers: Arc<RwLock<HashSet<iroh::EndpointId>>>,
    ) -> AuthorizedBlobsProtocol {
        AuthorizedBlobsProtocol {
            inner: BlobsProtocol::new(&self.store, None),
            authorized_peers,
        }
    }

    /// Encrypt and persist a file as one content-addressed ciphertext blob.
    /// The returned hash is over ciphertext and the random key is only in offer.
    pub async fn import_file(&self, path: impl AsRef<Path>) -> Result<StoredEncryptedFile, String> {
        let path = path.as_ref();
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "file path must have a valid UTF-8 file name".to_owned())?
            .to_owned();
        validate_filename(&filename)?;
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|error| format!("could not inspect selected file: {error}"))?;
        if !metadata.is_file() {
            return Err("selected path is not a regular file".to_owned());
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err(format!(
                "file exceeds the {} MiB transfer limit",
                MAX_FILE_BYTES / (1024 * 1024)
            ));
        }
        let total_bytes = metadata.len();
        let secrets = FileTransferSecrets::generate()?;
        let offer = FileOffer::from_secrets(&secrets, total_bytes, filename)?;
        let transfer_id = *secrets.transfer_id();
        let content_key = *secrets.content_key();
        let reader = tokio::fs::File::open(path)
            .await
            .map_err(|error| format!("could not open selected file: {error}"))?;
        let reader = Arc::new(tokio::sync::Mutex::new(reader));
        let stream = async_stream::try_stream! {
            let count = chunk_count(total_bytes).map_err(std::io::Error::other)?;
            for index in 0..count {
                let length = expected_plaintext_chunk_len(total_bytes, index)
                    .map_err(std::io::Error::other)?;
                let mut plaintext = zeroize::Zeroizing::new(vec![0; length]);
                reader
                    .lock()
                    .await
                    .read_exact(&mut plaintext)
                    .await
                    .map_err(|error| std::io::Error::other(format!("file changed during import: {error}")))?;
                let ciphertext = encrypt_chunk(
                    &transfer_id,
                    &content_key,
                    total_bytes,
                    index,
                    &plaintext,
                ).map_err(std::io::Error::other)?;
                yield Bytes::from(ciphertext);
            }
            let mut extra = [0; 1];
            if reader.lock().await.read(&mut extra).await? != 0 {
                Err(std::io::Error::other("file grew during encrypted import"))?;
            }
        };
        let tag_name = format!("slouching:file:{}", hex::encode(transfer_id));
        let blob = self
            .store
            .add_stream(stream)
            .await
            .with_named_tag(tag_name.as_bytes())
            .await
            .map_err(|error| format!("could not persist encrypted file blob: {error}"))?;
        let ciphertext_hash = *blob.hash.as_bytes();
        Ok(StoredEncryptedFile {
            offer,
            ciphertext_hash,
        })
    }

    /// Persist a received ciphertext stream only if its exact bounded length
    /// and content digest match the authenticated MLS attachment offer.
    pub async fn import_ciphertext_stream<R>(
        &self,
        mut reader: R,
        offer: &FileOffer,
        expected_hash: [u8; 32],
    ) -> Result<(), String>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        offer.encode()?;
        let ciphertext_bytes = offer
            .total_bytes
            .checked_add(u64::from(offer.chunk_count).saturating_mul(16))
            .ok_or_else(|| "encrypted attachment size overflowed".to_owned())?;
        let transfer_id = offer.transfer_id;
        let temp_path = self.root.join(format!(
            "received-{}-{}.tmp",
            std::process::id(),
            getrandom::u64()
                .map_err(|error| format!("could not name attachment staging file: {error}"))?
        ));
        let temporary = TemporaryCiphertextFile(temp_path);
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary.0)
            .await
            .map_err(|error| {
                format!("could not create restricted attachment staging file: {error}")
            })?;
        restrict_file_permissions(&temporary.0)?;
        let mut digest = blake3::Hasher::new();
        let mut remaining = ciphertext_bytes;
        while remaining > 0 {
            let count = remaining.min(64 * 1024) as usize;
            let mut buffer = vec![0; count];
            reader
                .read_exact(&mut buffer)
                .await
                .map_err(|error| format!("encrypted attachment stream ended early: {error}"))?;
            digest.update(&buffer);
            output
                .write_all(&buffer)
                .await
                .map_err(|error| format!("could not stage encrypted attachment: {error}"))?;
            remaining -= count as u64;
        }
        let mut extra = [0; 1];
        if reader
            .read(&mut extra)
            .await
            .map_err(|error| format!("could not finish encrypted attachment stream: {error}"))?
            != 0
        {
            return Err("encrypted attachment stream exceeded its declared size".to_owned());
        }
        if digest.finalize().as_bytes() != &expected_hash {
            return Err("encrypted attachment digest does not match its MLS offer".to_owned());
        }
        output
            .flush()
            .await
            .map_err(|error| format!("could not finish attachment staging file: {error}"))?;
        drop(output);
        let staged = tokio::fs::File::open(&temporary.0)
            .await
            .map_err(|error| format!("could not read verified attachment staging file: {error}"))?;
        let staged = Arc::new(tokio::sync::Mutex::new(staged));
        let stream = async_stream::try_stream! {
            let mut remaining = ciphertext_bytes;
            while remaining > 0 {
                let count = remaining.min(64 * 1024) as usize;
                let mut buffer = vec![0; count];
                staged.lock().await.read_exact(&mut buffer).await?;
                remaining -= count as u64;
                yield Bytes::from(buffer);
            }
        };
        let tag_name = format!("slouching:file:{}", hex::encode(transfer_id));
        let blob = self
            .store
            .add_stream(stream)
            .await
            .with_named_tag(tag_name.as_bytes())
            .await
            .map_err(|error| format!("could not persist received encrypted attachment: {error}"))?;
        if blob.hash.as_bytes() != &expected_hash {
            return Err("persisted encrypted attachment hash changed unexpectedly".to_owned());
        }
        Ok(())
    }

    pub async fn remove(&self, transfer_id: &[u8; 16]) -> Result<(), String> {
        let tag_name = format!("slouching:file:{}", hex::encode(transfer_id));
        self.store
            .tags()
            .delete(tag_name.as_bytes())
            .await
            .map_err(|error| format!("could not remove encrypted file reference: {error}"))?;
        Ok(())
    }

    #[cfg(test)]
    pub async fn read_ciphertext_for_test(&self, hash: [u8; 32]) -> Result<Bytes, String> {
        self.store
            .get_bytes(Hash::from_bytes(hash))
            .await
            .map_err(|error| format!("could not read stored ciphertext: {error}"))
    }

    #[cfg(test)]
    pub async fn has_reference_for_test(&self, transfer_id: &[u8; 16]) -> Result<bool, String> {
        let tag_name = format!("slouching:file:{}", hex::encode(transfer_id));
        self.store
            .tags()
            .get(tag_name.as_bytes())
            .await
            .map(|tag| tag.is_some())
            .map_err(|error| format!("could not inspect encrypted file reference: {error}"))
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        self.store
            .shutdown()
            .await
            .map_err(|error| format!("could not flush encrypted blob store: {error}"))
    }

    pub fn inner(&self) -> &Store {
        &self.store
    }

    /// Open a bounded reader for already verified encrypted blob bytes.
    pub fn ciphertext_reader(&self, hash: [u8; 32]) -> iroh_blobs::api::blobs::BlobReader {
        self.store.reader(Hash::from_bytes(hash))
    }

    /// Decrypt a stored attachment chunk by chunk and publish it only after
    /// the ciphertext digest and complete plaintext size have been verified.
    pub async fn save_decrypted_file(
        &self,
        offer: FileOffer,
        ciphertext_hash: [u8; 32],
        destination: impl AsRef<Path>,
    ) -> Result<std::path::PathBuf, String> {
        offer.encode()?;
        let chunk_count = offer.chunk_count;
        let total_bytes = offer.total_bytes;
        let mut reader = self.ciphertext_reader(ciphertext_hash);
        let mut output = IncomingFileWriter::create(offer, destination)?;
        for index in 0..chunk_count {
            let plaintext_len = expected_plaintext_chunk_len(total_bytes, index)?;
            let mut ciphertext = vec![0; plaintext_len + 16];
            reader
                .read_exact(&mut ciphertext)
                .await
                .map_err(|error| format!("encrypted attachment blob is incomplete: {error}"))?;
            output.write_chunk(index, &ciphertext)?;
            tokio::task::yield_now().await;
        }
        let mut extra = [0; 1];
        if reader
            .read(&mut extra)
            .await
            .map_err(|error| format!("could not finish reading encrypted attachment: {error}"))?
            != 0
        {
            return Err("encrypted attachment blob exceeds its offered size".to_owned());
        }
        output.finish(&ciphertext_hash)
    }
}

/// iroh-blobs provider that refuses requests from devices outside the current
/// authorization set. Populate this set from locally validated MLS membership.
#[derive(Clone, Debug)]
pub struct AuthorizedBlobsProtocol {
    inner: BlobsProtocol,
    authorized_peers: Arc<RwLock<HashSet<iroh::EndpointId>>>,
}

impl AuthorizedBlobsProtocol {
    pub fn authorize(&self, peer: iroh::EndpointId) -> Result<(), String> {
        self.authorized_peers
            .write()
            .map_err(|_| "blob authorization state is unavailable".to_owned())?
            .insert(peer);
        Ok(())
    }

    pub fn revoke(&self, peer: &iroh::EndpointId) -> Result<bool, String> {
        Ok(self
            .authorized_peers
            .write()
            .map_err(|_| "blob authorization state is unavailable".to_owned())?
            .remove(peer))
    }

    pub fn is_authorized(&self, peer: &iroh::EndpointId) -> bool {
        self.authorized_peers
            .read()
            .is_ok_and(|peers| peers.contains(peer))
    }
}

impl ProtocolHandler for AuthorizedBlobsProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        if !self.is_authorized(&connection.remote_id()) {
            return Err(AcceptError::from_err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "peer is not authorized to fetch file blobs",
            )));
        }
        self.inner.accept(connection).await
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not restrict blob-store directory permissions: {error}"))
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not restrict attachment staging file permissions: {error}"))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_transfer::decrypt_file_stream;
    use std::{io::Cursor, path::PathBuf};

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "slouching-{label}-{}-{}",
            std::process::id(),
            getrandom::u32().unwrap()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[tokio::test]
    async fn imported_file_is_stored_only_as_ciphertext_and_can_be_removed() {
        let root = test_root("blob-import");
        let source_path = root.join("crew.txt");
        let source = vec![0x6b; crate::file_transfer::FILE_CHUNK_PLAINTEXT_BYTES + 5];
        tokio::fs::write(&source_path, &source).await.unwrap();
        let store = EncryptedBlobStore::open(root.join("blobs")).await.unwrap();
        let stored = store.import_file(&source_path).await.unwrap();
        let ciphertext = store
            .read_ciphertext_for_test(stored.ciphertext_hash)
            .await
            .unwrap();
        assert_eq!(
            *blake3::hash(&ciphertext).as_bytes(),
            stored.ciphertext_hash
        );
        assert_ne!(ciphertext.as_ref(), source.as_slice());
        let mut plaintext = Vec::new();
        decrypt_file_stream(
            &mut Cursor::new(ciphertext),
            &mut plaintext,
            &stored.offer.transfer_id,
            &stored.offer.content_key,
            stored.offer.total_bytes,
            &stored.ciphertext_hash,
        )
        .unwrap();
        assert_eq!(plaintext, source);
        let transfer_id = stored.offer.transfer_id;
        let save_path = root.join("saved-crew.txt");
        store
            .save_decrypted_file(
                FileOffer::decode(&stored.offer.encode().unwrap()).unwrap(),
                stored.ciphertext_hash,
                &save_path,
            )
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&save_path).await.unwrap(), source);
        store.remove(&transfer_id).await.unwrap();
        assert!(!store.has_reference_for_test(&transfer_id).await.unwrap());
        store.shutdown().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn received_ciphertext_is_persisted_only_after_length_and_digest_verification() {
        let root = test_root("blob-receive");
        let source_path = root.join("source.bin");
        tokio::fs::write(&source_path, vec![0x5a; 8193])
            .await
            .unwrap();
        let provider = EncryptedBlobStore::open(root.join("provider"))
            .await
            .unwrap();
        let received = EncryptedBlobStore::open(root.join("received"))
            .await
            .unwrap();
        let artifact = provider.import_file(&source_path).await.unwrap();
        let ciphertext = provider
            .read_ciphertext_for_test(artifact.ciphertext_hash)
            .await
            .unwrap();
        let ciphertext_path = root.join("ciphertext.bin");
        tokio::fs::write(&ciphertext_path, &ciphertext)
            .await
            .unwrap();
        received
            .import_ciphertext_stream(
                tokio::fs::File::open(&ciphertext_path).await.unwrap(),
                &artifact.offer,
                artifact.ciphertext_hash,
            )
            .await
            .unwrap();
        assert_eq!(
            received
                .read_ciphertext_for_test(artifact.ciphertext_hash)
                .await
                .unwrap(),
            ciphertext
        );

        let bad_hash = [0xa5; 32];
        let rejected_id = [0xb6; 16];
        let mut rejected_offer = FileOffer::decode(&artifact.offer.encode().unwrap()).unwrap();
        rejected_offer.transfer_id = rejected_id;
        assert!(
            received
                .import_ciphertext_stream(
                    tokio::fs::File::open(&ciphertext_path).await.unwrap(),
                    &rejected_offer,
                    bad_hash,
                )
                .await
                .is_err()
        );
        assert!(!received.has_reference_for_test(&rejected_id).await.unwrap());

        let short_id = [0xc7; 16];
        let mut short_offer = FileOffer::decode(&artifact.offer.encode().unwrap()).unwrap();
        short_offer.transfer_id = short_id;
        tokio::fs::write(&ciphertext_path, &ciphertext[..ciphertext.len() - 1])
            .await
            .unwrap();
        assert!(
            received
                .import_ciphertext_stream(
                    tokio::fs::File::open(&ciphertext_path).await.unwrap(),
                    &short_offer,
                    artifact.ciphertext_hash,
                )
                .await
                .is_err()
        );
        assert!(!received.has_reference_for_test(&short_id).await.unwrap());

        let long_id = [0xd8; 16];
        let mut long_offer = FileOffer::decode(&artifact.offer.encode().unwrap()).unwrap();
        long_offer.transfer_id = long_id;
        let mut oversized_ciphertext = ciphertext.to_vec();
        oversized_ciphertext.push(0);
        tokio::fs::write(&ciphertext_path, oversized_ciphertext)
            .await
            .unwrap();
        assert!(
            received
                .import_ciphertext_stream(
                    tokio::fs::File::open(&ciphertext_path).await.unwrap(),
                    &long_offer,
                    artifact.ciphertext_hash,
                )
                .await
                .is_err()
        );
        assert!(!received.has_reference_for_test(&long_id).await.unwrap());

        provider.shutdown().await.unwrap();
        received.shutdown().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn authorized_iroh_peer_fetches_encrypted_blob_and_untrusted_peer_is_rejected() {
        let root = test_root("blob-peer");
        let source_path = root.join("crew.txt");
        let source = vec![0x39; 70 * 1024 + 11];
        tokio::fs::write(&source_path, &source).await.unwrap();
        let provider_store = EncryptedBlobStore::open(root.join("provider-store"))
            .await
            .unwrap();
        let artifact = provider_store.import_file(&source_path).await.unwrap();

        let provider_endpoint = local_endpoint(test_secret()).await;
        let client_endpoint = local_endpoint(test_secret()).await;
        let allowed = Arc::new(RwLock::new(HashSet::from([client_endpoint.id()])));
        let provider_router = iroh::protocol::Router::builder(provider_endpoint.clone())
            .accept(iroh_blobs::ALPN, provider_store.protocol(allowed))
            .spawn();
        let provider_addr = provider_endpoint
            .addr()
            .ip_addrs()
            .next()
            .copied()
            .expect("bound local endpoint has an IP socket address");
        let remote = iroh::EndpointAddr::new(provider_endpoint.id()).with_ip_addr(provider_addr);
        let connection = client_endpoint
            .connect(remote.clone(), iroh_blobs::ALPN)
            .await
            .unwrap();
        let client_store = EncryptedBlobStore::open(root.join("client-store"))
            .await
            .unwrap();
        client_store
            .inner()
            .remote()
            .fetch(connection, artifact.blob_hash())
            .await
            .unwrap();
        let ciphertext = client_store
            .read_ciphertext_for_test(artifact.ciphertext_hash)
            .await
            .unwrap();
        let mut restored = Vec::new();
        decrypt_file_stream(
            &mut Cursor::new(ciphertext),
            &mut restored,
            &artifact.offer.transfer_id,
            &artifact.offer.content_key,
            artifact.offer.total_bytes,
            &artifact.ciphertext_hash,
        )
        .unwrap();
        assert_eq!(restored, source);

        let stranger = local_endpoint(test_secret()).await;
        let connection = stranger.connect(remote, iroh_blobs::ALPN).await.unwrap();
        let stranger_store = EncryptedBlobStore::open(root.join("stranger-store"))
            .await
            .unwrap();
        assert!(
            stranger_store_fetch_fails(&stranger_store, connection, artifact.blob_hash()).await
        );

        stranger.close().await;
        stranger_store.shutdown().await.unwrap();
        client_store.shutdown().await.unwrap();
        provider_router.shutdown().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    async fn stranger_store_fetch_fails(
        stranger_store: &EncryptedBlobStore,
        connection: iroh::endpoint::Connection,
        hash: Hash,
    ) -> bool {
        stranger_store
            .inner()
            .remote()
            .fetch(connection, hash)
            .await
            .is_err()
    }

    fn test_secret() -> iroh::SecretKey {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).unwrap();
        iroh::SecretKey::from_bytes(&bytes)
    }

    async fn local_endpoint(secret: iroh::SecretKey) -> iroh::Endpoint {
        iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn blob_protocol_requires_explicit_device_authorization() {
        let authorized = Arc::new(RwLock::new(HashSet::new()));
        let peer = iroh::SecretKey::from_bytes(&[0x47; 32]).public();
        let id = iroh::EndpointId::from(peer);
        let store = iroh_blobs::store::mem::MemStore::new();
        let protocol = AuthorizedBlobsProtocol {
            inner: BlobsProtocol::new(&store, None),
            authorized_peers: authorized,
        };
        assert!(!protocol.is_authorized(&id));
        protocol.authorize(id).unwrap();
        assert!(protocol.is_authorized(&id));
        assert!(protocol.revoke(&id).unwrap());
        assert!(!protocol.is_authorized(&id));
    }
}
