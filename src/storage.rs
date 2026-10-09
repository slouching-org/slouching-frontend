use crate::identity::MlsSigningKeyBinding;
use directories::ProjectDirs;
use ed25519_dalek::SigningKey;
use keyring::{Entry, Error as KeyringError};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    ProtocolVersion, RatchetTreeIn, StagedWelcome, tls_codec::Serialize as TlsCodecSerialize,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec as OpenMlsCodec, SqliteStorageProvider};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "org.slouching.desktop";
const KEY_NAME: &str = "local-profile-database-v1";
const IDENTITY_KEY_NAME: &str = "device-signing-ed25519-v1";
const PROFILE_DB: &str = "profile.sqlite3";
const PROFILE_DB_KEY_LEN: usize = 32;
const PROFILE_SCHEMA_VERSION: u32 = 6;
const MAX_DIRECT_HISTORY_PER_PEER: i64 = 1000;
type StoredEventEnvelope = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    i64,
);

#[derive(Default)]
struct OpenMlsJsonCodec;

struct LocalOpenMlsProvider<'connection> {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<OpenMlsJsonCodec, &'connection mut Connection>,
}

impl<'connection> LocalOpenMlsProvider<'connection> {
    fn new(connection: &'connection mut Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(connection),
        }
    }

    fn run_migrations(&mut self) -> Result<(), String> {
        self.storage
            .run_migrations()
            .map_err(|error| error.to_string())
    }
}

impl<'connection> OpenMlsProvider for LocalOpenMlsProvider<'connection> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<OpenMlsJsonCodec, &'connection mut Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl OpenMlsCodec for OpenMlsJsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedEvent {
    pub event_id: [u8; 16],
    pub author_device: [u8; 32],
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub checkpoint: Option<Vec<u8>>,
    pub expires_at_unix: i64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreEventResult {
    Stored,
    AlreadyStored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundDeliveryState {
    Queued,
    HeldByPeer,
    ReceivedByDevice,
    Expired,
    Failed,
}

#[derive(Debug, Clone)]
pub struct StoredOutboundEvent {
    pub sequence: i64,
    pub event: EncryptedEvent,
    pub state: OutboundDeliveryState,
}

#[derive(Debug, Clone)]
pub struct StoredInboundEvent {
    pub sequence: i64,
    pub event: EncryptedEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectMessageDirection {
    Sent,
    Received,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDirectMessage {
    pub sequence: i64,
    pub direction: DirectMessageDirection,
    pub text: String,
}

/// Saves a delivered direct-LAN message in the per-device SQLCipher database.
pub fn store_direct_message(
    peer_device: [u8; 32],
    direction: DirectMessageDirection,
    text: &str,
) -> Result<StoredDirectMessage, String> {
    let mut connection = open_local_database()?;
    store_direct_message_in(&mut connection, peer_device, direction, text)
}

/// Loads the newest local messages with a peer, in display order.
pub fn list_direct_messages(
    peer_device: [u8; 32],
    limit: usize,
) -> Result<Vec<StoredDirectMessage>, String> {
    if !(1..=500).contains(&limit) {
        return Err("direct message history page must be between 1 and 500".to_owned());
    }
    let connection = open_local_database()?;
    list_direct_messages_in(&connection, peer_device, limit)
}

/// Removes only this peer's local direct-message history.
pub fn clear_direct_history(peer_device: [u8; 32]) -> Result<usize, String> {
    let mut connection = open_local_database()?;
    clear_direct_history_in(&mut connection, peer_device)
}

fn clear_direct_history_in(
    connection: &mut Connection,
    peer_device: [u8; 32],
) -> Result<usize, String> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| format!("could not begin direct history deletion: {error}"))?;
    let deleted = transaction
        .execute(
            "DELETE FROM local_direct_messages WHERE peer_device = ?1",
            [peer_device.as_slice()],
        )
        .map_err(|error| format!("could not clear direct history: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("could not commit direct history deletion: {error}"))?;
    Ok(deleted)
}

fn list_direct_messages_in(
    connection: &Connection,
    peer_device: [u8; 32],
    limit: usize,
) -> Result<Vec<StoredDirectMessage>, String> {
    if !(1..=500).contains(&limit) {
        return Err("direct message history page must be between 1 and 500".to_owned());
    }
    let mut statement = connection
        .prepare(
            "SELECT sequence, direction, text FROM (
                 SELECT sequence, direction, text FROM local_direct_messages
                 WHERE peer_device = ?1 ORDER BY sequence DESC LIMIT ?2
             ) ORDER BY sequence ASC",
        )
        .map_err(|error| format!("could not prepare direct message history query: {error}"))?;
    let rows = statement
        .query_map(params![peer_device.as_slice(), limit as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| format!("could not query direct message history: {error}"))?;
    rows.map(|row| {
        let (sequence, direction, text) =
            row.map_err(|error| format!("could not read direct message history: {error}"))?;
        Ok(StoredDirectMessage {
            sequence,
            direction: DirectMessageDirection::try_from(direction.as_str())?,
            text,
        })
    })
    .collect()
}

fn store_direct_message_in(
    connection: &mut Connection,
    peer_device: [u8; 32],
    direction: DirectMessageDirection,
    text: &str,
) -> Result<StoredDirectMessage, String> {
    if text.trim().is_empty() || text.len() > 16 * 1024 {
        return Err("direct message must contain 1 to 16384 UTF-8 bytes".to_owned());
    }
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| {
            format!("could not begin encrypted direct history transaction: {error}")
        })?;
    transaction
        .execute(
            "INSERT INTO local_direct_messages (peer_device, direction, text)
             VALUES (?1, ?2, ?3)",
            params![peer_device.as_slice(), direction.as_str(), text],
        )
        .map_err(|error| format!("could not save direct message in encrypted history: {error}"))?;
    let sequence = transaction.last_insert_rowid();
    transaction
        .execute(
            "DELETE FROM local_direct_messages
             WHERE peer_device = ?1 AND sequence NOT IN (
                 SELECT sequence FROM local_direct_messages
                 WHERE peer_device = ?1 ORDER BY sequence DESC LIMIT ?2
             )",
            params![peer_device.as_slice(), MAX_DIRECT_HISTORY_PER_PEER],
        )
        .map_err(|error| format!("could not enforce direct history limit: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("could not commit encrypted direct history: {error}"))?;
    Ok(StoredDirectMessage {
        sequence,
        direction,
        text: text.to_owned(),
    })
}

impl DirectMessageDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }
}

impl TryFrom<&str> for DirectMessageDirection {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "sent" => Ok(Self::Sent),
            "received" => Ok(Self::Received),
            _ => Err("saved direct message has an invalid direction".to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMlsKeyPackage {
    pub ciphersuite: u16,
    pub credential_binding: MlsSigningKeyBinding,
    /// Public MLS KeyPackage bytes; the corresponding private bundle stays in SQLCipher.
    pub public_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedMlsGroup {
    pub group_id: Vec<u8>,
    pub ciphersuite: u16,
    pub epoch: u64,
    pub designated_committer_device: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedMlsMember {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    /// Public MLS Commit bytes to distribute alongside the Welcome.
    pub commit: Vec<u8>,
    /// Encrypted MLS Welcome bytes for the admitted member.
    pub welcome: Vec<u8>,
    /// Public ratchet tree required to process the Welcome.
    pub ratchet_tree: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedMlsGroup {
    pub group_id: Vec<u8>,
    pub ciphersuite: u16,
    pub epoch: u64,
    pub designated_committer_device: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct LocalProfile {
    pub display_name: String,
    pub familiar: String,
}

pub fn familiar_id(label: &str) -> &'static str {
    match label {
        "Gnomo" => "gnome",
        "Vidente do Orbe" => "orb",
        _ => "frog",
    }
}

pub fn familiar_label(id: &str) -> &'static str {
    match id {
        "gnome" => "Gnomo",
        "orb" => "Vidente do Orbe",
        _ => "Sapo Mago",
    }
}

pub fn load_profile() -> Result<Option<LocalProfile>, String> {
    let entry = key_entry()?;
    let key = match entry.get_secret() {
        Ok(bytes) => secret_key(bytes)?,
        Err(KeyringError::NoEntry) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "could not access the system credential store: {error}"
            ));
        }
    };
    let path = database_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let connection = open_database(&path, &key)?;
    connection
        .query_row(
            "SELECT display_name, familiar FROM local_profile WHERE id = 1",
            [],
            |row| {
                Ok(LocalProfile {
                    display_name: row.get(0)?,
                    familiar: row.get(1)?,
                })
            },
        )
        .optional()
        .map_err(|error| format!("could not read encrypted local profile: {error}"))
}

pub fn save_profile(profile: &LocalProfile) -> Result<(), String> {
    let display_name = profile.display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > 40 {
        return Err("local display name must contain between 1 and 40 characters".to_owned());
    }
    let connection = open_local_database()?;
    connection
        .execute(
            "INSERT INTO local_profile (id, display_name, familiar) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name,
                 familiar = excluded.familiar",
            params![display_name, profile.familiar],
        )
        .map_err(|error| format!("could not save encrypted local profile: {error}"))?;
    Ok(())
}

pub fn new_event_id() -> Result<[u8; 16], String> {
    loop {
        let mut event_id = [0_u8; 16];
        getrandom::fill(&mut event_id)
            .map_err(|error| format!("could not generate local event id: {error}"))?;
        if event_id.iter().any(|byte| *byte != 0) {
            return Ok(event_id);
        }
    }
}

pub fn store_outbound_event(event: &EncryptedEvent) -> Result<StoreEventResult, String> {
    store_encrypted_event(event, "outbound")
}

pub fn store_inbound_event(event: &EncryptedEvent) -> Result<StoreEventResult, String> {
    store_encrypted_event(event, "inbound")
}

/// Loads a bounded page for a future delivery worker; this does not send it.
pub fn list_outbound_events(
    after_sequence: i64,
    limit: usize,
) -> Result<Vec<StoredOutboundEvent>, String> {
    if after_sequence < 0 || !(1..=500).contains(&limit) {
        return Err("outbound event batch size must be between 1 and 500".to_owned());
    }
    let connection = open_local_database()?;
    let mut statement = connection
        .prepare(
            "SELECT rowid, event_id, author_device, group_id, epoch, checkpoint,
                    expires_at_unix, ciphertext, delivery_state
             FROM local_events WHERE direction = 'outbound' AND rowid > ?1
             ORDER BY rowid LIMIT ?2",
        )
        .map_err(|error| format!("could not prepare local outbox query: {error}"))?;
    let rows = statement
        .query_map(params![after_sequence, limit as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|error| format!("could not query local outbox: {error}"))?;
    let mut events = Vec::new();
    for row in rows {
        let (
            sequence,
            event_id,
            author_device,
            group_id,
            epoch,
            checkpoint,
            expires_at_unix,
            ciphertext,
            state,
        ) = row.map_err(|error| format!("could not read local outbox event: {error}"))?;
        events.push(StoredOutboundEvent {
            sequence,
            event: EncryptedEvent {
                event_id: fixed_bytes(event_id, "event id")?,
                author_device: fixed_bytes(author_device, "author device key")?,
                group_id,
                epoch: u64::try_from(epoch)
                    .map_err(|_| "saved event has an invalid MLS epoch".to_owned())?,
                checkpoint,
                expires_at_unix,
                ciphertext,
            },
            state: OutboundDeliveryState::try_from(state.as_str())?,
        });
    }
    Ok(events)
}

/// Loads locally persisted inbound ciphertext in bounded cursor pages.
pub fn list_inbound_events(
    after_sequence: i64,
    limit: usize,
) -> Result<Vec<StoredInboundEvent>, String> {
    if after_sequence < 0 || !(1..=500).contains(&limit) {
        return Err("inbound event batch size must be between 1 and 500".to_owned());
    }
    let connection = open_local_database()?;
    let mut statement = connection
        .prepare(
            "SELECT rowid, event_id, author_device, group_id, epoch, checkpoint,
                    expires_at_unix, ciphertext
             FROM local_events WHERE direction = 'inbound' AND rowid > ?1
             ORDER BY rowid LIMIT ?2",
        )
        .map_err(|error| format!("could not prepare local inbox query: {error}"))?;
    let rows = statement
        .query_map(params![after_sequence, limit as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })
        .map_err(|error| format!("could not query local inbox: {error}"))?;
    let mut events = Vec::new();
    for row in rows {
        let (
            sequence,
            event_id,
            author_device,
            group_id,
            epoch,
            checkpoint,
            expires_at_unix,
            ciphertext,
        ) = row.map_err(|error| format!("could not read local inbox event: {error}"))?;
        events.push(StoredInboundEvent {
            sequence,
            event: EncryptedEvent {
                event_id: fixed_bytes(event_id, "event id")?,
                author_device: fixed_bytes(author_device, "author device key")?,
                group_id,
                epoch: u64::try_from(epoch)
                    .map_err(|_| "saved event has an invalid MLS epoch".to_owned())?,
                checkpoint,
                expires_at_unix,
                ciphertext,
            },
        });
    }
    Ok(events)
}

/// Records a state supplied by trusted local protocol code. A future transport
/// must authenticate receipts before passing `ReceivedByDevice` here.
pub fn update_outbound_delivery_state(
    event_id: [u8; 16],
    next: OutboundDeliveryState,
) -> Result<(), String> {
    let mut connection = open_local_database()?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| format!("could not begin local outbox transaction: {error}"))?;
    let current: Option<String> = transaction
        .query_row(
            "SELECT delivery_state FROM local_events
             WHERE event_id = ?1 AND direction = 'outbound'",
            [event_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("could not read local outbox state: {error}"))?;
    let current = current.ok_or_else(|| "outbound event was not found".to_owned())?;
    let current = OutboundDeliveryState::try_from(current.as_str())?;
    if !current.can_transition_to(next) {
        return Err(format!(
            "invalid outbound delivery state transition: {current:?} -> {next:?}"
        ));
    }
    transaction
        .execute(
            "UPDATE local_events SET delivery_state = ?1 WHERE event_id = ?2",
            params![next.as_str(), event_id.as_slice()],
        )
        .map_err(|error| format!("could not update local outbox state: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("could not commit local outbox state: {error}"))
}

impl OutboundDeliveryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::HeldByPeer => "held_by_peer",
            Self::ReceivedByDevice => "received_by_device",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }

    fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (
                    Self::Queued,
                    Self::HeldByPeer | Self::ReceivedByDevice | Self::Expired | Self::Failed
                ) | (
                    Self::HeldByPeer,
                    Self::Queued | Self::ReceivedByDevice | Self::Expired | Self::Failed
                ) | (Self::Failed, Self::Queued)
            )
    }
}

impl TryFrom<&str> for OutboundDeliveryState {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "queued" => Ok(Self::Queued),
            "held_by_peer" => Ok(Self::HeldByPeer),
            "received_by_device" => Ok(Self::ReceivedByDevice),
            "expired" => Ok(Self::Expired),
            "failed" => Ok(Self::Failed),
            _ => Err("saved event has an invalid delivery state".to_owned()),
        }
    }
}

fn fixed_bytes<const N: usize>(bytes: Vec<u8>, label: &str) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("saved event has an invalid {label}"))
}

fn store_encrypted_event(
    event: &EncryptedEvent,
    direction: &'static str,
) -> Result<StoreEventResult, String> {
    if event.event_id.iter().all(|byte| *byte == 0)
        || event.author_device.iter().all(|byte| *byte == 0)
        || event.group_id.is_empty()
        || event.epoch > i64::MAX as u64
        || event.expires_at_unix <= 0
        || event.ciphertext.is_empty()
    {
        return Err("encrypted event envelope is incomplete or invalid".to_owned());
    }

    let digest = blake3::hash(&event.ciphertext);
    let mut connection = open_local_database()?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| format!("could not begin local event transaction: {error}"))?;
    let existing: Option<StoredEventEnvelope> = transaction
        .query_row(
            "SELECT ciphertext_digest, ciphertext, author_device, group_id, epoch,
                    checkpoint, expires_at_unix
             FROM local_events WHERE event_id = ?1",
            [event.event_id.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("could not check local event deduplication: {error}"))?;

    if let Some((
        saved_digest,
        saved_ciphertext,
        author_device,
        group_id,
        epoch,
        checkpoint,
        expires_at,
    )) = existing
    {
        let saved_digest = blake3::Hash::from_slice(&saved_digest)
            .map_err(|_| "saved local event has an invalid digest".to_owned())?;
        if saved_digest != digest
            || saved_ciphertext != event.ciphertext
            || author_device != event.author_device
            || group_id != event.group_id
            || epoch != event.epoch as i64
            || checkpoint != event.checkpoint
            || expires_at != event.expires_at_unix
        {
            return Err(
                "event id was reused with different content or envelope metadata".to_owned(),
            );
        }
        transaction
            .commit()
            .map_err(|error| format!("could not finish local event transaction: {error}"))?;
        return Ok(StoreEventResult::AlreadyStored);
    }

    transaction
        .execute(
            "INSERT INTO local_events (
                 event_id, direction, author_device, group_id, epoch, checkpoint,
                 ciphertext_digest, ciphertext, expires_at_unix, delivery_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event.event_id.as_slice(),
                direction,
                event.author_device.as_slice(),
                event.group_id,
                event.epoch as i64,
                event.checkpoint,
                digest.as_bytes().as_slice(),
                event.ciphertext,
                event.expires_at_unix,
                if direction == "outbound" {
                    "queued"
                } else {
                    "received_by_device"
                },
            ],
        )
        .map_err(|error| format!("could not persist local encrypted event: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("could not commit local encrypted event: {error}"))?;
    Ok(StoreEventResult::Stored)
}

pub fn load_identity_public_key() -> Result<Option<[u8; 32]>, String> {
    let entry = identity_key_entry()?;
    match entry.get_secret() {
        Ok(secret) => public_key_from_seed(secret).map(Some),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(error) => Err(format!("could not access the device identity key: {error}")),
    }
}

pub fn create_or_load_identity_public_key() -> Result<[u8; 32], String> {
    let entry = identity_key_entry()?;
    match entry.get_secret() {
        Ok(secret) => public_key_from_seed(secret),
        Err(KeyringError::NoEntry) => {
            let mut seed = Zeroizing::new([0_u8; 32]);
            getrandom::fill(seed.as_mut())
                .map_err(|error| format!("could not generate Ed25519 device key: {error}"))?;
            let signing_key = SigningKey::from_bytes(&seed);
            let public_key = signing_key.verifying_key().to_bytes();
            entry.set_secret(seed.as_ref()).map_err(|error| {
                format!(
                    "could not save the device identity key in the system credential store: {error}"
                )
            })?;
            Ok(public_key)
        }
        Err(error) => Err(format!("could not access the device identity key: {error}")),
    }
}

/// Loads the existing device identity as an Iroh endpoint key without exposing raw seed bytes.
pub(crate) fn load_device_peer_secret_key() -> Result<iroh::SecretKey, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let signing_key = signing_key_from_secret(secret)?;
    peer_secret_key_from_signing_key(&signing_key)
}

fn peer_secret_key_from_signing_key(signing_key: &SigningKey) -> Result<iroh::SecretKey, String> {
    let peer_key = iroh::SecretKey::from_bytes(signing_key.as_bytes());
    if peer_key.public().as_bytes() != signing_key.verifying_key().as_bytes() {
        return Err("Iroh endpoint key does not match the device identity".to_owned());
    }
    Ok(peer_key)
}

/// Signs an MLS-key binding with the existing device identity held in the OS keyring.
/// The private seed is never returned to callers.
pub fn sign_mls_identity_binding(
    signature_scheme: u16,
    mls_signing_public_key: &[u8],
) -> Result<MlsSigningKeyBinding, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let signing_key = signing_key_from_secret(secret)?;
    MlsSigningKeyBinding::sign(&signing_key, signature_scheme, mls_signing_public_key).ok_or_else(
        || "MLS signing public key must be non-empty and fit the binding format".to_owned(),
    )
}

/// Creates or loads this device's MLS signing key for the caller-selected suite,
/// persists it in the encrypted local database, and signs its public key with
/// the existing long-term device identity.
pub fn create_or_load_mls_signing_key_binding(
    ciphersuite: Ciphersuite,
) -> Result<MlsSigningKeyBinding, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    create_or_load_mls_signing_key_binding_in(&mut connection, ciphersuite, &device_identity)
}

/// Create a one-use public KeyPackage whose BasicCredential carries the
/// device-signed binding for its MLS signing key. OpenMLS stores its private
/// bundle in the encrypted local database.
pub fn create_mls_key_package(ciphersuite: Ciphersuite) -> Result<PreparedMlsKeyPackage, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    create_mls_key_package_in(&mut connection, ciphersuite, &device_identity)
}

fn create_mls_key_package_in(
    connection: &mut Connection,
    ciphersuite: Ciphersuite,
    device_identity: &SigningKey,
) -> Result<PreparedMlsKeyPackage, String> {
    let credential_binding =
        create_or_load_mls_signing_key_binding_in(connection, ciphersuite, device_identity)?;
    let credential_identity = credential_binding
        .to_bytes()
        .ok_or_else(|| "MLS credential binding could not be encoded".to_owned())?;
    let key_package = {
        let provider = LocalOpenMlsProvider::new(connection);
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &credential_binding.mls_signing_public_key,
            ciphersuite.signature_algorithm(),
        )
        .ok_or_else(|| "persisted MLS signing key could not be loaded".to_owned())?;
        let credential = BasicCredential::new(credential_identity);
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: credential_binding.mls_signing_public_key.clone().into(),
        };
        let bundle = KeyPackage::builder()
            .build(ciphersuite, &provider, &signer, credential_with_key)
            .map_err(|error| format!("could not create MLS KeyPackage: {error:?}"))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|error| format!("could not serialize MLS KeyPackage: {error}"))?
    };
    Ok(PreparedMlsKeyPackage {
        ciphersuite: ciphersuite as u16,
        credential_binding,
        public_bytes: key_package,
    })
}

/// Create and persist a single-member MLS group locally. The device that creates
/// it is recorded as its designated committer; no invitation or network message
/// is produced by this operation.
pub fn create_mls_group(ciphersuite: Ciphersuite) -> Result<CreatedMlsGroup, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    create_mls_group_in(&mut connection, ciphersuite, &device_identity)
}

/// Admit one device-bound KeyPackage to a local MLS group. The local creator
/// device is the only device allowed to create the Commit; callers must deliver
/// both returned public messages to the invitee and existing group members.
pub fn add_mls_group_member(
    group_id: &[u8],
    serialized_key_package: &[u8],
) -> Result<AddedMlsMember, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    add_mls_group_member_in(
        &mut connection,
        group_id,
        serialized_key_package,
        &device_identity,
    )
}

fn add_mls_group_member_in(
    connection: &mut Connection,
    group_id: &[u8],
    serialized_key_package: &[u8],
    device_identity: &SigningKey,
) -> Result<AddedMlsMember, String> {
    use openmls::prelude::tls_codec::Deserialize as TlsCodecDeserialize;

    let group_id = GroupId::from_slice(group_id);
    let device_public_key = device_identity.verifying_key().to_bytes();
    let designated_committer: Vec<u8> = connection
        .query_row(
            "SELECT designated_committer_device FROM local_mls_groups WHERE group_id = ?1",
            [group_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not load local MLS group policy: {error}"))?;
    if designated_committer.as_slice() != device_public_key {
        return Err("this device is not the designated MLS committer".to_owned());
    }

    let incoming = KeyPackageIn::tls_deserialize_exact(serialized_key_package)
        .map_err(|error| format!("invalid serialized MLS KeyPackage: {error}"))?;
    let (package, ciphersuite, candidate_device) = {
        let provider = LocalOpenMlsProvider::new(connection);
        let package = incoming
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|error| format!("MLS KeyPackage validation failed: {error:?}"))?;
        let ciphersuite = package.ciphersuite();
        let binding =
            MlsSigningKeyBinding::from_bytes(package.leaf_node().credential().serialized_content())
                .ok_or_else(|| "KeyPackage credential has no valid device binding".to_owned())?;
        if !binding.verifies_mls_credential(
            &binding.device_public_key,
            ciphersuite.signature_algorithm() as u16,
            package.leaf_node().signature_key().as_slice(),
        ) {
            return Err("KeyPackage MLS key does not match its device binding".to_owned());
        }
        (package, ciphersuite, binding.device_public_key)
    };
    let committer_binding =
        create_or_load_mls_signing_key_binding_in(connection, ciphersuite, device_identity)?;

    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS member-add transaction: {error}"))?;
    let result = (|| {
        let (added, epoch) = {
            let provider = LocalOpenMlsProvider::new(connection);
            let mut group = MlsGroup::load(provider.storage(), &group_id)
                .map_err(|error| format!("could not load MLS group: {error}"))?
                .ok_or_else(|| "MLS group state is missing".to_owned())?;
            if group.ciphersuite() != ciphersuite {
                return Err("KeyPackage ciphersuite does not match the MLS group".to_owned());
            }
            if candidate_device == device_public_key {
                return Err("the designated committer cannot invite its own device".to_owned());
            }
            if group.members().any(|member| {
                MlsSigningKeyBinding::from_bytes(member.credential.serialized_content())
                    .is_some_and(|binding| binding.device_public_key == candidate_device)
            }) {
                return Err("this device is already a member of the MLS group".to_owned());
            }
            let signer = SignatureKeyPair::read(
                provider.storage(),
                &committer_binding.mls_signing_public_key,
                ciphersuite.signature_algorithm(),
            )
            .ok_or_else(|| "designated committer signing key is missing".to_owned())?;
            let (commit, welcome, _) = group
                .add_members(&provider, &signer, &[package])
                .map_err(|error| format!("could not add MLS group member: {error:?}"))?;
            group
                .merge_pending_commit(&provider)
                .map_err(|error| format!("could not persist MLS membership commit: {error:?}"))?;
            let added = AddedMlsMember {
                group_id: group.group_id().to_vec(),
                epoch: group.epoch().as_u64(),
                commit: commit
                    .tls_serialize_detached()
                    .map_err(|error| format!("could not serialize MLS Commit: {error}"))?,
                welcome: welcome
                    .tls_serialize_detached()
                    .map_err(|error| format!("could not serialize MLS Welcome: {error}"))?,
                ratchet_tree: group
                    .export_ratchet_tree()
                    .tls_serialize_detached()
                    .map_err(|error| format!("could not serialize MLS ratchet tree: {error}"))?,
            };
            (added, group.epoch().as_u64())
        };
        let updated = connection
            .execute(
                "UPDATE local_mls_groups SET epoch = ?1 WHERE group_id = ?2",
                params![epoch as i64, group_id.as_slice()],
            )
            .map_err(|error| format!("could not update local MLS group epoch: {error}"))?;
        if updated != 1 {
            return Err("local MLS group index disappeared during member addition".to_owned());
        }
        Ok(added)
    })();
    finish_sql_transaction(connection, result, "MLS member-add")
}

/// Process an MLS Welcome for a locally stored KeyPackage and persist the
/// admitted group in this device's encrypted database.
pub fn join_mls_group_from_welcome(
    serialized_welcome: &[u8],
    serialized_ratchet_tree: &[u8],
) -> Result<JoinedMlsGroup, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    join_mls_group_from_welcome_in(
        &mut connection,
        serialized_welcome,
        serialized_ratchet_tree,
        &device_identity,
    )
}

fn join_mls_group_from_welcome_in(
    connection: &mut Connection,
    serialized_welcome: &[u8],
    serialized_ratchet_tree: &[u8],
    device_identity: &SigningKey,
) -> Result<JoinedMlsGroup, String> {
    use openmls::prelude::tls_codec::Deserialize as TlsCodecDeserialize;

    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS Welcome transaction: {error}"))?;
    let result = (|| {
        let joined = {
            let provider = LocalOpenMlsProvider::new(connection);
            let message = MlsMessageIn::tls_deserialize_exact(serialized_welcome)
                .map_err(|error| format!("invalid serialized MLS Welcome: {error}"))?;
            let welcome = match message.extract() {
                MlsMessageBodyIn::Welcome(welcome) => welcome,
                _ => return Err("MLS message is not a Welcome".to_owned()),
            };
            let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(serialized_ratchet_tree)
                .map_err(|error| format!("invalid serialized MLS ratchet tree: {error}"))?;
            let staged = StagedWelcome::new_from_welcome(
                &provider,
                &MlsGroupJoinConfig::default(),
                welcome,
                Some(ratchet_tree),
            )
            .map_err(|error| format!("could not process MLS Welcome: {error:?}"))?;
            let device_public_key = device_identity.verifying_key().to_bytes();
            let suite = staged.group_context().ciphersuite();
            let own_leaf = staged
                .own_leaf_node()
                .ok_or_else(|| "MLS Welcome has no local member leaf".to_owned())?;
            let own_binding =
                MlsSigningKeyBinding::from_bytes(own_leaf.credential().serialized_content())
                    .ok_or_else(|| "Welcome member credential has no device binding".to_owned())?;
            if !own_binding.verifies_mls_credential(
                &device_public_key,
                suite.signature_algorithm() as u16,
                own_leaf.signature_key().as_slice(),
            ) {
                return Err("Welcome KeyPackage does not belong to this device".to_owned());
            }
            let sender = staged
                .welcome_sender()
                .map_err(|error| format!("could not inspect MLS Welcome sender: {error}"))?;
            let sender_binding =
                MlsSigningKeyBinding::from_bytes(sender.credential().serialized_content())
                    .ok_or_else(|| "Welcome sender credential has no device binding".to_owned())?;
            if !sender_binding.verifies_mls_credential(
                &sender_binding.device_public_key,
                suite.signature_algorithm() as u16,
                sender.signature_key().as_slice(),
            ) {
                return Err("Welcome sender MLS key does not match its device binding".to_owned());
            }
            let group = staged
                .into_group(&provider)
                .map_err(|error| format!("could not persist joined MLS group: {error:?}"))?;
            JoinedMlsGroup {
                group_id: group.group_id().to_vec(),
                ciphersuite: group.ciphersuite() as u16,
                epoch: group.epoch().as_u64(),
                designated_committer_device: sender_binding.device_public_key,
            }
        };
        connection
            .execute(
                "INSERT INTO local_mls_groups
                    (group_id, ciphersuite, designated_committer_device, epoch)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    joined.group_id,
                    joined.ciphersuite,
                    joined.designated_committer_device.as_slice(),
                    joined.epoch as i64
                ],
            )
            .map_err(|error| format!("could not index joined MLS group: {error}"))?;
        Ok(joined)
    })();
    finish_sql_transaction(connection, result, "MLS Welcome")
}

fn finish_sql_transaction<T>(
    connection: &Connection,
    result: Result<T, String>,
    operation: &str,
) -> Result<T, String> {
    match result {
        Ok(value) => {
            connection
                .execute_batch("COMMIT")
                .map_err(|error| format!("could not commit {operation} transaction: {error}"))?;
            Ok(value)
        }
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn create_mls_group_in(
    connection: &mut Connection,
    ciphersuite: Ciphersuite,
    device_identity: &SigningKey,
) -> Result<CreatedMlsGroup, String> {
    let binding =
        create_or_load_mls_signing_key_binding_in(connection, ciphersuite, device_identity)?;
    let credential_identity = binding
        .to_bytes()
        .ok_or_else(|| "MLS credential binding could not be encoded".to_owned())?;
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS group transaction: {error}"))?;

    let result = (|| {
        let (created_group, group_id) = {
            let provider = LocalOpenMlsProvider::new(connection);
            let signer = SignatureKeyPair::read(
                provider.storage(),
                &binding.mls_signing_public_key,
                ciphersuite.signature_algorithm(),
            )
            .ok_or_else(|| "persisted MLS signing key could not be loaded".to_owned())?;
            let credential = BasicCredential::new(credential_identity);
            let credential_with_key = CredentialWithKey {
                credential: credential.into(),
                signature_key: binding.mls_signing_public_key.clone().into(),
            };
            let group_id = GroupId::random(provider.rand());
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(ciphersuite)
                .build();
            let group = MlsGroup::new_with_group_id(
                &provider,
                &signer,
                &config,
                group_id.clone(),
                credential_with_key,
            )
            .map_err(|error| format!("could not create local MLS group: {error:?}"))?;
            let created_group = CreatedMlsGroup {
                group_id: group.group_id().to_vec(),
                ciphersuite: ciphersuite as u16,
                epoch: group.epoch().as_u64(),
                designated_committer_device: binding.device_public_key,
            };
            (created_group, group_id.to_vec())
        };
        connection
            .execute(
                "INSERT INTO local_mls_groups
                    (group_id, ciphersuite, designated_committer_device, epoch)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    group_id,
                    ciphersuite as u16,
                    binding.device_public_key.as_slice(),
                    created_group.epoch as i64
                ],
            )
            .map_err(|error| format!("could not index local MLS group: {error}"))?;
        Ok(created_group)
    })();

    match result {
        Ok(group) => {
            connection
                .execute_batch("COMMIT")
                .map_err(|error| format!("could not commit local MLS group: {error}"))?;
            Ok(group)
        }
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn create_or_load_mls_signing_key_binding_in(
    connection: &mut Connection,
    ciphersuite: Ciphersuite,
    device_identity: &SigningKey,
) -> Result<MlsSigningKeyBinding, String> {
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS signing-key transaction: {error}"))?;
    let result = (|| {
        let signature_scheme = ciphersuite.signature_algorithm();
        let ciphersuite_id = ciphersuite as u16;
        let stored_public_key = connection
            .query_row(
                "SELECT public_key FROM local_mls_signing_keys WHERE ciphersuite = ?1",
                [ciphersuite_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| format!("could not read MLS signing-key index: {error}"))?;
        let (binding, new_public_key) = {
            let storage = SqliteStorageProvider::<OpenMlsJsonCodec, _>::new(&mut *connection);
            let signer = if let Some(public_key) = stored_public_key.as_ref() {
                SignatureKeyPair::read(&storage, public_key, signature_scheme).ok_or_else(|| {
                    "MLS signing-key index points to missing key material; refusing to rotate identity silently".to_owned()
                })?
            } else {
                let signer = SignatureKeyPair::new(signature_scheme)
                    .map_err(|error| format!("could not generate MLS signing key: {error:?}"))?;
                signer
                    .store(&storage)
                    .map_err(|error| format!("could not persist MLS signing key: {error}"))?;
                signer
            };
            let binding = MlsSigningKeyBinding::sign(
                device_identity,
                signature_scheme as u16,
                signer.public(),
            )
            .ok_or_else(|| "OpenMLS returned an invalid signing public key".to_owned())?;
            let public_key = if stored_public_key.is_none() {
                Some(signer.to_public_vec())
            } else {
                None
            };
            (binding, public_key)
        };
        if let Some(public_key) = new_public_key {
            connection
                .execute(
                    "INSERT INTO local_mls_signing_keys (ciphersuite, public_key) VALUES (?1, ?2)",
                    params![ciphersuite_id, public_key],
                )
                .map_err(|error| format!("could not index MLS signing key: {error}"))?;
        }
        Ok(binding)
    })();
    match result {
        Ok(binding) => {
            connection.execute_batch("COMMIT").map_err(|error| {
                format!("could not commit MLS signing-key transaction: {error}")
            })?;
            Ok(binding)
        }
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn key_entry() -> Result<Entry, String> {
    Entry::new(SERVICE, KEY_NAME)
        .map_err(|error| format!("system credential store is unavailable: {error}"))
}

fn identity_key_entry() -> Result<Entry, String> {
    Entry::new(SERVICE, IDENTITY_KEY_NAME)
        .map_err(|error| format!("system credential store is unavailable: {error}"))
}

fn public_key_from_seed(secret: Vec<u8>) -> Result<[u8; 32], String> {
    Ok(signing_key_from_secret(secret)?.verifying_key().to_bytes())
}

fn signing_key_from_secret(secret: Vec<u8>) -> Result<SigningKey, String> {
    let mut secret = Zeroizing::new(secret);
    if secret.len() != 32 {
        return Err("saved Ed25519 device key has an invalid length".to_owned());
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&secret);
    secret.zeroize();
    Ok(SigningKey::from_bytes(&seed))
}

fn secret_key(bytes: Vec<u8>) -> Result<Zeroizing<[u8; PROFILE_DB_KEY_LEN]>, String> {
    let mut bytes = Zeroizing::new(bytes);
    if bytes.len() != PROFILE_DB_KEY_LEN {
        return Err("saved local database key has an invalid length".to_owned());
    }
    let mut key = Zeroizing::new([0_u8; PROFILE_DB_KEY_LEN]);
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(key)
}

fn open_local_database() -> Result<Connection, String> {
    let entry = key_entry()?;
    let key = match entry.get_secret() {
        Ok(bytes) => secret_key(bytes)?,
        Err(KeyringError::NoEntry) => {
            let mut key = Zeroizing::new([0_u8; PROFILE_DB_KEY_LEN]);
            getrandom::fill(key.as_mut())
                .map_err(|error| format!("could not generate local database key: {error}"))?;
            entry.set_secret(key.as_ref()).map_err(|error| {
                format!(
                    "could not save the local database key in the system credential store: {error}"
                )
            })?;
            key
        }
        Err(error) => {
            return Err(format!(
                "could not access the system credential store: {error}"
            ));
        }
    };
    open_database(&database_path()?, &key)
}

fn database_path() -> Result<PathBuf, String> {
    let project = ProjectDirs::from("org", "slouching", "Slouching")
        .ok_or_else(|| "could not locate the per-user application data directory".to_owned())?;
    let data_dir = project.data_dir();
    fs::create_dir_all(data_dir)
        .map_err(|error| format!("could not create local profile directory: {error}"))?;
    restrict_directory_permissions(data_dir)?;
    Ok(data_dir.join(PROFILE_DB))
}

fn open_database(path: &Path, key: &[u8; PROFILE_DB_KEY_LEN]) -> Result<Connection, String> {
    prepare_database_file(path)?;
    let mut connection = Connection::open(path)
        .map_err(|error| format!("could not open local profile database: {error}"))?;
    let key_hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    connection
        .execute_batch(&format!(
            "PRAGMA key = \"x'{key_hex}'\";
             PRAGMA cipher_memory_security = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;"
        ))
        .map_err(|error| format!("could not unlock encrypted local profile database: {error}"))?;

    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| format!("could not read local profile schema version: {error}"))?;
    if version > PROFILE_SCHEMA_VERSION {
        return Err(format!(
            "local profile database version {version} is newer than this app"
        ));
    }
    let transaction = connection
        .unchecked_transaction()
        .map_err(|error| format!("could not initialize local profile schema: {error}"))?;
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS local_profile (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 40),
                 familiar TEXT NOT NULL CHECK (familiar IN ('frog', 'gnome', 'orb'))
             );",
        )
        .map_err(|error| format!("could not initialize local profile schema: {error}"))?;
    if version < 2 {
        transaction
            .execute_batch(
                "CREATE TABLE local_events (
                     event_id BLOB PRIMARY KEY NOT NULL CHECK (length(event_id) = 16),
                     direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
                     author_device BLOB NOT NULL CHECK (length(author_device) = 32),
                     group_id BLOB NOT NULL CHECK (length(group_id) > 0),
                     epoch INTEGER NOT NULL CHECK (epoch >= 0),
                     checkpoint BLOB,
                     ciphertext_digest BLOB NOT NULL CHECK (length(ciphertext_digest) = 32),
                     ciphertext BLOB NOT NULL CHECK (length(ciphertext) > 0),
                     expires_at_unix INTEGER NOT NULL CHECK (expires_at_unix > 0)
                 );
                 CREATE INDEX local_events_by_group
                     ON local_events (group_id, epoch, event_id);
                 PRAGMA user_version = 2;",
            )
            .map_err(|error| format!("could not create local event storage: {error}"))?;
    }
    if version < 3 {
        transaction
            .execute_batch(
                "ALTER TABLE local_events
                    ADD COLUMN delivery_state TEXT NOT NULL DEFAULT 'queued'
                    CHECK (delivery_state IN (
                        'queued', 'held_by_peer', 'received_by_device', 'expired', 'failed'
                    ));
                 UPDATE local_events SET delivery_state = 'received_by_device'
                    WHERE direction = 'inbound';
                 PRAGMA user_version = 3;",
            )
            .map_err(|error| format!("could not migrate local outbox state: {error}"))?;
    }
    if version < 4 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_signing_keys (
                     ciphersuite INTEGER PRIMARY KEY NOT NULL CHECK (ciphersuite BETWEEN 1 AND 65535),
                     public_key BLOB NOT NULL CHECK (length(public_key) > 0)
                 );
                 PRAGMA user_version = 4;",
            )
            .map_err(|error| format!("could not create local MLS signing-key index: {error}"))?;
    }
    if version < 5 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_groups (
                     group_id BLOB PRIMARY KEY NOT NULL CHECK (length(group_id) = 16),
                     ciphersuite INTEGER NOT NULL CHECK (ciphersuite BETWEEN 1 AND 65535),
                     designated_committer_device BLOB NOT NULL
                         CHECK (length(designated_committer_device) = 32),
                     epoch INTEGER NOT NULL CHECK (epoch >= 0)
                 );
                 PRAGMA user_version = 5;",
            )
            .map_err(|error| format!("could not create local MLS group index: {error}"))?;
    }
    if version < 6 {
        transaction
            .execute_batch(
                "CREATE TABLE local_direct_messages (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     peer_device BLOB NOT NULL CHECK (length(peer_device) = 32),
                     direction TEXT NOT NULL CHECK (direction IN ('sent', 'received')),
                     text TEXT NOT NULL CHECK (length(CAST(text AS BLOB)) BETWEEN 1 AND 16384)
                 );
                 CREATE INDEX local_direct_messages_by_peer
                     ON local_direct_messages (peer_device, sequence);
                 PRAGMA user_version = 6;",
            )
            .map_err(|error| format!("could not create encrypted direct history: {error}"))?;
    }
    transaction
        .commit()
        .map_err(|error| format!("could not finish local profile migration: {error}"))?;
    LocalOpenMlsProvider::new(&mut connection)
        .run_migrations()
        .map_err(|error| format!("could not initialize encrypted OpenMLS storage: {error}"))?;
    Ok(connection)
}

fn prepare_database_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        if let Some(parent) = path.parent() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|error| {
                    format!("could not create private local profile directory: {error}")
                })?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("could not restrict local profile directory: {error}"))?;
        }
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("could not create private local profile database: {error}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("could not restrict local profile database: {error}"))?;
    }
    #[cfg(not(unix))]
    {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("could not create local profile directory: {error}"))?;
        }
    }
    Ok(())
}

fn restrict_directory_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("could not restrict local profile directory: {error}"))?;
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::BINDING_VERSION;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn iroh_endpoint_id_uses_the_pinned_device_public_key() {
        let device_identity = SigningKey::from_bytes(&[0x61; 32]);
        let peer_identity = peer_secret_key_from_signing_key(&device_identity)
            .expect("Iroh should accept the device Ed25519 seed");
        assert_eq!(
            peer_identity.public().as_bytes(),
            device_identity.verifying_key().as_bytes()
        );
    }

    #[test]
    fn direct_message_history_is_encrypted_peer_scoped_and_survives_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-direct-history-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let path = directory.join("profile.sqlite3");
        let key = [0x35; PROFILE_DB_KEY_LEN];
        let peer = [0x61; 32];
        let another_peer = [0x62; 32];

        {
            let mut connection = open_database(&path, &key)
                .expect("encrypted database should initialize with local history");
            let cipher_version: String = connection
                .query_row("PRAGMA cipher_version", [], |row| row.get(0))
                .expect("database should use SQLCipher");
            assert!(!cipher_version.is_empty());
            store_direct_message_in(
                &mut connection,
                peer,
                DirectMessageDirection::Received,
                "hello from peer",
            )
            .expect("inbound message should persist");
            store_direct_message_in(
                &mut connection,
                peer,
                DirectMessageDirection::Sent,
                "hello back",
            )
            .expect("outbound message should persist");
            store_direct_message_in(
                &mut connection,
                another_peer,
                DirectMessageDirection::Received,
                "separate peer",
            )
            .expect("another peer history should persist separately");
            assert!(store_direct_message_in(
                &mut connection,
                peer,
                DirectMessageDirection::Sent,
                "   ",
            )
            .is_err());
        }

        let connection = open_database(&path, &key).expect("encrypted history should reopen");
        let history = list_direct_messages_in(&connection, peer, 200)
            .expect("history should load for its pinned peer");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].direction, DirectMessageDirection::Received);
        assert_eq!(history[0].text, "hello from peer");
        assert_eq!(history[1].direction, DirectMessageDirection::Sent);
        assert_eq!(history[1].text, "hello back");
        assert!(
            list_direct_messages_in(&connection, another_peer, 200)
                .expect("another peer's history should load separately")
                .iter()
                .all(|message| message.text == "separate peer")
        );
        drop(connection);
        let mut connection =
            open_database(&path, &key).expect("encrypted history should reopen before deletion");
        assert_eq!(clear_direct_history_in(&mut connection, peer).unwrap(), 2);
        assert!(
            list_direct_messages_in(&connection, peer, 200)
                .expect("cleared peer history should remain queryable")
                .is_empty()
        );
        assert_eq!(
            list_direct_messages_in(&connection, another_peer, 200)
                .expect("another peer history should remain")
                .len(),
            1
        );

        fs::remove_dir_all(directory).expect("temporary database files should be removed");
    }

    #[test]
    fn direct_message_history_retains_only_the_newest_per_peer_limit() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-direct-history-limit-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let path = directory.join("profile.sqlite3");
        let key = [0x34; PROFILE_DB_KEY_LEN];
        let peer = [0x63; 32];
        let mut connection = open_database(&path, &key)
            .expect("encrypted database should initialize with local history");
        for index in 0..=MAX_DIRECT_HISTORY_PER_PEER {
            store_direct_message_in(
                &mut connection,
                peer,
                DirectMessageDirection::Sent,
                &format!("message {index}"),
            )
            .expect("message should save and enforce the peer history limit");
        }
        let history = list_direct_messages_in(&connection, peer, 500)
            .expect("bounded history page should load");
        assert_eq!(history.len(), 500);
        assert_eq!(history[0].text, "message 501");
        assert_eq!(history[499].text, "message 1000");
        let retained: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM local_direct_messages WHERE peer_device = ?1",
                [peer.as_slice()],
                |row| row.get(0),
            )
            .expect("peer history row count should be queryable");
        assert_eq!(retained, MAX_DIRECT_HISTORY_PER_PEER);
        fs::remove_dir_all(directory).expect("temporary database files should be removed");
    }

    #[test]
    fn encrypted_database_migrates_openmls_storage_idempotently() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-openmls-storage-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let path = directory.join("profile.sqlite3");
        let key = [0x5a; PROFILE_DB_KEY_LEN];
        use openmls::prelude::Ciphersuite;
        use openmls_basic_credential::SignatureKeyPair;

        let signature_scheme =
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm();
        let mut public_key = None;

        for attempt in 0..2 {
            let mut connection = open_database(&path, &key)
                .expect("encrypted profile and OpenMLS migrations should succeed");
            let cipher_version: String = connection
                .query_row("PRAGMA cipher_version", [], |row| row.get(0))
                .expect("database should use SQLCipher");
            assert!(!cipher_version.is_empty());

            let openmls_table_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'openmls_signature_keys'",
                    [],
                    |row| row.get(0),
                )
                .expect("OpenMLS signature-key table should be queryable");
            assert_eq!(openmls_table_count, 1);

            {
                let provider = LocalOpenMlsProvider::new(&mut connection);
                if attempt == 0 {
                    let signer = SignatureKeyPair::new(signature_scheme)
                        .expect("MLS signature key should be generated");
                    signer
                        .store(provider.storage())
                        .expect("MLS signature key should persist through the SQL provider");
                    public_key = Some(signer.to_public_vec());
                }
                let loaded_signer = SignatureKeyPair::read(
                    provider.storage(),
                    public_key
                        .as_deref()
                        .expect("MLS public key should be retained for this test"),
                    signature_scheme,
                )
                .expect("persisted MLS signature key should load through the SQL provider");
                assert_eq!(loaded_signer.public(), public_key.as_deref().unwrap());
            }
            let signature_key_count: i64 = connection
                .query_row("SELECT COUNT(*) FROM openmls_signature_keys", [], |row| {
                    row.get(0)
                })
                .expect("OpenMLS signature keys should be queryable");
            assert_eq!(signature_key_count, 1);
        }

        fs::remove_dir_all(directory).expect("temporary database files should be removed");
    }

    #[test]
    fn mls_signing_binding_is_stable_across_database_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-mls-binding-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let path = directory.join("profile.sqlite3");
        let database_key = [0x4c; PROFILE_DB_KEY_LEN];
        let device_identity = SigningKey::from_bytes(&[0x27; 32]);
        let device_public_key = device_identity.verifying_key().to_bytes();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let mut connection = open_database(&path, &database_key)
            .expect("temporary database should initialize with SQLCipher and OpenMLS");
        let first = create_or_load_mls_signing_key_binding_in(
            &mut connection,
            ciphersuite,
            &device_identity,
        )
        .expect("MLS signer and device-signed binding should be created");
        assert_eq!(
            first.signature_scheme,
            ciphersuite.signature_algorithm() as u16
        );
        assert_eq!(first.version, BINDING_VERSION);
        assert!(first.verify(&device_public_key));
        drop(connection);

        let mut reopened = open_database(&path, &database_key)
            .expect("encrypted database should reopen with stored MLS key");
        let second =
            create_or_load_mls_signing_key_binding_in(&mut reopened, ciphersuite, &device_identity)
                .expect("stored MLS signer and binding should load");
        assert_eq!(second, first);
        assert!(second.verify(&device_public_key));

        let p256_suite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
        let p256_binding =
            create_or_load_mls_signing_key_binding_in(&mut reopened, p256_suite, &device_identity)
                .expect("caller-selected P-256 suite should create its own MLS signing key");
        assert_eq!(
            p256_binding.signature_scheme,
            p256_suite.signature_algorithm() as u16
        );
        assert_ne!(
            p256_binding.mls_signing_public_key,
            second.mls_signing_public_key
        );
        assert!(p256_binding.verify(&device_public_key));

        drop(reopened);
        fs::remove_dir_all(directory).expect("temporary database files should be removed");
    }

    #[test]
    fn mls_key_package_is_device_bound_valid_and_stored_with_private_material() {
        use openmls::prelude::{
            Ciphersuite, KeyPackageIn, ProtocolVersion,
            tls_codec::Deserialize as TlsCodecDeserialize,
        };

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-key-package-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let path = directory.join("profile.sqlite3");
        let database_key = [0x3a; PROFILE_DB_KEY_LEN];
        let device_identity = SigningKey::from_bytes(&[0x6b; 32]);
        let device_public_key = device_identity.verifying_key().to_bytes();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let mut connection = open_database(&path, &database_key)
            .expect("temporary database should initialize with SQLCipher and OpenMLS");
        let prepared = create_mls_key_package_in(&mut connection, ciphersuite, &device_identity)
            .expect("KeyPackage and private bundle should be created");
        assert_eq!(prepared.ciphersuite, ciphersuite as u16);
        assert!(prepared.credential_binding.verify(&device_public_key));

        {
            let provider = LocalOpenMlsProvider::new(&mut connection);
            let incoming = KeyPackageIn::tls_deserialize_exact(&prepared.public_bytes)
                .expect("serialized public KeyPackage should decode without trailing bytes");
            let validated = incoming
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .expect("OpenMLS should validate the public KeyPackage");
            let credential_binding = MlsSigningKeyBinding::from_bytes(
                validated.leaf_node().credential().serialized_content(),
            )
            .expect("BasicCredential should contain the encoded device binding");
            assert_eq!(credential_binding, prepared.credential_binding);
            assert!(credential_binding.verifies_mls_credential(
                &device_public_key,
                validated.ciphersuite().signature_algorithm() as u16,
                validated.leaf_node().signature_key().as_slice(),
            ));
        }

        let private_bundle_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
                row.get(0)
            })
            .expect("OpenMLS private KeyPackage bundle should be stored in SQLCipher");
        assert_eq!(private_bundle_count, 1);

        drop(connection);
        fs::remove_dir_all(directory).expect("temporary database files should be removed");
    }

    #[test]
    fn local_mls_group_persists_creator_as_designated_committer() {
        use openmls::prelude::{Ciphersuite, GroupId, MlsGroup};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-mls-group-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let path = directory.join("profile.sqlite3");
        let database_key = [0x2d; PROFILE_DB_KEY_LEN];
        let device_identity = SigningKey::from_bytes(&[0x4f; 32]);
        let device_public_key = device_identity.verifying_key().to_bytes();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let mut connection = open_database(&path, &database_key)
            .expect("temporary database should initialize with SQLCipher and OpenMLS");
        let created = create_mls_group_in(&mut connection, ciphersuite, &device_identity)
            .expect("single-member group should be created and persisted");
        assert_eq!(created.ciphersuite, ciphersuite as u16);
        assert_eq!(created.epoch, 0);
        assert_eq!(created.designated_committer_device, device_public_key);
        assert_eq!(created.group_id.len(), 16);

        let (indexed_ciphersuite, indexed_committer, indexed_epoch): (i64, Vec<u8>, i64) =
            connection
                .query_row(
                    "SELECT ciphersuite, designated_committer_device, epoch
                     FROM local_mls_groups WHERE group_id = ?1",
                    [&created.group_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("local group policy row should be indexed");
        assert_eq!(indexed_ciphersuite, i64::from(ciphersuite as u16));
        assert_eq!(indexed_committer, device_public_key);
        assert_eq!(indexed_epoch, 0);

        {
            let provider = LocalOpenMlsProvider::new(&mut connection);
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&created.group_id))
                .expect("OpenMLS group state should load")
                .expect("created group should be present in OpenMLS storage");
            assert_eq!(group.epoch().as_u64(), created.epoch);
            assert_eq!(group.members().count(), 1);
            let credential = group
                .members()
                .next()
                .expect("single-member group should have its creator")
                .credential;
            let binding = MlsSigningKeyBinding::from_bytes(credential.serialized_content())
                .expect("creator credential should contain the signed device binding");
            assert!(binding.verify(&device_public_key));
        }

        drop(connection);
        fs::remove_dir_all(directory).expect("temporary database files should be removed");
    }

    #[test]
    fn designated_committer_adds_device_bound_member_and_invitee_joins_welcome() {
        use openmls::prelude::{Ciphersuite, GroupId, MlsGroup};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-mls-admission-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let creator_path = directory.join("creator.sqlite3");
        let invitee_path = directory.join("invitee.sqlite3");
        let creator_key = [0x51; PROFILE_DB_KEY_LEN];
        let invitee_key = [0x52; PROFILE_DB_KEY_LEN];
        let creator_identity = SigningKey::from_bytes(&[0x53; 32]);
        let invitee_identity = SigningKey::from_bytes(&[0x54; 32]);
        let creator_public_key = creator_identity.verifying_key().to_bytes();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let mut creator =
            open_database(&creator_path, &creator_key).expect("creator database should initialize");
        let group = create_mls_group_in(&mut creator, ciphersuite, &creator_identity)
            .expect("creator should create a local MLS group");

        let mut invitee =
            open_database(&invitee_path, &invitee_key).expect("invitee database should initialize");
        let package = create_mls_key_package_in(&mut invitee, ciphersuite, &invitee_identity)
            .expect("invitee should prepare a device-bound KeyPackage");
        let admission = add_mls_group_member_in(
            &mut creator,
            &group.group_id,
            &package.public_bytes,
            &creator_identity,
        )
        .expect("designated committer should add the valid KeyPackage");
        assert_eq!(admission.group_id, group.group_id);
        assert_eq!(admission.epoch, 1);
        assert!(!admission.commit.is_empty());
        assert!(!admission.welcome.is_empty());

        let joined = join_mls_group_from_welcome_in(
            &mut invitee,
            &admission.welcome,
            &admission.ratchet_tree,
            &invitee_identity,
        )
        .expect("invitee should process Welcome using its stored KeyPackage bundle");
        assert_eq!(joined.group_id, group.group_id);
        assert_eq!(joined.ciphersuite, ciphersuite as u16);
        assert_eq!(joined.epoch, 1);
        assert_eq!(joined.designated_committer_device, creator_public_key);

        {
            let provider = LocalOpenMlsProvider::new(&mut creator);
            let loaded = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group.group_id))
                .expect("creator group should reload")
                .expect("creator group should persist");
            assert_eq!(loaded.epoch().as_u64(), 1);
            assert_eq!(loaded.members().count(), 2);
        }
        {
            let provider = LocalOpenMlsProvider::new(&mut invitee);
            let loaded = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group.group_id))
                .expect("invitee group should reload")
                .expect("Welcome should persist joined group");
            assert_eq!(loaded.epoch().as_u64(), 1);
            assert_eq!(loaded.members().count(), 2);
        }

        let another_identity = SigningKey::from_bytes(&[0x55; 32]);
        let another_package =
            create_mls_key_package_in(&mut invitee, ciphersuite, &another_identity)
                .expect("third device should prepare a KeyPackage");
        let unauthorized = add_mls_group_member_in(
            &mut invitee,
            &group.group_id,
            &another_package.public_bytes,
            &invitee_identity,
        )
        .expect_err("a non-designated member must not create the group Commit");
        assert!(unauthorized.contains("designated MLS committer"));

        drop(invitee);
        drop(creator);
        fs::remove_dir_all(directory).expect("temporary database directory should be removed");
    }
}
