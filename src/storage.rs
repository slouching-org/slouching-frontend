use crate::file_transfer::FileOffer;
use crate::identity::MlsSigningKeyBinding;
use directories::ProjectDirs;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use keyring::{Entry, Error as KeyringError};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, KeyPackageIn,
    LeafNodeParameters, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn,
    MlsMessageIn, OpenMlsProvider, ProcessedMessageContent, Proposal, ProtocolVersion,
    RatchetTreeIn, StagedWelcome, tls_codec::Serialize as TlsCodecSerialize,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec as OpenMlsCodec, SqliteStorageProvider};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "org.slouching.desktop";
const KEY_NAME: &str = "local-profile-database-v1";
const IDENTITY_KEY_NAME: &str = "device-signing-ed25519-v1";
const PROFILE_DB: &str = "profile.sqlite3";
const PROFILE_DB_KEY_LEN: usize = 32;
const PROFILE_SCHEMA_VERSION: u32 = 21;
const MAX_DIRECT_HISTORY_PER_PEER: i64 = 1000;
const MAX_MLS_HISTORY_PER_GROUP: i64 = 1000;
const MAX_DELEGATED_COPY_BYTES: usize = 32 * 1024;
const MAX_DELEGATED_STORAGE_BYTES: i64 = 64 * 1024 * 1024;
const MAX_DELEGATED_STORAGE_EVENTS: i64 = 4096;
const MAX_DELEGATED_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
const MAX_DELEGATED_CHECKPOINT_BYTES: usize = 16 * 1024;
type StoredEventEnvelope = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    i64,
);
type StoredInboundEnvelope = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    i64,
    Vec<u8>,
);
type StoredPriorMlsCommit = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type StoredPriorFileAttachment = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type StoredDelegatedCopyEnvelope = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    i64,
    Vec<u8>,
    String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedMlsCopyGrant {
    pub event_id: [u8; 16],
    pub author_device: [u8; 32],
    pub recipient_device: [u8; 32],
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub expires_at_unix: i64,
    pub checkpoint: Option<Vec<u8>>,
    pub ciphertext_digest: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDelegatedMlsCopy {
    pub grant: DelegatedMlsCopyGrant,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegatedMlsStorageStatus {
    pub enabled: bool,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub queued_copies: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegatedCopyStoreResult {
    Stored,
    AlreadyStored,
}

pub fn set_delegated_mls_storage_policy(enabled: bool, quota_bytes: i64) -> Result<(), String> {
    let mut connection = open_local_database()?;
    set_delegated_mls_storage_policy_in(&mut connection, enabled, quota_bytes, unix_time_now()?)
}

fn set_delegated_mls_storage_policy_in(
    connection: &mut Connection,
    enabled: bool,
    quota_bytes: i64,
    now: i64,
) -> Result<(), String> {
    if !(0..=MAX_DELEGATED_STORAGE_BYTES).contains(&quota_bytes) {
        return Err(format!(
            "delegated storage quota must be between 0 and {MAX_DELEGATED_STORAGE_BYTES} bytes"
        ));
    }
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| format!("could not begin delegated storage policy update: {error}"))?;
    if !enabled {
        transaction
            .execute(
                "UPDATE local_delegated_mls_copies
                 SET delivery_state = 'expired', ciphertext = NULL
                 WHERE delivery_state = 'queued'",
                [],
            )
            .map_err(|error| format!("could not erase opted-out delegated copies: {error}"))?;
        cleanup_delegated_mls_tombstones(&transaction, now)?;
    }
    let used_bytes: i64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(length(ciphertext)), 0)
             FROM local_delegated_mls_copies WHERE delivery_state = 'queued'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not read delegated storage usage: {error}"))?;
    if enabled && quota_bytes < used_bytes {
        return Err("delegated storage quota cannot be lower than current usage".to_owned());
    }
    transaction
        .execute(
            "UPDATE local_delegation_policy SET enabled = ?1, quota_bytes = ?2 WHERE id = 1",
            params![enabled, quota_bytes],
        )
        .map_err(|error| format!("could not save delegated storage policy: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("could not commit delegated storage policy: {error}"))
}

pub fn load_delegated_mls_storage_status() -> Result<DelegatedMlsStorageStatus, String> {
    let connection = open_local_database()?;
    let now = unix_time_now()?;
    connection
        .execute(
            "UPDATE local_delegated_mls_copies
             SET delivery_state = 'expired', ciphertext = NULL
             WHERE delivery_state = 'queued' AND expires_at_unix <= ?1",
            [now],
        )
        .map_err(|error| format!("could not expire delegated MLS copies: {error}"))?;
    cleanup_delegated_mls_tombstones(&connection, now)?;
    connection
        .query_row(
            "SELECT p.enabled, p.quota_bytes,
                    COALESCE(SUM(CASE WHEN c.delivery_state = 'queued'
                                      THEN length(c.ciphertext) ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN c.delivery_state = 'queued' THEN 1 ELSE 0 END), 0)
             FROM local_delegation_policy p
             LEFT JOIN local_delegated_mls_copies c ON 1 = 1
             WHERE p.id = 1",
            [],
            |row| {
                Ok(DelegatedMlsStorageStatus {
                    enabled: row.get(0)?,
                    quota_bytes: row.get(1)?,
                    used_bytes: row.get(2)?,
                    queued_copies: row.get(3)?,
                })
            },
        )
        .map_err(|error| format!("could not load delegated storage status: {error}"))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPeerRoute {
    pub device_public_key: [u8; 32],
    pub address: String,
    pub relay_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMlsMessage {
    pub sequence: i64,
    pub event_id: [u8; 16],
    pub direction: DirectMessageDirection,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMlsGroup {
    pub group_id: [u8; 16],
    pub epoch: u64,
    pub quarantined: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StoredFileAttachment {
    pub group_id: [u8; 16],
    pub author_device: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub created_at_unix: i64,
    pub offer: FileOffer,
}

/// Saves an attachment offer and its content key inside the encrypted profile.
/// The key-bearing offer is never written to the blob store or plaintext files.
pub fn save_file_attachment(
    group_id: [u8; 16],
    author_device: [u8; 32],
    ciphertext_hash: [u8; 32],
    offer: &FileOffer,
) -> Result<(), String> {
    let mut connection = open_local_database()?;
    save_file_attachment_in(
        &mut connection,
        group_id,
        author_device,
        ciphertext_hash,
        offer,
    )
}

pub fn list_file_attachments(group_id: [u8; 16]) -> Result<Vec<StoredFileAttachment>, String> {
    let connection = open_local_database()?;
    list_file_attachments_in(&connection, group_id)
}

pub fn delete_file_attachment(transfer_id: [u8; 16]) -> Result<bool, String> {
    let connection = open_local_database()?;
    connection
        .execute(
            "DELETE FROM local_file_attachments WHERE transfer_id = ?1",
            params![transfer_id.as_slice()],
        )
        .map(|deleted| deleted == 1)
        .map_err(|error| format!("could not remove local file attachment: {error}"))
}

fn save_file_attachment_in(
    connection: &mut Connection,
    group_id: [u8; 16],
    author_device: [u8; 32],
    ciphertext_hash: [u8; 32],
    offer: &FileOffer,
) -> Result<(), String> {
    let encoded_offer = offer.encode()?;
    let transaction = connection
        .transaction()
        .map_err(|error| format!("could not begin file attachment save: {error}"))?;
    let group_state: Option<i64> = transaction
        .query_row(
            "SELECT quarantined FROM local_mls_groups WHERE group_id = ?1",
            params![group_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("could not validate attachment group: {error}"))?;
    match group_state {
        Some(0) => {}
        Some(_) => return Err("cannot attach a file to a quarantined group".to_owned()),
        None => return Err("cannot attach a file to an unknown local group".to_owned()),
    }
    let prior: Option<StoredPriorFileAttachment> = transaction
        .query_row(
            "SELECT group_id, author_device, ciphertext_hash, offer FROM local_file_attachments
             WHERE transfer_id = ?1",
            params![offer.transfer_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| format!("could not check duplicate attachment: {error}"))?;
    if let Some((prior_group, prior_author, prior_hash, prior_offer)) = prior {
        if prior_group == group_id
            && prior_author == author_device
            && prior_hash == ciphertext_hash
            && prior_offer == encoded_offer
        {
            return Ok(());
        }
        return Err("file transfer ID is already bound to another attachment".to_owned());
    }
    transaction
        .execute(
            "INSERT INTO local_file_attachments
                 (transfer_id, group_id, author_device, ciphertext_hash, offer, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                offer.transfer_id.as_slice(),
                group_id.as_slice(),
                author_device.as_slice(),
                ciphertext_hash.as_slice(),
                encoded_offer,
                unix_time_now()?
            ],
        )
        .map_err(|error| format!("could not save encrypted file attachment: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("could not commit file attachment: {error}"))
}

fn list_file_attachments_in(
    connection: &Connection,
    group_id: [u8; 16],
) -> Result<Vec<StoredFileAttachment>, String> {
    let mut statement = connection
        .prepare(
            "SELECT author_device, ciphertext_hash, offer, created_at_unix
             FROM local_file_attachments WHERE group_id = ?1 ORDER BY created_at_unix, transfer_id",
        )
        .map_err(|error| format!("could not prepare local attachment list: {error}"))?;
    let rows = statement
        .query_map(params![group_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| format!("could not query local attachments: {error}"))?;
    let mut attachments = Vec::new();
    for row in rows {
        let (author, hash, encoded_offer, created_at_unix) =
            row.map_err(|error| format!("could not read local attachment: {error}"))?;
        attachments.push(StoredFileAttachment {
            group_id,
            author_device: author
                .try_into()
                .map_err(|_| "stored attachment author key has invalid length".to_owned())?,
            ciphertext_hash: hash
                .try_into()
                .map_err(|_| "stored attachment digest has invalid length".to_owned())?,
            created_at_unix,
            offer: FileOffer::decode(&encoded_offer)?,
        });
    }
    Ok(attachments)
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

/// Stores a direct socket route only after the peer key has been pinned.
pub fn save_peer_route(peer_device: [u8; 32], address: &str) -> Result<(), String> {
    if peer_device.iter().all(|byte| *byte == 0) {
        return Err("peer route requires a nonzero pinned device key".to_owned());
    }
    let address = address
        .parse::<std::net::SocketAddr>()
        .map_err(|_| "peer route must be an IP address and UDP port".to_owned())?;
    if address.ip().is_unspecified() || address.port() == 0 {
        return Err("peer route must use a reachable IP and nonzero port".to_owned());
    }
    let mut connection = open_local_database()?;
    save_peer_route_in(&mut connection, peer_device, &address.to_string(), false)
}

/// Saves that a pinned peer is reachable through the participant relay configured locally.
pub fn save_peer_relay_route(peer_device: [u8; 32]) -> Result<(), String> {
    if peer_device.iter().all(|byte| *byte == 0) {
        return Err("peer route requires a nonzero pinned device key".to_owned());
    }
    let mut connection = open_local_database()?;
    save_peer_route_in(&mut connection, peer_device, "via group relay", true)
}

/// Adds a relay route for a pinned peer only if no route was saved yet.
pub fn ensure_peer_relay_route(peer_device: [u8; 32]) -> Result<(), String> {
    if peer_device.iter().all(|byte| *byte == 0) {
        return Err("peer route requires a nonzero pinned device key".to_owned());
    }
    let connection = open_local_database()?;
    connection
        .execute(
            "INSERT INTO local_peer_routes (device_public_key, socket_address, relay_only)
             VALUES (?1, 'via group relay', 1)
             ON CONFLICT(device_public_key) DO NOTHING",
            params![peer_device.as_slice()],
        )
        .map_err(|error| format!("could not add the pinned peer relay route: {error}"))?;
    Ok(())
}

pub fn list_peer_routes() -> Result<Vec<StoredPeerRoute>, String> {
    let connection = open_local_database()?;
    list_peer_routes_in(&connection)
}

/// Returns whether this exact device public key was manually verified locally.
pub fn peer_key_is_verified(device_public_key: [u8; 32]) -> Result<bool, String> {
    let connection = open_local_database()?;
    peer_key_is_verified_in(&connection, device_public_key)
}

fn peer_key_is_verified_in(
    connection: &Connection,
    device_public_key: [u8; 32],
) -> Result<bool, String> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM local_verified_peers WHERE device_public_key = ?1)",
            [device_public_key.as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not query peer verification: {error}"))
}

/// Stores or removes the user's out-of-band verification of an exact device key.
pub fn set_peer_key_verified(device_public_key: [u8; 32], verified: bool) -> Result<(), String> {
    let connection = open_local_database()?;
    set_peer_key_verified_in(&connection, device_public_key, verified)
}

fn set_peer_key_verified_in(
    connection: &Connection,
    device_public_key: [u8; 32],
    verified: bool,
) -> Result<(), String> {
    if verified {
        connection
            .execute(
                "INSERT INTO local_verified_peers (device_public_key, verified_at_unix)
                 VALUES (?1, ?2)
                 ON CONFLICT(device_public_key) DO UPDATE SET verified_at_unix = excluded.verified_at_unix",
                params![device_public_key.as_slice(), unix_time_now()?],
            )
            .map_err(|error| format!("could not save verified peer identity: {error}"))?;
    } else {
        connection
            .execute(
                "DELETE FROM local_verified_peers WHERE device_public_key = ?1",
                [device_public_key.as_slice()],
            )
            .map_err(|error| format!("could not remove verified peer identity: {error}"))?;
    }
    Ok(())
}

/// Removes only this peer's local direct-message history.
pub fn clear_direct_history(peer_device: [u8; 32]) -> Result<usize, String> {
    let mut connection = open_local_database()?;
    clear_direct_history_in(&mut connection, peer_device)
}

pub fn list_mls_messages(group_id: &[u8], limit: usize) -> Result<Vec<StoredMlsMessage>, String> {
    if group_id.len() != 16 || !(1..=500).contains(&limit) {
        return Err("MLS history requires a 16-byte group and a page between 1 and 500".to_owned());
    }
    let connection = open_local_database()?;
    list_mls_messages_in(&connection, group_id, limit)
}

pub fn list_mls_groups() -> Result<Vec<StoredMlsGroup>, String> {
    let connection = open_local_database()?;
    list_mls_groups_in(&connection)
}

/// Lists authenticated proposals awaiting a Commit for the selected group epoch.
pub fn list_pending_mls_proposals(group_id: &[u8]) -> Result<Vec<StoredMlsProposal>, String> {
    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    let connection = open_local_database()?;
    list_pending_mls_proposals_in(&connection, group_id)
}

fn list_pending_mls_proposals_in(
    connection: &Connection,
    group_id: &[u8],
) -> Result<Vec<StoredMlsProposal>, String> {
    let mut statement = connection
        .prepare(
            "SELECT p.proposal_id, p.epoch, p.author_device, p.decision
             FROM local_mls_proposals p
             JOIN local_mls_groups g ON g.group_id = p.group_id
             WHERE p.group_id = ?1 AND p.epoch = g.epoch
             ORDER BY p.rowid",
        )
        .map_err(|error| format!("could not prepare pending MLS proposal list: {error}"))?;
    let rows = statement
        .query_map([group_id], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| format!("could not query pending MLS proposals: {error}"))?;
    rows.map(|row| {
        let (proposal_id, epoch, author_device, decision) =
            row.map_err(|error| format!("could not read pending MLS proposal: {error}"))?;
        Ok(StoredMlsProposal {
            proposal_id: fixed_bytes(proposal_id, "MLS proposal ID")?,
            epoch: u64::try_from(epoch).map_err(|_| "MLS proposal has invalid epoch".to_owned())?,
            author_device: fixed_bytes(author_device, "MLS proposal author device")?,
            approved: decision == 1,
            rejected: decision == 2,
        })
    })
    .collect()
}

/// Records the committer's explicit decision for one authenticated proposal.
pub fn set_mls_proposal_approval(
    group_id: &[u8],
    proposal_id: [u8; 16],
    approved: bool,
) -> Result<(), String> {
    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    let connection = open_local_database()?;
    set_mls_proposal_approval_in(&connection, group_id, proposal_id, approved)
}

fn set_mls_proposal_approval_in(
    connection: &Connection,
    group_id: &[u8],
    proposal_id: [u8; 16],
    approved: bool,
) -> Result<(), String> {
    let changed = connection
        .execute(
            "UPDATE local_mls_proposals SET decision = ?1
             WHERE group_id = ?2 AND proposal_id = ?3
               AND epoch = (SELECT epoch FROM local_mls_groups WHERE group_id = ?2)",
            params![
                if approved { 1 } else { 2 },
                group_id,
                proposal_id.as_slice()
            ],
        )
        .map_err(|error| format!("could not save MLS proposal decision: {error}"))?;
    if changed != 1 {
        return Err("proposal is no longer pending in the current group epoch".to_owned());
    }
    Ok(())
}

fn list_mls_groups_in(connection: &Connection) -> Result<Vec<StoredMlsGroup>, String> {
    let mut statement = connection
        .prepare("SELECT group_id, epoch, quarantined FROM local_mls_groups ORDER BY rowid DESC")
        .map_err(|error| format!("could not prepare local MLS group list: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|error| format!("could not query local MLS groups: {error}"))?;
    rows.map(|row| {
        let (group_id, epoch, quarantined) =
            row.map_err(|error| format!("could not read local MLS group: {error}"))?;
        Ok(StoredMlsGroup {
            group_id: fixed_bytes(group_id, "MLS group ID")?,
            epoch: u64::try_from(epoch).map_err(|_| "MLS group has invalid epoch".to_owned())?,
            quarantined: quarantined != 0,
        })
    })
    .collect()
}

pub fn load_mls_group_quarantine(group_id: &[u8]) -> Result<Option<String>, String> {
    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    let connection = open_local_database()?;
    connection
        .query_row(
            "SELECT quarantine_reason FROM local_mls_groups
             WHERE group_id = ?1 AND quarantined = 1",
            [group_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("could not load MLS quarantine state: {error}"))
}

fn list_mls_messages_in(
    connection: &Connection,
    group_id: &[u8],
    limit: usize,
) -> Result<Vec<StoredMlsMessage>, String> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, event_id, direction, text FROM (
                 SELECT sequence, event_id, direction, text FROM local_mls_messages
                 WHERE group_id = ?1 ORDER BY sequence DESC LIMIT ?2
             ) ORDER BY sequence ASC",
        )
        .map_err(|error| format!("could not prepare MLS history query: {error}"))?;
    let rows = statement
        .query_map(params![group_id, limit as i64], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| format!("could not query MLS history: {error}"))?;
    rows.map(|row| {
        let (sequence, event_id, direction, text) =
            row.map_err(|error| format!("could not read MLS history row: {error}"))?;
        Ok(StoredMlsMessage {
            sequence,
            event_id: fixed_bytes(event_id, "MLS event id")?,
            direction: DirectMessageDirection::try_from(direction.as_str())?,
            text,
        })
    })
    .collect()
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

fn save_peer_route_in(
    connection: &mut Connection,
    peer_device: [u8; 32],
    address: &str,
    relay_only: bool,
) -> Result<(), String> {
    connection
        .execute(
            "INSERT INTO local_peer_routes (device_public_key, socket_address, relay_only)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(device_public_key) DO UPDATE SET
                 socket_address = excluded.socket_address,
                 relay_only = excluded.relay_only",
            params![peer_device.as_slice(), address, relay_only],
        )
        .map_err(|error| format!("could not save pinned peer route: {error}"))?;
    Ok(())
}

fn list_peer_routes_in(connection: &Connection) -> Result<Vec<StoredPeerRoute>, String> {
    let mut statement = connection
        .prepare(
            "SELECT device_public_key, socket_address, relay_only FROM local_peer_routes
             ORDER BY socket_address, device_public_key",
        )
        .map_err(|error| format!("could not prepare pinned peer route query: {error}"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })
        .map_err(|error| format!("could not query pinned peer routes: {error}"))?;
    rows.map(|row| {
        let (device_public_key, address, relay_only) =
            row.map_err(|error| format!("could not read pinned peer route: {error}"))?;
        Ok(StoredPeerRoute {
            device_public_key: fixed_bytes(device_public_key, "pinned peer route key")?,
            address,
            relay_only,
        })
    })
    .collect()
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
    pub commit_event_id: [u8; 16],
    pub invited_device: [u8; 32],
    /// Public MLS Commit bytes to distribute alongside the Welcome.
    pub commit: Vec<u8>,
    /// Encrypted MLS Welcome bytes for the admitted member.
    pub welcome: Vec<u8>,
    /// Public ratchet tree required to process the Welcome.
    pub ratchet_tree: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMlsWelcome {
    pub event_id: [u8; 16],
    pub group_id: Vec<u8>,
    pub commit_event_id: [u8; 16],
    pub invitee_device: [u8; 32],
    pub welcome: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
}

pub fn mls_welcome_event_id(welcome: &[u8], ratchet_tree: &[u8]) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(&(welcome.len() as u32).to_be_bytes());
    digest.update(welcome);
    digest.update(&(ratchet_tree.len() as u32).to_be_bytes());
    digest.update(ratchet_tree);
    let mut event_id = [0; 16];
    event_id.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    event_id
}

pub fn list_queued_mls_welcomes_for_peer(
    group_id: &[u8],
    invitee_device: [u8; 32],
) -> Result<Vec<StoredMlsWelcome>, String> {
    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    let connection = open_local_database()?;
    list_queued_mls_welcomes_for_peer_in(&connection, group_id, invitee_device)
}

fn list_queued_mls_welcomes_for_peer_in(
    connection: &Connection,
    group_id: &[u8],
    invitee_device: [u8; 32],
) -> Result<Vec<StoredMlsWelcome>, String> {
    let mut statement = connection
        .prepare(
            "SELECT event_id, group_id, commit_event_id, invitee_device, welcome_bytes, ratchet_tree
             FROM local_mls_welcome_outbox
             WHERE group_id = ?1 AND invitee_device = ?2 AND delivery_state = 'queued'
             ORDER BY rowid",
        )
        .map_err(|error| format!("could not prepare MLS Welcome outbox query: {error}"))?;
    let rows = statement
        .query_map(params![group_id, invitee_device.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .map_err(|error| format!("could not query MLS Welcome outbox: {error}"))?;
    rows.map(|row| {
        let (event_id, stored_group, commit_event_id, stored_invitee, welcome, ratchet_tree) =
            row.map_err(|error| format!("could not read MLS Welcome outbox: {error}"))?;
        let event_id = fixed_bytes(event_id, "MLS Welcome event ID")?;
        if event_id != mls_welcome_event_id(&welcome, &ratchet_tree) {
            return Err("saved MLS Welcome bundle failed its digest check".to_owned());
        }
        Ok(StoredMlsWelcome {
            event_id,
            group_id: fixed_bytes::<16>(stored_group, "MLS Welcome group ID")?.to_vec(),
            commit_event_id: fixed_bytes(commit_event_id, "MLS Welcome Commit ID")?,
            invitee_device: fixed_bytes(stored_invitee, "MLS Welcome invitee")?,
            welcome,
            ratchet_tree,
        })
    })
    .collect()
}

pub fn mark_mls_welcome_delivered(event_id: [u8; 16]) -> Result<(), String> {
    let connection = open_local_database()?;
    mark_mls_welcome_delivered_in(&connection, event_id)
}

fn mark_mls_welcome_delivered_in(
    connection: &Connection,
    event_id: [u8; 16],
) -> Result<(), String> {
    let delivered_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is invalid: {error}"))?
        .as_secs() as i64;
    let updated = connection
        .execute(
            "UPDATE local_mls_welcome_outbox SET delivery_state = 'delivered', delivered_at = ?1
             WHERE event_id = ?2 AND delivery_state = 'queued'",
            params![delivered_at, event_id.as_slice()],
        )
        .map_err(|error| format!("could not record MLS Welcome ACK: {error}"))?;
    if updated == 1 {
        return Ok(());
    }
    let existing: Option<String> = connection
        .query_row(
            "SELECT delivery_state FROM local_mls_welcome_outbox WHERE event_id = ?1",
            [event_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("could not check MLS Welcome ACK: {error}"))?;
    if existing.as_deref() == Some("delivered") {
        Ok(())
    } else {
        Err("ACK does not match a queued MLS Welcome".to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMlsCommit {
    pub event_id: [u8; 16],
    pub group_id: Vec<u8>,
    pub predecessor_epoch: u64,
    pub epoch: u64,
    pub author_device: [u8; 32],
    pub commit_hash: [u8; 32],
    pub commit: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMlsUpdateProposal {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub proposal: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMlsProposal {
    pub proposal_id: [u8; 16],
    pub epoch: u64,
    pub author_device: [u8; 32],
    pub approved: bool,
    pub rejected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessedMlsProposal {
    Accepted { epoch: u64 },
    Duplicate { epoch: u64 },
}

type StoredMlsCommitRow = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>);
type StoredMlsWelcomeReceiptRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64);

#[derive(Serialize, serde::Deserialize)]
struct MlsEpochSnapshot {
    group_data: Vec<(i64, String, Vec<u8>)>,
    epoch_key_pairs: Vec<(i64, Vec<u8>, i64, Vec<u8>)>,
    own_leaf_nodes: Vec<(i64, Vec<u8>)>,
    proposals: Vec<(i64, Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsCommitQuarantine {
    pub predecessor_epoch: u64,
    pub accepted_event_id: [u8; 16],
    pub conflicting_event_id: [u8; 16],
    pub author_device: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsCommitRecipientStatus {
    pub event_id: [u8; 16],
    pub epoch: u64,
    pub device_public_key: [u8; 32],
    pub delivered: bool,
}

pub fn list_mls_commit_recipient_status(
    group_id: &[u8],
    limit: usize,
) -> Result<Vec<MlsCommitRecipientStatus>, String> {
    let connection = open_local_database()?;
    list_mls_commit_recipient_status_in(&connection, group_id, limit)
}

pub fn list_queued_mls_commit_recipients(group_id: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    let connection = open_local_database()?;
    list_queued_mls_commit_recipients_in(&connection, group_id)
}

fn list_queued_mls_commit_recipients_in(
    connection: &Connection,
    group_id: &[u8],
) -> Result<Vec<[u8; 32]>, String> {
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT r.device_public_key
             FROM local_mls_commit_recipients r
             JOIN local_mls_commits c ON c.event_id = r.commit_event_id
             WHERE c.group_id = ?1 AND r.delivery_state = 'queued'
             ORDER BY r.device_public_key",
        )
        .map_err(|error| format!("could not prepare queued MLS recipient query: {error}"))?;
    let rows = statement
        .query_map(params![group_id], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|error| format!("could not query queued MLS recipients: {error}"))?;
    rows.map(|row| {
        fixed_bytes(
            row.map_err(|error| format!("could not read queued MLS recipient: {error}"))?,
            "MLS recipient device key",
        )
    })
    .collect()
}

fn list_mls_commit_recipient_status_in(
    connection: &Connection,
    group_id: &[u8],
    limit: usize,
) -> Result<Vec<MlsCommitRecipientStatus>, String> {
    if group_id.len() != 16 || !(1..=500).contains(&limit) {
        return Err(
            "MLS recipient status query requires a 16-byte group ID and limit 1..500".to_owned(),
        );
    }
    let mut statement = connection
        .prepare(
            "SELECT c.event_id, c.epoch, r.device_public_key, r.delivery_state
             FROM local_mls_commits c
             JOIN local_mls_commit_recipients r ON r.commit_event_id = c.event_id
             WHERE c.group_id = ?1
             ORDER BY c.epoch DESC, r.device_public_key LIMIT ?2",
        )
        .map_err(|error| format!("could not prepare MLS recipient status query: {error}"))?;
    let rows = statement
        .query_map(params![group_id, limit as i64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| format!("could not query MLS recipient status: {error}"))?;
    rows.map(|row| {
        let (event_id, epoch, device_public_key, delivery_state) =
            row.map_err(|error| format!("could not read MLS recipient status: {error}"))?;
        Ok(MlsCommitRecipientStatus {
            event_id: fixed_bytes(event_id, "MLS recipient Commit ID")?,
            epoch: u64::try_from(epoch)
                .map_err(|_| "MLS recipient status has an invalid epoch".to_owned())?,
            device_public_key: fixed_bytes(device_public_key, "MLS recipient device key")?,
            delivered: delivery_state == "delivered",
        })
    })
    .collect()
}

pub fn list_queued_mls_commits(
    group_id: &[u8],
    limit: usize,
) -> Result<Vec<StoredMlsCommit>, String> {
    if group_id.len() != 16 || !(1..=100).contains(&limit) {
        return Err("MLS commit query requires a 16-byte group ID and limit 1..100".to_owned());
    }
    let connection = open_local_database()?;
    list_queued_mls_commits_in(&connection, group_id, limit)
}

pub fn list_queued_mls_commits_for_peer(
    group_id: &[u8],
    peer_device: &[u8; 32],
    limit: usize,
) -> Result<Vec<StoredMlsCommit>, String> {
    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    let mut connection = open_local_database()?;
    list_queued_mls_commits_for_peer_in(&mut connection, group_id, peer_device, limit)
}

pub fn load_authorized_mls_commit_for_peer(
    group_id: &[u8],
    predecessor_epoch: u64,
    peer_device: &[u8; 32],
) -> Result<Option<StoredMlsCommit>, String> {
    if group_id.len() != 16 || predecessor_epoch > i64::MAX as u64 {
        return Err("MLS predecessor request has invalid group or epoch".to_owned());
    }
    let connection = open_local_database()?;
    load_authorized_mls_commit_for_peer_in(&connection, group_id, predecessor_epoch, peer_device)
}

fn load_authorized_mls_commit_for_peer_in(
    connection: &Connection,
    group_id: &[u8],
    predecessor_epoch: u64,
    peer_device: &[u8; 32],
) -> Result<Option<StoredMlsCommit>, String> {
    if group_id.len() != 16 || predecessor_epoch > i64::MAX as u64 {
        return Err("MLS predecessor request has invalid group or epoch".to_owned());
    }
    let row: Option<StoredMlsCommitRow> = connection
        .query_row(
            "SELECT c.event_id, c.group_id, c.predecessor_epoch, c.epoch,
                    c.author_device, c.commit_hash, c.commit_bytes
             FROM local_mls_commits c
             JOIN local_mls_commit_recipients r ON r.commit_event_id = c.event_id
             JOIN local_mls_groups g ON g.group_id = c.group_id
             WHERE c.group_id = ?1 AND c.predecessor_epoch = ?2
               AND r.device_public_key = ?3
               AND g.quarantined = 0
               AND c.author_device = g.designated_committer_device",
            params![group_id, predecessor_epoch as i64, peer_device.as_slice()],
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
        .map_err(|error| format!("could not load requested MLS predecessor: {error}"))?;
    row.map(
        |(event_id, group_id, predecessor_epoch, epoch, author_device, commit_hash, commit)| {
            let event_id = fixed_bytes(event_id, "MLS Commit event ID")?;
            let commit_hash = fixed_bytes(commit_hash, "MLS Commit hash")?;
            if commit_hash != *blake3::hash(&commit).as_bytes()
                || event_id.as_slice() != &commit_hash[..16]
            {
                return Err("stored MLS predecessor failed its digest check".to_owned());
            }
            Ok(StoredMlsCommit {
                event_id,
                group_id,
                predecessor_epoch: u64::try_from(predecessor_epoch)
                    .map_err(|_| "MLS Commit has an invalid predecessor epoch".to_owned())?,
                epoch: u64::try_from(epoch)
                    .map_err(|_| "MLS Commit has an invalid epoch".to_owned())?,
                author_device: fixed_bytes(author_device, "MLS Commit author device")?,
                commit_hash,
                commit,
            })
        },
    )
    .transpose()
}

fn list_queued_mls_commits_for_peer_in(
    connection: &mut Connection,
    group_id: &[u8],
    peer_device: &[u8; 32],
    limit: usize,
) -> Result<Vec<StoredMlsCommit>, String> {
    if group_id.len() != 16 || !(1..=100).contains(&limit) {
        return Err("MLS group ID must be 16 bytes and limit must be 1..100".to_owned());
    }
    ensure_mls_group_not_quarantined(connection, group_id)?;
    let mut statement = connection
        .prepare(
            "SELECT c.event_id, c.group_id, c.predecessor_epoch, c.epoch,
                    c.author_device, c.commit_hash, c.commit_bytes
             FROM local_mls_commits c
             JOIN local_mls_commit_recipients r ON r.commit_event_id = c.event_id
             WHERE c.group_id = ?1 AND r.device_public_key = ?2
               AND r.delivery_state = 'queued'
             ORDER BY c.predecessor_epoch, c.epoch LIMIT ?3",
        )
        .map_err(|error| format!("could not prepare peer MLS Commit query: {error}"))?;
    let rows = statement
        .query_map(
            params![group_id, peer_device.as_slice(), limit as i64],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .map_err(|error| format!("could not query peer MLS Commits: {error}"))?;
    let mut queued = Vec::new();
    for row in rows {
        let (event_id, stored_group_id, predecessor_epoch, epoch, author_device, digest, commit) =
            row.map_err(|error| format!("could not read peer MLS Commit: {error}"))?;
        let commit_hash = fixed_bytes(digest, "MLS Commit digest")?;
        if blake3::hash(&commit).as_bytes() != &commit_hash {
            return Err("saved MLS Commit bytes do not match their digest".to_owned());
        }
        let predecessor_epoch = u64::try_from(predecessor_epoch)
            .map_err(|_| "saved MLS Commit has an invalid predecessor epoch".to_owned())?;
        let epoch =
            u64::try_from(epoch).map_err(|_| "saved MLS Commit has an invalid epoch".to_owned())?;
        if epoch != predecessor_epoch.saturating_add(1) {
            return Err("saved MLS Commit is not the next group epoch".to_owned());
        }
        queued.push(StoredMlsCommit {
            event_id: fixed_bytes(event_id, "MLS Commit event id")?,
            group_id: fixed_bytes::<16>(stored_group_id, "MLS Commit group id")?.to_vec(),
            predecessor_epoch,
            epoch,
            author_device: fixed_bytes(author_device, "MLS Commit author")?,
            commit_hash,
            commit,
        });
    }
    Ok(queued)
}

pub fn mark_mls_commit_delivered(
    event_id: [u8; 16],
    recipient_device: [u8; 32],
) -> Result<(), String> {
    let mut connection = open_local_database()?;
    mark_mls_commit_delivered_in(&mut connection, event_id, recipient_device)
}

fn mark_mls_commit_delivered_in(
    connection: &mut Connection,
    event_id: [u8; 16],
    recipient_device: [u8; 32],
) -> Result<(), String> {
    let delivered_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is invalid: {error}"))?
        .as_secs() as i64;
    let updated = connection
        .execute(
            "UPDATE local_mls_commit_recipients
             SET delivery_state = 'delivered', delivered_at = ?1
             WHERE commit_event_id = ?2 AND device_public_key = ?3
               AND delivery_state = 'queued'",
            params![
                delivered_at,
                event_id.as_slice(),
                recipient_device.as_slice()
            ],
        )
        .map_err(|error| format!("could not persist MLS Commit delivery ACK: {error}"))?;
    if updated == 1 {
        return Ok(());
    }
    let existing: Option<String> = connection
        .query_row(
            "SELECT delivery_state FROM local_mls_commit_recipients
             WHERE commit_event_id = ?1 AND device_public_key = ?2",
            params![event_id.as_slice(), recipient_device.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("could not check MLS Commit delivery ACK: {error}"))?;
    if existing.as_deref() == Some("delivered") {
        Ok(())
    } else {
        Err("ACK does not match a queued MLS Commit recipient".to_owned())
    }
}

pub fn process_inbound_mls_commit_envelope(
    envelope: &crate::peer::MlsCommitEnvelope,
) -> Result<ProcessedMlsCommit, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    process_inbound_mls_commit_envelope_in(&mut connection, envelope, &device_identity)
}

fn process_inbound_mls_commit_envelope_in(
    connection: &mut Connection,
    envelope: &crate::peer::MlsCommitEnvelope,
    device_identity: &SigningKey,
) -> Result<ProcessedMlsCommit, String> {
    use openmls::prelude::tls_codec::Deserialize as TlsCodecDeserialize;

    if envelope.epoch != envelope.predecessor_epoch.saturating_add(1)
        || envelope.event_id.as_slice() != &blake3::hash(&envelope.commit).as_bytes()[..16]
    {
        return Err("MLS Commit envelope metadata does not match its bytes".to_owned());
    }
    let protocol_message = MlsMessageIn::tls_deserialize_exact(&envelope.commit)
        .map_err(|error| format!("invalid serialized MLS Commit: {error}"))?
        .try_into_protocol_message()
        .map_err(|error| format!("MLS Commit is not a protocol message: {error}"))?;
    if protocol_message.group_id().as_slice() != envelope.group_id
        || protocol_message.epoch().as_u64() != envelope.predecessor_epoch
    {
        return Err("MLS Commit envelope group or epoch does not match the MLS message".to_owned());
    }
    let expected_author: Vec<u8> = connection
        .query_row(
            "SELECT designated_committer_device FROM local_mls_groups WHERE group_id = ?1",
            [&envelope.group_id],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not load MLS designated committer: {error}"))?;
    if expected_author.as_slice() != envelope.author_device {
        return Err("MLS Commit envelope author is not the designated committer".to_owned());
    }
    process_inbound_mls_commit_in(
        connection,
        &envelope.group_id,
        &envelope.commit,
        device_identity,
    )
}

fn list_queued_mls_commits_in(
    connection: &Connection,
    group_id: &[u8],
    limit: usize,
) -> Result<Vec<StoredMlsCommit>, String> {
    ensure_mls_group_not_quarantined(connection, group_id)?;
    let mut statement = connection
        .prepare(
            "SELECT event_id, group_id, predecessor_epoch, epoch, author_device,
                    commit_hash, commit_bytes FROM local_mls_commits
             WHERE group_id = ?1 AND delivery_state = 'queued'
             ORDER BY predecessor_epoch, epoch LIMIT ?2",
        )
        .map_err(|error| format!("could not prepare MLS Commit outbox query: {error}"))?;
    let rows = statement
        .query_map(params![group_id, limit as i64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })
        .map_err(|error| format!("could not query MLS Commit outbox: {error}"))?;
    let mut commits = Vec::new();
    for row in rows {
        let (id, group, predecessor, epoch, author, digest, commit) =
            row.map_err(|error| format!("could not read MLS Commit outbox: {error}"))?;
        let commit_hash = fixed_bytes(digest, "MLS Commit digest")?;
        if blake3::hash(&commit).as_bytes() != &commit_hash {
            return Err("saved MLS Commit bytes do not match their digest".to_owned());
        }
        let predecessor_epoch = u64::try_from(predecessor)
            .map_err(|_| "saved MLS Commit has an invalid predecessor epoch".to_owned())?;
        let epoch =
            u64::try_from(epoch).map_err(|_| "saved MLS Commit has an invalid epoch".to_owned())?;
        if epoch != predecessor_epoch.saturating_add(1) {
            return Err("saved MLS Commit is not the next group epoch".to_owned());
        }
        commits.push(StoredMlsCommit {
            event_id: fixed_bytes(id, "MLS Commit event id")?,
            group_id: fixed_bytes::<16>(group, "MLS Commit group id")?.to_vec(),
            predecessor_epoch,
            epoch,
            author_device: fixed_bytes(author, "MLS Commit author")?,
            commit_hash,
            commit,
        });
    }
    Ok(commits)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedMlsGroup {
    pub group_id: Vec<u8>,
    pub ciphersuite: u16,
    pub epoch: u64,
    pub designated_committer_device: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PreparedMlsApplicationEvent {
    pub event: EncryptedEvent,
    pub wire_message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessedMlsApplicationEvent {
    Received(Vec<u8>),
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessedMlsCommit {
    Applied { epoch: u64 },
    Duplicate { epoch: u64 },
    EquivocationDetected { predecessor_epoch: u64 },
}

#[derive(Debug, Clone)]
pub struct LocalProfile {
    pub display_name: String,
    pub familiar: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerRelayConfig {
    pub url: String,
    pub token: String,
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

pub fn load_peer_relay_config() -> Result<PeerRelayConfig, String> {
    load_peer_relay_config_in(&open_local_database()?)
}

fn load_peer_relay_config_in(connection: &Connection) -> Result<PeerRelayConfig, String> {
    connection
        .query_row(
            "SELECT relay_url, access_token FROM local_peer_relay_config WHERE id = 1",
            [],
            |row| {
                Ok(PeerRelayConfig {
                    url: row.get(0)?,
                    token: row.get(1)?,
                })
            },
        )
        .optional()
        .map(|config| config.unwrap_or_default())
        .map_err(|error| format!("could not load participant relay settings: {error}"))
}

pub fn save_peer_relay_config(config: &PeerRelayConfig) -> Result<(), String> {
    save_peer_relay_config_in(&open_local_database()?, config)
}

fn save_peer_relay_config_in(
    connection: &Connection,
    config: &PeerRelayConfig,
) -> Result<(), String> {
    if config.url.len() > 2048 || config.token.len() > 512 {
        return Err("relay URL or access token exceeds its size limit".to_owned());
    }
    connection
        .execute(
            "INSERT INTO local_peer_relay_config (id, relay_url, access_token)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET relay_url = excluded.relay_url,
                 access_token = excluded.access_token",
            params![config.url, config.token],
        )
        .map_err(|error| format!("could not save participant relay settings: {error}"))?;
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

/// Encrypts an application payload with the group's current MLS epoch and
/// persists both the ratchet update and retryable ciphertext in one transaction.
pub fn create_mls_application_event(
    group_id: &[u8],
    plaintext: &[u8],
    expires_at_unix: i64,
) -> Result<PreparedMlsApplicationEvent, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    create_mls_application_event_in(
        &mut connection,
        group_id,
        plaintext,
        expires_at_unix,
        &device_identity,
    )
}

fn create_mls_application_event_in(
    connection: &mut Connection,
    group_id: &[u8],
    plaintext: &[u8],
    expires_at_unix: i64,
    device_identity: &SigningKey,
) -> Result<PreparedMlsApplicationEvent, String> {
    use openmls::prelude::GroupId;

    if group_id.len() != 16 || plaintext.is_empty() || plaintext.len() > 16 * 1024 {
        return Err(
            "MLS application message must have a valid group and 1 to 16 KiB payload".to_owned(),
        );
    }
    if expires_at_unix <= 0 {
        return Err("MLS application event expiry must be a positive Unix timestamp".to_owned());
    }
    if expires_at_unix <= unix_time_now()? {
        return Err("MLS application event expiry must be in the future".to_owned());
    }
    let plaintext_text = std::str::from_utf8(plaintext)
        .map_err(|_| "MLS chat text must be valid UTF-8".to_owned())?;
    let author_device = device_identity.verifying_key().to_bytes();
    let group_id = GroupId::from_slice(group_id);
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS outbox transaction: {error}"))?;
    let result = (|| {
        ensure_mls_group_not_quarantined(connection, group_id.as_slice())?;
        let (event, wire_message, recipients) = {
            let provider = LocalOpenMlsProvider::new(connection);
            let mut group = MlsGroup::load(provider.storage(), &group_id)
                .map_err(|error| format!("could not load MLS group: {error}"))?
                .ok_or_else(|| "MLS group state is missing".to_owned())?;
            if !group.is_active() {
                return Err("MLS group is inactive on this device".to_owned());
            }
            let ciphersuite = group.ciphersuite();
            let own_leaf = group
                .own_leaf()
                .ok_or_else(|| "local MLS member leaf is missing".to_owned())?;
            let binding =
                MlsSigningKeyBinding::from_bytes(own_leaf.credential().serialized_content())
                    .ok_or_else(|| {
                        "local MLS credential has no device identity binding".to_owned()
                    })?;
            if binding.device_public_key != author_device
                || !binding.verifies_mls_credential(
                    &author_device,
                    ciphersuite.signature_algorithm() as u16,
                    own_leaf.signature_key().as_slice(),
                )
            {
                return Err("MLS group is not bound to this device identity".to_owned());
            }
            let mut recipients = Vec::new();
            for member in group.members() {
                let member_binding =
                    MlsSigningKeyBinding::from_bytes(member.credential.serialized_content())
                        .ok_or_else(|| "MLS member has no device identity binding".to_owned())?;
                if !member_binding.verifies_mls_credential(
                    &member_binding.device_public_key,
                    ciphersuite.signature_algorithm() as u16,
                    member.signature_key.as_slice(),
                ) {
                    return Err("MLS member has an invalid device binding".to_owned());
                }
                let peer = member_binding.device_public_key;
                if peer != author_device && !recipients.contains(&peer) {
                    recipients.push(peer);
                }
            }
            if recipients.is_empty() {
                return Err("MLS group has no other device to receive this message".to_owned());
            }
            let signer = SignatureKeyPair::read(
                provider.storage(),
                &binding.mls_signing_public_key,
                ciphersuite.signature_algorithm(),
            )
            .ok_or_else(|| "MLS signing key material is missing".to_owned())?;
            let epoch = group.epoch().as_u64();
            let mut event_id = [0_u8; 16];
            getrandom::fill(&mut event_id)
                .map_err(|error| format!("could not generate MLS event id: {error}"))?;
            let event = EncryptedEvent {
                event_id,
                author_device,
                group_id: group_id.to_vec(),
                epoch,
                checkpoint: None,
                expires_at_unix,
                ciphertext: Vec::new(),
            };
            group.set_aad(mls_event_aad(&event));
            let message = group
                .create_message(&provider, &signer, plaintext)
                .map_err(|error| format!("could not encrypt MLS application message: {error:?}"))?;
            let wire_message = message
                .tls_serialize_detached()
                .map_err(|error| format!("could not serialize MLS application message: {error}"))?;
            let event = EncryptedEvent {
                ciphertext: wire_message.clone(),
                ..event
            };
            (event, wire_message, recipients)
        };
        let digest = blake3::hash(&event.ciphertext);
        connection
            .execute(
                "INSERT INTO local_events
                    (event_id, direction, author_device, group_id, epoch, checkpoint,
                     ciphertext_digest, ciphertext, expires_at_unix, delivery_state)
                 VALUES (?1, 'outbound', ?2, ?3, ?4, NULL, ?5, ?6, ?7, 'queued')",
                params![
                    event.event_id.as_slice(),
                    event.author_device.as_slice(),
                    event.group_id,
                    event.epoch as i64,
                    digest.as_bytes().as_slice(),
                    event.ciphertext,
                    event.expires_at_unix
                ],
            )
            .map_err(|error| {
                format!("could not persist MLS ciphertext in local outbox: {error}")
            })?;
        for recipient in recipients {
            connection
                .execute(
                    "INSERT INTO local_mls_event_recipients
                        (event_id, device_public_key, delivery_state)
                     VALUES (?1, ?2, 'queued')",
                    params![event.event_id.as_slice(), recipient.as_slice()],
                )
                .map_err(|error| format!("could not persist MLS event recipient: {error}"))?;
        }
        insert_mls_history_in(
            connection,
            &event.group_id,
            event.event_id,
            "sent",
            plaintext_text,
        )?;
        Ok(PreparedMlsApplicationEvent {
            event,
            wire_message,
        })
    })();
    finish_sql_transaction(connection, result, "MLS application outbox")
}

/// Creates a signed self-update proposal for the selected MLS group. The
/// returned public message can be transferred to the designated committer.
pub fn create_mls_self_update_proposal(
    group_id: &[u8],
) -> Result<PreparedMlsUpdateProposal, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    create_mls_self_update_proposal_in(&mut connection, group_id, &device_identity)
}

fn create_mls_self_update_proposal_in(
    connection: &mut Connection,
    group_id: &[u8],
    device_identity: &SigningKey,
) -> Result<PreparedMlsUpdateProposal, String> {
    use openmls::prelude::tls_codec::Serialize as TlsCodecSerialize;

    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS update proposal transaction: {error}"))?;
    let result = (|| {
        ensure_mls_group_not_quarantined(connection, group_id)?;
        let proposal = {
            let provider = LocalOpenMlsProvider::new(connection);
            let group_identifier = GroupId::from_slice(group_id);
            let mut group = MlsGroup::load(provider.storage(), &group_identifier)
                .map_err(|error| format!("could not load MLS group: {error}"))?
                .ok_or_else(|| "MLS group state is missing".to_owned())?;
            if !group.is_active() {
                return Err("MLS group is inactive on this device".to_owned());
            }
            let ciphersuite = group.ciphersuite();
            let own_leaf = group
                .own_leaf()
                .ok_or_else(|| "local MLS member leaf is missing".to_owned())?;
            let binding =
                MlsSigningKeyBinding::from_bytes(own_leaf.credential().serialized_content())
                    .ok_or_else(|| {
                        "local MLS credential has no device identity binding".to_owned()
                    })?;
            if binding.device_public_key != device_identity.verifying_key().to_bytes()
                || !binding.verifies_mls_credential(
                    &binding.device_public_key,
                    ciphersuite.signature_algorithm() as u16,
                    own_leaf.signature_key().as_slice(),
                )
            {
                return Err("MLS group is not bound to this device identity".to_owned());
            }
            let signer = SignatureKeyPair::read(
                provider.storage(),
                &binding.mls_signing_public_key,
                ciphersuite.signature_algorithm(),
            )
            .ok_or_else(|| "MLS signing key material is missing".to_owned())?;
            let (proposal, _) = group
                .propose_self_update(&provider, &signer, LeafNodeParameters::default())
                .map_err(|error| format!("could not create MLS update proposal: {error:?}"))?;
            proposal
                .tls_serialize_detached()
                .map_err(|error| format!("could not serialize MLS update proposal: {error}"))?
        };
        let epoch = connection
            .query_row(
                "SELECT epoch FROM local_mls_groups WHERE group_id = ?1",
                [group_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| format!("could not load MLS update proposal epoch: {error}"))?;
        Ok(PreparedMlsUpdateProposal {
            group_id: group_id.to_vec(),
            epoch: u64::try_from(epoch).map_err(|_| "invalid MLS epoch".to_owned())?,
            proposal,
        })
    })();
    finish_sql_transaction(connection, result, "MLS update proposal")
}

/// Authenticates a member's self-update proposal and stores it in OpenMLS's
/// pending proposal queue before returning. Exact delivery is deduplicated.
pub fn process_mls_self_update_proposal(
    group_id: &[u8],
    proposal_bytes: &[u8],
) -> Result<ProcessedMlsProposal, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    process_mls_self_update_proposal_in(&mut connection, group_id, proposal_bytes, &device_identity)
}

/// Processes a direct-session proposal only when its signed MLS author is the
/// same device authenticated by the pinned peer transport.
pub fn process_mls_self_update_proposal_from_peer(
    envelope: &crate::peer::MlsProposalEnvelope,
    pinned_peer_device: [u8; 32],
) -> Result<ProcessedMlsProposal, String> {
    if envelope.author_device != pinned_peer_device
        || envelope.event_id.as_slice() != &blake3::hash(&envelope.proposal).as_bytes()[..16]
    {
        return Err("MLS proposal envelope does not match its pinned author or bytes".to_owned());
    }
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    process_mls_self_update_proposal_with_author_in(
        &mut connection,
        &envelope.group_id,
        &envelope.proposal,
        &device_identity,
        Some(pinned_peer_device),
        Some(envelope.epoch),
    )
}

fn process_mls_self_update_proposal_in(
    connection: &mut Connection,
    group_id: &[u8],
    proposal_bytes: &[u8],
    device_identity: &SigningKey,
) -> Result<ProcessedMlsProposal, String> {
    process_mls_self_update_proposal_with_author_in(
        connection,
        group_id,
        proposal_bytes,
        device_identity,
        None,
        None,
    )
}

fn process_mls_self_update_proposal_with_author_in(
    connection: &mut Connection,
    group_id: &[u8],
    proposal_bytes: &[u8],
    device_identity: &SigningKey,
    expected_author: Option<[u8; 32]>,
    expected_epoch: Option<u64>,
) -> Result<ProcessedMlsProposal, String> {
    use openmls::prelude::tls_codec::{
        Deserialize as TlsCodecDeserialize, Serialize as TlsCodecSerialize,
    };

    if group_id.len() != 16 || proposal_bytes.is_empty() || proposal_bytes.len() > 64 * 1024 {
        return Err("MLS update proposal has an invalid group ID or size".to_owned());
    }
    let message = MlsMessageIn::tls_deserialize_exact(proposal_bytes)
        .map_err(|error| format!("invalid serialized MLS proposal: {error}"))?
        .try_into_protocol_message()
        .map_err(|error| format!("MLS update is not a protocol message: {error}"))?;
    if message.group_id().as_slice() != group_id {
        return Err("MLS proposal belongs to another group".to_owned());
    }
    let epoch = message.epoch().as_u64();
    if expected_epoch.is_some_and(|expected| expected != epoch) {
        return Err("MLS proposal envelope epoch does not match its signed message".to_owned());
    }
    let digest = *blake3::hash(proposal_bytes).as_bytes();
    let mut proposal_id = [0; 16];
    proposal_id.copy_from_slice(&digest[..16]);
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin inbound MLS proposal transaction: {error}"))?;
    let result = (|| {
        ensure_mls_group_not_quarantined(connection, group_id)?;
        let (indexed_epoch, designated_committer): (i64, Vec<u8>) = connection
            .query_row(
                "SELECT epoch, designated_committer_device FROM local_mls_groups WHERE group_id = ?1",
                [group_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| format!("could not load MLS proposal policy: {error}"))?;
        if designated_committer.as_slice() != device_identity.verifying_key().as_bytes() {
            return Err("only the designated committer can accept an MLS proposal".to_owned());
        }
        let duplicate: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT author_device, proposal_hash, proposal_bytes
                 FROM local_mls_proposals WHERE proposal_id = ?1",
                [proposal_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| format!("could not check MLS proposal redelivery: {error}"))?;
        if let Some((saved_author, saved_hash, saved_bytes)) = duplicate {
            if saved_hash.as_slice() == digest
                && saved_bytes == proposal_bytes
                && expected_author.is_none_or(|expected| saved_author.as_slice() == expected)
            {
                return Ok(ProcessedMlsProposal::Duplicate { epoch });
            }
            return Err("MLS proposal ID collision".to_owned());
        }
        if epoch != indexed_epoch as u64 {
            return Err("MLS proposal is not for the current group epoch".to_owned());
        }
        let (accepted_epoch, author_device, proposal_ref) = {
            let provider = LocalOpenMlsProvider::new(connection);
            let group_identifier = GroupId::from_slice(group_id);
            let mut group = MlsGroup::load(provider.storage(), &group_identifier)
                .map_err(|error| format!("could not load MLS group for proposal: {error}"))?
                .ok_or_else(|| "MLS group state is missing".to_owned())?;
            if group.epoch().as_u64() != epoch {
                return Err("MLS group epoch disagrees with its local index".to_owned());
            }
            let own_leaf = group
                .own_leaf()
                .ok_or_else(|| "local MLS member leaf is missing".to_owned())?;
            let own_binding =
                MlsSigningKeyBinding::from_bytes(own_leaf.credential().serialized_content())
                    .ok_or_else(|| {
                        "local MLS credential has no device identity binding".to_owned()
                    })?;
            if own_binding.device_public_key != device_identity.verifying_key().to_bytes()
                || !own_binding.verifies_mls_credential(
                    &own_binding.device_public_key,
                    group.ciphersuite().signature_algorithm() as u16,
                    own_leaf.signature_key().as_slice(),
                )
            {
                return Err("MLS group is not bound to this device identity".to_owned());
            }
            let processed = group
                .process_message(&provider, message)
                .map_err(|error| format!("could not authenticate MLS proposal: {error:?}"))?;
            let sender_credential = processed.credential().serialized_content().to_vec();
            let sender_member = group
                .members()
                .find(|member| member.credential.serialized_content() == sender_credential)
                .ok_or_else(|| "MLS proposal author is not a current group member".to_owned())?;
            let sender_binding = MlsSigningKeyBinding::from_bytes(&sender_credential)
                .ok_or_else(|| "MLS proposal author has no device identity binding".to_owned())?;
            if !sender_binding.verifies_mls_credential(
                &sender_binding.device_public_key,
                group.ciphersuite().signature_algorithm() as u16,
                sender_member.signature_key.as_slice(),
            ) {
                return Err("MLS proposal author has an invalid device binding".to_owned());
            }
            if expected_author.is_some_and(|expected| expected != sender_binding.device_public_key)
            {
                return Err("MLS proposal author does not match the pinned peer device".to_owned());
            }
            let queued = match processed.into_content() {
                ProcessedMessageContent::ProposalMessage(proposal) => proposal,
                _ => return Err("MLS message is not a standalone proposal".to_owned()),
            };
            if !matches!(queued.proposal(), Proposal::Update(_)) {
                return Err("only a member self-update proposal is accepted here".to_owned());
            }
            let proposal_ref = queued
                .proposal_reference_ref()
                .tls_serialize_detached()
                .map_err(|error| format!("could not serialize MLS proposal reference: {error}"))?;
            group
                .store_pending_proposal(provider.storage(), *queued)
                .map_err(|error| format!("could not persist MLS pending proposal: {error}"))?;
            (
                group.epoch().as_u64(),
                sender_binding.device_public_key,
                proposal_ref,
            )
        };
        connection
            .execute(
                "INSERT INTO local_mls_proposals
                    (proposal_id, group_id, epoch, author_device, proposal_hash, proposal_bytes,
                     proposal_ref, decision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                params![
                    proposal_id.as_slice(),
                    group_id,
                    epoch as i64,
                    author_device.as_slice(),
                    digest.as_slice(),
                    proposal_bytes,
                    proposal_ref
                ],
            )
            .map_err(|error| format!("could not journal accepted MLS proposal: {error}"))?;
        Ok(ProcessedMlsProposal::Accepted {
            epoch: accepted_epoch,
        })
    })();
    finish_sql_transaction(connection, result, "inbound MLS proposal")
}

/// Authenticates and decrypts a queued MLS event, saving its ciphertext before
/// returning plaintext to the caller. Callers may acknowledge only after this
/// function succeeds.
pub fn process_inbound_mls_application_event(
    event: &EncryptedEvent,
) -> Result<ProcessedMlsApplicationEvent, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    process_inbound_mls_application_event_in(&mut connection, event, &device_identity)
}

fn process_inbound_mls_application_event_in(
    connection: &mut Connection,
    event: &EncryptedEvent,
    device_identity: &SigningKey,
) -> Result<ProcessedMlsApplicationEvent, String> {
    process_inbound_mls_application_event_at(connection, event, device_identity, unix_time_now()?)
}

fn process_inbound_mls_application_event_at(
    connection: &mut Connection,
    event: &EncryptedEvent,
    device_identity: &SigningKey,
    now: i64,
) -> Result<ProcessedMlsApplicationEvent, String> {
    use openmls::prelude::{
        MlsMessageIn, ProcessedMessageContent, tls_codec::Deserialize as TlsCodecDeserialize,
    };

    if event.event_id.iter().all(|byte| *byte == 0)
        || event.author_device.iter().all(|byte| *byte == 0)
        || event.group_id.len() != 16
        || event.epoch > i64::MAX as u64
        || event.expires_at_unix <= 0
        || event.ciphertext.is_empty()
        || event.ciphertext.len() > 32 * 1024
    {
        return Err("inbound MLS event envelope is incomplete or invalid".to_owned());
    }
    let digest = blake3::hash(&event.ciphertext);
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin inbound MLS transaction: {error}"))?;
    let result = (|| {
        ensure_mls_group_not_quarantined(connection, &event.group_id)?;
        let existing: Option<StoredInboundEnvelope> = connection
            .query_row(
                "SELECT author_device, group_id, ciphertext_digest, epoch, checkpoint,
                            expires_at_unix, ciphertext FROM local_events WHERE event_id = ?1",
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
            .map_err(|error| format!("could not check inbound MLS deduplication: {error}"))?;
        if let Some((author, group, stored_digest, epoch, checkpoint, expiry, ciphertext)) =
            existing
        {
            if author != event.author_device
                || group != event.group_id
                || stored_digest != digest.as_bytes()
                || epoch != event.epoch as i64
                || checkpoint != event.checkpoint
                || expiry != event.expires_at_unix
                || ciphertext != event.ciphertext
            {
                return Err(
                    "MLS event id was reused with different envelope or ciphertext".to_owned(),
                );
            }
            return Ok(ProcessedMlsApplicationEvent::Duplicate);
        }
        if event.expires_at_unix <= now {
            return Err("inbound MLS application event has expired".to_owned());
        }

        let incoming = MlsMessageIn::tls_deserialize_exact(&event.ciphertext)
            .map_err(|error| format!("invalid serialized MLS message: {error}"))?;
        let expected_group_id = GroupId::from_slice(&event.group_id);
        let (plaintext, processed_epoch, processed_group_id, authenticated_data, sender_device) = {
            let provider = LocalOpenMlsProvider::new(connection);
            let mut group = MlsGroup::load(provider.storage(), &expected_group_id)
                .map_err(|error| format!("could not load inbound MLS group: {error}"))?
                .ok_or_else(|| "inbound MLS group is not joined on this device".to_owned())?;
            let own_leaf = group
                .own_leaf()
                .ok_or_else(|| "local MLS member leaf is missing".to_owned())?;
            let own_binding =
                MlsSigningKeyBinding::from_bytes(own_leaf.credential().serialized_content())
                    .ok_or_else(|| {
                        "local MLS credential has no device identity binding".to_owned()
                    })?;
            if own_binding.device_public_key != device_identity.verifying_key().to_bytes()
                || !own_binding.verifies_mls_credential(
                    &own_binding.device_public_key,
                    group.ciphersuite().signature_algorithm() as u16,
                    own_leaf.signature_key().as_slice(),
                )
            {
                return Err("MLS group is not bound to this device identity".to_owned());
            }
            let processed = group
                .process_message(
                    &provider,
                    incoming.try_into_protocol_message().map_err(|error| {
                        format!("inbound message is not an MLS protocol message: {error}")
                    })?,
                )
                .map_err(|error| {
                    format!("could not authenticate or decrypt MLS message: {error:?}")
                })?;
            let sender_binding =
                MlsSigningKeyBinding::from_bytes(processed.credential().serialized_content())
                    .ok_or_else(|| {
                        "MLS sender credential has no device identity binding".to_owned()
                    })?;
            if sender_binding.device_public_key != event.author_device
                || !sender_binding.verifies_mls_credential(
                    &event.author_device,
                    group.ciphersuite().signature_algorithm() as u16,
                    // OpenMLS has authenticated the sender's credential and signature.
                    &sender_binding.mls_signing_public_key,
                )
            {
                return Err("MLS sender does not match the event author device".to_owned());
            }
            let authenticated_data = processed.aad().to_vec();
            let processed_group_id = processed.group_id().to_vec();
            let processed_epoch = processed.epoch().as_u64();
            let plaintext = match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
                _ => return Err("inbound MLS event is not an application message".to_owned()),
            };
            (
                plaintext,
                processed_epoch,
                processed_group_id,
                authenticated_data,
                sender_binding.device_public_key,
            )
        };
        if processed_group_id != event.group_id
            || processed_epoch != event.epoch
            || sender_device != event.author_device
            || authenticated_data != mls_event_aad(event)
        {
            return Err("authenticated MLS message does not match its event envelope".to_owned());
        }
        let plaintext_text = String::from_utf8(plaintext.clone())
            .map_err(|_| "MLS chat message is not valid UTF-8".to_owned())?;
        if plaintext_text.is_empty() || plaintext_text.len() > 16 * 1024 {
            return Err("MLS chat text must contain 1 to 16384 UTF-8 bytes".to_owned());
        }
        connection
            .execute(
                "INSERT INTO local_events
                    (event_id, direction, author_device, group_id, epoch, checkpoint,
                     ciphertext_digest, ciphertext, expires_at_unix, delivery_state)
                 VALUES (?1, 'inbound', ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'received_by_device')",
                params![
                    event.event_id.as_slice(),
                    event.author_device.as_slice(),
                    event.group_id,
                    event.epoch as i64,
                    event.checkpoint,
                    digest.as_bytes().as_slice(),
                    event.ciphertext,
                    event.expires_at_unix
                ],
            )
            .map_err(|error| format!("could not persist inbound MLS event: {error}"))?;
        insert_mls_history_in(
            connection,
            &event.group_id,
            event.event_id,
            "received",
            &plaintext_text,
        )?;
        Ok(ProcessedMlsApplicationEvent::Received(plaintext))
    })();
    finish_sql_transaction(connection, result, "inbound MLS event")
}

pub fn process_inbound_mls_commit(
    group_id: &[u8],
    commit_bytes: &[u8],
) -> Result<ProcessedMlsCommit, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    process_inbound_mls_commit_in(&mut connection, group_id, commit_bytes, &device_identity)
}

fn process_inbound_mls_commit_in(
    connection: &mut Connection,
    group_id: &[u8],
    commit_bytes: &[u8],
    device_identity: &SigningKey,
) -> Result<ProcessedMlsCommit, String> {
    use openmls::prelude::{
        MlsMessageIn, ProcessedMessageContent, tls_codec::Deserialize as TlsCodecDeserialize,
    };

    if group_id.len() != 16 || commit_bytes.is_empty() || commit_bytes.len() > 64 * 1024 {
        return Err("inbound MLS Commit has an invalid group ID or size".to_owned());
    }
    let incoming = MlsMessageIn::tls_deserialize_exact(commit_bytes)
        .map_err(|error| format!("invalid serialized MLS Commit: {error}"))?
        .try_into_protocol_message()
        .map_err(|error| format!("MLS Commit is not a protocol message: {error}"))?;
    if incoming.group_id().as_slice() != group_id {
        return Err("MLS Commit belongs to another group".to_owned());
    }
    let predecessor_epoch = incoming.epoch().as_u64();
    let commit_hash = *blake3::hash(commit_bytes).as_bytes();
    let mut event_id = [0; 16];
    event_id.copy_from_slice(&commit_hash[..16]);
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin inbound MLS Commit transaction: {error}"))?;
    let result = (|| {
        let policy: (Vec<u8>, i64, bool) = connection
            .query_row(
                "SELECT designated_committer_device, epoch, quarantined
                 FROM local_mls_groups WHERE group_id = ?1",
                [group_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0)),
            )
            .map_err(|error| format!("could not load MLS group policy: {error}"))?;
        if policy.2 {
            return Err(
                "MLS group is quarantined after authenticated committer equivocation".to_owned(),
            );
        }
        if predecessor_epoch < policy.1 as u64 {
            let existing: Option<StoredPriorMlsCommit> = connection
                .query_row(
                    "SELECT event_id, commit_hash, commit_bytes, author_device
                     FROM local_mls_inbound_commits
                     WHERE group_id = ?1 AND predecessor_epoch = ?2",
                    params![group_id, predecessor_epoch as i64],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|error| format!("could not check MLS Commit redelivery: {error}"))?;
            if let Some((accepted_event_id, digest, bytes, accepted_author)) = existing {
                if digest.as_slice() == commit_hash && bytes == commit_bytes {
                    return Ok(ProcessedMlsCommit::Duplicate {
                        epoch: predecessor_epoch.saturating_add(1),
                    });
                }
                let author_device = authenticate_mls_commit_from_epoch_snapshot(
                    connection,
                    group_id,
                    predecessor_epoch,
                    commit_bytes,
                    device_identity,
                    &policy.0,
                )?;
                if accepted_author.as_slice() != author_device {
                    return Err(
                        "conflicting Commit author differs from the accepted historical author"
                            .to_owned(),
                    );
                }
                let accepted_event_id: [u8; 16] =
                    fixed_bytes(accepted_event_id, "accepted MLS Commit event ID")?;
                let accepted_hash: [u8; 32] = fixed_bytes(digest, "accepted MLS Commit digest")?;
                let mut accepted_author_id = [0; 16];
                accepted_author_id.copy_from_slice(&accepted_hash[..16]);
                if accepted_author_id != accepted_event_id {
                    return Err(
                        "accepted MLS Commit journal has an invalid event digest".to_owned()
                    );
                }
                connection
                    .execute(
                        "INSERT INTO local_mls_equivocations
                            (group_id, predecessor_epoch, accepted_event_id, accepted_hash,
                             accepted_bytes, conflicting_event_id, conflicting_hash,
                             conflicting_bytes, author_device)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            group_id,
                            predecessor_epoch as i64,
                            accepted_event_id.as_slice(),
                            accepted_hash.as_slice(),
                            bytes,
                            event_id.as_slice(),
                            commit_hash.as_slice(),
                            commit_bytes,
                            author_device.as_slice(),
                        ],
                    )
                    .map_err(|error| {
                        format!("could not preserve MLS equivocation evidence: {error}")
                    })?;
                let updated = connection
                    .execute(
                        "UPDATE local_mls_groups
                         SET quarantined = 1,
                             quarantine_reason = 'authenticated designated committer equivocation'
                         WHERE group_id = ?1 AND quarantined = 0",
                        [group_id],
                    )
                    .map_err(|error| {
                        format!("could not quarantine equivocated MLS group: {error}")
                    })?;
                if updated != 1 {
                    return Err(
                        "MLS group quarantine state changed during evidence storage".to_owned()
                    );
                }
                return Ok(ProcessedMlsCommit::EquivocationDetected { predecessor_epoch });
            }
            return Err("MLS Commit predecessor is older than local state but has no matching journal entry".to_owned());
        }
        if predecessor_epoch > policy.1 as u64 {
            return Err(format!(
                "MLS Commit is out of order: expected predecessor epoch {}, received {predecessor_epoch}",
                policy.1
            ));
        }
        let collision: Option<Vec<u8>> = connection
            .query_row(
                "SELECT commit_hash FROM local_mls_inbound_commits WHERE event_id = ?1",
                [event_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("could not check MLS Commit event ID: {error}"))?;
        if collision.is_some() {
            return Err("MLS Commit event ID collision".to_owned());
        }

        capture_mls_epoch_snapshot_in(connection, group_id, predecessor_epoch)?;

        let (epoch, author_device) = {
            let provider = LocalOpenMlsProvider::new(connection);
            let group_identifier = GroupId::from_slice(group_id);
            let mut group = MlsGroup::load(provider.storage(), &group_identifier)
                .map_err(|error| format!("could not load MLS group for Commit: {error}"))?
                .ok_or_else(|| "MLS group state is missing".to_owned())?;
            if group.epoch().as_u64() != predecessor_epoch {
                return Err("MLS group epoch disagrees with its local group index".to_owned());
            }
            let own_leaf = group
                .own_leaf()
                .ok_or_else(|| "local MLS member leaf is missing".to_owned())?;
            let own_binding =
                MlsSigningKeyBinding::from_bytes(own_leaf.credential().serialized_content())
                    .ok_or_else(|| {
                        "local MLS credential has no device identity binding".to_owned()
                    })?;
            if own_binding.device_public_key != device_identity.verifying_key().to_bytes()
                || !own_binding.verifies_mls_credential(
                    &own_binding.device_public_key,
                    group.ciphersuite().signature_algorithm() as u16,
                    own_leaf.signature_key().as_slice(),
                )
            {
                return Err("MLS group is not bound to this device identity".to_owned());
            }
            let processed = group
                .process_message(&provider, incoming)
                .map_err(|error| format!("could not authenticate MLS Commit: {error:?}"))?;
            let sender_binding =
                MlsSigningKeyBinding::from_bytes(processed.credential().serialized_content())
                    .ok_or_else(|| "MLS Commit sender has no device identity binding".to_owned())?;
            let sender_member = group
                .members()
                .find(|member| {
                    member.credential.serialized_content()
                        == processed.credential().serialized_content()
                })
                .ok_or_else(|| "MLS Commit sender is not a current group member".to_owned())?;
            let author_device = sender_binding.device_public_key;
            if author_device.as_slice() != policy.0
                || !sender_binding.verifies_mls_credential(
                    &author_device,
                    group.ciphersuite().signature_algorithm() as u16,
                    sender_member.signature_key.as_slice(),
                )
            {
                return Err("MLS Commit author is not the bound designated committer".to_owned());
            }
            let staged_commit = match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged) => *staged,
                _ => return Err("inbound MLS message is not a staged Commit".to_owned()),
            };
            if staged_commit.epoch().as_u64() != predecessor_epoch.saturating_add(1) {
                return Err("MLS Commit does not advance exactly one epoch".to_owned());
            }
            for proposal in staged_commit.add_proposals() {
                let key_package = proposal.add_proposal().key_package();
                validate_mls_credential_binding(
                    key_package.leaf_node().credential(),
                    key_package.leaf_node().signature_key().as_slice(),
                    group.ciphersuite().signature_algorithm() as u16,
                )?;
            }
            for proposal in staged_commit.update_proposals() {
                let leaf = proposal.update_proposal().leaf_node();
                validate_mls_credential_binding(
                    leaf.credential(),
                    leaf.signature_key().as_slice(),
                    group.ciphersuite().signature_algorithm() as u16,
                )?;
            }
            if let Some(leaf) = staged_commit.update_path_leaf_node() {
                validate_mls_credential_binding(
                    leaf.credential(),
                    leaf.signature_key().as_slice(),
                    group.ciphersuite().signature_algorithm() as u16,
                )?;
            }
            group
                .merge_staged_commit(&provider, staged_commit)
                .map_err(|error| format!("could not merge authenticated MLS Commit: {error:?}"))?;
            (group.epoch().as_u64(), author_device)
        };
        if epoch != predecessor_epoch.saturating_add(1) {
            return Err("merged MLS Commit produced an unexpected group epoch".to_owned());
        }
        connection
            .execute(
                "INSERT INTO local_mls_inbound_commits
                    (event_id, group_id, predecessor_epoch, epoch, author_device,
                     commit_hash, commit_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event_id.as_slice(),
                    group_id,
                    predecessor_epoch as i64,
                    epoch as i64,
                    author_device.as_slice(),
                    commit_hash.as_slice(),
                    commit_bytes
                ],
            )
            .map_err(|error| format!("could not persist inbound MLS Commit: {error}"))?;
        let updated = connection
            .execute(
                "UPDATE local_mls_groups SET epoch = ?1 WHERE group_id = ?2 AND epoch = ?3",
                params![epoch as i64, group_id, predecessor_epoch as i64],
            )
            .map_err(|error| format!("could not advance indexed MLS group epoch: {error}"))?;
        if updated != 1 {
            return Err("MLS group index changed during Commit processing".to_owned());
        }
        Ok(ProcessedMlsCommit::Applied { epoch })
    })();
    finish_sql_transaction(connection, result, "inbound MLS Commit")
}

fn validate_mls_credential_binding(
    credential: &openmls::prelude::Credential,
    signature_key: &[u8],
    signature_scheme: u16,
) -> Result<(), String> {
    let binding = MlsSigningKeyBinding::from_bytes(credential.serialized_content())
        .ok_or_else(|| "MLS Commit contains a credential without device binding".to_owned())?;
    if !binding.verifies_mls_credential(&binding.device_public_key, signature_scheme, signature_key)
    {
        return Err("MLS Commit contains an invalid device-bound credential".to_owned());
    }
    Ok(())
}

fn insert_mls_history_in(
    connection: &Connection,
    group_id: &[u8],
    event_id: [u8; 16],
    direction: &'static str,
    text: &str,
) -> Result<(), String> {
    connection
        .execute(
            "INSERT INTO local_mls_messages (group_id, event_id, direction, text)
             VALUES (?1, ?2, ?3, ?4)",
            params![group_id, event_id.as_slice(), direction, text],
        )
        .map_err(|error| format!("could not persist MLS local history: {error}"))?;
    connection
        .execute(
            "DELETE FROM local_mls_messages
             WHERE group_id = ?1 AND sequence NOT IN (
                 SELECT sequence FROM local_mls_messages
                 WHERE group_id = ?1 ORDER BY sequence DESC LIMIT ?2
             )",
            params![group_id, MAX_MLS_HISTORY_PER_GROUP],
        )
        .map_err(|error| format!("could not enforce MLS history limit: {error}"))?;
    Ok(())
}

fn mls_event_aad(event: &EncryptedEvent) -> Vec<u8> {
    let mut aad = Vec::with_capacity(80 + event.group_id.len());
    aad.extend_from_slice(b"slouching/mls-event/v1");
    aad.extend_from_slice(&event.event_id);
    aad.extend_from_slice(&event.author_device);
    aad.extend_from_slice(&(event.group_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(&event.group_id);
    aad.extend_from_slice(&event.epoch.to_be_bytes());
    aad.extend_from_slice(&event.expires_at_unix.to_be_bytes());
    aad
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
    expire_queued_mls_events_in(&connection, unix_time_now()?)?;
    let mut statement = connection
        .prepare(
            "SELECT e.rowid, e.event_id, e.author_device, e.group_id, e.epoch, e.checkpoint,
                    e.expires_at_unix, e.ciphertext, e.delivery_state
             FROM local_events e
             LEFT JOIN local_mls_groups g ON g.group_id = e.group_id
             WHERE e.direction = 'outbound' AND e.rowid > ?1
               AND (g.group_id IS NULL OR g.quarantined = 0)
             ORDER BY e.rowid LIMIT ?2",
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

pub fn list_queued_mls_event_recipients(group_id: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    let connection = open_local_database()?;
    list_queued_mls_event_recipients_in(&connection, group_id)
}

pub fn expire_queued_mls_events(group_id: &[u8]) -> Result<usize, String> {
    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    let connection = open_local_database()?;
    connection
        .execute(
            "UPDATE local_events SET delivery_state = 'expired'
             WHERE group_id = ?1 AND direction = 'outbound'
               AND delivery_state = 'queued' AND expires_at_unix <= ?2",
            params![group_id, unix_time_now()?],
        )
        .map_err(|error| format!("could not expire queued MLS events: {error}"))
}

fn list_queued_mls_event_recipients_in(
    connection: &Connection,
    group_id: &[u8],
) -> Result<Vec<[u8; 32]>, String> {
    expire_queued_mls_events_in(connection, unix_time_now()?)?;
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT r.device_public_key
             FROM local_mls_event_recipients r
             JOIN local_events e ON e.event_id = r.event_id
             WHERE e.group_id = ?1 AND r.delivery_state = 'queued'
               AND e.delivery_state = 'queued'
             ORDER BY r.device_public_key",
        )
        .map_err(|error| format!("could not prepare MLS event recipients: {error}"))?;
    let rows = statement
        .query_map(params![group_id], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|error| format!("could not query MLS event recipients: {error}"))?;
    rows.map(|row| {
        fixed_bytes(
            row.map_err(|error| format!("could not read MLS event recipient: {error}"))?,
            "MLS event recipient device key",
        )
    })
    .collect()
}

pub fn list_queued_mls_events_for_peer(
    group_id: &[u8],
    peer_device: [u8; 32],
    limit: usize,
) -> Result<Vec<StoredOutboundEvent>, String> {
    if group_id.len() != 16 || !(1..=500).contains(&limit) {
        return Err("MLS event query requires a 16-byte group ID and limit 1..500".to_owned());
    }
    let connection = open_local_database()?;
    list_queued_mls_events_for_peer_in(&connection, group_id, peer_device, limit)
}

fn list_queued_mls_events_for_peer_in(
    connection: &Connection,
    group_id: &[u8],
    peer_device: [u8; 32],
    limit: usize,
) -> Result<Vec<StoredOutboundEvent>, String> {
    expire_queued_mls_events_in(connection, unix_time_now()?)?;
    let mut statement = connection
        .prepare(
            "SELECT e.rowid, e.event_id, e.author_device, e.group_id, e.epoch,
                    e.checkpoint, e.expires_at_unix, e.ciphertext, e.delivery_state
             FROM local_events e
             JOIN local_mls_event_recipients r ON r.event_id = e.event_id
             JOIN local_mls_groups g ON g.group_id = e.group_id
             WHERE e.group_id = ?1 AND e.direction = 'outbound'
               AND r.device_public_key = ?2 AND r.delivery_state = 'queued'
               AND e.delivery_state = 'queued' AND g.quarantined = 0
             ORDER BY e.rowid LIMIT ?3",
        )
        .map_err(|error| format!("could not prepare peer MLS event query: {error}"))?;
    let rows = statement
        .query_map(
            params![group_id, peer_device.as_slice(), limit as i64],
            |row| {
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
            },
        )
        .map_err(|error| format!("could not query peer MLS events: {error}"))?;
    rows.map(|row| {
        let (sequence, event_id, author, group, epoch, checkpoint, expires, ciphertext, state) =
            row.map_err(|error| format!("could not read peer MLS event: {error}"))?;
        Ok(StoredOutboundEvent {
            sequence,
            event: EncryptedEvent {
                event_id: fixed_bytes(event_id, "MLS application event ID")?,
                author_device: fixed_bytes(author, "MLS application author")?,
                group_id: fixed_bytes::<16>(group, "MLS application group ID")?.to_vec(),
                epoch: u64::try_from(epoch)
                    .map_err(|_| "saved MLS event has an invalid epoch".to_owned())?,
                checkpoint,
                expires_at_unix: expires,
                ciphertext,
            },
            state: OutboundDeliveryState::try_from(state.as_str())?,
        })
    })
    .collect()
}

pub fn mark_mls_event_delivered_to_peer(
    event_id: [u8; 16],
    peer_device: [u8; 32],
) -> Result<(), String> {
    let mut connection = open_local_database()?;
    mark_mls_event_delivered_to_peer_in(&mut connection, event_id, peer_device)
}

fn mark_mls_event_delivered_to_peer_in(
    connection: &mut Connection,
    event_id: [u8; 16],
    peer_device: [u8; 32],
) -> Result<(), String> {
    expire_queued_mls_events_in(connection, unix_time_now()?)?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| format!("could not begin MLS event delivery transaction: {error}"))?;
    let delivered_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is invalid: {error}"))?
        .as_secs() as i64;
    let event_state: Option<String> = transaction
        .query_row(
            "SELECT delivery_state FROM local_events
             WHERE event_id = ?1 AND direction = 'outbound'",
            [event_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("could not read MLS event state for ACK: {error}"))?;
    let event_state = event_state.ok_or_else(|| "outbound MLS event was not found".to_owned())?;
    if event_state == "expired" {
        return Err("ACK arrived after the MLS event expired".to_owned());
    }
    let changed = transaction
        .execute(
            "UPDATE local_mls_event_recipients SET delivery_state = 'delivered', delivered_at = ?1
             WHERE event_id = ?2 AND device_public_key = ?3 AND delivery_state = 'queued'",
            params![delivered_at, event_id.as_slice(), peer_device.as_slice()],
        )
        .map_err(|error| format!("could not save MLS event peer ACK: {error}"))?;
    if changed == 0 {
        let already_delivered: Option<String> = transaction
            .query_row(
                "SELECT delivery_state FROM local_mls_event_recipients
                 WHERE event_id = ?1 AND device_public_key = ?2",
                params![event_id.as_slice(), peer_device.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("could not verify MLS event peer ACK: {error}"))?;
        if already_delivered.as_deref() != Some("delivered") {
            return Err("ACK does not match a queued MLS event recipient".to_owned());
        }
    }
    let queued: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM local_mls_event_recipients
             WHERE event_id = ?1 AND delivery_state = 'queued'",
            [event_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not check MLS event recipients: {error}"))?;
    if queued == 0 {
        transaction
            .execute(
                "UPDATE local_events SET delivery_state = 'held_by_peer'
                 WHERE event_id = ?1 AND direction = 'outbound' AND delivery_state = 'queued'",
                [event_id.as_slice()],
            )
            .map_err(|error| format!("could not finish MLS event outbox state: {error}"))?;
    }
    transaction
        .commit()
        .map_err(|error| format!("could not commit MLS event delivery ACK: {error}"))
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
    if event.expires_at_unix <= unix_time_now()? {
        return Err("encrypted event has expired".to_owned());
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

fn unix_time_now() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is invalid: {error}"))?
        .as_secs()
        .try_into()
        .map_err(|_| "system clock exceeds supported Unix timestamp range".to_owned())
}

fn expire_queued_mls_events_in(connection: &Connection, now: i64) -> Result<usize, String> {
    connection
        .execute(
            "UPDATE local_events SET delivery_state = 'expired'
             WHERE direction = 'outbound' AND delivery_state = 'queued'
               AND expires_at_unix <= ?1",
            [now],
        )
        .map_err(|error| format!("could not expire queued MLS events: {error}"))
}

/// Signs a bounded authorization for a named helper device to retain one
/// opaque MLS ciphertext for one recipient until the event expiry.
pub fn sign_delegated_mls_copy_grant(
    event: &EncryptedEvent,
    recipient_device: [u8; 32],
) -> Result<DelegatedMlsCopyGrant, String> {
    let entry = identity_key_entry()?;
    let identity = signing_key_from_secret(
        entry
            .get_secret()
            .map_err(|error| format!("could not load the device identity key: {error}"))?,
    )?;
    sign_delegated_mls_copy_grant_with_identity(event, recipient_device, &identity)
}

fn sign_delegated_mls_copy_grant_with_identity(
    event: &EncryptedEvent,
    recipient_device: [u8; 32],
    identity: &SigningKey,
) -> Result<DelegatedMlsCopyGrant, String> {
    if event.author_device != identity.verifying_key().to_bytes() {
        return Err("only the event author device can authorize a delegated copy".to_owned());
    }
    if event.group_id.len() != 16
        || event.ciphertext.is_empty()
        || event.ciphertext.len() > MAX_DELEGATED_COPY_BYTES
        || event
            .checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.len() > MAX_DELEGATED_CHECKPOINT_BYTES)
    {
        return Err("delegated MLS event has an invalid or oversized envelope".to_owned());
    }
    let group_id = fixed_bytes(event.group_id.clone(), "MLS group ID")?;
    let ciphertext_digest = *blake3::hash(&event.ciphertext).as_bytes();
    let mut grant = DelegatedMlsCopyGrant {
        event_id: event.event_id,
        author_device: event.author_device,
        recipient_device,
        group_id,
        epoch: event.epoch,
        expires_at_unix: event.expires_at_unix,
        checkpoint: event.checkpoint.clone(),
        ciphertext_digest,
        signature: [0; 64],
    };
    grant.signature = identity
        .sign(&delegated_copy_signature_payload(&grant))
        .to_bytes();
    Ok(grant)
}

/// Stores an opaque event only when the authenticated session peer is the
/// author named by its device signature and local delegated storage is enabled.
pub fn store_delegated_mls_copy(
    grant: &DelegatedMlsCopyGrant,
    event: &EncryptedEvent,
    authenticated_author: [u8; 32],
) -> Result<DelegatedCopyStoreResult, String> {
    let mut connection = open_local_database()?;
    store_delegated_mls_copy_in(
        &mut connection,
        grant,
        event,
        authenticated_author,
        unix_time_now()?,
    )
}

/// Verifies an author's signed copy grant and exact ciphertext envelope.
/// The recipient device key must be the current local device identity.
pub fn verify_delegated_mls_copy(
    grant: &DelegatedMlsCopyGrant,
    event: &EncryptedEvent,
    recipient_device: [u8; 32],
) -> Result<(), String> {
    if grant.recipient_device != recipient_device {
        return Err("delegated MLS copy targets another device".to_owned());
    }
    validate_delegated_copy_grant(grant, event, grant.author_device, unix_time_now()?)
}

fn store_delegated_mls_copy_in(
    connection: &mut Connection,
    grant: &DelegatedMlsCopyGrant,
    event: &EncryptedEvent,
    authenticated_author: [u8; 32],
    now: i64,
) -> Result<DelegatedCopyStoreResult, String> {
    validate_delegated_copy_grant(grant, event, authenticated_author, now)?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| format!("could not begin delegated MLS copy transaction: {error}"))?;
    transaction
        .execute(
            "UPDATE local_delegated_mls_copies
             SET delivery_state = 'expired', ciphertext = NULL
             WHERE delivery_state = 'queued' AND expires_at_unix <= ?1",
            [now],
        )
        .map_err(|error| format!("could not expire delegated MLS copies: {error}"))?;
    cleanup_delegated_mls_tombstones(&transaction, now)?;
    let existing: Option<StoredDelegatedCopyEnvelope> = transaction
        .query_row(
            "SELECT ciphertext_digest, author_device, group_id, epoch, checkpoint,
                    expires_at_unix, grant_signature, delivery_state
             FROM local_delegated_mls_copies
             WHERE event_id = ?1 AND recipient_device = ?2",
            params![grant.event_id.as_slice(), grant.recipient_device.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| format!("could not check delegated MLS copy deduplication: {error}"))?;
    if let Some((digest, author, group, epoch, checkpoint, expires, signature, state)) = existing {
        if digest != grant.ciphertext_digest
            || author != grant.author_device
            || group != grant.group_id
            || epoch != grant.epoch as i64
            || checkpoint != grant.checkpoint
            || expires != grant.expires_at_unix
            || signature != grant.signature
        {
            return Err(
                "delegated event ID was reused with different content or authorization".to_owned(),
            );
        }
        if state == "expired" {
            return Err("delegated copy is no longer retained by this device".to_owned());
        }
        transaction.commit().map_err(|error| {
            format!("could not finish delegated MLS copy deduplication: {error}")
        })?;
        return Ok(DelegatedCopyStoreResult::AlreadyStored);
    }
    let (enabled, quota_bytes): (bool, i64) = transaction
        .query_row(
            "SELECT enabled, quota_bytes FROM local_delegation_policy WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("could not load delegated storage policy: {error}"))?;
    if !enabled {
        return Err("this device has not enabled delegated ciphertext storage".to_owned());
    }
    let used_bytes: i64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(length(ciphertext)), 0)
             FROM local_delegated_mls_copies WHERE delivery_state = 'queued'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not read delegated storage usage: {error}"))?;
    let used_events: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM local_delegated_mls_copies
             WHERE delivery_state = 'queued'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not read delegated event usage: {error}"))?;
    let copy_bytes = i64::try_from(event.ciphertext.len())
        .map_err(|_| "delegated MLS copy exceeds the storage limit".to_owned())?;
    if used_bytes.saturating_add(copy_bytes) > quota_bytes
        || used_events >= MAX_DELEGATED_STORAGE_EVENTS
    {
        return Err("delegated ciphertext storage quota is full".to_owned());
    }
    transaction
        .execute(
            "INSERT INTO local_delegated_mls_copies (
                 event_id, recipient_device, author_device, group_id, epoch,
                 checkpoint, expires_at_unix, ciphertext_digest, ciphertext,
                 grant_signature, delivery_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'queued')",
            params![
                grant.event_id.as_slice(),
                grant.recipient_device.as_slice(),
                grant.author_device.as_slice(),
                grant.group_id.as_slice(),
                grant.epoch as i64,
                grant.checkpoint,
                grant.expires_at_unix,
                grant.ciphertext_digest.as_slice(),
                event.ciphertext,
                grant.signature.as_slice(),
            ],
        )
        .map_err(|error| format!("could not persist delegated MLS ciphertext: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("could not commit delegated MLS ciphertext: {error}"))?;
    Ok(DelegatedCopyStoreResult::Stored)
}

pub fn list_delegated_mls_copies_for_device(
    recipient_device: [u8; 32],
    limit: usize,
) -> Result<Vec<StoredDelegatedMlsCopy>, String> {
    if !(1..=100).contains(&limit) {
        return Err("delegated MLS copy page size must be between 1 and 100".to_owned());
    }
    let connection = open_local_database()?;
    list_delegated_mls_copies_for_device_in(&connection, recipient_device, limit, unix_time_now()?)
}

fn list_delegated_mls_copies_for_device_in(
    connection: &Connection,
    recipient_device: [u8; 32],
    limit: usize,
    now: i64,
) -> Result<Vec<StoredDelegatedMlsCopy>, String> {
    connection
        .execute(
            "UPDATE local_delegated_mls_copies
             SET delivery_state = 'expired', ciphertext = NULL
             WHERE delivery_state = 'queued' AND expires_at_unix <= ?1",
            [now],
        )
        .map_err(|error| format!("could not expire delegated MLS copies: {error}"))?;
    cleanup_delegated_mls_tombstones(connection, now)?;
    let enabled: bool = connection
        .query_row(
            "SELECT enabled FROM local_delegation_policy WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not read delegated storage policy: {error}"))?;
    if !enabled {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT event_id, author_device, group_id, epoch, checkpoint,
                    expires_at_unix, ciphertext_digest, grant_signature, ciphertext
             FROM local_delegated_mls_copies
             WHERE recipient_device = ?1 AND delivery_state = 'queued'
             ORDER BY expires_at_unix, event_id LIMIT ?2",
        )
        .map_err(|error| format!("could not prepare delegated MLS mailbox query: {error}"))?;
    let rows = statement
        .query_map(params![recipient_device.as_slice(), limit as i64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })
        .map_err(|error| format!("could not query delegated MLS mailbox: {error}"))?;
    rows.map(|row| {
        let (id, author, group, epoch, checkpoint, expires, digest, signature, ciphertext) =
            row.map_err(|error| format!("could not read delegated MLS mailbox entry: {error}"))?;
        let grant = DelegatedMlsCopyGrant {
            event_id: fixed_bytes(id, "delegated event ID")?,
            author_device: fixed_bytes(author, "delegated author device")?,
            recipient_device,
            group_id: fixed_bytes(group, "delegated group ID")?,
            epoch: u64::try_from(epoch)
                .map_err(|_| "delegated MLS copy has an invalid epoch".to_owned())?,
            expires_at_unix: expires,
            checkpoint,
            ciphertext_digest: fixed_bytes(digest, "delegated ciphertext digest")?,
            signature: fixed_bytes(signature, "delegated copy signature")?,
        };
        let event = EncryptedEvent {
            event_id: grant.event_id,
            author_device: grant.author_device,
            group_id: grant.group_id.to_vec(),
            epoch: grant.epoch,
            checkpoint: grant.checkpoint.clone(),
            expires_at_unix: grant.expires_at_unix,
            ciphertext: ciphertext.clone(),
        };
        validate_delegated_copy_grant(&grant, &event, grant.author_device, now)?;
        Ok(StoredDelegatedMlsCopy { grant, ciphertext })
    })
    .collect()
}

pub fn acknowledge_delegated_mls_copy(
    event_id: [u8; 16],
    recipient_device: [u8; 32],
) -> Result<bool, String> {
    let connection = open_local_database()?;
    acknowledge_delegated_mls_copy_in(&connection, event_id, recipient_device, unix_time_now()?)
}

fn acknowledge_delegated_mls_copy_in(
    connection: &Connection,
    event_id: [u8; 16],
    recipient_device: [u8; 32],
    now: i64,
) -> Result<bool, String> {
    connection
        .execute(
            "UPDATE local_delegated_mls_copies
             SET delivery_state = 'expired', ciphertext = NULL
             WHERE event_id = ?1 AND recipient_device = ?2
               AND delivery_state = 'queued' AND expires_at_unix <= ?3",
            params![event_id.as_slice(), recipient_device.as_slice(), now],
        )
        .map_err(|error| format!("could not expire acknowledged MLS copy: {error}"))?;
    cleanup_delegated_mls_tombstones(connection, now)?;
    let changed = connection
        .execute(
            "UPDATE local_delegated_mls_copies
             SET delivery_state = 'received_by_device', ciphertext = NULL
             WHERE event_id = ?1 AND recipient_device = ?2
               AND delivery_state = 'queued' AND expires_at_unix > ?3",
            params![event_id.as_slice(), recipient_device.as_slice(), now],
        )
        .map_err(|error| format!("could not acknowledge delegated MLS copy: {error}"))?;
    Ok(changed == 1)
}

fn cleanup_delegated_mls_tombstones(connection: &Connection, now: i64) -> Result<usize, String> {
    connection
        .execute(
            "DELETE FROM local_delegated_mls_copies
             WHERE delivery_state != 'queued' AND expires_at_unix <= ?1",
            [now.saturating_sub(MAX_DELEGATED_TTL_SECONDS)],
        )
        .map_err(|error| format!("could not clean up delegated MLS tombstones: {error}"))
}

fn validate_delegated_copy_grant(
    grant: &DelegatedMlsCopyGrant,
    event: &EncryptedEvent,
    authenticated_author: [u8; 32],
    now: i64,
) -> Result<(), String> {
    if authenticated_author != grant.author_device
        || grant.event_id.iter().all(|byte| *byte == 0)
        || grant.author_device.iter().all(|byte| *byte == 0)
        || grant.recipient_device.iter().all(|byte| *byte == 0)
        || event.author_device != grant.author_device
        || event.event_id != grant.event_id
        || event.group_id.as_slice() != grant.group_id
        || event.epoch != grant.epoch
        || event.expires_at_unix != grant.expires_at_unix
        || event.checkpoint != grant.checkpoint
        || event.ciphertext.is_empty()
        || event.ciphertext.len() > MAX_DELEGATED_COPY_BYTES
        || grant.expires_at_unix <= now
        || grant.expires_at_unix > now.saturating_add(MAX_DELEGATED_TTL_SECONDS)
        || grant.epoch > i64::MAX as u64
        || grant
            .checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.len() > MAX_DELEGATED_CHECKPOINT_BYTES)
        || blake3::hash(&event.ciphertext).as_bytes() != &grant.ciphertext_digest
    {
        return Err("delegated MLS copy grant does not match a valid event".to_owned());
    }
    let verifying_key = VerifyingKey::from_bytes(&grant.author_device)
        .map_err(|_| "delegated MLS copy author key is invalid".to_owned())?;
    let signature = Signature::from_bytes(&grant.signature);
    verifying_key
        .verify_strict(&delegated_copy_signature_payload(grant), &signature)
        .map_err(|_| "delegated MLS copy authorization signature is invalid".to_owned())
}

fn delegated_copy_signature_payload(grant: &DelegatedMlsCopyGrant) -> Vec<u8> {
    let checkpoint = grant.checkpoint.as_deref().unwrap_or_default();
    let mut payload = Vec::with_capacity(160 + checkpoint.len());
    payload.extend_from_slice(b"slouching/delegated-mls-copy/v1");
    payload.extend_from_slice(&grant.event_id);
    payload.extend_from_slice(&grant.author_device);
    payload.extend_from_slice(&grant.recipient_device);
    payload.extend_from_slice(&grant.group_id);
    payload.extend_from_slice(&grant.epoch.to_be_bytes());
    payload.extend_from_slice(&grant.expires_at_unix.to_be_bytes());
    payload.extend_from_slice(&(checkpoint.len() as u32).to_be_bytes());
    payload.extend_from_slice(checkpoint);
    payload.extend_from_slice(&grant.ciphertext_digest);
    payload
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
    add_mls_group_member_with_peer_in(
        &mut connection,
        group_id,
        serialized_key_package,
        &device_identity,
        None,
    )
}

/// Admits a KeyPackage only when its signed device binding matches the peer
/// authenticated by the active pinned transport session.
pub fn add_mls_group_member_from_peer(
    group_id: &[u8],
    serialized_key_package: &[u8],
    pinned_peer_device: [u8; 32],
) -> Result<AddedMlsMember, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    add_mls_group_member_with_peer_in(
        &mut connection,
        group_id,
        serialized_key_package,
        &device_identity,
        Some(pinned_peer_device),
    )
}

#[cfg(test)]
fn add_mls_group_member_in(
    connection: &mut Connection,
    group_id: &[u8],
    serialized_key_package: &[u8],
    device_identity: &SigningKey,
) -> Result<AddedMlsMember, String> {
    add_mls_group_member_with_peer_in(
        connection,
        group_id,
        serialized_key_package,
        device_identity,
        None,
    )
}

fn add_mls_group_member_with_peer_in(
    connection: &mut Connection,
    group_id: &[u8],
    serialized_key_package: &[u8],
    device_identity: &SigningKey,
    expected_invited_device: Option<[u8; 32]>,
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
    if expected_invited_device.is_some_and(|expected| expected != candidate_device) {
        return Err("KeyPackage device does not match the pinned peer".to_owned());
    }
    let committer_binding =
        create_or_load_mls_signing_key_binding_in(connection, ciphersuite, device_identity)?;

    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS member-add transaction: {error}"))?;
    let result = (|| {
        ensure_mls_group_not_quarantined(connection, group_id.as_slice())?;
        let predecessor_epoch: i64 = connection
            .query_row(
                "SELECT epoch FROM local_mls_groups WHERE group_id = ?1",
                [group_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| format!("could not load MLS snapshot epoch: {error}"))?;
        capture_mls_epoch_snapshot_in(connection, group_id.as_slice(), predecessor_epoch as u64)?;
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
            let predecessor_epoch = group.epoch().as_u64();
            let mut existing_devices = Vec::new();
            for member in group.members() {
                let binding =
                    MlsSigningKeyBinding::from_bytes(member.credential.serialized_content())
                        .ok_or_else(|| {
                            "existing MLS member has no device identity binding".to_owned()
                        })?;
                if !binding.verifies_mls_credential(
                    &binding.device_public_key,
                    ciphersuite.signature_algorithm() as u16,
                    member.signature_key.as_slice(),
                ) {
                    return Err("existing MLS member has an invalid device binding".to_owned());
                }
                if binding.device_public_key != device_public_key
                    && !existing_devices.contains(&binding.device_public_key)
                {
                    existing_devices.push(binding.device_public_key);
                }
            }
            let (commit, welcome, _) = group
                .add_members(&provider, &signer, &[package])
                .map_err(|error| format!("could not add MLS group member: {error:?}"))?;
            let commit_bytes = commit
                .tls_serialize_detached()
                .map_err(|error| format!("could not serialize MLS Commit: {error}"))?;
            group
                .merge_pending_commit(&provider)
                .map_err(|error| format!("could not persist MLS membership commit: {error:?}"))?;
            let commit_hash = *blake3::hash(&commit_bytes).as_bytes();
            let mut commit_event_id = [0; 16];
            commit_event_id.copy_from_slice(&commit_hash[..16]);
            let added = AddedMlsMember {
                group_id: group.group_id().to_vec(),
                epoch: group.epoch().as_u64(),
                commit_event_id,
                invited_device: candidate_device,
                commit: commit_bytes.clone(),
                welcome: welcome
                    .tls_serialize_detached()
                    .map_err(|error| format!("could not serialize MLS Welcome: {error}"))?,
                ratchet_tree: group
                    .export_ratchet_tree()
                    .tls_serialize_detached()
                    .map_err(|error| format!("could not serialize MLS ratchet tree: {error}"))?,
            };
            connection
                .execute(
                    "INSERT INTO local_mls_commits
                        (event_id, group_id, predecessor_epoch, epoch, author_device,
                         commit_hash, commit_bytes, delivery_state)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued')",
                    params![
                        commit_event_id.as_slice(),
                        group.group_id().as_slice(),
                        predecessor_epoch as i64,
                        group.epoch().as_u64() as i64,
                        device_public_key.as_slice(),
                        commit_hash.as_slice(),
                        commit_bytes
                    ],
                )
                .map_err(|error| {
                    format!("could not persist MLS Commit in the local outbox: {error}")
                })?;
            let welcome_event_id = mls_welcome_event_id(&added.welcome, &added.ratchet_tree);
            connection
                .execute(
                    "INSERT INTO local_mls_welcome_outbox
                        (event_id, group_id, commit_event_id, invitee_device,
                         welcome_bytes, ratchet_tree, delivery_state)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued')",
                    params![
                        welcome_event_id.as_slice(),
                        added.group_id.as_slice(),
                        added.commit_event_id.as_slice(),
                        added.invited_device.as_slice(),
                        added.welcome,
                        added.ratchet_tree
                    ],
                )
                .map_err(|error| format!("could not persist MLS Welcome outbox: {error}"))?;
            for existing_device in existing_devices {
                connection
                    .execute(
                        "INSERT INTO local_mls_commit_recipients
                            (commit_event_id, device_public_key, delivery_state)
                         VALUES (?1, ?2, 'queued')",
                        params![commit_event_id.as_slice(), existing_device.as_slice()],
                    )
                    .map_err(|error| format!("could not persist MLS Commit recipient: {error}"))?;
            }
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

/// Commits the authenticated proposal queue on the designated committer and
/// atomically records the new OpenMLS epoch and per-member delivery ledger.
pub fn commit_pending_mls_proposals(group_id: &[u8]) -> Result<StoredMlsCommit, String> {
    let proposals = list_pending_mls_proposals(group_id)?;
    let approved = proposals
        .into_iter()
        .filter(|proposal| proposal.approved)
        .map(|proposal| proposal.proposal_id)
        .collect::<Vec<_>>();
    commit_approved_mls_proposals(group_id, &approved)
}

pub fn commit_approved_mls_proposals(
    group_id: &[u8],
    proposal_ids: &[[u8; 16]],
) -> Result<StoredMlsCommit, String> {
    let entry = identity_key_entry()?;
    let secret = entry
        .get_secret()
        .map_err(|error| format!("could not load the device identity key: {error}"))?;
    let device_identity = signing_key_from_secret(secret)?;
    let mut connection = open_local_database()?;
    commit_pending_mls_proposals_in(&mut connection, group_id, proposal_ids, &device_identity)
}

fn commit_pending_mls_proposals_in(
    connection: &mut Connection,
    group_id: &[u8],
    proposal_ids: &[[u8; 16]],
    device_identity: &SigningKey,
) -> Result<StoredMlsCommit, String> {
    use openmls::prelude::tls_codec::Serialize as TlsCodecSerialize;

    if group_id.len() != 16 {
        return Err("MLS group ID must be 16 bytes".to_owned());
    }
    if proposal_ids.is_empty() {
        return Err("select at least one approved MLS proposal to commit".to_owned());
    }
    let device_public_key = device_identity.verifying_key().to_bytes();
    let (indexed_epoch, designated_committer): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT epoch, designated_committer_device FROM local_mls_groups WHERE group_id = ?1",
            [group_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("could not load MLS group policy: {error}"))?;
    if designated_committer.as_slice() != device_public_key {
        return Err("this device is not the designated MLS committer".to_owned());
    }
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS proposal Commit transaction: {error}"))?;
    let result = (|| {
        ensure_mls_group_not_quarantined(connection, group_id)?;
        let predecessor_epoch = u64::try_from(indexed_epoch)
            .map_err(|_| "MLS group has an invalid indexed epoch".to_owned())?;
        let mut approved_refs = Vec::with_capacity(proposal_ids.len());
        for proposal_id in proposal_ids {
            let proposal_ref: Vec<u8> = connection
                .query_row(
                    "SELECT proposal_ref FROM local_mls_proposals
                     WHERE group_id = ?1 AND epoch = ?2 AND proposal_id = ?3 AND decision = 1",
                    params![group_id, predecessor_epoch as i64, proposal_id.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|error| format!("approved MLS proposal is unavailable: {error}"))?;
            if proposal_ref.is_empty() {
                return Err("approved proposal predates individual review; receive it again before committing".to_owned());
            }
            approved_refs.push(proposal_ref);
        }
        capture_mls_epoch_snapshot_in(connection, group_id, predecessor_epoch)?;
        let (stored, recipients) = {
            let provider = LocalOpenMlsProvider::new(connection);
            let group_identifier = GroupId::from_slice(group_id);
            let mut group = MlsGroup::load(provider.storage(), &group_identifier)
                .map_err(|error| format!("could not load MLS group for Commit: {error}"))?
                .ok_or_else(|| "MLS group state is missing".to_owned())?;
            if group.epoch().as_u64() != predecessor_epoch {
                return Err("MLS group epoch disagrees with its local index".to_owned());
            }
            if !group.has_pending_proposals() {
                return Err("there are no authenticated MLS proposals to commit".to_owned());
            }
            let ciphersuite = group.ciphersuite();
            let own_leaf = group
                .own_leaf()
                .ok_or_else(|| "local MLS member leaf is missing".to_owned())?;
            let binding =
                MlsSigningKeyBinding::from_bytes(own_leaf.credential().serialized_content())
                    .ok_or_else(|| "MLS committer credential has no device binding".to_owned())?;
            if binding.device_public_key != device_public_key
                || !binding.verifies_mls_credential(
                    &device_public_key,
                    ciphersuite.signature_algorithm() as u16,
                    own_leaf.signature_key().as_slice(),
                )
            {
                return Err(
                    "MLS group is not bound to the designated committer identity".to_owned(),
                );
            }
            let signer = SignatureKeyPair::read(
                provider.storage(),
                &binding.mls_signing_public_key,
                ciphersuite.signature_algorithm(),
            )
            .ok_or_else(|| "MLS committer signing key material is missing".to_owned())?;
            let mut recipients = Vec::new();
            for member in group.members() {
                let binding =
                    MlsSigningKeyBinding::from_bytes(member.credential.serialized_content())
                        .ok_or_else(|| "MLS member has no device identity binding".to_owned())?;
                if !binding.verifies_mls_credential(
                    &binding.device_public_key,
                    ciphersuite.signature_algorithm() as u16,
                    member.signature_key.as_slice(),
                ) {
                    return Err("MLS member has an invalid device binding".to_owned());
                }
                if binding.device_public_key != device_public_key
                    && !recipients.contains(&binding.device_public_key)
                {
                    recipients.push(binding.device_public_key);
                }
            }
            let builder = group
                .commit_builder()
                .consume_proposal_store(true)
                .load_psks(provider.storage())
                .map_err(|error| format!("could not load MLS Commit PSKs: {error:?}"))?
                .build(provider.rand(), provider.crypto(), &signer, |queued| {
                    approved_refs
                        .iter()
                        .any(|reference| queued.proposal_reference_ref().as_slice() == reference)
                })
                .map_err(|error| format!("could not create proposal Commit: {error:?}"))?;
            let bundle = builder
                .stage_commit(&provider)
                .map_err(|error| format!("could not stage proposal Commit: {error:?}"))?;
            let (commit, _, _) = bundle.into_contents();
            let commit_bytes = commit
                .tls_serialize_detached()
                .map_err(|error| format!("could not serialize proposal Commit: {error}"))?;
            group
                .merge_pending_commit(&provider)
                .map_err(|error| format!("could not persist proposal Commit: {error:?}"))?;
            let commit_hash = *blake3::hash(&commit_bytes).as_bytes();
            let mut event_id = [0; 16];
            event_id.copy_from_slice(&commit_hash[..16]);
            (
                StoredMlsCommit {
                    event_id,
                    group_id: group_id.to_vec(),
                    predecessor_epoch,
                    epoch: group.epoch().as_u64(),
                    author_device: device_public_key,
                    commit_hash,
                    commit: commit_bytes,
                },
                recipients,
            )
        };
        if stored.epoch != predecessor_epoch.saturating_add(1) {
            return Err("proposal Commit did not advance exactly one epoch".to_owned());
        }
        connection
            .execute(
                "INSERT INTO local_mls_commits
                    (event_id, group_id, predecessor_epoch, epoch, author_device,
                     commit_hash, commit_bytes, delivery_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued')",
                params![
                    stored.event_id.as_slice(),
                    stored.group_id,
                    stored.predecessor_epoch as i64,
                    stored.epoch as i64,
                    stored.author_device.as_slice(),
                    stored.commit_hash.as_slice(),
                    stored.commit
                ],
            )
            .map_err(|error| format!("could not persist proposal Commit outbox: {error}"))?;
        for recipient in recipients {
            connection
                .execute(
                    "INSERT INTO local_mls_commit_recipients
                        (commit_event_id, device_public_key, delivery_state)
                     VALUES (?1, ?2, 'queued')",
                    params![stored.event_id.as_slice(), recipient.as_slice()],
                )
                .map_err(|error| format!("could not persist proposal Commit recipient: {error}"))?;
        }
        let updated = connection
            .execute(
                "UPDATE local_mls_groups SET epoch = ?1 WHERE group_id = ?2 AND epoch = ?3",
                params![stored.epoch as i64, group_id, predecessor_epoch as i64],
            )
            .map_err(|error| format!("could not update MLS proposal Commit epoch: {error}"))?;
        if updated != 1 {
            return Err("MLS group epoch changed while committing proposals".to_owned());
        }
        Ok(stored)
    })();
    finish_sql_transaction(connection, result, "MLS proposal Commit")
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
        None,
        None,
        None,
    )
}

pub fn join_mls_group_from_pinned_peer(
    serialized_welcome: &[u8],
    serialized_ratchet_tree: &[u8],
    expected_committer_device: [u8; 32],
    expected_group_id: [u8; 16],
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
        Some(expected_committer_device),
        Some(expected_group_id),
        None,
    )
}

pub fn join_mls_group_from_pinned_peer_event(
    event_id: [u8; 16],
    serialized_welcome: &[u8],
    serialized_ratchet_tree: &[u8],
    expected_committer_device: [u8; 32],
    expected_group_id: [u8; 16],
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
        Some(expected_committer_device),
        Some(expected_group_id),
        Some(event_id),
    )
}

fn join_mls_group_from_welcome_in(
    connection: &mut Connection,
    serialized_welcome: &[u8],
    serialized_ratchet_tree: &[u8],
    device_identity: &SigningKey,
    expected_committer_device: Option<[u8; 32]>,
    expected_group_id: Option<[u8; 16]>,
    expected_event_id: Option<[u8; 16]>,
) -> Result<JoinedMlsGroup, String> {
    use openmls::prelude::tls_codec::Deserialize as TlsCodecDeserialize;

    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| format!("could not begin MLS Welcome transaction: {error}"))?;
    let result = (|| {
        if let Some(event_id) = expected_event_id {
            if event_id != mls_welcome_event_id(serialized_welcome, serialized_ratchet_tree) {
                return Err("Welcome event ID does not match its payload".to_owned());
            }
            let receipt: Option<StoredMlsWelcomeReceiptRow> = connection
                .query_row(
                    "SELECT group_id, committer_device, invitee_device, epoch
                     FROM local_mls_welcome_receipts WHERE event_id = ?1",
                    [event_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|error| format!("could not query MLS Welcome receipt: {error}"))?;
            if let Some((group_id, committer, invitee, epoch)) = receipt {
                let local_device = device_identity.verifying_key().to_bytes();
                let group_id = fixed_bytes::<16>(group_id, "MLS Welcome receipt group")?;
                let committer = fixed_bytes::<32>(committer, "MLS Welcome receipt committer")?;
                let invitee = fixed_bytes::<32>(invitee, "MLS Welcome receipt invitee")?;
                if Some(group_id) != expected_group_id
                    || Some(committer) != expected_committer_device
                    || invitee != local_device
                {
                    return Err("duplicate Welcome event does not match its original pins".into());
                }
                let ciphersuite: u16 = connection
                    .query_row(
                        "SELECT ciphersuite FROM local_mls_groups WHERE group_id = ?1",
                        [group_id.as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|error| format!("could not load joined MLS group: {error}"))?;
                return Ok(JoinedMlsGroup {
                    group_id: group_id.to_vec(),
                    ciphersuite,
                    epoch: u64::try_from(epoch)
                        .map_err(|_| "MLS Welcome receipt has invalid epoch".to_owned())?,
                    designated_committer_device: committer,
                });
            }
        }
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
            if expected_committer_device
                .is_some_and(|expected| sender_binding.device_public_key != expected)
            {
                return Err("Welcome sender does not match the pinned committer device".to_owned());
            }
            let group = staged
                .into_group(&provider)
                .map_err(|error| format!("could not persist joined MLS group: {error:?}"))?;
            if expected_group_id.is_some_and(|expected| group.group_id().as_slice() != expected) {
                return Err("Welcome MLS group ID does not match its transport envelope".to_owned());
            }
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
        capture_mls_epoch_snapshot_in(connection, &joined.group_id, joined.epoch)?;
        if let Some(event_id) = expected_event_id {
            connection
                .execute(
                    "INSERT INTO local_mls_welcome_receipts
                        (event_id, group_id, committer_device, invitee_device, epoch)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        event_id.as_slice(),
                        joined.group_id.as_slice(),
                        joined.designated_committer_device.as_slice(),
                        device_identity.verifying_key().to_bytes().as_slice(),
                        joined.epoch as i64
                    ],
                )
                .map_err(|error| format!("could not persist MLS Welcome receipt: {error}"))?;
        }
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

fn capture_mls_epoch_snapshot_in(
    connection: &Connection,
    group_id: &[u8],
    epoch: u64,
) -> Result<(), String> {
    if group_id.len() != 16 || epoch > i64::MAX as u64 {
        return Err("MLS epoch snapshot has an invalid group or epoch".to_owned());
    }
    // openmls_sqlite_storage encodes storage keys through its configured Codec.
    // GroupId is serialized as a JSON object, unlike the raw ID used by our index.
    let storage_group_id = serde_json::to_vec(&GroupId::from_slice(group_id))
        .map_err(|error| format!("could not encode MLS storage group ID: {error}"))?;
    let group_data = {
        let mut statement = connection
            .prepare(
                "SELECT provider_version, data_type, group_data
                 FROM openmls_group_data WHERE group_id = ?1 ORDER BY data_type",
            )
            .map_err(|error| format!("could not prepare MLS group snapshot: {error}"))?;
        statement
            .query_map([&storage_group_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| format!("could not read MLS group snapshot: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("could not read MLS group snapshot row: {error}"))?
    };
    if group_data.is_empty() {
        return Err("MLS group snapshot has no OpenMLS group data".to_owned());
    }
    let epoch_key_pairs = {
        let mut statement = connection
            .prepare(
                "SELECT provider_version, epoch_id, leaf_index, key_pairs
                 FROM openmls_epoch_keys_pairs WHERE group_id = ?1
                 ORDER BY epoch_id, leaf_index",
            )
            .map_err(|error| format!("could not prepare MLS epoch-key snapshot: {error}"))?;
        statement
            .query_map([&storage_group_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|error| format!("could not read MLS epoch-key snapshot: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("could not read MLS epoch-key snapshot row: {error}"))?
    };
    let own_leaf_nodes = {
        let mut statement = connection
            .prepare(
                "SELECT provider_version, leaf_node
                 FROM openmls_own_leaf_nodes WHERE group_id = ?1 ORDER BY id",
            )
            .map_err(|error| format!("could not prepare MLS own-leaf snapshot: {error}"))?;
        statement
            .query_map([&storage_group_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|error| format!("could not read MLS own-leaf snapshot: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("could not read MLS own-leaf snapshot row: {error}"))?
    };
    let proposals = {
        let mut statement = connection
            .prepare(
                "SELECT provider_version, proposal_ref, proposal
                 FROM openmls_proposals WHERE group_id = ?1 ORDER BY proposal_ref",
            )
            .map_err(|error| format!("could not prepare MLS proposal snapshot: {error}"))?;
        statement
            .query_map([&storage_group_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| format!("could not read MLS proposal snapshot: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("could not read MLS proposal snapshot row: {error}"))?
    };
    let snapshot = serde_json::to_vec(&MlsEpochSnapshot {
        group_data,
        epoch_key_pairs,
        own_leaf_nodes,
        proposals,
    })
    .map_err(|error| format!("could not encode MLS epoch snapshot: {error}"))?;
    let snapshot_hash = blake3::hash(&snapshot);
    connection
        .execute(
            "INSERT OR REPLACE INTO local_mls_epoch_snapshots
                (group_id, epoch, snapshot, snapshot_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                group_id,
                epoch as i64,
                snapshot,
                snapshot_hash.as_bytes().as_slice()
            ],
        )
        .map_err(|error| format!("could not persist MLS epoch snapshot: {error}"))?;
    Ok(())
}

fn ensure_mls_group_not_quarantined(
    connection: &Connection,
    group_id: &[u8],
) -> Result<(), String> {
    let quarantined: Option<i64> = connection
        .query_row(
            "SELECT quarantined FROM local_mls_groups WHERE group_id = ?1",
            [group_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("could not check MLS quarantine state: {error}"))?;
    match quarantined {
        Some(0) => Ok(()),
        Some(_) => {
            Err("MLS group is quarantined after authenticated committer equivocation".to_owned())
        }
        None => Err("MLS group is not present on this device".to_owned()),
    }
}

fn restore_mls_epoch_snapshot_in(
    connection: &Connection,
    group_id: &[u8],
    epoch: u64,
) -> Result<(), String> {
    let storage_group_id = serde_json::to_vec(&GroupId::from_slice(group_id))
        .map_err(|error| format!("could not encode MLS storage group ID: {error}"))?;
    let (snapshot_bytes, expected_hash): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT snapshot, snapshot_hash FROM local_mls_epoch_snapshots
             WHERE group_id = ?1 AND epoch = ?2",
            params![group_id, epoch as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| format!("could not load historical MLS epoch snapshot: {error}"))?;
    if expected_hash.as_slice() != blake3::hash(&snapshot_bytes).as_bytes() {
        return Err("historical MLS epoch snapshot failed its digest check".to_owned());
    }
    let snapshot: MlsEpochSnapshot = serde_json::from_slice(&snapshot_bytes)
        .map_err(|error| format!("historical MLS epoch snapshot is invalid: {error}"))?;
    connection
        .execute(
            "DELETE FROM openmls_group_data WHERE group_id = ?1",
            [&storage_group_id],
        )
        .map_err(|error| format!("could not restore historical MLS group data: {error}"))?;
    for (provider_version, data_type, group_data) in snapshot.group_data {
        connection
            .execute(
                "INSERT INTO openmls_group_data
                    (provider_version, group_id, data_type, group_data)
                 VALUES (?1, ?2, ?3, ?4)",
                params![provider_version, &storage_group_id, data_type, group_data],
            )
            .map_err(|error| format!("could not restore historical MLS group data row: {error}"))?;
    }
    connection
        .execute(
            "DELETE FROM openmls_epoch_keys_pairs WHERE group_id = ?1",
            [&storage_group_id],
        )
        .map_err(|error| format!("could not restore historical MLS epoch keys: {error}"))?;
    for (provider_version, epoch_id, leaf_index, key_pairs) in snapshot.epoch_key_pairs {
        connection
            .execute(
                "INSERT INTO openmls_epoch_keys_pairs
                    (provider_version, group_id, epoch_id, leaf_index, key_pairs)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    provider_version,
                    &storage_group_id,
                    epoch_id,
                    leaf_index,
                    key_pairs
                ],
            )
            .map_err(|error| format!("could not restore historical MLS epoch-key row: {error}"))?;
    }
    connection
        .execute(
            "DELETE FROM openmls_own_leaf_nodes WHERE group_id = ?1",
            [&storage_group_id],
        )
        .map_err(|error| format!("could not restore historical MLS own leaves: {error}"))?;
    for (provider_version, leaf_node) in snapshot.own_leaf_nodes {
        connection
            .execute(
                "INSERT INTO openmls_own_leaf_nodes (provider_version, group_id, leaf_node)
                 VALUES (?1, ?2, ?3)",
                params![provider_version, &storage_group_id, leaf_node],
            )
            .map_err(|error| format!("could not restore historical MLS own-leaf row: {error}"))?;
    }
    connection
        .execute(
            "DELETE FROM openmls_proposals WHERE group_id = ?1",
            [&storage_group_id],
        )
        .map_err(|error| format!("could not restore historical MLS proposals: {error}"))?;
    for (provider_version, proposal_ref, proposal) in snapshot.proposals {
        connection
            .execute(
                "INSERT INTO openmls_proposals
                    (provider_version, group_id, proposal_ref, proposal)
                 VALUES (?1, ?2, ?3, ?4)",
                params![provider_version, &storage_group_id, proposal_ref, proposal],
            )
            .map_err(|error| format!("could not restore historical MLS proposal row: {error}"))?;
    }
    Ok(())
}

fn authenticate_mls_commit_from_epoch_snapshot(
    connection: &mut Connection,
    group_id: &[u8],
    predecessor_epoch: u64,
    commit_bytes: &[u8],
    device_identity: &SigningKey,
    designated_committer: &[u8],
) -> Result<[u8; 32], String> {
    use openmls::prelude::{
        ProcessedMessageContent, tls_codec::Deserialize as TlsCodecDeserialize,
    };

    connection
        .execute_batch("SAVEPOINT verify_mls_equivocation")
        .map_err(|error| {
            format!("could not open historical MLS verification savepoint: {error}")
        })?;
    let validation = (|| {
        restore_mls_epoch_snapshot_in(connection, group_id, predecessor_epoch)?;
        let protocol_message = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(|error| format!("invalid conflicting MLS Commit: {error}"))?
            .try_into_protocol_message()
            .map_err(|error| {
                format!("conflicting MLS message is not a protocol message: {error}")
            })?;
        if protocol_message.group_id().as_slice() != group_id
            || protocol_message.epoch().as_u64() != predecessor_epoch
        {
            return Err("conflicting Commit does not match its historical group epoch".to_owned());
        }
        let author_device = {
            let provider = LocalOpenMlsProvider::new(connection);
            let group_identifier = GroupId::from_slice(group_id);
            let mut group = MlsGroup::load(provider.storage(), &group_identifier)
                .map_err(|error| format!("could not load historical MLS group: {error}"))?
                .ok_or_else(|| "historical MLS group snapshot is incomplete".to_owned())?;
            if group.epoch().as_u64() != predecessor_epoch {
                return Err("historical MLS group snapshot has the wrong epoch".to_owned());
            }
            let own_leaf = group
                .own_leaf()
                .ok_or_else(|| "historical MLS local leaf is missing".to_owned())?;
            let own_binding =
                MlsSigningKeyBinding::from_bytes(own_leaf.credential().serialized_content())
                    .ok_or_else(|| {
                        "historical local credential has no device binding".to_owned()
                    })?;
            if own_binding.device_public_key != device_identity.verifying_key().to_bytes()
                || !own_binding.verifies_mls_credential(
                    &own_binding.device_public_key,
                    group.ciphersuite().signature_algorithm() as u16,
                    own_leaf.signature_key().as_slice(),
                )
            {
                return Err("historical MLS group is not bound to this device".to_owned());
            }
            let processed = group
                .process_message(&provider, protocol_message)
                .map_err(|error| format!("conflicting Commit signature is invalid: {error:?}"))?;
            let sender_binding =
                MlsSigningKeyBinding::from_bytes(processed.credential().serialized_content())
                    .ok_or_else(|| "conflicting Commit has no device-bound author".to_owned())?;
            let sender = group
                .members()
                .find(|member| {
                    member.credential.serialized_content()
                        == processed.credential().serialized_content()
                })
                .ok_or_else(|| "conflicting Commit author is not a historical member".to_owned())?;
            let author_device = sender_binding.device_public_key;
            if author_device.as_slice() != designated_committer
                || !sender_binding.verifies_mls_credential(
                    &author_device,
                    group.ciphersuite().signature_algorithm() as u16,
                    sender.signature_key.as_slice(),
                )
            {
                return Err(
                    "conflicting Commit is not signed by the bound designated committer".to_owned(),
                );
            }
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged)
                    if staged.epoch().as_u64() == predecessor_epoch.saturating_add(1) => {}
                ProcessedMessageContent::StagedCommitMessage(_) => {
                    return Err("conflicting Commit does not advance one epoch".to_owned());
                }
                _ => return Err("conflicting MLS message is not a Commit".to_owned()),
            }
            author_device
        };
        Ok(author_device)
    })();
    let rollback = connection
        .execute_batch("ROLLBACK TO verify_mls_equivocation; RELEASE verify_mls_equivocation;");
    match (validation, rollback) {
        (Ok(author), Ok(())) => Ok(author),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(format!(
            "could not restore active MLS state after verification: {error}"
        )),
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
        capture_mls_epoch_snapshot_in(connection, &group_id, created_group.epoch)?;
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
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|error| format!("could not configure local database lock wait: {error}"))?;
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
    if version < 7 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_messages (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
                     direction TEXT NOT NULL CHECK (direction IN ('sent', 'received')),
                     text TEXT NOT NULL CHECK (length(CAST(text AS BLOB)) BETWEEN 1 AND 16384)
                 );
                 CREATE INDEX local_mls_messages_by_group
                     ON local_mls_messages (group_id, sequence);
                 PRAGMA user_version = 7;",
            )
            .map_err(|error| format!("could not create encrypted MLS message history: {error}"))?;
    }
    if version < 8 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_commits (
                     event_id BLOB PRIMARY KEY NOT NULL CHECK (length(event_id) = 16),
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     predecessor_epoch INTEGER NOT NULL CHECK (predecessor_epoch >= 0),
                     epoch INTEGER NOT NULL CHECK (epoch = predecessor_epoch + 1),
                     author_device BLOB NOT NULL CHECK (length(author_device) = 32),
                     commit_hash BLOB NOT NULL CHECK (length(commit_hash) = 32),
                     commit_bytes BLOB NOT NULL CHECK (length(commit_bytes) > 0),
                     delivery_state TEXT NOT NULL DEFAULT 'queued'
                         CHECK (delivery_state IN ('queued', 'held_by_peer'))
                 );
                 CREATE INDEX local_mls_commits_by_group
                     ON local_mls_commits (group_id, predecessor_epoch, epoch);
                 PRAGMA user_version = 8;",
            )
            .map_err(|error| format!("could not create durable MLS Commit outbox: {error}"))?;
    }
    if version < 9 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_inbound_commits (
                     event_id BLOB PRIMARY KEY NOT NULL CHECK (length(event_id) = 16),
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     predecessor_epoch INTEGER NOT NULL CHECK (predecessor_epoch >= 0),
                     epoch INTEGER NOT NULL CHECK (epoch = predecessor_epoch + 1),
                     author_device BLOB NOT NULL CHECK (length(author_device) = 32),
                     commit_hash BLOB NOT NULL CHECK (length(commit_hash) = 32),
                     commit_bytes BLOB NOT NULL CHECK (length(commit_bytes) > 0),
                     UNIQUE(group_id, predecessor_epoch)
                 );
                 PRAGMA user_version = 9;",
            )
            .map_err(|error| format!("could not create inbound MLS Commit journal: {error}"))?;
    }
    if version < 10 {
        transaction
            .execute_batch(
                "UPDATE local_mls_commits
                 SET event_id = substr(commit_hash, 1, 16);
                 CREATE TABLE local_mls_commit_recipients (
                     commit_event_id BLOB NOT NULL CHECK (length(commit_event_id) = 16),
                     device_public_key BLOB NOT NULL CHECK (length(device_public_key) = 32),
                     delivery_state TEXT NOT NULL DEFAULT 'queued'
                         CHECK (delivery_state IN ('queued', 'delivered')),
                     delivered_at INTEGER,
                     PRIMARY KEY (commit_event_id, device_public_key)
                 );
                 CREATE INDEX local_mls_commit_recipients_by_device
                     ON local_mls_commit_recipients (device_public_key, delivery_state);
                 PRAGMA user_version = 10;",
            )
            .map_err(|error| format!("could not create MLS Commit recipient ledger: {error}"))?;
    }
    if version < 11 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_epoch_snapshots (
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     epoch INTEGER NOT NULL CHECK (epoch >= 0),
                     snapshot BLOB NOT NULL CHECK (length(snapshot) > 0),
                     snapshot_hash BLOB NOT NULL CHECK (length(snapshot_hash) = 32),
                     PRIMARY KEY (group_id, epoch)
                 );
                 ALTER TABLE local_mls_groups
                     ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0
                     CHECK (quarantined IN (0, 1));
                 ALTER TABLE local_mls_groups
                     ADD COLUMN quarantine_reason TEXT;
                 CREATE TABLE local_mls_equivocations (
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     predecessor_epoch INTEGER NOT NULL CHECK (predecessor_epoch >= 0),
                     accepted_event_id BLOB NOT NULL CHECK (length(accepted_event_id) = 16),
                     accepted_hash BLOB NOT NULL CHECK (length(accepted_hash) = 32),
                     accepted_bytes BLOB NOT NULL CHECK (length(accepted_bytes) > 0),
                     conflicting_event_id BLOB NOT NULL CHECK (length(conflicting_event_id) = 16),
                     conflicting_hash BLOB NOT NULL CHECK (length(conflicting_hash) = 32),
                     conflicting_bytes BLOB NOT NULL CHECK (length(conflicting_bytes) > 0),
                     author_device BLOB NOT NULL CHECK (length(author_device) = 32),
                     PRIMARY KEY (group_id, predecessor_epoch)
                 );
                 PRAGMA user_version = 11;",
            )
            .map_err(|error| {
                format!("could not create MLS epoch snapshots and quarantine ledger: {error}")
            })?;
    }
    if version < 12 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_proposals (
                     proposal_id BLOB PRIMARY KEY NOT NULL CHECK (length(proposal_id) = 16),
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     epoch INTEGER NOT NULL CHECK (epoch >= 0),
                     author_device BLOB NOT NULL CHECK (length(author_device) = 32),
                     proposal_hash BLOB NOT NULL CHECK (length(proposal_hash) = 32),
                     proposal_bytes BLOB NOT NULL CHECK (length(proposal_bytes) > 0)
                 );
                 CREATE INDEX local_mls_proposals_by_group
                     ON local_mls_proposals (group_id, epoch);
                 PRAGMA user_version = 12;",
            )
            .map_err(|error| format!("could not create encrypted MLS proposal journal: {error}"))?;
    }
    if version < 13 {
        transaction
            .execute_batch(
                "CREATE TABLE local_peer_routes (
                     device_public_key BLOB PRIMARY KEY NOT NULL
                         CHECK (length(device_public_key) = 32),
                     socket_address TEXT NOT NULL
                         CHECK (length(socket_address) BETWEEN 1 AND 128)
                 );
                 PRAGMA user_version = 13;",
            )
            .map_err(|error| format!("could not create encrypted peer route book: {error}"))?;
    }
    if version < 14 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_welcome_outbox (
                     event_id BLOB PRIMARY KEY NOT NULL CHECK (length(event_id) = 16),
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     commit_event_id BLOB NOT NULL CHECK (length(commit_event_id) = 16),
                     invitee_device BLOB NOT NULL CHECK (length(invitee_device) = 32),
                     welcome_bytes BLOB NOT NULL CHECK (length(welcome_bytes) > 0),
                     ratchet_tree BLOB NOT NULL CHECK (length(ratchet_tree) > 0),
                     delivery_state TEXT NOT NULL DEFAULT 'queued'
                         CHECK (delivery_state IN ('queued', 'delivered')),
                     delivered_at INTEGER,
                     UNIQUE(commit_event_id, invitee_device)
                 );
                 CREATE INDEX local_mls_welcomes_by_recipient
                     ON local_mls_welcome_outbox(group_id, invitee_device, delivery_state);
                 CREATE TABLE local_mls_welcome_receipts (
                     event_id BLOB PRIMARY KEY NOT NULL CHECK (length(event_id) = 16),
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     committer_device BLOB NOT NULL CHECK (length(committer_device) = 32),
                     invitee_device BLOB NOT NULL CHECK (length(invitee_device) = 32),
                     epoch INTEGER NOT NULL CHECK (epoch >= 0)
                 );
                 PRAGMA user_version = 14;",
            )
            .map_err(|error| format!("could not create durable MLS Welcome outbox: {error}"))?;
    }
    if version < 15 {
        transaction
            .execute_batch(
                "CREATE TABLE local_mls_event_recipients (
                     event_id BLOB NOT NULL CHECK (length(event_id) = 16),
                     device_public_key BLOB NOT NULL CHECK (length(device_public_key) = 32),
                     delivery_state TEXT NOT NULL DEFAULT 'queued'
                         CHECK (delivery_state IN ('queued', 'delivered')),
                     delivered_at INTEGER,
                     PRIMARY KEY (event_id, device_public_key)
                 );
                 CREATE INDEX local_mls_event_recipients_by_peer
                     ON local_mls_event_recipients(device_public_key, delivery_state);
                 PRAGMA user_version = 15;",
            )
            .map_err(|error| format!("could not create MLS event recipient ledger: {error}"))?;
    }
    if version < 16 {
        transaction
            .execute_batch(
                "CREATE TABLE local_delegation_policy (
                     id INTEGER PRIMARY KEY CHECK (id = 1),
                     enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                     quota_bytes INTEGER NOT NULL CHECK (quota_bytes BETWEEN 0 AND 67108864)
                 );
                 INSERT INTO local_delegation_policy (id, enabled, quota_bytes)
                     VALUES (1, 0, 67108864);
                 CREATE TABLE local_delegated_mls_copies (
                     event_id BLOB NOT NULL CHECK (length(event_id) = 16),
                     recipient_device BLOB NOT NULL CHECK (length(recipient_device) = 32),
                     author_device BLOB NOT NULL CHECK (length(author_device) = 32),
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     epoch INTEGER NOT NULL CHECK (epoch >= 0),
                     checkpoint BLOB,
                     expires_at_unix INTEGER NOT NULL CHECK (expires_at_unix > 0),
                     ciphertext_digest BLOB NOT NULL CHECK (length(ciphertext_digest) = 32),
                     ciphertext BLOB,
                     grant_signature BLOB NOT NULL CHECK (length(grant_signature) = 64),
                     delivery_state TEXT NOT NULL CHECK (
                         delivery_state IN ('queued', 'received_by_device', 'expired')
                     ),
                     PRIMARY KEY (event_id, recipient_device),
                     CHECK (
                         (delivery_state = 'queued' AND ciphertext IS NOT NULL
                             AND length(ciphertext) BETWEEN 1 AND 32768)
                         OR (delivery_state != 'queued' AND ciphertext IS NULL)
                     )
                 );
                 CREATE INDEX local_delegated_mls_copies_by_recipient
                     ON local_delegated_mls_copies(recipient_device, delivery_state, expires_at_unix);
                 PRAGMA user_version = 16;",
            )
            .map_err(|error| format!("could not create delegated MLS copy storage: {error}"))?;
    }
    if version < 17 {
        transaction
            .execute_batch(
                "CREATE TABLE local_peer_relay_config (
                     id INTEGER PRIMARY KEY CHECK (id = 1),
                     relay_url TEXT NOT NULL CHECK (length(relay_url) <= 2048),
                     access_token TEXT NOT NULL CHECK (length(access_token) <= 512)
                 );
                 INSERT INTO local_peer_relay_config (id, relay_url, access_token)
                     VALUES (1, '', '');
                 PRAGMA user_version = 17;",
            )
            .map_err(|error| format!("could not create local relay settings: {error}"))?;
    }
    if version < 18 {
        transaction
            .execute_batch(
                "ALTER TABLE local_peer_routes
                     ADD COLUMN relay_only INTEGER NOT NULL DEFAULT 0
                         CHECK (relay_only IN (0, 1));
                 PRAGMA user_version = 18;",
            )
            .map_err(|error| {
                format!("could not add relay routes to the encrypted route book: {error}")
            })?;
    }
    if version < 19 {
        transaction
            .execute_batch(
                "ALTER TABLE local_mls_proposals
                     ADD COLUMN proposal_ref BLOB NOT NULL DEFAULT X'';
                 ALTER TABLE local_mls_proposals
                     ADD COLUMN decision INTEGER NOT NULL DEFAULT 0 CHECK (decision IN (0, 1, 2));
                 UPDATE local_mls_proposals SET decision = 2;
                 PRAGMA user_version = 19;",
            )
            .map_err(|error| format!("could not add MLS proposal review decisions: {error}"))?;
    }
    if version < 20 {
        transaction
            .execute_batch(
                "CREATE TABLE local_verified_peers (
                     device_public_key BLOB PRIMARY KEY NOT NULL
                         CHECK (length(device_public_key) = 32),
                     verified_at_unix INTEGER NOT NULL CHECK (verified_at_unix > 0)
                 );
                 PRAGMA user_version = 20;",
            )
            .map_err(|error| format!("could not add local verified peer storage: {error}"))?;
    }
    if version < 21 {
        transaction
            .execute_batch(
                "CREATE TABLE local_file_attachments (
                     transfer_id BLOB PRIMARY KEY NOT NULL CHECK (length(transfer_id) = 16),
                     group_id BLOB NOT NULL CHECK (length(group_id) = 16),
                     author_device BLOB NOT NULL CHECK (length(author_device) = 32),
                     ciphertext_hash BLOB NOT NULL CHECK (length(ciphertext_hash) = 32),
                     offer BLOB NOT NULL CHECK (length(offer) BETWEEN 69 AND 323),
                     created_at_unix INTEGER NOT NULL CHECK (created_at_unix > 0)
                 );
                 CREATE INDEX local_file_attachments_by_group
                     ON local_file_attachments (group_id, created_at_unix, transfer_id);
                 PRAGMA user_version = 21;",
            )
            .map_err(|error| {
                format!("could not create encrypted file attachment storage: {error}")
            })?;
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
    use crate::file_transfer::{FILE_CHUNK_PLAINTEXT_BYTES, FileTransferSecrets};
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
    fn pinned_peer_routes_persist_and_update_by_device_key() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-peer-routes-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let path = directory.join("profile.sqlite3");
        let key = [0x37; PROFILE_DB_KEY_LEN];
        let peer = [0x61; 32];
        let another_peer = [0x62; 32];
        let mut connection =
            open_database(&path, &key).expect("encrypted peer route database should initialize");

        save_peer_route_in(&mut connection, peer, "192.168.1.20:45873", false)
            .expect("first pinned peer route should persist");
        save_peer_route_in(&mut connection, peer, "192.168.1.21:45873", false)
            .expect("updated address should replace the prior route");
        save_peer_route_in(&mut connection, another_peer, "[fd00::2]:45874", false)
            .expect("IPv6 peer route should persist");
        let relay_peer = [0x63; 32];
        save_peer_route_in(&mut connection, relay_peer, "via group relay", true)
            .expect("relay-only peer route should persist");

        let routes = list_peer_routes_in(&connection).expect("pinned routes should reload");
        assert_eq!(routes.len(), 3);
        assert!(routes.iter().any(|route| {
            route.device_public_key == peer
                && route.address == "192.168.1.21:45873"
                && !route.relay_only
        }));
        assert!(routes.iter().any(|route| {
            route.device_public_key == another_peer
                && route.address == "[fd00::2]:45874"
                && !route.relay_only
        }));
        assert!(routes.iter().any(|route| {
            route.device_public_key == relay_peer
                && route.address == "via group relay"
                && route.relay_only
        }));
        drop(connection);
        fs::remove_dir_all(directory).expect("temporary peer route database should be removed");
    }

    #[test]
    fn out_of_band_peer_verification_is_key_scoped_and_persists() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-peer-verification-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let path = directory.join("profile.sqlite3");
        let mut connection = open_database(&path, &[0x76; 32])
            .expect("encrypted profile database should initialize");
        let verified_key = [0x77; 32];
        let changed_key = [0x78; 32];
        assert!(!peer_key_is_verified_in(&connection, verified_key).unwrap());
        set_peer_key_verified_in(&connection, verified_key, true).unwrap();
        assert!(peer_key_is_verified_in(&connection, verified_key).unwrap());
        assert!(!peer_key_is_verified_in(&connection, changed_key).unwrap());
        drop(connection);

        connection = open_database(&path, &[0x76; 32]).expect("profile should reopen");
        assert!(peer_key_is_verified_in(&connection, verified_key).unwrap());
        set_peer_key_verified_in(&connection, verified_key, false).unwrap();
        assert!(!peer_key_is_verified_in(&connection, verified_key).unwrap());
        connection
            .execute_batch(
                "DROP TABLE local_verified_peers;
                 DROP TABLE local_file_attachments;
                 PRAGMA user_version = 19;",
            )
            .expect("test should restore the previous schema version");
        drop(connection);
        connection = open_database(&path, &[0x76; 32])
            .expect("schema 19 should migrate to peer verification storage");
        assert!(!peer_key_is_verified_in(&connection, verified_key).unwrap());
        drop(connection);
        fs::remove_dir_all(directory).expect("temporary database files should be removed");
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
            let schema_version: u32 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("local profile schema version should be readable");
            assert_eq!(schema_version, PROFILE_SCHEMA_VERSION);
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
        let listed = list_mls_groups_in(&connection)
            .expect("local group picker should list persisted groups");
        assert_eq!(
            listed,
            vec![StoredMlsGroup {
                group_id: created
                    .group_id
                    .as_slice()
                    .try_into()
                    .expect("created group ID should be 16 bytes"),
                epoch: 0,
                quarantined: false,
            }]
        );

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
    fn designated_committer_persists_and_deduplicates_member_self_update_proposals() {
        use openmls::prelude::{Ciphersuite, GroupId, MlsGroup};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-mls-update-proposal-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let creator_identity = SigningKey::from_bytes(&[0x4a; 32]);
        let member_identity = SigningKey::from_bytes(&[0x4b; 32]);
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let mut creator = open_database(&directory.join("creator.sqlite3"), &[0x4c; 32])
            .expect("committer database should initialize");
        let group = create_mls_group_in(&mut creator, ciphersuite, &creator_identity)
            .expect("designated committer should create the group");
        let mut member = open_database(&directory.join("member.sqlite3"), &[0x4d; 32])
            .expect("member database should initialize");
        let package = create_mls_key_package_in(&mut member, ciphersuite, &member_identity)
            .expect("member should prepare a bound KeyPackage");
        let admission = add_mls_group_member_in(
            &mut creator,
            &group.group_id,
            &package.public_bytes,
            &creator_identity,
        )
        .expect("committer should admit the member");
        join_mls_group_from_welcome_in(
            &mut member,
            &admission.welcome,
            &admission.ratchet_tree,
            &member_identity,
            None,
            None,
            None,
        )
        .expect("member should join with its Welcome");

        let proposal =
            create_mls_self_update_proposal_in(&mut member, &group.group_id, &member_identity)
                .expect("member should create a self-update proposal");
        assert_eq!(proposal.epoch, 1);
        assert!(
            process_mls_self_update_proposal_with_author_in(
                &mut creator,
                &group.group_id,
                &proposal.proposal,
                &creator_identity,
                Some([0x99; 32]),
                Some(proposal.epoch),
            )
            .is_err()
        );
        assert_eq!(
            process_mls_self_update_proposal_with_author_in(
                &mut creator,
                &group.group_id,
                &proposal.proposal,
                &creator_identity,
                Some(member_identity.verifying_key().to_bytes()),
                Some(proposal.epoch),
            )
            .expect("designated committer should accept the signed update proposal"),
            ProcessedMlsProposal::Accepted { epoch: 1 }
        );
        assert_eq!(
            process_mls_self_update_proposal_in(
                &mut creator,
                &group.group_id,
                &proposal.proposal,
                &creator_identity,
            )
            .expect("exact proposal redelivery should be acknowledged idempotently"),
            ProcessedMlsProposal::Duplicate { epoch: 1 }
        );
        assert!(
            process_mls_self_update_proposal_in(
                &mut member,
                &group.group_id,
                &proposal.proposal,
                &member_identity,
            )
            .is_err()
        );
        let journal_rows: i64 = creator
            .query_row(
                "SELECT COUNT(*) FROM local_mls_proposals WHERE group_id = ?1",
                [&group.group_id],
                |row| row.get(0),
            )
            .expect("proposal journal should be queryable");
        assert_eq!(journal_rows, 1);
        let pending = list_pending_mls_proposals_in(&creator, &group.group_id)
            .expect("proposal review list should load the current epoch");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].epoch, proposal.epoch);
        assert_eq!(
            pending[0].author_device,
            member_identity.verifying_key().to_bytes()
        );
        assert!(!pending[0].approved);
        set_mls_proposal_approval_in(&creator, &group.group_id, pending[0].proposal_id, false)
            .expect("committer should be able to reject an authenticated proposal");
        assert!(
            commit_pending_mls_proposals_in(&mut creator, &group.group_id, &[], &creator_identity,)
                .is_err()
        );
        set_mls_proposal_approval_in(&creator, &group.group_id, pending[0].proposal_id, true)
            .expect("committer should be able to approve an authenticated proposal");
        creator
            .execute_batch(
                "CREATE TRIGGER force_proposal_commit_outbox_failure
                 BEFORE INSERT ON local_mls_commits
                 BEGIN SELECT RAISE(ABORT, 'simulated proposal outbox failure'); END;",
            )
            .expect("test should install a proposal Commit outbox failure");
        assert!(
            commit_pending_mls_proposals_in(
                &mut creator,
                &group.group_id,
                &[pending[0].proposal_id],
                &creator_identity,
            )
            .is_err()
        );
        {
            let provider = LocalOpenMlsProvider::new(&mut creator);
            let loaded = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group.group_id))
                .expect("proposal transaction rollback should leave group loadable")
                .expect("proposal transaction rollback should retain group state");
            assert_eq!(loaded.epoch().as_u64(), 1);
            assert!(loaded.has_pending_proposals());
        }
        creator
            .execute_batch("DROP TRIGGER force_proposal_commit_outbox_failure;")
            .expect("test should remove its proposal Commit failure trigger");
        let commit = commit_pending_mls_proposals_in(
            &mut creator,
            &group.group_id,
            &[pending[0].proposal_id],
            &creator_identity,
        )
        .expect("designated committer should atomically commit accepted proposals");
        assert_eq!(commit.predecessor_epoch, 1);
        assert_eq!(commit.epoch, 2);
        assert!(!commit.commit.is_empty());
        assert!(
            list_pending_mls_proposals_in(&creator, &group.group_id)
                .expect("committed proposal should leave the review queue")
                .is_empty()
        );
        assert_eq!(
            process_mls_self_update_proposal_in(
                &mut creator,
                &group.group_id,
                &proposal.proposal,
                &creator_identity,
            )
            .expect("redelivery after the group advanced should still be acknowledged"),
            ProcessedMlsProposal::Duplicate { epoch: 1 }
        );
        assert_eq!(
            process_inbound_mls_commit_in(
                &mut member,
                &group.group_id,
                &commit.commit,
                &member_identity,
            )
            .expect("member should authenticate and apply the proposal Commit"),
            ProcessedMlsCommit::Applied { epoch: 2 }
        );
        {
            let provider = LocalOpenMlsProvider::new(&mut creator);
            let loaded = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group.group_id))
                .expect("committer group should reload")
                .expect("committer group should persist");
            assert!(!loaded.has_pending_proposals());
            assert_eq!(loaded.epoch().as_u64(), 2);
        }
        drop(member);
        drop(creator);
        fs::remove_dir_all(directory).expect("temporary proposal databases should be removed");
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
        let invitee_public_key = invitee_identity.verifying_key().to_bytes();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let mut creator =
            open_database(&creator_path, &creator_key).expect("creator database should initialize");
        let group = create_mls_group_in(&mut creator, ciphersuite, &creator_identity)
            .expect("creator should create a local MLS group");

        let mut invitee =
            open_database(&invitee_path, &invitee_key).expect("invitee database should initialize");
        let package = create_mls_key_package_in(&mut invitee, ciphersuite, &invitee_identity)
            .expect("invitee should prepare a device-bound KeyPackage");
        creator
            .execute_batch(
                "CREATE TRIGGER force_mls_commit_outbox_failure
                 BEFORE INSERT ON local_mls_commits
                 BEGIN SELECT RAISE(ABORT, 'simulated outbox disk failure'); END;",
            )
            .expect("test should install a one-shot commit outbox failure");
        assert!(
            add_mls_group_member_in(
                &mut creator,
                &group.group_id,
                &package.public_bytes,
                &creator_identity,
            )
            .is_err()
        );
        let (rolled_back_epoch, rolled_back_members): (i64, usize) = {
            let provider = LocalOpenMlsProvider::new(&mut creator);
            let loaded = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group.group_id))
                .expect("group should reload after transaction rollback")
                .expect("original group should remain available");
            (loaded.epoch().as_u64() as i64, loaded.members().count())
        };
        let queued_after_rollback: i64 = creator
            .query_row(
                "SELECT COUNT(*) FROM local_mls_commits WHERE group_id = ?1",
                [&group.group_id],
                |row| row.get(0),
            )
            .expect("outbox should remain queryable after rollback");
        assert_eq!((rolled_back_epoch, rolled_back_members), (0, 1));
        assert_eq!(queued_after_rollback, 0);
        creator
            .execute_batch("DROP TRIGGER force_mls_commit_outbox_failure;")
            .expect("test should remove its failure trigger");
        let mismatched_pin = add_mls_group_member_with_peer_in(
            &mut creator,
            &group.group_id,
            &package.public_bytes,
            &creator_identity,
            Some([0xab; 32]),
        )
        .expect_err("KeyPackage from another device must not satisfy the pinned peer");
        assert!(mismatched_pin.contains("does not match the pinned peer"));
        let admission = add_mls_group_member_with_peer_in(
            &mut creator,
            &group.group_id,
            &package.public_bytes,
            &creator_identity,
            Some(invitee_public_key),
        )
        .expect("designated committer should add the valid KeyPackage");
        assert_eq!(admission.group_id, group.group_id);
        assert_eq!(admission.epoch, 1);
        assert_eq!(admission.invited_device, invitee_public_key);
        assert!(!admission.commit.is_empty());
        assert!(!admission.welcome.is_empty());
        let (stored_group, predecessor_epoch, stored_epoch): (Vec<u8>, i64, i64) = creator
            .query_row(
                "SELECT group_id, predecessor_epoch, epoch FROM local_mls_commits
                 WHERE event_id = ?1",
                [admission.commit_event_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("membership Commit row should persist");
        let (author, commit_hash, commit_bytes, state): (Vec<u8>, Vec<u8>, Vec<u8>, String) =
            creator
                .query_row(
                    "SELECT author_device, commit_hash, commit_bytes, delivery_state
                     FROM local_mls_commits WHERE event_id = ?1",
                    [admission.commit_event_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .expect("membership Commit payload and outbox state should persist");
        assert_eq!(stored_group, group.group_id);
        assert_eq!((predecessor_epoch, stored_epoch), (0, 1));
        assert_eq!(author, creator_public_key);
        assert_eq!(commit_hash, blake3::hash(&admission.commit).as_bytes());
        assert_eq!(commit_bytes, admission.commit);
        assert_eq!(state, "queued");
        let recovered_commits = list_queued_mls_commits_in(&creator, &group.group_id, 10)
            .expect("pending Commit should reload from its outbox");
        assert_eq!(recovered_commits.len(), 1);
        assert_eq!(recovered_commits[0].event_id, admission.commit_event_id);
        assert_eq!(recovered_commits[0].commit, admission.commit);
        assert_eq!(
            (
                recovered_commits[0].predecessor_epoch,
                recovered_commits[0].epoch
            ),
            (0, 1)
        );
        let queued_welcomes =
            list_queued_mls_welcomes_for_peer_in(&creator, &group.group_id, invitee_public_key)
                .expect("admission should persist a retryable Welcome");
        assert_eq!(queued_welcomes.len(), 1);
        assert_eq!(queued_welcomes[0].welcome, admission.welcome);
        assert_eq!(queued_welcomes[0].ratchet_tree, admission.ratchet_tree);
        assert_eq!(
            queued_welcomes[0].commit_event_id,
            admission.commit_event_id
        );
        mark_mls_welcome_delivered_in(&creator, queued_welcomes[0].event_id)
            .expect("durable Welcome ACK should clear the retry queue");
        mark_mls_welcome_delivered_in(&creator, queued_welcomes[0].event_id)
            .expect("duplicate Welcome ACK should be idempotent");
        assert!(
            list_queued_mls_welcomes_for_peer_in(&creator, &group.group_id, invitee_public_key)
                .expect("Welcome queue should remain queryable")
                .is_empty()
        );
        let wrong_committer = join_mls_group_from_welcome_in(
            &mut invitee,
            &admission.welcome,
            &admission.ratchet_tree,
            &invitee_identity,
            Some([0xabu8; 32]),
            Some(group.group_id.as_slice().try_into().unwrap()),
            None,
        )
        .expect_err("Welcome must match the direct session's pinned committer");
        assert!(wrong_committer.contains("pinned committer device"));
        let joined = join_mls_group_from_welcome_in(
            &mut invitee,
            &admission.welcome,
            &admission.ratchet_tree,
            &invitee_identity,
            Some(creator_public_key),
            Some(group.group_id.as_slice().try_into().unwrap()),
            Some(mls_welcome_event_id(
                &admission.welcome,
                &admission.ratchet_tree,
            )),
        )
        .expect("invitee should process Welcome using its stored KeyPackage bundle");
        assert_eq!(joined.group_id, group.group_id);
        assert_eq!(joined.ciphersuite, ciphersuite as u16);
        assert_eq!(joined.epoch, 1);
        let duplicate_join = join_mls_group_from_welcome_in(
            &mut invitee,
            &admission.welcome,
            &admission.ratchet_tree,
            &invitee_identity,
            Some(creator_public_key),
            Some(group.group_id.as_slice().try_into().unwrap()),
            Some(mls_welcome_event_id(
                &admission.welcome,
                &admission.ratchet_tree,
            )),
        )
        .expect("redelivered Welcome should return the previously joined group");
        assert_eq!(duplicate_join, joined);
        assert_eq!(joined.designated_committer_device, creator_public_key);
        assert!(
            list_queued_mls_commits_for_peer_in(
                &mut creator,
                &group.group_id,
                &invitee_identity.verifying_key().to_bytes(),
                10,
            )
            .expect("new invitee should have no predecessor-epoch Commit to receive")
            .is_empty()
        );
        assert!(
            list_queued_mls_commits_for_peer_in(&mut creator, &group.group_id, &[0x99; 32], 10,)
                .unwrap()
                .is_empty()
        );

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

        let another_path = directory.join("third.sqlite3");
        let another_key = [0x56; PROFILE_DB_KEY_LEN];
        let another_identity = SigningKey::from_bytes(&[0x55; 32]);
        let mut another_device = open_database(&another_path, &another_key)
            .expect("third device database should initialize");
        let another_package =
            create_mls_key_package_in(&mut another_device, ciphersuite, &another_identity)
                .expect("third device should prepare a KeyPackage");
        let creator_binding =
            create_or_load_mls_signing_key_binding_in(&mut creator, ciphersuite, &creator_identity)
                .expect("designated committer should have its bound MLS signer");
        let conflicting_commit = {
            use openmls::prelude::{
                KeyPackageIn,
                tls_codec::{Deserialize as TlsCodecDeserialize, Serialize as TlsCodecSerialize},
            };
            let provider = LocalOpenMlsProvider::new(&mut creator);
            let signer = SignatureKeyPair::read(
                provider.storage(),
                &creator_binding.mls_signing_public_key,
                ciphersuite.signature_algorithm(),
            )
            .expect("designated committer signing key should load");
            let key_package = KeyPackageIn::tls_deserialize_exact(&another_package.public_bytes)
                .expect("third device KeyPackage should decode")
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .expect("third device KeyPackage should validate");
            let mut fork =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&group.group_id))
                    .expect("current designated committer group should load")
                    .expect("current designated committer group should exist");
            let (commit, _, _) = fork
                .add_members(&provider, &signer, std::slice::from_ref(&key_package))
                .expect("committer should generate alternate valid Commit");
            let serialized = commit
                .tls_serialize_detached()
                .expect("alternate Commit should serialize");
            fork.clear_pending_commit(provider.storage())
                .expect("test should discard alternate local pending Commit");
            let (second_commit, _, _) = fork
                .add_members(&provider, &signer, &[key_package])
                .expect("committer should generate canonical Commit after clearing fork");
            let canonical = second_commit
                .tls_serialize_detached()
                .expect("canonical Commit should serialize");
            assert_ne!(serialized, canonical);
            // Keep the group at the predecessor epoch; the production admission below
            // generates a fresh canonical Commit using the same provider state.
            fork.clear_pending_commit(provider.storage())
                .expect("test should discard second locally staged Commit");
            serialized
        };
        let invitee_binding =
            create_or_load_mls_signing_key_binding_in(&mut invitee, ciphersuite, &invitee_identity)
                .expect("existing noncommitter should have a device-bound MLS signer");
        let noncommitter_commit = {
            use openmls::prelude::{
                KeyPackageIn,
                tls_codec::{Deserialize as TlsCodecDeserialize, Serialize as TlsCodecSerialize},
            };
            let provider = LocalOpenMlsProvider::new(&mut invitee);
            let signer = SignatureKeyPair::read(
                provider.storage(),
                &invitee_binding.mls_signing_public_key,
                ciphersuite.signature_algorithm(),
            )
            .expect("noncommitter MLS signing key should load");
            let key_package = KeyPackageIn::tls_deserialize_exact(&another_package.public_bytes)
                .expect("third device KeyPackage should decode")
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .expect("third device KeyPackage should validate");
            let mut group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&group.group_id))
                    .expect("existing member group should load")
                    .expect("existing member should have joined the group");
            let (commit, _, _) = group
                .add_members(&provider, &signer, &[key_package])
                .expect("test noncommitter can create a cryptographically valid Commit");
            commit
                .tls_serialize_detached()
                .expect("noncommitter Commit should serialize")
        };
        let rejected_noncommitter = process_inbound_mls_commit_in(
            &mut creator,
            &group.group_id,
            &noncommitter_commit,
            &creator_identity,
        )
        .expect_err("a valid MLS Commit from a non-designated member must be rejected");
        assert!(rejected_noncommitter.contains("designated committer"));
        {
            let provider = LocalOpenMlsProvider::new(&mut invitee);
            let mut local_group =
                MlsGroup::load(provider.storage(), &GroupId::from_slice(&group.group_id))
                    .expect("existing member group should reload")
                    .expect("existing member group should remain stored");
            local_group
                .clear_pending_commit(provider.storage())
                .expect("test should clear its intentionally forged local pending Commit");
        }
        creator
            .execute_batch(
                "CREATE TRIGGER force_mls_recipient_failure
                 BEFORE INSERT ON local_mls_commit_recipients
                 BEGIN SELECT RAISE(ABORT, 'simulated recipient ledger failure'); END;",
            )
            .expect("test should install a Commit recipient ledger failure");
        assert!(
            add_mls_group_member_in(
                &mut creator,
                &group.group_id,
                &another_package.public_bytes,
                &creator_identity,
            )
            .is_err()
        );
        let (epoch_after_recipient_failure, recipient_rows): (i64, i64) = creator
            .query_row(
                "SELECT (SELECT epoch FROM local_mls_groups WHERE group_id = ?1),
                        (SELECT COUNT(*) FROM local_mls_commit_recipients)",
                [&group.group_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("group and recipient ledger should remain queryable after rollback");
        assert_eq!((epoch_after_recipient_failure, recipient_rows), (1, 0));
        creator
            .execute_batch("DROP TRIGGER force_mls_recipient_failure;")
            .expect("test should remove recipient ledger failure");

        let second_admission = add_mls_group_member_in(
            &mut creator,
            &group.group_id,
            &another_package.public_bytes,
            &creator_identity,
        );
        assert_eq!(second_admission.as_ref().unwrap().epoch, 2);
        let second_admission = second_admission
            .expect("designated committer should generate the next membership Commit");
        assert_eq!(second_admission.epoch, 2);
        let invitee_queue = list_queued_mls_commits_for_peer_in(
            &mut creator,
            &group.group_id,
            &invitee_public_key,
            100,
        )
        .expect("peer fan-out query should find its queued membership Commit");
        assert_eq!(invitee_queue.len(), 1);
        assert_eq!(invitee_queue[0].event_id, second_admission.commit_event_id);
        assert_eq!(
            second_admission.commit_event_id.as_slice(),
            &blake3::hash(&second_admission.commit).as_bytes()[..16]
        );
        let fourth_identity = SigningKey::from_bytes(&[0x57; 32]);
        let mut fourth_device = open_database(
            &directory.join("fourth.sqlite3"),
            &[0x58; PROFILE_DB_KEY_LEN],
        )
        .expect("fourth device database should initialize");
        let fourth_package =
            create_mls_key_package_in(&mut fourth_device, ciphersuite, &fourth_identity)
                .expect("fourth device should prepare a KeyPackage");
        let third_admission = add_mls_group_member_in(
            &mut creator,
            &group.group_id,
            &fourth_package.public_bytes,
            &creator_identity,
        )
        .expect("designated committer should generate the following Commit");
        assert_eq!(third_admission.epoch, 3);
        let invitee_device = invitee_identity.verifying_key().to_bytes();
        let recipient_commits =
            list_queued_mls_commits_for_peer_in(&mut creator, &group.group_id, &invitee_device, 10)
                .expect("predecessor member should receive its eligible Commit chain");
        assert_eq!(recipient_commits.len(), 2);
        assert_eq!(
            recipient_commits[0].event_id,
            second_admission.commit_event_id
        );
        assert_eq!(
            recipient_commits[1].event_id,
            third_admission.commit_event_id
        );
        assert_eq!(recipient_commits[0].epoch, 2);
        assert_eq!(recipient_commits[1].epoch, 3);
        mark_mls_commit_delivered_in(
            &mut creator,
            second_admission.commit_event_id,
            invitee_device,
        )
        .expect("recipient ACK should persist in the delivery ledger");
        mark_mls_commit_delivered_in(
            &mut creator,
            second_admission.commit_event_id,
            invitee_device,
        )
        .expect("duplicate recipient ACK should be idempotent");
        drop(creator);
        let mut creator = open_database(&creator_path, &creator_key)
            .expect("recipient ACK ledger should survive an encrypted database reopen");
        let retryable_welcome = list_queued_mls_welcomes_for_peer_in(
            &creator,
            &group.group_id,
            second_admission.invited_device,
        )
        .expect("undelivered Welcome should survive an encrypted database reopen");
        assert_eq!(retryable_welcome.len(), 1);
        assert_eq!(
            retryable_welcome[0].commit_event_id,
            second_admission.commit_event_id
        );
        let recipient_status = list_mls_commit_recipient_status_in(&creator, &group.group_id, 20)
            .expect("per-device Commit delivery state should reload");
        let invitee_status: Vec<_> = recipient_status
            .iter()
            .filter(|status| status.device_public_key == invitee_device)
            .collect();
        assert_eq!(invitee_status.len(), 2);
        let delivered_status = recipient_status
            .iter()
            .find(|status| {
                status.event_id == second_admission.commit_event_id
                    && status.device_public_key == invitee_device
            })
            .expect("first Commit should remain visible in delivery history");
        assert_eq!(delivered_status.epoch, 2);
        assert_eq!(delivered_status.device_public_key, invitee_device);
        assert!(delivered_status.delivered);
        let queued_status = recipient_status
            .iter()
            .find(|status| {
                status.event_id == third_admission.commit_event_id
                    && status.device_public_key == invitee_device
            })
            .expect("next Commit should remain visible until its own ACK");
        assert_eq!(queued_status.epoch, 3);
        assert!(!queued_status.delivered);
        let next_commit =
            list_queued_mls_commits_for_peer_in(&mut creator, &group.group_id, &invitee_device, 10)
                .expect("unacknowledged next Commit should be available after database reopen");
        assert_eq!(next_commit.len(), 1);
        assert_eq!(next_commit[0].event_id, third_admission.commit_event_id);
        let recovered_predecessor =
            load_authorized_mls_commit_for_peer_in(&creator, &group.group_id, 1, &invitee_device)
                .expect("authorized predecessor should be recoverable after ACK and restart")
                .expect("recipient snapshot should authorize Commit recovery");
        assert_eq!(
            recovered_predecessor.event_id,
            second_admission.commit_event_id
        );
        assert_eq!(recovered_predecessor.commit, second_admission.commit);
        assert!(
            load_authorized_mls_commit_for_peer_in(
                &creator,
                &group.group_id,
                1,
                &another_identity.verifying_key().to_bytes(),
            )
            .expect("unauthorized peer lookup should not disclose data")
            .is_none()
        );
        assert!(
            mark_mls_commit_delivered_in(
                &mut creator,
                second_admission.commit_event_id,
                [0x99; 32],
            )
            .is_err()
        );
        let inbound_envelope = crate::peer::MlsCommitEnvelope {
            event_id: second_admission.commit_event_id,
            author_device: creator_public_key,
            group_id: group.group_id.clone(),
            predecessor_epoch: 1,
            epoch: 2,
            commit: second_admission.commit.clone(),
        };
        let mut wrong_epoch = inbound_envelope.clone();
        wrong_epoch.predecessor_epoch = 0;
        assert!(
            process_inbound_mls_commit_envelope_in(&mut invitee, &wrong_epoch, &invitee_identity,)
                .is_err()
        );
        let mut wrong_author = inbound_envelope.clone();
        wrong_author.author_device = [0xa7; 32];
        assert!(
            process_inbound_mls_commit_envelope_in(&mut invitee, &wrong_author, &invitee_identity,)
                .is_err()
        );
        let mut tampered_commit = second_admission.commit.clone();
        let last = tampered_commit
            .last_mut()
            .expect("serialized Commit should not be empty");
        *last ^= 1;
        assert!(
            process_inbound_mls_commit_in(
                &mut invitee,
                &group.group_id,
                &tampered_commit,
                &invitee_identity,
            )
            .is_err()
        );
        invitee
            .execute_batch(
                "CREATE TRIGGER force_inbound_commit_journal_failure
                 BEFORE INSERT ON local_mls_inbound_commits
                 BEGIN SELECT RAISE(ABORT, 'simulated inbound journal failure'); END;",
            )
            .expect("test should install an inbound Commit journal failure");
        assert!(
            process_inbound_mls_commit_envelope_in(
                &mut invitee,
                &inbound_envelope,
                &invitee_identity,
            )
            .is_err()
        );
        let epoch_after_failed_journal: i64 = invitee
            .query_row(
                "SELECT epoch FROM local_mls_groups WHERE group_id = ?1",
                [&group.group_id],
                |row| row.get(0),
            )
            .expect("local group epoch should remain queryable after rollback");
        assert_eq!(epoch_after_failed_journal, 1);
        invitee
            .execute_batch("DROP TRIGGER force_inbound_commit_journal_failure;")
            .expect("test should remove inbound journal failure");
        assert_eq!(
            process_inbound_mls_commit_in(
                &mut invitee,
                &group.group_id,
                &second_admission.commit,
                &invitee_identity,
            )
            .expect("existing member should authenticate and merge the committer's Commit"),
            ProcessedMlsCommit::Applied { epoch: 2 }
        );
        assert_eq!(
            process_inbound_mls_commit_in(
                &mut invitee,
                &group.group_id,
                &second_admission.commit,
                &invitee_identity,
            )
            .expect("exact Commit redelivery should be idempotent"),
            ProcessedMlsCommit::Duplicate { epoch: 2 }
        );
        let invitee_group_epoch: i64 = invitee
            .query_row(
                "SELECT epoch FROM local_mls_groups WHERE group_id = ?1",
                [&group.group_id],
                |row| row.get(0),
            )
            .expect("existing member's group index should advance with the Commit");
        assert_eq!(invitee_group_epoch, 2);

        let unauthorized = add_mls_group_member_in(
            &mut invitee,
            &group.group_id,
            &another_package.public_bytes,
            &invitee_identity,
        )
        .expect_err("a non-designated member must not create the group Commit");
        assert!(unauthorized.contains("designated MLS committer"));

        drop(invitee);
        let start = std::sync::Arc::new(std::sync::Barrier::new(3));
        let delivery_attempts = [
            (second_admission.commit.clone(), start.clone()),
            (conflicting_commit.clone(), start.clone()),
        ];
        let outcomes = delivery_attempts.map(|(commit, barrier)| {
            let path = invitee_path.clone();
            let group_id = group.group_id.clone();
            std::thread::spawn(move || {
                let mut connection = open_database(&path, &[0x52; PROFILE_DB_KEY_LEN])
                    .expect("concurrent delivery connection should open");
                barrier.wait();
                process_inbound_mls_commit_in(
                    &mut connection,
                    &group_id,
                    &commit,
                    &SigningKey::from_bytes(&[0x54; 32]),
                )
            })
        });
        start.wait();
        let outcomes = outcomes.map(|thread| {
            thread
                .join()
                .expect("concurrent Commit processing should not panic")
        });
        assert!(
            outcomes.iter().any(|outcome| matches!(
                outcome,
                Ok(ProcessedMlsCommit::EquivocationDetected {
                    predecessor_epoch: 1
                })
            )),
            "concurrent valid conflict must be authenticated and recorded"
        );
        assert!(
            outcomes.iter().all(|outcome| match outcome {
                Ok(ProcessedMlsCommit::Duplicate { epoch: 2 })
                | Ok(ProcessedMlsCommit::EquivocationDetected {
                    predecessor_epoch: 1,
                }) => true,
                Err(error) => error.contains("quarantined"),
                _ => false,
            }),
            "concurrent redelivery may be accepted before quarantine or rejected after it"
        );
        let mut invitee = open_database(&invitee_path, &invitee_key)
            .expect("concurrent quarantine database should reopen");
        let (quarantined, evidence_count, current_epoch): (i64, i64, i64) = invitee
            .query_row(
                "SELECT quarantined,
                        (SELECT COUNT(*) FROM local_mls_equivocations WHERE group_id = ?1),
                        epoch
                 FROM local_mls_groups WHERE group_id = ?1",
                [&group.group_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("quarantine and its evidence should persist");
        assert_eq!((quarantined, evidence_count, current_epoch), (1, 1, 2));
        assert!(
            create_mls_application_event_in(
                &mut invitee,
                &group.group_id,
                b"blocked after equivocation",
                1,
                &invitee_identity,
            )
            .is_err(),
            "quarantined groups must not create outbound application messages"
        );
        assert!(
            list_queued_mls_commits_in(&invitee, &group.group_id, 10)
                .expect_err("quarantined groups must not expose queued Commits")
                .contains("quarantined")
        );
        drop(invitee);
        let invitee = open_database(&invitee_path, &invitee_key)
            .expect("quarantined group database should reopen");
        let (persisted_reason, persisted_epoch): (Option<String>, i64) = invitee
            .query_row(
                "SELECT quarantine_reason, epoch FROM local_mls_groups
                 WHERE group_id = ?1 AND quarantined = 1",
                [&group.group_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("quarantine should survive database reopen");
        assert!(persisted_reason.is_some());
        assert_eq!(persisted_epoch, 2);
        assert_eq!(
            list_mls_groups_in(&invitee).expect("local group picker should reload quarantine"),
            vec![StoredMlsGroup {
                group_id: group
                    .group_id
                    .as_slice()
                    .try_into()
                    .expect("group ID should be 16 bytes"),
                epoch: 2,
                quarantined: true,
            }]
        );

        drop(another_device);
        drop(fourth_device);
        drop(invitee);
        drop(creator);
        fs::remove_dir_all(directory).expect("temporary database directory should be removed");
    }

    #[test]
    fn mls_application_event_encrypts_and_atomically_enters_retryable_outbox() {
        use openmls::prelude::Ciphersuite;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-mls-application-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let sender_identity = SigningKey::from_bytes(&[0x31; 32]);
        let receiver_identity = SigningKey::from_bytes(&[0x32; 32]);
        let mut sender = open_database(&directory.join("sender.sqlite3"), &[0x33; 32])
            .expect("sender database should initialize");
        let group = create_mls_group_in(&mut sender, suite, &sender_identity)
            .expect("sender should create MLS group");
        let mut receiver = open_database(&directory.join("receiver.sqlite3"), &[0x34; 32])
            .expect("receiver database should initialize");
        let package = create_mls_key_package_in(&mut receiver, suite, &receiver_identity)
            .expect("receiver should prepare its MLS KeyPackage");
        let admission = add_mls_group_member_in(
            &mut sender,
            &group.group_id,
            &package.public_bytes,
            &sender_identity,
        )
        .expect("sender should add receiver");
        join_mls_group_from_welcome_in(
            &mut receiver,
            &admission.welcome,
            &admission.ratchet_tree,
            &receiver_identity,
            None,
            None,
            None,
        )
        .expect("receiver should join group");
        let second_identity = SigningKey::from_bytes(&[0x35; 32]);
        let mut second_receiver =
            open_database(&directory.join("second-receiver.sqlite3"), &[0x36; 32])
                .expect("second receiver database should initialize");
        let second_package =
            create_mls_key_package_in(&mut second_receiver, suite, &second_identity)
                .expect("second receiver should prepare its KeyPackage");
        let second_admission = add_mls_group_member_in(
            &mut sender,
            &group.group_id,
            &second_package.public_bytes,
            &sender_identity,
        )
        .expect("sender should add the second receiver");
        assert_eq!(
            process_inbound_mls_commit_in(
                &mut receiver,
                &group.group_id,
                &second_admission.commit,
                &receiver_identity,
            )
            .expect("first receiver should apply the second admission Commit"),
            ProcessedMlsCommit::Applied { epoch: 2 }
        );
        join_mls_group_from_welcome_in(
            &mut second_receiver,
            &second_admission.welcome,
            &second_admission.ratchet_tree,
            &second_identity,
            None,
            None,
            None,
        )
        .expect("second receiver should join from its Welcome");

        let payload = b"MLS application payload";
        assert!(
            create_mls_application_event_in(
                &mut sender,
                &group.group_id,
                payload,
                1,
                &sender_identity,
            )
            .is_err()
        );
        let prepared = create_mls_application_event_in(
            &mut sender,
            &group.group_id,
            payload,
            2_000_000_000,
            &sender_identity,
        )
        .expect("application payload should encrypt and persist");
        assert_eq!(prepared.event.epoch, 2);
        assert_eq!(prepared.event.ciphertext, prepared.wire_message);
        let queued: (String, Vec<u8>) = sender
            .query_row(
                "SELECT delivery_state, ciphertext FROM local_events WHERE event_id = ?1",
                [prepared.event.event_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("ciphertext should be saved in the outbox");
        assert_eq!(queued.0, "queued");
        assert_eq!(queued.1, prepared.wire_message);
        let recipients = list_queued_mls_event_recipients_in(&sender, &group.group_id)
            .expect("group application event should snapshot peer recipients");
        assert_eq!(recipients.len(), 2);
        assert!(recipients.contains(&receiver_identity.verifying_key().to_bytes()));
        assert!(recipients.contains(&second_identity.verifying_key().to_bytes()));
        let receiver_queue = list_queued_mls_events_for_peer_in(
            &sender,
            &group.group_id,
            receiver_identity.verifying_key().to_bytes(),
            100,
        )
        .expect("recipient should see its queued MLS event");
        assert_eq!(receiver_queue.len(), 1);
        assert_eq!(receiver_queue[0].event.event_id, prepared.event.event_id);
        assert!(
            list_queued_mls_events_for_peer_in(&sender, &group.group_id, [0x98; 32], 100)
                .expect("unrelated peer queue should be queryable")
                .is_empty()
        );
        let sender_history = list_mls_messages_in(&sender, &group.group_id, 20)
            .expect("outbound plaintext should persist in encrypted local history");
        assert_eq!(sender_history.len(), 1);
        assert_eq!(sender_history[0].direction, DirectMessageDirection::Sent);
        assert_eq!(sender_history[0].text, "MLS application payload");
        mark_mls_event_delivered_to_peer_in(
            &mut sender,
            prepared.event.event_id,
            receiver_identity.verifying_key().to_bytes(),
        )
        .expect("ACK should clear only the acknowledging recipient queue");
        mark_mls_event_delivered_to_peer_in(
            &mut sender,
            prepared.event.event_id,
            receiver_identity.verifying_key().to_bytes(),
        )
        .expect("duplicate event ACK should be idempotent");
        let remaining = list_queued_mls_events_for_peer_in(
            &sender,
            &group.group_id,
            second_identity.verifying_key().to_bytes(),
            100,
        )
        .expect("the other recipient should remain queued after a partial ACK");
        assert_eq!(remaining.len(), 1);
        let state_after_partial_ack: String = sender
            .query_row(
                "SELECT delivery_state FROM local_events WHERE event_id = ?1",
                [prepared.event.event_id.as_slice()],
                |row| row.get(0),
            )
            .expect("global event should remain queued while one recipient is pending");
        assert_eq!(state_after_partial_ack, "queued");
        mark_mls_event_delivered_to_peer_in(
            &mut sender,
            prepared.event.event_id,
            second_identity.verifying_key().to_bytes(),
        )
        .expect("second recipient ACK should finish the event outbox");
        let final_state: String = sender
            .query_row(
                "SELECT delivery_state FROM local_events WHERE event_id = ?1",
                [prepared.event.event_id.as_slice()],
                |row| row.get(0),
            )
            .expect("global event should leave the outbox after all ACKs");
        assert_eq!(final_state, "held_by_peer");
        assert!(
            list_queued_mls_events_for_peer_in(
                &sender,
                &group.group_id,
                receiver_identity.verifying_key().to_bytes(),
                100
            )
            .expect("recipient event queue should reload")
            .is_empty()
        );

        let expiring = create_mls_application_event_in(
            &mut sender,
            &group.group_id,
            b"expires before delivery",
            2_000_000_000,
            &sender_identity,
        )
        .expect("future event should queue before its deadline");
        assert_eq!(
            expire_queued_mls_events_in(&sender, 2_000_000_000)
                .expect("expired outbox entries should be marked"),
            1
        );
        let expired_state: String = sender
            .query_row(
                "SELECT delivery_state FROM local_events WHERE event_id = ?1",
                [expiring.event.event_id.as_slice()],
                |row| row.get(0),
            )
            .expect("expired event state should persist");
        assert_eq!(expired_state, "expired");
        assert!(
            mark_mls_event_delivered_to_peer_in(
                &mut sender,
                expiring.event.event_id,
                receiver_identity.verifying_key().to_bytes(),
            )
            .is_err()
        );
        assert!(
            list_queued_mls_events_for_peer_in(
                &sender,
                &group.group_id,
                receiver_identity.verifying_key().to_bytes(),
                100,
            )
            .expect("expired events should not be listed for delivery")
            .is_empty()
        );

        let mut forged = prepared.event.clone();
        forged.event_id = [0x91; 16];
        forged.author_device = [0x92; 32];
        assert!(
            process_inbound_mls_application_event_in(&mut receiver, &forged, &receiver_identity,)
                .is_err()
        );
        let rejected_rows: i64 = receiver
            .query_row(
                "SELECT COUNT(*) FROM local_events WHERE event_id = ?1",
                [forged.event_id.as_slice()],
                |row| row.get(0),
            )
            .expect("rejected message should not remain in the inbox");
        assert_eq!(rejected_rows, 0);

        assert!(
            process_inbound_mls_application_event_at(
                &mut receiver,
                &prepared.event,
                &receiver_identity,
                prepared.event.expires_at_unix,
            )
            .is_err()
        );
        let expired_rows: i64 = receiver
            .query_row(
                "SELECT COUNT(*) FROM local_events WHERE event_id = ?1",
                [prepared.event.event_id.as_slice()],
                |row| row.get(0),
            )
            .expect("expired event should not be persisted");
        assert_eq!(expired_rows, 0);

        assert_eq!(
            process_inbound_mls_application_event_in(
                &mut receiver,
                &prepared.event,
                &receiver_identity,
            )
            .expect("receiver should authenticate, persist, and decrypt MLS message"),
            ProcessedMlsApplicationEvent::Received(payload.to_vec())
        );
        assert_eq!(
            process_inbound_mls_application_event_in(
                &mut receiver,
                &prepared.event,
                &receiver_identity,
            )
            .expect("redelivery of the same event should deduplicate"),
            ProcessedMlsApplicationEvent::Duplicate
        );
        let inbound_count: i64 = receiver
            .query_row(
                "SELECT COUNT(*) FROM local_events
                 WHERE event_id = ?1 AND direction = 'inbound'
                   AND delivery_state = 'received_by_device'",
                [prepared.event.event_id.as_slice()],
                |row| row.get(0),
            )
            .expect("inbound ciphertext should be durable before returning plaintext");
        assert_eq!(inbound_count, 1);
        let receiver_history = list_mls_messages_in(&receiver, &group.group_id, 20)
            .expect("authenticated inbound plaintext should persist in encrypted history");
        assert_eq!(receiver_history.len(), 1);
        assert_eq!(
            receiver_history[0].direction,
            DirectMessageDirection::Received
        );
        assert_eq!(receiver_history[0].text, "MLS application payload");
        drop(receiver);
        drop(second_receiver);
        drop(sender);
        fs::remove_dir_all(directory).expect("temporary databases should be removed");
    }

    #[test]
    fn delegated_mls_copies_require_authorization_opt_in_quota_and_recipient_ack() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-delegated-mls-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary database directory should be created");
        let mut connection = open_database(&directory.join("helper.sqlite3"), &[0xa1; 32])
            .expect("helper database should initialize");
        let author = SigningKey::from_bytes(&[0xa2; 32]);
        let recipient = [0xa3; 32];
        let now = unix_time_now().expect("system clock should be valid");
        let event = EncryptedEvent {
            event_id: [0xa4; 16],
            author_device: author.verifying_key().to_bytes(),
            group_id: vec![0xa5; 16],
            epoch: 7,
            checkpoint: Some(vec![0xa6; 8]),
            expires_at_unix: now + 100,
            ciphertext: b"cipher!!".to_vec(),
        };
        let grant = sign_delegated_mls_copy_grant_with_identity(&event, recipient, &author)
            .expect("author should sign a recipient-bound copy grant");
        assert!(
            store_delegated_mls_copy_in(&mut connection, &grant, &event, event.author_device, now)
                .is_err()
        );
        connection
            .execute(
                "UPDATE local_delegation_policy SET enabled = 1, quota_bytes = 8 WHERE id = 1",
                [],
            )
            .expect("test helper should opt into delegated storage");
        assert!(
            store_delegated_mls_copy_in(&mut connection, &grant, &event, [0xff; 32], now).is_err()
        );
        let mut wrong_target_grant = grant.clone();
        wrong_target_grant.recipient_device = [0xae; 32];
        assert!(
            store_delegated_mls_copy_in(
                &mut connection,
                &wrong_target_grant,
                &event,
                event.author_device,
                now,
            )
            .is_err()
        );
        let too_long = EncryptedEvent {
            event_id: [0xaf; 16],
            expires_at_unix: now + MAX_DELEGATED_TTL_SECONDS + 1,
            ..event.clone()
        };
        let too_long_grant =
            sign_delegated_mls_copy_grant_with_identity(&too_long, recipient, &author)
                .expect("author can sign an event that the helper must reject for its long TTL");
        assert!(
            store_delegated_mls_copy_in(
                &mut connection,
                &too_long_grant,
                &too_long,
                event.author_device,
                now,
            )
            .is_err()
        );
        assert_eq!(
            store_delegated_mls_copy_in(&mut connection, &grant, &event, event.author_device, now)
                .expect("valid authorized copy should persist"),
            DelegatedCopyStoreResult::Stored
        );
        assert_eq!(
            store_delegated_mls_copy_in(&mut connection, &grant, &event, event.author_device, now)
                .expect("exact repeated copy should deduplicate"),
            DelegatedCopyStoreResult::AlreadyStored
        );
        assert!(
            list_delegated_mls_copies_for_device_in(&connection, [0xa7; 32], 10, now)
                .expect("other recipient mailbox should be empty")
                .is_empty()
        );
        let copies = list_delegated_mls_copies_for_device_in(&connection, recipient, 10, now)
            .expect("authorized target should list its pending copy");
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].grant, grant);
        assert_eq!(copies[0].ciphertext, event.ciphertext);
        assert!(verify_delegated_mls_copy(&grant, &event, recipient).is_ok());
        assert!(verify_delegated_mls_copy(&grant, &event, [0xa7; 32]).is_err());
        let mut altered_grant = grant.clone();
        altered_grant.signature[0] ^= 1;
        assert!(verify_delegated_mls_copy(&altered_grant, &event, recipient).is_err());
        assert!(
            !acknowledge_delegated_mls_copy_in(&connection, event.event_id, [0xa7; 32], now)
                .expect("wrong recipient should not acknowledge another device's copy")
        );
        assert!(
            acknowledge_delegated_mls_copy_in(&connection, event.event_id, recipient, now)
                .expect("recipient should acknowledge the stored copy")
        );
        assert!(
            !acknowledge_delegated_mls_copy_in(&connection, event.event_id, recipient, now)
                .expect("duplicate ACK should be idempotent")
        );
        let stored_state: (String, Option<Vec<u8>>) = connection
            .query_row(
                "SELECT delivery_state, ciphertext FROM local_delegated_mls_copies
                 WHERE event_id = ?1 AND recipient_device = ?2",
                params![event.event_id.as_slice(), recipient.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("copy receipt should retain a tombstone and clear the ciphertext");
        assert_eq!(stored_state, ("received_by_device".to_owned(), None));

        let expiring = EncryptedEvent {
            event_id: [0xa8; 16],
            expires_at_unix: now + 50,
            ciphertext: b"12345678".to_vec(),
            ..event.clone()
        };
        let expiring_grant =
            sign_delegated_mls_copy_grant_with_identity(&expiring, recipient, &author)
                .expect("author should sign the second target copy");
        assert_eq!(
            store_delegated_mls_copy_in(
                &mut connection,
                &expiring_grant,
                &expiring,
                event.author_device,
                now
            )
            .expect("copy within quota should persist"),
            DelegatedCopyStoreResult::Stored
        );
        let over_quota = EncryptedEvent {
            event_id: [0xa9; 16],
            ciphertext: b"x".to_vec(),
            ..expiring.clone()
        };
        let over_quota_grant =
            sign_delegated_mls_copy_grant_with_identity(&over_quota, recipient, &author)
                .expect("author should sign the quota test copy");
        assert!(
            store_delegated_mls_copy_in(
                &mut connection,
                &over_quota_grant,
                &over_quota,
                event.author_device,
                now,
            )
            .is_err()
        );
        assert!(
            list_delegated_mls_copies_for_device_in(
                &connection,
                recipient,
                10,
                expiring.expires_at_unix,
            )
            .expect("expired copies should not be offered to recipients")
            .is_empty()
        );
        let expired_state: (String, Option<Vec<u8>>) = connection
            .query_row(
                "SELECT delivery_state, ciphertext FROM local_delegated_mls_copies
                 WHERE event_id = ?1 AND recipient_device = ?2",
                params![expiring.event_id.as_slice(), recipient.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("expired receipt tombstone should persist");
        assert_eq!(expired_state, ("expired".to_owned(), None));
        let opt_out_event = EncryptedEvent {
            event_id: [0xaa; 16],
            expires_at_unix: now + 40,
            ciphertext: b"retain?".to_vec(),
            ..event.clone()
        };
        let opt_out_grant =
            sign_delegated_mls_copy_grant_with_identity(&opt_out_event, recipient, &author)
                .expect("author should sign the opt-out test copy");
        assert_eq!(
            store_delegated_mls_copy_in(
                &mut connection,
                &opt_out_grant,
                &opt_out_event,
                event.author_device,
                now,
            )
            .expect("enabled helper should store the copy before opt-out"),
            DelegatedCopyStoreResult::Stored
        );
        set_delegated_mls_storage_policy_in(&mut connection, false, 0, now)
            .expect("opting out should erase retained ciphertext even when lowering quota");
        let opted_out_state: (String, Option<Vec<u8>>) = connection
            .query_row(
                "SELECT delivery_state, ciphertext FROM local_delegated_mls_copies
                 WHERE event_id = ?1 AND recipient_device = ?2",
                params![opt_out_event.event_id.as_slice(), recipient.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("opt-out tombstone should remain for deduplication");
        assert_eq!(opted_out_state, ("expired".to_owned(), None));
        assert!(
            store_delegated_mls_copy_in(
                &mut connection,
                &opt_out_grant,
                &opt_out_event,
                event.author_device,
                now,
            )
            .is_err()
        );
        drop(connection);
        fs::remove_dir_all(directory).expect("temporary helper database should be removed");
    }

    #[test]
    fn participant_relay_url_and_token_persist_in_encrypted_profile() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-relay-config-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary relay database directory should exist");
        let path = directory.join("profile.sqlite3");
        let key = [0x72; PROFILE_DB_KEY_LEN];
        let config = PeerRelayConfig {
            url: "https://relay.crew.example".to_owned(),
            token: "crew-shared-token-0123456789".to_owned(),
        };
        let connection = open_database(&path, &key).expect("encrypted schema should migrate");
        save_peer_relay_config_in(&connection, &config)
            .expect("relay URL and token should be stored");
        assert_eq!(
            load_peer_relay_config_in(&connection).expect("relay configuration should load"),
            config
        );
        drop(connection);
        let reopened = open_database(&path, &key).expect("encrypted profile should reopen");
        assert_eq!(
            load_peer_relay_config_in(&reopened).expect("relay configuration should persist"),
            config
        );
        drop(reopened);
        fs::remove_dir_all(directory).expect("temporary relay database should be removed");
    }

    #[test]
    fn file_attachment_manifest_and_key_persist_only_in_encrypted_profile() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "slouching-file-attachments-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("temporary attachment directory should exist");
        let path = directory.join("profile.sqlite3");
        let key = [0x6b; PROFILE_DB_KEY_LEN];
        let group_id = [0x21; 16];
        let author = [0x42; 32];
        let digest = [0x63; 32];
        let secrets = FileTransferSecrets::from_parts([0x84; 16], [0x95; 32]);
        let offer = FileOffer::from_secrets(
            &secrets,
            FILE_CHUNK_PLAINTEXT_BYTES as u64 + 3,
            "notes.pdf".to_owned(),
        )
        .expect("file offer should validate");

        let mut connection = open_database(&path, &key).expect("encrypted profile should migrate");
        connection
            .execute(
                "INSERT INTO local_mls_groups
                     (group_id, ciphersuite, designated_committer_device, epoch)
                 VALUES (?1, 1, ?2, 0)",
                params![group_id.as_slice(), author.as_slice()],
            )
            .expect("test group should be indexed");
        save_file_attachment_in(&mut connection, group_id, author, digest, &offer)
            .expect("attachment manifest should save");
        save_file_attachment_in(&mut connection, group_id, author, digest, &offer)
            .expect("identical retries should be idempotent");
        assert!(
            save_file_attachment_in(&mut connection, group_id, author, [0x64; 32], &offer)
                .expect_err("a transfer ID cannot be rebound to a different digest")
                .contains("already bound")
        );
        let listed = list_file_attachments_in(&connection, group_id)
            .expect("attachment should be listed from the encrypted profile");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].group_id, group_id);
        assert_eq!(listed[0].author_device, author);
        assert_eq!(listed[0].ciphertext_hash, digest);
        assert_eq!(listed[0].offer.filename, "notes.pdf");
        assert_eq!(listed[0].offer.content_key, [0x95; 32]);
        drop(listed);
        drop(connection);

        let reopened = open_database(&path, &key).expect("encrypted profile should reopen");
        let persisted = list_file_attachments_in(&reopened, group_id)
            .expect("manifest and key should survive reopening");
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].offer.transfer_id, [0x84; 16]);
        assert_eq!(persisted[0].offer.content_key, [0x95; 32]);
        assert!(
            list_file_attachments_in(&reopened, [0x22; 16])
                .expect("other groups should have independent manifests")
                .is_empty()
        );
        drop(persisted);
        drop(reopened);
        fs::remove_dir_all(directory).expect("temporary attachment directory should be removed");
    }
}
