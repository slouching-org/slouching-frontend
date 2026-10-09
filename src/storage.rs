use directories::ProjectDirs;
use ed25519_dalek::SigningKey;
use keyring::{Entry, Error as KeyringError};
use rusqlite::{Connection, OptionalExtension, params};
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
const PROFILE_SCHEMA_VERSION: u32 = 2;

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
    let existing: Option<(Vec<u8>, Vec<u8>, Vec<u8>, i64, Option<Vec<u8>>, i64)> = transaction
        .query_row(
            "SELECT ciphertext_digest, ciphertext, group_id, epoch, checkpoint,
                    expires_at_unix
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
                ))
            },
        )
        .optional()
        .map_err(|error| format!("could not check local event deduplication: {error}"))?;

    if let Some((saved_digest, saved_ciphertext, group_id, epoch, checkpoint, expires_at)) =
        existing
    {
        let saved_digest = blake3::Hash::from_slice(&saved_digest)
            .map_err(|_| "saved local event has an invalid digest".to_owned())?;
        if saved_digest != digest
            || saved_ciphertext != event.ciphertext
            || group_id != event.group_id
            || epoch != event.epoch as i64
            || checkpoint != event.checkpoint
            || expires_at != event.expires_at_unix
        {
            return Err("event id was reused with different ciphertext".to_owned());
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
                 ciphertext_digest, ciphertext, expires_at_unix
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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

fn key_entry() -> Result<Entry, String> {
    Entry::new(SERVICE, KEY_NAME)
        .map_err(|error| format!("system credential store is unavailable: {error}"))
}

fn identity_key_entry() -> Result<Entry, String> {
    Entry::new(SERVICE, IDENTITY_KEY_NAME)
        .map_err(|error| format!("system credential store is unavailable: {error}"))
}

fn public_key_from_seed(secret: Vec<u8>) -> Result<[u8; 32], String> {
    let mut secret = Zeroizing::new(secret);
    if secret.len() != 32 {
        return Err("saved Ed25519 device key has an invalid length".to_owned());
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&secret);
    secret.zeroize();
    let signing_key = SigningKey::from_bytes(&seed);
    Ok(signing_key.verifying_key().to_bytes())
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
    let connection = Connection::open(path)
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
    transaction
        .commit()
        .map_err(|error| format!("could not finish local profile migration: {error}"))?;
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
