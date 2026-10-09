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

    let path = database_path()?;
    let connection = open_database(&path, &key)?;
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
    if version > 1 {
        return Err(format!(
            "local profile database version {version} is newer than this app"
        ));
    }
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS local_profile (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 40),
                 familiar TEXT NOT NULL CHECK (familiar IN ('frog', 'gnome', 'orb'))
             );
             PRAGMA user_version = 1;
             COMMIT;",
        )
        .map_err(|error| format!("could not initialize local profile schema: {error}"))?;
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
