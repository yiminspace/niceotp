use std::collections::HashSet;

use niceotp_protocol::{FORMAT_VERSION, Sealed, ServerItem, VaultHeader};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{MAX_PLAINTEXT_BYTES, aad, open_raw, seal_raw, validate_header};
use crate::{Error, Result, VaultKey, decrypt_entry, unlock_password, unlock_recovery};

const MAX_BACKUP_FILE_BYTES: usize = 48 * 1024 * 1024;
const MAX_BACKUP_ITEMS: usize = 10_000;

/// The complete authenticated manifest, including item IDs, revisions and tombstones.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub format_version: u32,
    pub header: VaultHeader,
    pub items: Vec<ServerItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableBackup {
    format_version: u32,
    header: VaultHeader,
    sealed: Sealed,
}

/// Export one authenticated envelope containing the *entire* serialized manifest.
/// The exposed unlock header is also bound as AAD, not merely stored beside it.
pub fn export_backup(key: &VaultKey, backup: &Backup) -> Result<Vec<u8>> {
    validate_manifest(backup, key)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(backup).map_err(|_| Error::InvalidBackup)?);
    let sealed = seal_raw(key.as_bytes(), &backup_aad(&backup.header)?, &plaintext)?;
    let portable = PortableBackup {
        format_version: FORMAT_VERSION,
        header: backup.header.clone(),
        sealed,
    };
    let bytes = serde_json::to_vec(&portable).map_err(|_| Error::InvalidBackup)?;
    if bytes.len() > MAX_BACKUP_FILE_BYTES {
        return Err(Error::InputTooLarge);
    }
    Ok(bytes)
}

/// Import using a key already obtained from the OS keyring or a trusted vault.
pub fn import_backup(bytes: &[u8], key: &VaultKey) -> Result<Backup> {
    open_manifest(parse_portable(bytes)?, key)
}

pub fn import_backup_password(bytes: &[u8], password: &str) -> Result<(Backup, VaultKey)> {
    let portable = parse_portable(bytes)?;
    let key = unlock_password(&portable.header, password)?;
    Ok((open_manifest(portable, &key)?, key))
}

pub fn import_backup_recovery(bytes: &[u8], recovery: &str) -> Result<(Backup, VaultKey)> {
    let portable = parse_portable(bytes)?;
    let key = unlock_recovery(&portable.header, recovery)?;
    Ok((open_manifest(portable, &key)?, key))
}

fn parse_portable(bytes: &[u8]) -> Result<PortableBackup> {
    if bytes.len() > MAX_BACKUP_FILE_BYTES {
        return Err(Error::InputTooLarge);
    }
    let portable: PortableBackup =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidBackup)?;
    if portable.format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedFormat);
    }
    validate_header(&portable.header)?;
    // Validate exposed header size before doing any password KDF work.
    backup_aad(&portable.header)?;
    Ok(portable)
}

fn open_manifest(portable: PortableBackup, key: &VaultKey) -> Result<Backup> {
    let plaintext = Zeroizing::new(open_raw(
        key.as_bytes(),
        &backup_aad(&portable.header)?,
        &portable.sealed,
        MAX_PLAINTEXT_BYTES,
    )?);
    let backup: Backup = serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidBackup)?;
    if backup.header != portable.header {
        return Err(Error::InvalidBackup);
    }
    validate_manifest(&backup, key)?;
    Ok(backup)
}

fn backup_aad(header: &VaultHeader) -> Result<Vec<u8>> {
    let header_json = serde_json::to_vec(header).map_err(|_| Error::InvalidBackup)?;
    aad(header.vault_id, "backup-manifest", &header_json)
}

fn validate_manifest(backup: &Backup, key: &VaultKey) -> Result<()> {
    if backup.format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedFormat);
    }
    validate_header(&backup.header)?;
    if backup.items.len() > MAX_BACKUP_ITEMS {
        return Err(Error::InvalidBackup);
    }
    let mut seen = HashSet::with_capacity(backup.items.len());
    for item in &backup.items {
        if item.revision < 0 || !seen.insert(item.id) {
            return Err(Error::InvalidBackup);
        }
        if let Some(payload) = &item.payload {
            // Also reject valid envelopes containing records bound to another ID.
            decrypt_entry(key, backup.header.vault_id, item.id, payload)?;
        }
    }
    Ok(())
}
