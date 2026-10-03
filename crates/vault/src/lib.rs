//! Client-only vault cryptography, portable authenticated backups, and RFC 6238 TOTP.
//!
//! Keys and entries intentionally do not implement `Debug`. All error messages are
//! fixed strings: callers may display them without disclosing plaintext input.
mod backup;
mod crypto;
mod entry;

pub use backup::{
    Backup, export_backup, import_backup, import_backup_password, import_backup_recovery,
};
pub use crypto::{
    VaultKey, change_password, change_recovery, create_vault, open_bytes, seal_bytes,
    unlock_password, unlock_recovery,
};
pub use entry::{Entry, decrypt_entry, encrypt_entry};

/// Failures contain no passwords, OTP secrets, recovery codes, or supplied input.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unsupported vault or backup format")]
    UnsupportedFormat,
    #[error("invalid encoded envelope")]
    InvalidEnvelope,
    #[error("password or recovery code is incorrect, or the data was altered")]
    Authentication,
    #[error("password must contain between 1 and 1024 bytes")]
    InvalidPassword,
    #[error("KDF parameters are outside the supported safety bounds")]
    InvalidKdf,
    #[error("operating system randomness is unavailable")]
    Randomness,
    #[error("encryption failed")]
    Encryption,
    #[error("invalid OTP entry or provisioning URI")]
    InvalidEntry,
    #[error("invalid or oversized backup")]
    InvalidBackup,
    #[error("input exceeds the supported size")]
    InputTooLarge,
}

pub type Result<T> = std::result::Result<T, Error>;
