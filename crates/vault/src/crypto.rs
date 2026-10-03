use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use niceotp_protocol::{FORMAT_VERSION, KdfParams, PasswordEnvelope, Sealed, VaultHeader};
use rand::{RngCore, rngs::OsRng};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub(crate) const MAX_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 4096;
const BASELINE_MEMORY_KIB: u32 = 64 * 1024;
const BASELINE_ITERATIONS: u32 = 3;
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_ITERATIONS: u32 = 10;
// Bounds cap both memory and aggregate KDF work for attacker-controlled headers.
const MAX_KDF_WORK: u64 = 1024 * 1024;

/// An opaque, zeroizing vault key. Deliberately neither `Debug` nor serializable.
pub struct VaultKey(Zeroizing<[u8; 32]>);

impl VaultKey {
    /// Restore a key from the operating system keyring, never a plaintext file.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Expose the key only when writing to an operating system keyring.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn create_vault(password: &str) -> Result<(VaultHeader, VaultKey, String)> {
    validate_password(password)?;
    let key = VaultKey(random_bytes()?);
    let vault_id = Uuid::from_bytes(*random_bytes::<16>()?);
    // UUID v4 metadata is not key material, but use the same fallible OS entropy path.
    let vault_id = uuid::Builder::from_random_bytes(*vault_id.as_bytes()).into_uuid();
    let recovery_key = random_bytes::<32>()?;
    let header = VaultHeader {
        format_version: FORMAT_VERSION,
        vault_id,
        password: wrap_password(&key, vault_id, password)?,
        recovery: seal_raw(
            &recovery_key,
            &aad(vault_id, "recovery-wrap", b"")?,
            key.as_bytes(),
        )?,
    };
    Ok((header, key, URL_SAFE_NO_PAD.encode(recovery_key.as_ref())))
}

pub fn unlock_password(header: &VaultHeader, password: &str) -> Result<VaultKey> {
    validate_header(header)?;
    validate_password(password)?;
    let wrapping_key = password_key(password, &header.password.kdf)?;
    let kdf_json = serde_json::to_vec(&header.password.kdf).map_err(|_| Error::InvalidEnvelope)?;
    let plain = Zeroizing::new(open_raw(
        &wrapping_key,
        &aad(header.vault_id, "password-wrap", &kdf_json)?,
        &header.password.sealed,
        32,
    )?);
    key_from_plaintext(&plain)
}

pub fn unlock_recovery(header: &VaultHeader, recovery: &str) -> Result<VaultKey> {
    validate_header(header)?;
    let recovery_key = decode_key(recovery).map_err(|_| Error::Authentication)?;
    let plain = Zeroizing::new(open_raw(
        &recovery_key,
        &aad(header.vault_id, "recovery-wrap", b"")?,
        &header.recovery,
        32,
    )?);
    key_from_plaintext(&plain)
}

/// Rewraps an already unlocked key. Old header/backup copies remain usable.
pub fn change_password(header: &mut VaultHeader, key: &VaultKey, password: &str) -> Result<()> {
    validate_header(header)?;
    validate_password(password)?;
    let replacement = wrap_password(key, header.vault_id, password)?;
    header.password = replacement;
    Ok(())
}

/// Replaces the recovery wrapper independently from the password wrapper.
pub fn change_recovery(header: &mut VaultHeader, key: &VaultKey) -> Result<String> {
    validate_header(header)?;
    let recovery_key = random_bytes::<32>()?;
    let replacement = seal_raw(
        &recovery_key,
        &aad(header.vault_id, "recovery-wrap", b"")?,
        key.as_bytes(),
    )?;
    header.recovery = replacement;
    Ok(URL_SAFE_NO_PAD.encode(recovery_key.as_ref()))
}

/// Seal local state under a caller-controlled context, e.g. `local-state:v1`.
/// Entry, backup and key-wrapper domains are separate from this API's domain.
pub fn seal_bytes(key: &VaultKey, vault_id: Uuid, context: &str, bytes: &[u8]) -> Result<Sealed> {
    seal_raw(
        key.as_bytes(),
        &aad(vault_id, "bytes", context.as_bytes())?,
        bytes,
    )
}

pub fn open_bytes(
    key: &VaultKey,
    vault_id: Uuid,
    context: &str,
    sealed: &Sealed,
) -> Result<Vec<u8>> {
    open_raw(
        key.as_bytes(),
        &aad(vault_id, "bytes", context.as_bytes())?,
        sealed,
        MAX_PLAINTEXT_BYTES,
    )
}

pub(crate) fn validate_header(header: &VaultHeader) -> Result<()> {
    if header.format_version != FORMAT_VERSION {
        return Err(Error::UnsupportedFormat);
    }
    // Recovery must not require a functioning password KDF. Validate KDF only
    // when deriving the password wrapping key so recovery can repair its wrapper.
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    if password.is_empty() || password.len() > 1024 {
        return Err(Error::InvalidPassword);
    }
    Ok(())
}

fn wrap_password(key: &VaultKey, vault_id: Uuid, password: &str) -> Result<PasswordEnvelope> {
    let salt = random_bytes::<16>()?;
    let kdf = KdfParams {
        salt: URL_SAFE_NO_PAD.encode(salt.as_ref()),
        memory_kib: BASELINE_MEMORY_KIB,
        iterations: BASELINE_ITERATIONS,
        parallelism: 1,
    };
    let wrapping_key = password_key(password, &kdf)?;
    let kdf_json = serde_json::to_vec(&kdf).map_err(|_| Error::InvalidEnvelope)?;
    let sealed = seal_raw(
        &wrapping_key,
        &aad(vault_id, "password-wrap", &kdf_json)?,
        key.as_bytes(),
    )?;
    Ok(PasswordEnvelope { kdf, sealed })
}

fn password_key(password: &str, kdf: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    // These checks must precede Params construction and allocation by Argon2.
    if !(BASELINE_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&kdf.memory_kib)
        || !(BASELINE_ITERATIONS..=MAX_ITERATIONS).contains(&kdf.iterations)
        || !(1..=4).contains(&kdf.parallelism)
        || u64::from(kdf.memory_kib) * u64::from(kdf.iterations) > MAX_KDF_WORK
    {
        return Err(Error::InvalidKdf);
    }
    let salt = decode_fixed::<16>(&kdf.salt).map_err(|_| Error::InvalidKdf)?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| Error::InvalidKdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), &salt, key.as_mut())
        .map_err(|_| Error::InvalidKdf)?;
    Ok(key)
}

fn key_from_plaintext(plain: &[u8]) -> Result<VaultKey> {
    let bytes: [u8; 32] = plain.try_into().map_err(|_| Error::InvalidEnvelope)?;
    Ok(VaultKey::from_bytes(bytes))
}

pub(crate) fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0_u8; N]);
    OsRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| Error::Randomness)?;
    Ok(bytes)
}

fn decode_key(value: &str) -> Result<Zeroizing<[u8; 32]>> {
    if value.len() != 43 {
        return Err(Error::InvalidEnvelope);
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| Error::InvalidEnvelope)?,
    );
    let key = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidEnvelope)?;
    Ok(Zeroizing::new(key))
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != (N * 4).div_ceil(3) {
        return Err(Error::InvalidEnvelope);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::InvalidEnvelope)?
        .try_into()
        .map_err(|_| Error::InvalidEnvelope)
}

/// Binary length-prefix encoding makes each purpose/vault/context tuple unique.
pub(crate) fn aad(vault_id: Uuid, purpose: &str, context: &[u8]) -> Result<Vec<u8>> {
    if purpose.len() > MAX_CONTEXT_BYTES || context.len() > MAX_CONTEXT_BYTES {
        return Err(Error::InputTooLarge);
    }
    let mut bytes = b"niceotp\0v1\0".to_vec();
    bytes.extend_from_slice(&(purpose.len() as u32).to_be_bytes());
    bytes.extend_from_slice(purpose.as_bytes());
    bytes.extend_from_slice(vault_id.as_bytes());
    bytes.extend_from_slice(&(context.len() as u32).to_be_bytes());
    bytes.extend_from_slice(context);
    Ok(bytes)
}

pub(crate) fn seal_raw(key: &[u8; 32], associated_data: &[u8], bytes: &[u8]) -> Result<Sealed> {
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::InputTooLarge);
    }
    let nonce = random_bytes::<24>()?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce.as_ref()),
            Payload {
                msg: bytes,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::Encryption)?;
    Ok(Sealed {
        nonce: URL_SAFE_NO_PAD.encode(nonce.as_ref()),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub(crate) fn open_raw(
    key: &[u8; 32],
    associated_data: &[u8],
    sealed: &Sealed,
    max_plaintext: usize,
) -> Result<Vec<u8>> {
    let nonce = decode_fixed::<24>(&sealed.nonce)?;
    let limit = max_plaintext.min(MAX_PLAINTEXT_BYTES) + 16;
    if sealed.ciphertext.len() > (limit * 4).div_ceil(3) {
        return Err(Error::InputTooLarge);
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&sealed.ciphertext)
        .map_err(|_| Error::InvalidEnvelope)?;
    if ciphertext.len() < 16 || ciphertext.len() > limit {
        return Err(Error::InvalidEnvelope);
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod interoperability {
    use super::*;
    use crate::{Backup, Entry, decrypt_entry, import_backup_password, import_backup_recovery};
    use niceotp_protocol::ServerItem;
    use serde_json::{Value, json};

    // A fixed nonce is available ONLY inside this test module. Production calls
    // always use the operating system CSPRNG through seal_raw.
    fn fixed_seal(key: &[u8; 32], nonce_start: u8, associated_data: &[u8], bytes: &[u8]) -> Sealed {
        let nonce: [u8; 24] = std::array::from_fn(|i| nonce_start + i as u8);
        let ciphertext = XChaCha20Poly1305::new(key.into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: bytes,
                    aad: associated_data,
                },
            )
            .unwrap();
        Sealed {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        }
    }

    #[test]
    fn public_v1_interoperability_vector() {
        let vault_id = Uuid::parse_str("00112233-4455-4677-8899-aabbccddeeff").unwrap();
        let item_id = Uuid::parse_str("10213243-5465-4768-99aa-bbccddeeff00").unwrap();
        let tombstone_id = Uuid::parse_str("20314253-6475-4879-aabb-ccddeeff0011").unwrap();
        let key = VaultKey::from_bytes(std::array::from_fn(|i| i as u8));
        let recovery_key: [u8; 32] = std::array::from_fn(|i| 32 + i as u8);
        let recovery = URL_SAFE_NO_PAD.encode(recovery_key);
        let password = "NiceOTP public test password";
        let kdf = KdfParams {
            salt: URL_SAFE_NO_PAD.encode(std::array::from_fn::<_, 16, _>(|i| i as u8)),
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
        };
        let password_key = password_key(password, &kdf).unwrap();
        let password_aad = aad(
            vault_id,
            "password-wrap",
            &serde_json::to_vec(&kdf).unwrap(),
        )
        .unwrap();
        let recovery_aad = aad(vault_id, "recovery-wrap", b"").unwrap();
        let header = VaultHeader {
            format_version: 1,
            vault_id,
            password: PasswordEnvelope {
                kdf,
                sealed: fixed_seal(&password_key, 0, &password_aad, key.as_bytes()),
            },
            recovery: fixed_seal(&recovery_key, 24, &recovery_aad, key.as_bytes()),
        };
        let entry=Entry::from_uri("otpauth://totp/Public%20Example:alice%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Public%20Example").unwrap();
        let entry_plain = serde_json::to_string(&entry).unwrap();
        let entry_aad = aad(vault_id, "entry", item_id.as_bytes()).unwrap();
        let entry_sealed = fixed_seal(key.as_bytes(), 48, &entry_aad, entry_plain.as_bytes());
        let local_context = "local-state:v1";
        let local_plain = "public interoperability fixture";
        let local_aad = aad(vault_id, "bytes", local_context.as_bytes()).unwrap();
        let local_sealed = fixed_seal(key.as_bytes(), 72, &local_aad, local_plain.as_bytes());
        let backup = Backup {
            format_version: 1,
            header: header.clone(),
            items: vec![
                ServerItem {
                    id: item_id,
                    revision: 7,
                    payload: Some(entry_sealed.clone()),
                },
                ServerItem {
                    id: tombstone_id,
                    revision: 8,
                    payload: None,
                },
            ],
        };
        let backup_plain = serde_json::to_string(&backup).unwrap();
        let backup_aad = aad(
            vault_id,
            "backup-manifest",
            &serde_json::to_vec(&header).unwrap(),
        )
        .unwrap();
        let backup_sealed = fixed_seal(key.as_bytes(), 96, &backup_aad, backup_plain.as_bytes());
        let envelope = json!({"format_version":1,"header":header,"sealed":backup_sealed});
        let vector = json!({
            "description":"PUBLIC TEST DATA ONLY. Fixed keys and nonces are unsafe for real vaults.",
            "password":password,
            "vault_key_base64url":URL_SAFE_NO_PAD.encode(key.as_bytes()),
            "recovery_code":recovery,
            "password_key_base64url":URL_SAFE_NO_PAD.encode(password_key.as_ref()),
            "header":header,
            "password_aad_base64url":URL_SAFE_NO_PAD.encode(password_aad),
            "recovery_aad_base64url":URL_SAFE_NO_PAD.encode(recovery_aad),
            "entry":{"item_id":item_id,"plaintext_utf8":entry_plain,"aad_base64url":URL_SAFE_NO_PAD.encode(entry_aad),"sealed":entry_sealed},
            "local_state":{"context":local_context,"plaintext_utf8":local_plain,"aad_base64url":URL_SAFE_NO_PAD.encode(local_aad),"sealed":local_sealed},
            "backup":{"plaintext_utf8":backup_plain,"aad_base64url":URL_SAFE_NO_PAD.encode(backup_aad),"envelope":envelope},
        });
        // Explicitly requested fixture regeneration, confined to tests. Normal
        // CI compares against the committed file and never changes it.
        if std::env::var_os("NICEOTP_UPDATE_PUBLIC_VECTOR").is_some() {
            std::fs::write(
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1.json"),
                serde_json::to_string_pretty(&vector).unwrap() + "\n",
            )
            .unwrap();
        } else {
            let expected: Value =
                serde_json::from_str(include_str!("../tests/fixtures/v1.json")).unwrap();
            assert_eq!(vector, expected);
        }
        // Decode via the production APIs too, including the complete backup.
        assert_eq!(
            unlock_password(&header, password).unwrap().as_bytes(),
            key.as_bytes()
        );
        assert_eq!(
            unlock_recovery(&header, &recovery).unwrap().as_bytes(),
            key.as_bytes()
        );
        assert_eq!(
            decrypt_entry(&key, vault_id, item_id, &entry_sealed)
                .unwrap()
                .account,
            "alice@example.test"
        );
        assert_eq!(
            open_bytes(&key, vault_id, local_context, &local_sealed).unwrap(),
            local_plain.as_bytes()
        );
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert!(import_backup_password(&bytes, password).unwrap().0.items == backup.items);
        assert!(import_backup_recovery(&bytes, &recovery).unwrap().0.items == backup.items);
    }
}
