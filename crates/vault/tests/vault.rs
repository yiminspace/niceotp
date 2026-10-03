use std::sync::OnceLock;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use data_encoding::BASE32_NOPAD;
use niceotp_protocol::{FORMAT_VERSION, Sealed, ServerItem, VaultHeader};
use niceotp_vault::{
    Backup, Entry, Error, VaultKey, change_password, change_recovery, create_vault, decrypt_entry,
    encrypt_entry, export_backup, import_backup, import_backup_password, import_backup_recovery,
    open_bytes, seal_bytes, unlock_password, unlock_recovery,
};
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery staple (test fixture only)";

fn fixture() -> &'static (VaultHeader, VaultKey, String) {
    static FIXTURE: OnceLock<(VaultHeader, VaultKey, String)> = OnceLock::new();
    FIXTURE.get_or_init(|| create_vault(PASSWORD).unwrap())
}

fn entry() -> Entry {
    Entry::from_uri(
        "otpauth://totp/Example:alice%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    )
    .unwrap()
}

fn altered(sealed: &Sealed) -> Sealed {
    let mut sealed = sealed.clone();
    let mut ciphertext = URL_SAFE_NO_PAD.decode(&sealed.ciphertext).unwrap();
    ciphertext[0] ^= 1;
    sealed.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    sealed
}

#[test]
fn password_and_recovery_unwrap_the_same_random_key() {
    let (header, key, recovery) = fixture();
    assert_eq!(header.password.kdf.memory_kib, 65_536);
    assert_eq!(header.password.kdf.iterations, 3);
    assert_eq!(header.password.kdf.parallelism, 1);
    assert_eq!(URL_SAFE_NO_PAD.decode(recovery).unwrap().len(), 32);
    assert_eq!(
        unlock_password(header, PASSWORD).unwrap().as_bytes(),
        key.as_bytes()
    );
    assert_eq!(
        unlock_recovery(header, recovery).unwrap().as_bytes(),
        key.as_bytes()
    );
    assert!(matches!(
        unlock_password(header, "incorrect"),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        unlock_recovery(header, &URL_SAFE_NO_PAD.encode([0_u8; 32])),
        Err(Error::Authentication)
    ));
    assert!(unlock_recovery(header, "not-a-key").is_err());
}

#[test]
fn recovery_is_independent_and_can_repair_a_broken_password_wrapper() {
    let (original, key, recovery) = fixture();
    let mut header = original.clone();
    header.password.kdf.memory_kib = u32::MAX;
    header.password.sealed.ciphertext = "corrupt".into();
    assert!(matches!(
        unlock_password(&header, PASSWORD),
        Err(Error::InvalidKdf)
    ));
    let recovered = unlock_recovery(&header, recovery).unwrap();
    assert_eq!(recovered.as_bytes(), key.as_bytes());
    change_password(&mut header, &recovered, "new long password for test").unwrap();
    assert_eq!(
        unlock_password(&header, "new long password for test")
            .unwrap()
            .as_bytes(),
        key.as_bytes()
    );
    assert_eq!(
        unlock_recovery(&header, recovery).unwrap().as_bytes(),
        key.as_bytes()
    );
    assert!(unlock_password(&header, PASSWORD).is_err());
    // Changing a wrapper does not revoke a previously copied header.
    assert_eq!(
        unlock_password(original, PASSWORD).unwrap().as_bytes(),
        key.as_bytes()
    );
}

#[test]
fn recovery_rotation_leaves_password_wrapper_unchanged() {
    let (original, key, recovery) = fixture();
    let mut header = original.clone();
    let replacement = change_recovery(&mut header, key).unwrap();
    assert!(header.password == original.password);
    assert_ne!(&replacement, recovery);
    assert!(unlock_recovery(&header, recovery).is_err());
    assert_eq!(
        unlock_recovery(&header, &replacement).unwrap().as_bytes(),
        key.as_bytes()
    );
    assert_eq!(
        unlock_password(&header, PASSWORD).unwrap().as_bytes(),
        key.as_bytes()
    );
    assert!(unlock_recovery(original, recovery).is_ok());
}

#[test]
fn kdf_bounds_are_enforced_before_derivation() {
    let (original, _, _) = fixture();
    for (memory, iterations, parallelism) in [
        (0, 3, 1),
        (65_535, 3, 1),
        (u32::MAX, 3, 1),
        (65_536, 0, 1),
        (65_536, 2, 1),
        (65_536, u32::MAX, 1),
        (65_536, 3, 0),
        (65_536, 3, u32::MAX),
        (262_144, 10, 1),
    ] {
        let mut header = original.clone();
        header.password.kdf.memory_kib = memory;
        header.password.kdf.iterations = iterations;
        header.password.kdf.parallelism = parallelism;
        assert!(matches!(
            unlock_password(&header, PASSWORD),
            Err(Error::InvalidKdf)
        ));
    }
    let mut header = original.clone();
    header.password.kdf.salt = URL_SAFE_NO_PAD.encode([0_u8; 8]);
    assert!(matches!(
        unlock_password(&header, PASSWORD),
        Err(Error::InvalidKdf)
    ));
    header.format_version = 999;
    assert!(matches!(
        unlock_password(&header, PASSWORD),
        Err(Error::UnsupportedFormat)
    ));
}

#[test]
fn aead_binds_vault_context_item_and_protocol_purpose() {
    let (header, key, _) = fixture();
    let local = seal_bytes(key, header.vault_id, "local-state:v1", b"secret state").unwrap();
    assert_eq!(
        open_bytes(key, header.vault_id, "local-state:v1", &local).unwrap(),
        b"secret state"
    );
    assert!(open_bytes(key, header.vault_id, "other", &local).is_err());
    assert!(open_bytes(key, Uuid::new_v4(), "local-state:v1", &local).is_err());
    assert!(
        open_bytes(
            &VaultKey::from_bytes([0; 32]),
            header.vault_id,
            "local-state:v1",
            &local
        )
        .is_err()
    );
    assert!(open_bytes(key, header.vault_id, "local-state:v1", &altered(&local)).is_err());
    let mut wrong_nonce = local.clone();
    wrong_nonce.nonce = URL_SAFE_NO_PAD.encode([0_u8; 24]);
    assert!(open_bytes(key, header.vault_id, "local-state:v1", &wrong_nonce).is_err());
    let again = seal_bytes(key, header.vault_id, "local-state:v1", b"secret state").unwrap();
    assert!(local.nonce != again.nonce);
    assert!(local.ciphertext != again.ciphertext);

    let id = Uuid::new_v4();
    let sealed = encrypt_entry(key, header.vault_id, id, &entry()).unwrap();
    assert_eq!(
        decrypt_entry(key, header.vault_id, id, &sealed)
            .unwrap()
            .account,
        "alice@example.test"
    );
    assert!(decrypt_entry(key, header.vault_id, Uuid::new_v4(), &sealed).is_err());
    assert!(decrypt_entry(key, Uuid::new_v4(), id, &sealed).is_err());
    assert!(open_bytes(key, header.vault_id, &id.to_string(), &sealed).is_err());
    assert!(decrypt_entry(key, header.vault_id, id, &altered(&sealed)).is_err());
}

#[test]
fn wrapped_keys_are_bound_to_vault_and_purpose() {
    let (original, _, recovery) = fixture();
    let mut header = original.clone();
    header.vault_id = Uuid::new_v4();
    assert!(unlock_recovery(&header, recovery).is_err());
    assert!(unlock_password(&header, PASSWORD).is_err());
    header = original.clone();
    header.recovery = original.password.sealed.clone();
    assert!(unlock_recovery(&header, recovery).is_err());
    header = original.clone();
    header.password.sealed = original.recovery.clone();
    assert!(unlock_password(&header, PASSWORD).is_err());
}

fn backup_fixture() -> Backup {
    let (header, key, _) = fixture();
    let id = Uuid::new_v4();
    Backup {
        format_version: FORMAT_VERSION,
        header: header.clone(),
        items: vec![
            ServerItem {
                id,
                revision: 7,
                payload: Some(encrypt_entry(key, header.vault_id, id, &entry()).unwrap()),
            },
            ServerItem {
                id: Uuid::new_v4(),
                revision: 8,
                payload: None,
            },
        ],
    }
}

#[test]
fn portable_backup_roundtrips_offline_with_either_unlock_method() {
    let (_, key, recovery) = fixture();
    let backup = backup_fixture();
    let bytes = export_backup(key, &backup).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json.get("items").is_none());
    assert!(json.get("sealed").is_some());
    assert!(!String::from_utf8_lossy(&bytes).contains("alice@example.test"));
    assert!(!String::from_utf8_lossy(&bytes).contains("JBSWY3DPEHPK3PXP"));
    let (restored, password_key) = import_backup_password(&bytes, PASSWORD).unwrap();
    assert!(restored.header == backup.header);
    assert!(restored.items == backup.items);
    assert_eq!(password_key.as_bytes(), key.as_bytes());
    let (restored, recovery_key) = import_backup_recovery(&bytes, recovery).unwrap();
    assert!(restored.items == backup.items);
    assert_eq!(recovery_key.as_bytes(), key.as_bytes());
    assert!(import_backup_password(&bytes, "wrong").is_err());
    assert!(import_backup_recovery(&bytes, &URL_SAFE_NO_PAD.encode([0_u8; 32])).is_err());
    assert!(import_backup(&bytes, &VaultKey::from_bytes([0; 32])).is_err());
}

#[test]
fn backup_authenticates_header_and_complete_manifest() {
    let (_, key, recovery) = fixture();
    let backup = backup_fixture();
    let bytes = export_backup(key, &backup).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut modified = json.clone();
    modified["header"]["password"]["kdf"]["iterations"] = 4.into();
    // Recovery still unwraps independently, but authentication catches changed KDF metadata.
    assert!(matches!(
        import_backup_recovery(&serde_json::to_vec(&modified).unwrap(), recovery),
        Err(Error::Authentication)
    ));
    modified = json.clone();
    modified["header"]["vault_id"] = Uuid::new_v4().to_string().into();
    assert!(import_backup(&serde_json::to_vec(&modified).unwrap(), key).is_err());
    modified = json.clone();
    let sealed: Sealed = serde_json::from_value(modified["sealed"].clone()).unwrap();
    modified["sealed"] = serde_json::to_value(altered(&sealed)).unwrap();
    assert!(matches!(
        import_backup(&serde_json::to_vec(&modified).unwrap(), key),
        Err(Error::Authentication)
    ));
    // Records cannot be removed, reordered or replaced in an unauthenticated list.
    modified = json.clone();
    modified["items"] = serde_json::json!([]);
    assert!(import_backup(&serde_json::to_vec(&modified).unwrap(), key).is_err());
    modified = json;
    let ciphertext = modified["sealed"]["ciphertext"]
        .as_str()
        .unwrap()
        .to_owned();
    modified["sealed"]["ciphertext"] = ciphertext[..ciphertext.len() - 20].into();
    assert!(import_backup(&serde_json::to_vec(&modified).unwrap(), key).is_err());
    assert!(import_backup(&bytes[..bytes.len() / 2], key).is_err());
}

#[test]
fn malformed_backup_records_are_rejected() {
    let (_, key, _) = fixture();
    let mut backup = backup_fixture();
    backup.items.push(backup.items[0].clone());
    assert!(matches!(
        export_backup(key, &backup),
        Err(Error::InvalidBackup)
    ));
    backup.items.pop();
    backup.items[0].revision = -1;
    assert!(matches!(
        export_backup(key, &backup),
        Err(Error::InvalidBackup)
    ));
    backup.items[0].revision = 1;
    backup.items[0].id = Uuid::new_v4();
    assert!(matches!(
        export_backup(key, &backup),
        Err(Error::Authentication)
    ));
}

#[test]
fn rfc6238_appendix_b_vectors_all_algorithms_and_long_timestamps() {
    // Public RFC 6238 Appendix B known-answer vectors, with its SHA-specific test keys.
    let times = [
        59,
        1_111_111_109,
        1_111_111_111,
        1_234_567_890,
        2_000_000_000,
        20_000_000_000,
    ];
    let cases = [
        (
            "SHA1",
            "12345678901234567890",
            [
                "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
            ],
        ),
        (
            "SHA256",
            "12345678901234567890123456789012",
            [
                "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
            ],
        ),
        (
            "SHA512",
            "1234567890123456789012345678901234567890123456789012345678901234",
            [
                "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
            ],
        ),
    ];
    for (algorithm, secret, expected) in cases {
        let mut item = entry();
        item.algorithm = algorithm.into();
        item.secret = BASE32_NOPAD.encode(secret.as_bytes());
        item.digits = 8;
        for (timestamp, expected) in times.iter().zip(expected) {
            assert_eq!(item.code_at(*timestamp).unwrap(), expected);
            item.digits = 6;
            assert_eq!(item.code_at(*timestamp).unwrap(), &expected[2..]);
            item.digits = 8;
        }
    }
}

#[test]
fn uri_parser_preserves_labels_defaults_and_rejects_ambiguous_or_unsupported_input() {
    let item = entry();
    assert_eq!(item.issuer, "Example");
    assert_eq!(item.account, "alice@example.test");
    assert_eq!(item.digits, 6);
    assert_eq!(item.period, 30);
    assert_eq!(item.algorithm, "SHA1");
    let mixed = Entry::from_uri(
        "otpauth://totp/alice?secret=jbswy3dpehpk3pxp&algorithm=sha256&digits=8&period=60",
    )
    .unwrap();
    assert_eq!(mixed.secret, "JBSWY3DPEHPK3PXP");
    assert_eq!(mixed.algorithm, "SHA256");
    assert_eq!(mixed.period, 60);
    for uri in [
        "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=0",
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&secret=AAAAAAAAAAAAAAAA",
        "otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP&issuer=B",
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0",
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=7",
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        "otpauth://totp/a?secret=INVALID0",
        "otpauth://totp/a?secret=AA",
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&counter=3",
        "https://totp/a?secret=JBSWY3DPEHPK3PXP",
    ] {
        assert!(Entry::from_uri(uri).is_err());
    }
}

#[test]
fn malformed_envelopes_and_passwords_fail_without_panicking() {
    let (header, key, _) = fixture();
    for sealed in [
        Sealed {
            nonce: "".into(),
            ciphertext: "".into(),
        },
        Sealed {
            nonce: URL_SAFE_NO_PAD.encode([0_u8; 24]),
            ciphertext: URL_SAFE_NO_PAD.encode([0_u8; 15]),
        },
        Sealed {
            nonce: URL_SAFE_NO_PAD.encode([0_u8; 23]),
            ciphertext: URL_SAFE_NO_PAD.encode([0_u8; 16]),
        },
        Sealed {
            nonce: URL_SAFE_NO_PAD.encode([0_u8; 24]),
            ciphertext: "====".into(),
        },
    ] {
        assert!(open_bytes(key, header.vault_id, "state", &sealed).is_err());
    }
    assert!(matches!(create_vault(""), Err(Error::InvalidPassword)));
    assert!(matches!(
        create_vault(&"a".repeat(1025)),
        Err(Error::InvalidPassword)
    ));
}
