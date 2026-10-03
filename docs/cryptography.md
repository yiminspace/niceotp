# Client cryptography and portable backups

NiceOTP v0.1 encrypts on the client. The server receives encrypted entries and key
wrappers, never the vault password, recovery code, unwrapped vault key, or OTP
entry plaintext. OIDC authentication controls access to stored ciphertext; it is
independent from unlocking a vault. Password reset at the identity provider does
not recover a vault.

This is an independent implementation using public specifications and publicly
licensed RustCrypto dependencies. It has not undergone an independent security
audit. Weak passwords permit offline guessing of a copied password wrapper.
Malware, an unlocked client, or a malicious client update can access plaintext;
this design does not protect against those cases.

## Keys and wrappers

- The vault key is 32 random bytes from the operating system CSPRNG.
- Password wrapping uses Argon2id v0x13, a fresh 16-byte salt, 65,536 KiB memory,
  3 iterations and parallelism 1, producing a 32-byte wrapping key.
- Recovery codes are a separate 32 random bytes, encoded as 43-character unpadded
  base64url. The decoded recovery code is the recovery wrapping key; it is already
  high-entropy key material and needs no password KDF.
- Both wrappers independently encrypt the same vault key using
  XChaCha20-Poly1305 and a fresh random 24-byte nonce. AEAD purpose tags differ
  between password and recovery. Password AAD includes the KDF parameters.
- Encrypted records use the vault key and an independent random nonce for every
  encryption. Tags are appended to ciphertext by the RustCrypto AEAD API.
- All binary wire fields use RFC 4648 unpadded base64url. Decoding rejects invalid
  lengths, noncanonical trailing bits and malformed inputs.

Before allocating the Argon2 working memory, a client checks memory is between
65,536 and 262,144 KiB, iterations between 3 and 10, parallelism between 1 and 4,
and `memory_kib * iterations <= 1,048,576`. Salt length must be exactly 16 bytes.
The bounds prevent an untrusted header from requesting unbounded resources or a
weaker KDF. Passwords are nonempty and at most 1,024 bytes. Passwords are used as
supplied UTF-8 bytes, without Unicode normalization or trimming.

`VaultKey` is opaque, zeroizes on drop and implements neither `Debug`, `Clone`,
nor serialization. Its byte accessors exist solely for an OS keyring integration.
Temporary derived keys and serialized plaintext buffers are zeroizing wrappers;
plaintext `Entry` strings zeroize on drop. The library cannot promise erasure of
all compiler copies, caller-owned strings, URI parser internals, allocator
history, swap, HMAC implementation state or crash dumps. Callers must avoid
logging or otherwise persisting input passwords, provisioning URIs and entries.
Library error messages contain no supplied values.

## Authenticated context

The binary AEAD associated data is the concatenation of:

1. ASCII `niceotp`, zero byte, ASCII `v1`, zero byte;
2. a big-endian u32 purpose byte length, then the UTF-8 purpose;
3. the vault UUID's 16 bytes;
4. a big-endian u32 context byte length, then the context bytes.

Supported purposes and contexts:

| Purpose | Context |
| --- | --- |
| `password-wrap` | Compact JSON `KdfParams` in protocol field declaration order |
| `recovery-wrap` | Empty |
| `entry` | Item UUID's 16 bytes |
| `bytes` | Caller-supplied local-state context, e.g. `local-state:v1` |
| `backup-manifest` | Compact JSON of the entire exposed `VaultHeader` |

Length prefixes prevent tuple ambiguity. Separate purpose tags prevent a local
state envelope from being interpreted as an entry or key wrapper. Entry AEAD
binds both vault ID and item ID, so copying ciphertext between IDs fails. Format
versions other than 1 fail closed. Metadata outside authenticated entry content
such as server revisions is governed by the sync protocol; the server can delete
or withhold data and replay an older valid snapshot. This format does not provide
an externally anchored rollback-detection mechanism.

`seal_bytes` caps plaintext at 32 MiB and its context at 4 KiB. Entry serialization
is capped at 16 KiB. Decryption checks encoded size before allocating a decoded
ciphertext and rejects malformed nonce, tag or plaintext lengths.

## Portable backup format

The public in-memory `Backup` is:

```text
Backup { format_version: 1, header: VaultHeader, items: Vec<ServerItem> }
```

Do not persist that struct directly as the backup format. Use
`export_backup(&key, &backup)`, which produces this JSON envelope:

```json
{
  "format_version": 1,
  "header": { "format_version": 1, "vault_id": "...", "password": {}, "recovery": {} },
  "sealed": { "nonce": "...", "ciphertext": "..." }
}
```

The displayed header is schematic; actual password and recovery fields contain
the complete protocol wrappers. `sealed` encrypts the *entire* serialized Backup,
including its header, ordered item list, item UUIDs, revisions, record ciphertexts
and tombstones. The full exposed header is also included in AEAD AAD. After
successful decryption, the inner and outer headers must match. Therefore a party
without the vault key cannot remove, reorder, relabel or substitute individual
records, change a tombstone, or alter the unlock header without detection. An
attacker can still replace the whole file with an older valid backup.

The following APIs return errors on failed authentication and make no network
request:

```rust,ignore
export_backup(key: &VaultKey, backup: &Backup) -> Result<Vec<u8>>
import_backup(bytes: &[u8], key: &VaultKey) -> Result<Backup>
import_backup_password(bytes: &[u8], password: &str) -> Result<(Backup, VaultKey)>
import_backup_recovery(bytes: &[u8], recovery: &str) -> Result<(Backup, VaultKey)>
```

Import limits file size to 48 MiB, decrypted content to 32 MiB and item count to
10,000. Manifest validation rejects duplicate IDs and negative revisions;
revision 0 is allowed for unsynced local records. Each live payload is also
verified against its vault and item IDs and parsed as a valid Entry. Unknown JSON
fields are rejected. A restore into a new server vault should allocate fresh
item IDs and re-encrypt live records under those IDs before queuing creates;
server tombstones must never be resurrected using old IDs.

## Password change and recovery

`change_password` and `change_recovery` rewrap a supplied, already unlocked vault
key. Callers must supply the key unlocked from that vault. New wrapping completes
before changing the header, so an error leaves it unchanged. Neither operation
changes entry ciphertext or rotates the vault key. Recovery unlock intentionally
does not evaluate the password KDF, allowing a valid recovery wrapper to recover
a vault with a corrupted password wrapper. A portable backup, however, also
requires its full header authentication to succeed before accepting any records.

Store the recovery code separately from the vault and the device. It grants
complete vault access when paired with the matching header. If both the password
and recovery code are lost and no unlocked/keyring key remains, the server has no
means of recovering the entries. Replacing a wrapper does **not** revoke copied
old headers, old backups, or copies of the vault key. Full compromised-key
rotation is outside v0.1 scope.

## TOTP and provisioning

TOTP follows RFC 6238 with T0=0 and a 64-bit moving factor. HMAC-SHA1,
HMAC-SHA256 and HMAC-SHA512 are supported, with RFC 4226 dynamic truncation and
6 or 8 output digits. Provisioning defaults to SHA1, 6 digits and a 30-second
period. Periods from 1 through 86,400 seconds are accepted. Local clock accuracy
is the caller's responsibility.

`Entry::from_uri` accepts `otpauth://totp/` URIs, percent-decodes the label and
query values, checks label/parameter issuer agreement, and rejects duplicate or
unknown parameters and HOTP. Allowed parameters are `secret`, `issuer`,
`algorithm`, `digits` and `period`. Lowercase Base32 and correctly padded Base32
are accepted and normalized to uppercase unpadded Base32. Secrets must decode
to 10–1,024 bytes; 80-bit secrets are accepted for compatibility, while issuers
should generate at least 160 random bits. No account, label, secret or URI is
included in library error text.

## Verification and sources

`cargo test -p niceotp-vault` includes all 18 RFC 6238 Appendix B known-answer
vectors, their 6-digit truncations and timestamps beyond 2038; wrong passwords
and recovery keys; damaged envelopes; vault/item/purpose binding; independent
wrapper replacement; early KDF bounds; offline backup recovery; whole-manifest
and header tampering; malformed records; and provisioning parser rejection.

Public sources:

- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [RFC 4226: HOTP](https://www.rfc-editor.org/rfc/rfc4226)
- [RustCrypto XChaCha20-Poly1305 API](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/)
- [RustCrypto Argon2 API](https://docs.rs/argon2/0.5.3/argon2/)
- [Google Authenticator key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)

## Cross-language v1 fixture

[`crates/vault/tests/fixtures/v1.json`](../crates/vault/tests/fixtures/v1.json)
contains public deterministic keys, password, salt, nonces, derived wrapping key,
encoded AAD, plaintext JSON and expected ciphertexts for both key wrappers,
one entry, local state and a complete backup containing a tombstone. Every value
is synthetic test data. Never reuse these keys/nonces for real vaults.

An independent client should first reproduce the Argon2id wrapping key, then
verify byte-for-byte AAD and ciphertext equality, and finally import the complete
backup through both password and recovery paths. The fixture's
`plaintext_utf8` strings are the exact UTF-8 bytes to encrypt. Use unsigned
64-bit integers for TOTP moving factors; JavaScript implementations must avoid
32-bit bitwise conversions of the full time counter.

For AAD only, reconstruct the compact header/KDF JSON in this exact field order:

- `KdfParams`: `salt`, `memory_kib`, `iterations`, `parallelism`.
- `VaultHeader`: `format_version`, `vault_id`, `password`, `recovery`.
- Password envelope: `kdf`, `sealed`.
- Sealed envelope: `nonce`, `ciphertext`.

Encode UUIDs in canonical lowercase hyphenated form and numbers as decimal
integers, without whitespace. Do not use the input file's object-key order for
AAD: parsers may reorder JSON keys. Entry/backup plaintext field ordering need
not match for imports, but known-answer encryption comparisons must use the
fixture's exact plaintext bytes.

The test-only fixed-nonce helper is compiled only under `cfg(test)`; production
APIs have no injectable nonce or deterministic randomness option. Ordinary
`cargo test -p niceotp-vault` regenerates the expected values in memory and checks
the static fixture. Maintainers can explicitly regenerate public fixture data:

```sh
NICEOTP_UPDATE_PUBLIC_VECTOR=1 cargo test -p niceotp-vault public_v1_interoperability_vector
```

Review any resulting fixture diff as a protocol compatibility change. The fixture
validates format stability against this implementation; it is not a substitute
for verification by an independent cryptographic implementation.
