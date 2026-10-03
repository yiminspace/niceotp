# v0.1 implementation contract

Independent implementation. No proprietary source or infrastructure is an input.

## Components
- `crates/protocol`: shared versioned JSON DTOs, no crypto or persistence.
- `crates/vault`: client-only cryptography, TOTP, backup format.
- `apps/server`: Axum/SQLx PostgreSQL, OIDC identity, opaque bearer sessions, opaque storage.
- `apps/cli`: clap/reqwest, encrypted local state, real HTTP, OIDC browser login.

## Server endpoints
- GET /health: {"status":"ok","version":"0.1.0"}; GET /ready checks DB.
- GET /v1/auth/config -> AuthConfig (configured issuer and public client_id).
- POST /v1/sessions SessionRequest -> SessionResponse: validate OIDC ID token signature,
  issuer, audience, expiry using configured discovery/JWKS; map (iss,sub) to local UUID.
- DELETE /v1/session: revoke current opaque session. All endpoints below require it.
- POST /v1/vault VaultHeader -> VaultState, 201; 409 if already exists.
- GET /v1/vault -> VaultState; 404 if absent.
- PUT /v1/vault UpdateVault -> VaultState: compare header revision; immutable vault_id.
- POST /v1/sync SyncRequest -> SyncResponse.

## Sync rules
Lock the authenticated user's vault row in one PostgreSQL transaction. Server-assigned
entry revisions increase under this lock (not client time or an unlocked global sequence).
Process explicit mutations even if cursor is current. Creation base_revision=0; edits and
deletion require the current revision. A permanent tombstone can never be changed again.
Mutation IDs deduplicate retries; reuse with a different body is an error. Conflicts are
reported and not applied, other valid operations commit together. SQL failure rolls back
all operations and revision/idempotency records. Return current rows newer than cursor and
the matching cursor under the same transaction. Retain tombstones and idempotency records.
Bound request bytes, mutation count, and ciphertext sizes. Limit one mutation per item per
request. Reject future/negative cursors and negative base revisions. No unbounded body logs.

## Client rules
Retain encrypted local changes until server confirms mutation IDs. A repeated edit before
sync keeps the original base revision but gets a fresh mutation ID; after an ambiguous
HTTP failure resolve that submitted operation before editing it again. Serialize local
commands with an exclusive process lock. Save atomically with private file permissions.
Track conflicts without dropping either version; use explicit local/remote resolution.
Never resurrect tombstones with the same ID. New IDs are used for intentional re-import.

## Client crypto API (to be implemented by vault crate)
`VaultKey` opaque 32-byte zeroizing type, no Debug.
`create_vault(password: &str) -> Result<(VaultHeader, VaultKey, String)>` returns recovery code.
`unlock_password(header: &VaultHeader, password: &str) -> Result<VaultKey>`
`unlock_recovery(header: &VaultHeader, recovery: &str) -> Result<VaultKey>`
`change_password(header: &mut VaultHeader, key: &VaultKey, password: &str) -> Result<()>`
`change_recovery(header: &mut VaultHeader, key: &VaultKey) -> Result<String>`
`seal_bytes(key: &VaultKey, vault_id: Uuid, context: &str, bytes: &[u8]) -> Result<Sealed>`
`open_bytes(key: &VaultKey, vault_id: Uuid, context: &str, sealed: &Sealed) -> Result<Vec<u8>>`
`VaultKey::from_bytes([u8;32])`, `VaultKey::as_bytes() -> &[u8;32]` only for OS keyring.
Public serializable `Entry {name:String, account:String, issuer:String, secret:String,
algorithm:String, digits:u32, period:u64, pinned:bool, trashed:bool}`.
`Entry::from_uri(&str) -> Result<Entry>`, `Entry::validate() -> Result<()>`,
`Entry::code_at(timestamp:u64) -> Result<String>` (RFC6238 SHA1/256/512, 6/8 digits).
`encrypt_entry(key, vault_id, item_id, &Entry) -> Result<Sealed>` and inverse `decrypt_entry`.
`Backup {format_version:u32, header:VaultHeader, items:Vec<ServerItem>}`. Entire backup
contents/authenticated manifest must be authenticated, not merely individual records. Let
vault agent define export/import API and coordinate with CLI agent before implementing.

Use XChaCha20-Poly1305 AEAD, Argon2id password wrapping (64 MiB, 3 passes, p=1 baseline),
OS randomness, base64url unpadded encoding; enforce bounded KDF parameters before allocating.
AAD binds protocol purpose, vault UUID, item UUID for entries. Recovery code is random 256
bits; password and recovery independently wrap the same vault key with distinct AAD.
No server plaintext keys. Wrong secrets/tampering fail closed. Local metadata can include
server URL, cursor and IDs; entry content/pending payloads are always encrypted at rest.

## Scope and release
macOS/Linux CLI; standard OIDC; Docker self-hosting. No WeChat UI/adapter, HOTP, sharing,
public hosted launch, old data migration, or compromised-key full rotation in v0.1.
Changing wrappers does not revoke old backups or copies of the vault key. Not independently
audited; do not claim operator-unreadability against malicious client updates or weak passwords.
