# Architecture and protocol v1

The implementation is independently authored from NiceOTP requirements, public
Rust library documentation, and public standards. The server never links the
client cryptography crate.

```text
CLI: OIDC login / local entry operations / encrypted durable outbox / OS keyring
  -> shared protocol DTOs over HTTPS
Server: HTTP adapters -> authenticated identity -> atomic storage operations
  -> dedicated PostgreSQL database

Client-only vault crate: key wrapping / AEAD / RFC6238 / authenticated backup
```

`apps/server/src/vault.rs` contains thin HTTP adapters. `storage.rs` owns input
invariants and complete vault transactions. `auth.rs` verifies external identity
and issues/revokes opaque sessions. Configuration is assembled only at startup.
The CLI separates HTTP, encrypted local persistence, OIDC and command handling.
`crates/protocol` defines the actual Serde request/response types used on both ends;
real HTTP tests validate these contracts. There is no shared database model or
server decryption API.

## HTTP

JSON requests use `Content-Type: application/json`. Except health/readiness,
auth configuration and session creation, endpoints require `Authorization: Bearer
<opaque-session>`. User identity is never taken from a client-controlled user-ID
header. Unexpected JSON fields are rejected. Responses have `Cache-Control:
no-store`; errors use `{ "code": "stable_machine_code", "message": "safe text" }`.

| Method/path | Request | Success |
| --- | --- | --- |
| `GET /health` | — | `{status,version}` |
| `GET /ready` | — | 200 when PostgreSQL responds, 503 otherwise |
| `GET /v1/auth/config` | — | `{issuer,client_id}` |
| `POST /v1/sessions` | `{id_token}` | `{account_id,access_token,expires_at}` |
| `DELETE /v1/session` | — | 204; revokes the calling session |
| `POST /v1/vault` | `VaultHeader` | 201 `VaultState`; 409 if present |
| `GET /v1/vault` | — | `VaultState`; 404 if absent |
| `PUT /v1/vault` | `{base_revision,header}` | Updated `VaultState`; 409 on stale header |
| `POST /v1/sync` | `{cursor,mutations}` | `{cursor,changes,applied,conflicts}` |

The versioned types are defined in [`crates/protocol/src/lib.rs`](../crates/protocol/src/lib.rs).
`VaultState.revision` versions the key-wrapping header. Entry revisions and the
sync cursor are a separate sequence. Vault UUID cannot change through a header
update. Format version is 1; unsupported cryptographic versions fail closed.

## Mutation and cursor semantics

A mutation is `{mutation_id,id,base_revision,payload}`. Payload is an opaque
`{nonce,ciphertext}` envelope. A null payload means **permanent deletion**;
trash/pin/name are encrypted fields inside a live entry. Creation uses base
revision 0; edits and deletion require the last observed server revision.

For each request the server locks that account's vault row and performs one
transaction. It validates/deduplicates operations, writes rows and receipts,
advances the cursor, reads the delta, then commits. Revisions are assigned under
this lock, so an uncommitted lower revision cannot be skipped by another sync.
No client timestamps control updates or deletion.

- Explicit mutations are processed even when the cursor is already current.
- One mutation per item ID per batch, at most 128; negative/future cursors fail.
- A repeated mutation ID with the same request returns its outcome; changed bodies
  return 409. Conflicted mutations also reserve their IDs. Receipts retain a
  SHA-256 fingerprint of PostgreSQL-normalized request JSON, not historical entry
  ciphertext. Existing storage backups can still contain older encrypted records.
- Conflicts do not apply. Other valid mutations in that batch commit together.
  A request/storage error rolls back **all** changes, including receipt/cursor writes.
- A tombstone cannot be changed or recreated under the same ID, even with its
  current revision. An intentional re-import must allocate a fresh UUID.
- Delta rows contain the latest state of each changed item, not every intermediate
  event. The cursor and returned rows come from the same locked transaction.
- Owner identity scopes vaults, entries, receipts and sessions; UUID knowledge
  does not grant access to another account.

## Durable clients

A local profile stores ciphertext for entries, pending changes and conflicts.
Local IDs, revision metadata, the server URL and bearer session are plaintext in
private 0600 files inside a 0700 directory. The bearer grants ciphertext access
but cannot unlock the vault. One process holds an exclusive profile lock; state
updates use a new private file, fsync, atomic rename, and directory fsync.

Before sending a sync, the exact batch is saved as `inflight`. An ambiguous
transport/5xx failure keeps it, blocking edits until the identical request is
retried. A definitive HTTP rejection releases `inflight` while retaining pending
edits. Confirmed results, conflicts and cursor are saved together. Batches over
128 operations are drained sequentially. Responses must acknowledge every
submitted mutation exactly once before local changes are removed.

Concurrent edits keep local ciphertext alongside the remote version. Users pick
`local` or `remote`; selecting local creates a new mutation against the observed
remote revision. Remote permanent deletion cannot be overridden under that ID.

Header creation/update also reconciles a lost response with GET before reporting
success. Password/recovery changes wrap the same vault key; they do not revoke
already-unlocked devices, copied keys or old backups. Server rollback/withholding
and malicious client updates remain outside the cryptographic guarantee.
