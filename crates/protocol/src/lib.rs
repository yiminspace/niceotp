//! Versioned, opaque wire types shared by independent clients and the server.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub salt: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordEnvelope {
    pub kdf: KdfParams,
    pub sealed: Sealed,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultHeader {
    pub format_version: u32,
    pub vault_id: Uuid,
    pub password: PasswordEnvelope,
    pub recovery: Sealed,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultState {
    pub header: VaultHeader,
    pub revision: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateVault {
    pub base_revision: i64,
    pub header: VaultHeader,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerItem {
    pub id: Uuid,
    pub revision: i64,
    /// None is a permanent tombstone, never a soft-delete/trash operation.
    pub payload: Option<Sealed>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub mutation_id: Uuid,
    pub id: Uuid,
    pub base_revision: i64,
    pub payload: Option<Sealed>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    pub cursor: i64,
    pub mutations: Vec<Mutation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applied {
    pub mutation_id: Uuid,
    pub revision: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub mutation: Mutation,
    pub current: Option<ServerItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncResponse {
    pub cursor: i64,
    pub changes: Vec<ServerItem>,
    pub applied: Vec<Applied>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub id_token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionResponse {
    pub account_id: Uuid,
    pub access_token: String,
    pub expires_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthConfig {
    pub issuer: String,
    pub client_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}
