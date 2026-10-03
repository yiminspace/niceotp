//! Atomic vault operations. Every write transaction owns both data and sync revision changes.
use crate::error::{Error, Result};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use niceotp_protocol::*;
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use uuid::Uuid;

fn seal_valid(s: &Sealed) -> Result<()> {
    if s.ciphertext.len() > 24000
        || URL_SAFE_NO_PAD
            .decode(&s.nonce)
            .map_or(true, |v| v.len() != 24)
        || URL_SAFE_NO_PAD
            .decode(&s.ciphertext)
            .map_or(true, |v| v.len() < 16 || v.len() > 16400)
    {
        return Err(Error::bad("invalid_ciphertext"));
    }
    Ok(())
}
fn header_valid(h: &VaultHeader) -> Result<()> {
    let k = &h.password.kdf;
    if h.format_version != FORMAT_VERSION
        || h.vault_id.is_nil()
        || k.memory_kib < 65536
        || k.memory_kib > 262144
        || !(3..=10).contains(&k.iterations)
        || !(1..=4).contains(&k.parallelism)
        || u64::from(k.memory_kib) * u64::from(k.iterations) > 1048576
        || URL_SAFE_NO_PAD
            .decode(&k.salt)
            .map_or(true, |v| v.len() != 16)
    {
        return Err(Error::bad("invalid_vault_header"));
    }
    seal_valid(&h.password.sealed)?;
    seal_valid(&h.recovery)?;
    if URL_SAFE_NO_PAD
        .decode(&h.password.sealed.ciphertext)
        .map_or(true, |v| v.len() != 48)
        || URL_SAFE_NO_PAD
            .decode(&h.recovery.ciphertext)
            .map_or(true, |v| v.len() != 48)
    {
        return Err(Error::bad("invalid_key_envelope"));
    }
    Ok(())
}
pub async fn create(db: &PgPool, account: Uuid, header: VaultHeader) -> Result<VaultState> {
    header_valid(&header)?;
    let result =
        sqlx::query("INSERT INTO vaults (account_id,header) VALUES ($1,$2) ON CONFLICT DO NOTHING")
            .bind(account)
            .bind(sqlx::types::Json(&header))
            .execute(db)
            .await?;
    if result.rows_affected() == 0 {
        return Err(Error::conflict("vault_exists"));
    }
    Ok(VaultState {
        header,
        revision: 1,
    })
}
pub async fn get(db: &PgPool, account: Uuid) -> Result<VaultState> {
    let row = sqlx::query("SELECT header,header_revision FROM vaults WHERE account_id=$1")
        .bind(account)
        .fetch_optional(db)
        .await?
        .ok_or_else(Error::missing)?;
    Ok(VaultState {
        header: row.get::<sqlx::types::Json<VaultHeader>, _>("header").0,
        revision: row.get("header_revision"),
    })
}
pub async fn update(db: &PgPool, account: Uuid, input: UpdateVault) -> Result<VaultState> {
    header_valid(&input.header)?;
    let mut tx = db.begin().await?;
    let row =
        sqlx::query("SELECT header,header_revision FROM vaults WHERE account_id=$1 FOR UPDATE")
            .bind(account)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(Error::missing)?;
    let old = row.get::<sqlx::types::Json<VaultHeader>, _>("header").0;
    let revision: i64 = row.get("header_revision");
    if revision != input.base_revision {
        return Err(Error::conflict("header_conflict"));
    }
    if old.vault_id != input.header.vault_id {
        return Err(Error::bad("immutable_vault_id"));
    }
    sqlx::query(
        "UPDATE vaults SET header=$2,header_revision=header_revision+1 WHERE account_id=$1",
    )
    .bind(account)
    .bind(sqlx::types::Json(&input.header))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(VaultState {
        header: input.header,
        revision: revision + 1,
    })
}
fn item(row: sqlx::postgres::PgRow) -> ServerItem {
    ServerItem {
        id: row.get("id"),
        revision: row.get("revision"),
        payload: row
            .get::<Option<sqlx::types::Json<Sealed>>, _>("payload")
            .map(|v| v.0),
    }
}
pub async fn sync(db: &PgPool, account: Uuid, input: SyncRequest) -> Result<SyncResponse> {
    if input.cursor < 0 || input.mutations.len() > 128 {
        return Err(Error::bad("invalid_sync_request"));
    }
    let mut ids = HashSet::new();
    let mut ops = HashSet::new();
    for m in &input.mutations {
        if m.id.is_nil()
            || m.mutation_id.is_nil()
            || m.base_revision < 0
            || !ids.insert(m.id)
            || !ops.insert(m.mutation_id)
        {
            return Err(Error::bad("invalid_mutation"));
        }
        if let Some(p) = &m.payload {
            seal_valid(p)?;
        }
    }
    let mut tx = db.begin().await?;
    let mut cursor: i64 =
        sqlx::query_scalar("SELECT cursor FROM vaults WHERE account_id=$1 FOR UPDATE")
            .bind(account)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(Error::missing)?;
    if input.cursor > cursor {
        return Err(Error::bad("future_cursor"));
    }
    let mut applied = Vec::new();
    let mut conflicts = Vec::new();
    for m in input.mutations {
        let prior =
            sqlx::query("SELECT revision, request_hash=encode(sha256(convert_to($3::jsonb::text, 'UTF8')), 'hex') AS matches FROM mutations WHERE account_id=$1 AND id=$2")
                .bind(account)
                .bind(m.mutation_id)
                .bind(sqlx::types::Json(&m))
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(prior) = prior {
            if !prior.get::<bool, _>("matches") {
                return Err(Error::conflict("mutation_id_reused"));
            }
            let revision: i64 = prior.get("revision");
            if revision == 0 {
                let current = sqlx::query(
                    "SELECT id,revision,payload FROM items WHERE account_id=$1 AND id=$2",
                )
                .bind(account)
                .bind(m.id)
                .fetch_optional(&mut *tx)
                .await?
                .map(item);
                conflicts.push(Conflict {
                    mutation: m,
                    current,
                });
            } else {
                applied.push(Applied {
                    mutation_id: m.mutation_id,
                    revision,
                });
            }
            continue;
        }
        let current =
            sqlx::query("SELECT id,revision,payload FROM items WHERE account_id=$1 AND id=$2")
                .bind(account)
                .bind(m.id)
                .fetch_optional(&mut *tx)
                .await?
                .map(item);
        let conflict = match &current {
            Some(c) => c.payload.is_none() || c.revision != m.base_revision,
            None => m.base_revision != 0 || m.payload.is_none(),
        };
        if conflict {
            sqlx::query(
                "INSERT INTO mutations (account_id,id,request_hash,revision) VALUES ($1,$2,encode(sha256(convert_to($3::jsonb::text, 'UTF8')), 'hex'),0)",
            )
            .bind(account)
            .bind(m.mutation_id)
            .bind(sqlx::types::Json(&m))
            .execute(&mut *tx)
            .await?;
            conflicts.push(Conflict {
                mutation: m,
                current,
            });
            continue;
        }
        if current.is_none() {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM items WHERE account_id=$1")
                .bind(account)
                .fetch_one(&mut *tx)
                .await?;
            if count >= 1000 {
                return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "vault_item_limit"));
            }
        }
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| Error::bad("revision_exhausted"))?;
        sqlx::query("INSERT INTO items (account_id,id,revision,payload) VALUES ($1,$2,$3,$4) ON CONFLICT (account_id,id) DO UPDATE SET revision=EXCLUDED.revision,payload=EXCLUDED.payload")
            .bind(account).bind(m.id).bind(cursor).bind(m.payload.as_ref().map(sqlx::types::Json)).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mutations (account_id,id,request_hash,revision) VALUES ($1,$2,encode(sha256(convert_to($3::jsonb::text, 'UTF8')), 'hex'),$4)")
            .bind(account)
            .bind(m.mutation_id)
            .bind(sqlx::types::Json(&m))
            .bind(cursor)
            .execute(&mut *tx)
            .await?;
        applied.push(Applied {
            mutation_id: m.mutation_id,
            revision: cursor,
        });
    }
    sqlx::query("UPDATE vaults SET cursor=$2 WHERE account_id=$1")
        .bind(account)
        .bind(cursor)
        .execute(&mut *tx)
        .await?;
    let changes=sqlx::query("SELECT id,revision,payload FROM items WHERE account_id=$1 AND revision>$2 ORDER BY revision")
        .bind(account).bind(input.cursor).fetch_all(&mut *tx).await?.into_iter().map(item).collect();
    tx.commit().await?;
    Ok(SyncResponse {
        cursor,
        changes,
        applied,
        conflicts,
    })
}
