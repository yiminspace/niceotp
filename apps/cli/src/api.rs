use crate::store::{Local, Store};
use anyhow::{Context, Result, ensure};
use niceotp_protocol::*;
use reqwest::{Client, Method};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;

#[derive(Debug)]
struct HttpFailure {
    status: u16,
    code: String,
}
impl std::fmt::Display for HttpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}: {}", self.status, self.code)
    }
}
impl std::error::Error for HttpFailure {}

pub struct Api {
    client: Client,
    base: String,
    token: Option<String>,
}
impl Api {
    pub fn new(s: &Local) -> Result<Self> {
        let url = reqwest::Url::parse(&s.server)?;
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "Invalid server URL"
        );
        ensure!(
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))),
            "Server requires HTTPS (HTTP is only allowed on loopback)"
        );
        Ok(Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
            base: s.server.clone(),
            token: s.session.clone(),
        })
    }
    pub async fn call<I: Serialize + ?Sized, O: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        input: Option<&I>,
    ) -> Result<O> {
        let mut r = self.client.request(method, format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            r = r.bearer_auth(t);
        }
        if let Some(i) = input {
            r = r.json(i);
        }
        let mut response = r.send().await.map_err(|_| {
            anyhow::anyhow!("HTTP transport failed; a mutation may have committed. Retry sync.")
        })?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("Incomplete HTTP response; retry the operation"))?
        {
            ensure!(
                bytes.len() + chunk.len() <= 64 * 1024 * 1024,
                "Server response exceeds size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let code = serde_json::from_slice::<ApiError>(&bytes)
                .map(|e| e.code)
                .unwrap_or_else(|_| "http_error".into());
            // Do not print arbitrary response content: it may contain sensitive inputs.
            let safe: String = code
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(80)
                .collect();
            return Err(HttpFailure {
                status: status.as_u16(),
                code: safe,
            }
            .into());
        }
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(serde_json::from_slice(b"null")?);
        }
        serde_json::from_slice(&bytes).context("Invalid server response")
    }
}
pub async fn sync(store: &Store, s: &mut Local) -> Result<SyncResponse> {
    ensure!(s.session.is_some(), "Log in first");
    let api = Api::new(s)?;
    let vault: VaultState = api.call::<(), _>(Method::GET, "/v1/vault", None).await?;
    if let Some(old) = &s.vault {
        ensure!(
            old.header.vault_id == vault.header.vault_id,
            "Server vault identity changed; refusing to merge"
        );
    }
    s.vault = Some(vault);
    if s.inflight.is_none() {
        s.inflight = Some(SyncRequest {
            cursor: s.cursor,
            mutations: s.pending.iter().take(128).cloned().collect(),
        });
    }
    store.save(s)?;
    let result: SyncResponse = match api
        .call(Method::POST, "/v1/sync", s.inflight.as_ref())
        .await
    {
        Ok(result) => result,
        Err(error) => {
            if error
                .downcast_ref::<HttpFailure>()
                .is_some_and(|e| matches!(e.status, 400 | 401 | 403 | 404 | 409 | 413 | 422))
            {
                s.inflight = None;
                store.save(s)?;
            }
            return Err(error);
        }
    };
    let submitted = s.inflight.as_ref().context("Missing inflight request")?;
    let mut acknowledged = std::collections::HashSet::new();
    for a in &result.applied {
        ensure!(
            a.revision > 0
                && a.revision <= result.cursor
                && submitted
                    .mutations
                    .iter()
                    .any(|m| m.mutation_id == a.mutation_id)
                && acknowledged.insert(a.mutation_id),
            "Invalid mutation acknowledgement"
        );
    }
    for c in &result.conflicts {
        ensure!(
            submitted.mutations.iter().any(|m| m == &c.mutation)
                && acknowledged.insert(c.mutation.mutation_id),
            "Invalid conflict acknowledgement"
        );
    }
    ensure!(
        acknowledged.len() == submitted.mutations.len(),
        "Server did not acknowledge all mutations; retry sync"
    );
    ensure!(
        result.cursor >= s.cursor,
        "Server cursor rolled back; refusing to discard local state"
    );
    for change in &result.changes {
        ensure!(
            change.revision > 0 && change.revision <= result.cursor,
            "Invalid server revision"
        );
        s.items.insert(change.id, change.clone());
        for c in &mut s.conflicts {
            if c.mutation.id == change.id {
                c.current = Some(change.clone());
            }
        }
    }
    for a in &result.applied {
        s.pending.retain(|m| m.mutation_id != a.mutation_id);
    }
    for c in &result.conflicts {
        s.pending
            .retain(|m| m.mutation_id != c.mutation.mutation_id);
        s.conflicts.retain(|old| old.mutation.id != c.mutation.id);
        s.conflicts.push(c.clone());
    }
    s.cursor = result.cursor;
    s.inflight = None;
    store.save(s)?;
    Ok(result)
}
