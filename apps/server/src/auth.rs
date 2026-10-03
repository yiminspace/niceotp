use crate::{
    App,
    error::{Error, Result},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use niceotp_protocol::{AuthConfig, SessionRequest, SessionResponse};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct Oidc {
    pub issuer: String,
    pub client_id: String,
    jwks_uri: String,
    client: reqwest::Client,
    keys: RwLock<(Instant, JwkSet)>,
}
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}
#[derive(Deserialize)]
struct Claims {
    sub: String,
    azp: Option<String>,
    aud: serde_json::Value,
}
fn permitted(url: &str, insecure: bool) -> anyhow::Result<()> {
    let u = reqwest::Url::parse(url)?;
    anyhow::ensure!(
        u.username().is_empty() && u.password().is_none() && u.fragment().is_none(),
        "invalid OIDC URL"
    );
    let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    anyhow::ensure!(
        u.scheme() == "https" || (u.scheme() == "http" && (local || insecure)),
        "OIDC requires HTTPS"
    );
    Ok(())
}
impl Oidc {
    pub async fn discover(
        issuer: String,
        client_id: String,
        insecure: bool,
    ) -> anyhow::Result<Self> {
        permitted(&issuer, insecure)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        let d: Discovery = client
            .get(format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        anyhow::ensure!(d.issuer == issuer, "issuer mismatch");
        permitted(&d.jwks_uri, insecure)?;
        let keys = client
            .get(&d.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json::<JwkSet>()
            .await?;
        Ok(Self {
            issuer,
            client_id,
            jwks_uri: d.jwks_uri,
            client,
            keys: RwLock::new((Instant::now(), keys)),
        })
    }
    async fn subject(&self, token: &str) -> Result<String> {
        if token.len() > 16384 {
            return Err(Error::unauthorized());
        }
        let header = decode_header(token).map_err(|_| Error::unauthorized())?;
        if header.alg != Algorithm::RS256 {
            return Err(Error::unauthorized());
        }
        let kid = header.kid.ok_or_else(Error::unauthorized)?;
        {
            let mut keys = self.keys.write().await;
            if keys.0.elapsed() > Duration::from_secs(300) {
                let next = self
                    .client
                    .get(&self.jwks_uri)
                    .send()
                    .await
                    .map_err(|_| Error::unauthorized())?
                    .error_for_status()
                    .map_err(|_| Error::unauthorized())?
                    .json::<JwkSet>()
                    .await
                    .map_err(|_| Error::unauthorized())?;
                *keys = (Instant::now(), next);
            }
        }
        let keys = self.keys.read().await;
        let jwk = keys.1.find(&kid).ok_or_else(Error::unauthorized)?;
        let key = DecodingKey::from_jwk(jwk).map_err(|_| Error::unauthorized())?;
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[&self.issuer]);
        v.set_audience(&[&self.client_id]);
        v.required_spec_claims =
            HashSet::from(["exp".into(), "iss".into(), "aud".into(), "sub".into()]);
        v.validate_nbf = true;
        v.leeway = 30;
        let c = decode::<Claims>(token, &key, &v)
            .map_err(|_| Error::unauthorized())?
            .claims;
        let multiple_audiences = c.aud.as_array().is_some_and(|a| a.len() > 1);
        if c.sub.is_empty()
            || c.sub.len() > 1024
            || c.azp.as_ref().is_some_and(|a| a != &self.client_id)
            || (multiple_audiences && c.azp.is_none())
        {
            return Err(Error::unauthorized());
        }
        Ok(c.sub)
    }
}
pub fn token_hash(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(s.as_bytes()))
}
pub async fn owner(app: &App, h: &HeaderMap) -> Result<Uuid> {
    let token = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 43)
        .ok_or_else(Error::unauthorized)?;
    sqlx::query_scalar("SELECT account_id FROM sessions WHERE token_hash=$1 AND expires_at > now()")
        .bind(token_hash(token))
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(Error::unauthorized)
}
pub async fn config(State(app): State<Arc<App>>) -> Json<AuthConfig> {
    Json(AuthConfig {
        issuer: app.oidc.issuer.clone(),
        client_id: app.oidc.client_id.clone(),
    })
}
pub async fn login(
    State(app): State<Arc<App>>,
    Json(input): Json<SessionRequest>,
) -> Result<Json<SessionResponse>> {
    let subject = app.oidc.subject(&input.id_token).await?;
    let mut tx = app.db.begin().await?;
    let account:Uuid=sqlx::query_scalar("INSERT INTO accounts (id,issuer,subject) VALUES ($1,$2,$3) ON CONFLICT (issuer,subject) DO UPDATE SET subject=EXCLUDED.subject RETURNING id")
        .bind(Uuid::new_v4()).bind(&app.oidc.issuer).bind(subject).fetch_one(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE account_id=$1 AND expires_at <= now()")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT count(*) AS n FROM sessions WHERE account_id=$1")
        .bind(account)
        .fetch_one(&mut *tx)
        .await?;
    if row.get::<i64, _>("n") >= 50 {
        return Err(Error(StatusCode::TOO_MANY_REQUESTS, "session_limit"));
    }
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let expires = Utc::now() + ChronoDuration::days(30);
    sqlx::query("INSERT INTO sessions (token_hash,account_id,expires_at) VALUES ($1,$2,$3)")
        .bind(token_hash(&token))
        .bind(account)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(SessionResponse {
        account_id: account,
        access_token: token,
        expires_at: expires.to_rfc3339(),
    }))
}
pub async fn logout(State(app): State<Arc<App>>, h: HeaderMap) -> Result<StatusCode> {
    owner(&app, &h).await?;
    let token = h["authorization"]
        .to_str()
        .map_err(|_| Error::unauthorized())?
        .trim_start_matches("Bearer ");
    sqlx::query("DELETE FROM sessions WHERE token_hash=$1")
        .bind(token_hash(token))
        .execute(&app.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
