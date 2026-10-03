//! HTTP adapters: establish identity, decode typed requests, delegate atomic operations.
use crate::{App, auth::owner, error::Result, storage};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use niceotp_protocol::*;
use std::sync::Arc;

pub async fn create(
    State(app): State<Arc<App>>,
    h: HeaderMap,
    Json(input): Json<VaultHeader>,
) -> Result<(StatusCode, Json<VaultState>)> {
    let account = owner(&app, &h).await?;
    Ok((
        StatusCode::CREATED,
        Json(storage::create(&app.db, account, input).await?),
    ))
}
pub async fn get(State(app): State<Arc<App>>, h: HeaderMap) -> Result<Json<VaultState>> {
    Ok(Json(storage::get(&app.db, owner(&app, &h).await?).await?))
}
pub async fn update(
    State(app): State<Arc<App>>,
    h: HeaderMap,
    Json(input): Json<UpdateVault>,
) -> Result<Json<VaultState>> {
    Ok(Json(
        storage::update(&app.db, owner(&app, &h).await?, input).await?,
    ))
}
pub async fn sync(
    State(app): State<Arc<App>>,
    h: HeaderMap,
    Json(input): Json<SyncRequest>,
) -> Result<Json<SyncResponse>> {
    Ok(Json(
        storage::sync(&app.db, owner(&app, &h).await?, input).await?,
    ))
}
