mod auth;
mod error;
mod storage;
mod vault;
use auth::Oidc;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use serde_json::json;
use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{env, sync::Arc, time::Duration};

pub struct App {
    db: PgPool,
    oidc: Oidc,
}
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("niceotp_server=info,sqlx=off")
        .init();
    if run().await.is_err() {
        tracing::error!(event = "startup_or_runtime_failure");
        std::process::exit(1);
    }
}
async fn run() -> anyhow::Result<()> {
    let opts = env::var("DATABASE_URL")?
        .parse::<PgConnectOptions>()?
        .disable_statement_logging();
    let db = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(opts)
        .await?;
    sqlx::migrate!().run(&db).await?;
    let oidc = Oidc::discover(
        env::var("OIDC_ISSUER")?,
        env::var("OIDC_CLIENT_ID")?,
        env::var("ALLOW_INSECURE_OIDC").as_deref() == Ok("true"),
    )
    .await?;
    let state = Arc::new(App {
        db: db.clone(),
        oidc,
    });
    let router = Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"status":"ok","version":env!("CARGO_PKG_VERSION")})) }),
        )
        .route("/ready", get(ready))
        .route("/v1/auth/config", get(auth::config))
        .route("/v1/sessions", post(auth::login))
        .route("/v1/session", delete(auth::logout))
        .route(
            "/v1/vault",
            get(vault::get).post(vault::create).put(vault::update),
        )
        .route("/v1/sync", post(vault::sync))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(axum::middleware::from_fn(request_boundary))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(
        env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into()),
    )
    .await?;
    tracing::info!(
        event = "server_started",
        version = env!("CARGO_PKG_VERSION")
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown())
        .await?;
    db.close().await;
    Ok(())
}
async fn ready(State(app): State<Arc<App>>) -> StatusCode {
    match tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query("SELECT 1").execute(&app.db),
    )
    .await
    {
        Ok(Ok(_)) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=term.recv()=>{} }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

async fn request_boundary(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let started = std::time::Instant::now();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|v| v.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".into());
    let mut response = match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await
    {
        Ok(response) => response,
        Err(_) => error::Error(StatusCode::GATEWAY_TIMEOUT, "request_timeout").into_response(),
    };
    if (response.status().is_client_error() || response.status().is_server_error())
        && response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        response = error::Error(response.status(), "invalid_request").into_response();
    }
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    tracing::info!(
        event = "request",
        route,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64
    );
    response
}
