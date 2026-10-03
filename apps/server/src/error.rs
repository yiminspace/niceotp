use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use niceotp_protocol::ApiError;

pub struct Error(pub StatusCode, pub &'static str);
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn bad(code: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, code)
    }
    pub fn conflict(code: &'static str) -> Self {
        Self(StatusCode::CONFLICT, code)
    }
    pub fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "unauthorized")
    }
    pub fn missing() -> Self {
        Self(StatusCode::NOT_FOUND, "vault_not_found")
    }
}
impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        tracing::error!(event = "storage_error");
        Self(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(ApiError {
                code: self.1.into(),
                message: self.1.replace('_', " "),
            }),
        )
            .into_response()
    }
}
