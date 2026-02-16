use axum::{
    Json,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::json;

use crate::http::AppState;

fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    // Minimal cookie parsing: "a=b; c=d"
    for part in cookie_header.split(';') {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        if k.trim() == name {
            return Some(v.trim());
        }
    }
    None
}

pub fn generate_admin_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub async fn enforce_origin(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok());
    if let Some(origin) = origin {
        let allowed = state.allowed_origins.iter().any(|o| o == origin);
        if !allowed {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "forbidden origin" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

pub async fn require_admin(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let bearer_ok = auth
        .and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|token| token == state.admin_token);

    let cookie_ok = req
        .headers()
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| cookie_value(h, "xsend_admin_token"))
        .is_some_and(|token| token == state.admin_token);

    let ok = bearer_ok || cookie_ok;

    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid admin token" })),
        )
            .into_response();
    }

    next.run(req).await
}
