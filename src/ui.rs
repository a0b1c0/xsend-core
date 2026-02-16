use axum::{
    extract::State,
    http::{HeaderMap, header},
    response::IntoResponse,
};

use crate::http::AppState;

pub async fn index(State(state): State<AppState>) -> impl IntoResponse {
    // UI uses an HttpOnly cookie for auth; users shouldn't have to handle tokens.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(
        header::SET_COOKIE,
        format!(
            "xsend_admin_token={}; HttpOnly; SameSite=Strict; Path=/",
            state.admin_token
        )
        .parse()
        .unwrap(),
    );
    (headers, include_str!("../web/index.html"))
}

pub async fn app_js() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/javascript; charset=utf-8".parse().unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    (headers, include_str!("../web/app.js"))
}
