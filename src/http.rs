use std::path::PathBuf;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    discovery, fs, jobs, metrics, relay, relay_e2ee, relay_keys, security, sessions, transfers,
    ui,
};

#[derive(Clone)]
pub struct AppState {
    pub admin_token: String,
    pub allowed_origins: Vec<String>,
    pub daemon_id: Uuid,
    pub lan_port: u16,
    pub lan_endpoints: Vec<String>,
    pub wan_port: u16,
    pub wan_endpoints: Vec<String>,
    pub jobs: jobs::JobManager,
    pub sessions: sessions::SessionManager,
    pub transfers: transfers::TransferManager,
    pub relay_base_url: Option<String>,
    pub relay_keys: relay_keys::RelayKeyStore,
    pub relay_pair_pending: relay_keys::RelayPairPendingStore,
    pub discovery: discovery::DiscoveryService,
    pub metrics: metrics::Metrics,
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/info", get(api_info))
        .route("/metrics", get(api_metrics))
        .route("/fs/roots", get(list_fs_roots))
        .route("/fs/list", get(list_fs_dir))
        .route("/jobs", get(list_jobs).post(create_job))
        .route("/jobs/:id", get(get_job))
        .route("/jobs/:id/pause", post(pause_job))
        .route("/jobs/:id/resume", post(resume_job))
        .route("/jobs/:id/cancel", post(cancel_job))
        .route("/sessions", get(list_sessions))
        .route("/sessions/receive", post(create_receive_session))
        .route("/sessions/receive/:code", post(open_receive_session))
        .route("/transfers", get(list_transfers))
        .route("/transfers/send", post(create_send_transfer))
        .route("/transfers/send_wan", post(create_send_transfer_wan))
        .route("/transfers/send_by_code", post(create_send_transfer_by_code))
        .route("/transfers/:id", get(get_transfer))
        .route("/transfers/:id/cancel", post(cancel_transfer))
        .route("/peers", get(list_peers))
        .route("/relay/channel", post(create_relay_channel))
        .route("/relay/channel/:code", post(ensure_relay_channel))
        .route("/relay/channel/:code/files", post(relay_upload_bytes))
        .route("/relay/me/channel", get(relay_me_channel))
        .route("/relay/me/plan", get(relay_me_plan))
        .route("/relay/me/billing", get(relay_me_billing))
        .route("/relay/turn/credentials", get(relay_turn_credentials))
        .route("/relay/me/upload", post(relay_me_upload))
        .route("/relay/me/pull", post(relay_me_pull))
        .route("/relay/me/pull_all", post(relay_me_pull_all))
        .route("/relay/e2ee/status", get(relay_e2ee_status))
        .route("/relay/e2ee/pair/start", post(relay_e2ee_pair_start))
        .route("/relay/e2ee/pair/:code/send", post(relay_e2ee_pair_send))
        .route("/relay/e2ee/pair/:code/accept", post(relay_e2ee_pair_accept))
        .route("/relay/upload", post(relay_upload))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            observe_http_metrics,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::enforce_origin,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security::require_admin,
        ))
        .with_state(state.clone());

    Router::new()
        .route("/", get(ui::index))
        .route("/app.js", get(ui::app_js))
        .nest("/api/v1", api)
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct ApiInfo {
    version: &'static str,
    daemon_id: Uuid,
    lan_port: u16,
    lan_endpoints: Vec<String>,
    wan_port: u16,
    wan_endpoints: Vec<String>,
    relay_base_url: Option<String>,
    stats: jobs::JobManagerStats,
}

async fn api_info(State(state): State<AppState>) -> Json<ApiInfo> {
    let stats = state.jobs.stats().await;
    Json(ApiInfo {
        version: env!("CARGO_PKG_VERSION"),
        daemon_id: state.daemon_id,
        lan_port: state.lan_port,
        lan_endpoints: state.lan_endpoints.clone(),
        wan_port: state.wan_port,
        wan_endpoints: state.wan_endpoints.clone(),
        relay_base_url: state.relay_base_url.clone(),
        stats,
    })
}

async fn api_metrics(State(state): State<AppState>) -> Response {
    let body = state.metrics.render_prometheus();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn observe_http_metrics(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    state.metrics.observe_http_start();
    let res = next.run(req).await;
    state.metrics.observe_http_status(res.status().as_u16());
    res
}

async fn list_fs_roots() -> Json<Vec<fs::FsRoot>> {
    Json(fs::roots())
}

#[derive(Debug, Deserialize)]
struct FsListQuery {
    path: String,
}

async fn list_fs_dir(axum::extract::Query(q): axum::extract::Query<FsListQuery>) -> Response {
    let path = std::path::PathBuf::from(q.path);
    if !path.is_absolute() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "path must be absolute" })),
        )
            .into_response();
    }
    match fs::list_dir(&path).await {
        Ok(list) => Json(list).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn list_jobs(State(state): State<AppState>) -> Json<Vec<jobs::JobView>> {
    Json(state.jobs.list_jobs().await)
}

async fn get_job(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Ok(id) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid job id" })),
        )
            .into_response();
    };

    match state.jobs.get_job(id).await {
        Some(job) => Json(job).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "job not found" })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct CreateJobRequest {
    path: String,
    #[serde(default)]
    network: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateJobResponse {
    id: Uuid,
}

async fn create_job(State(state): State<AppState>, Json(req): Json<CreateJobRequest>) -> Response {
    let path = PathBuf::from(req.path);
    if !path.is_absolute() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "path must be absolute" })),
        )
            .into_response();
    }

    let network = match req.network.as_deref() {
        None | Some("lan") => jobs::Network::Lan,
        Some("wan") => jobs::Network::Wan,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "network must be 'lan' or 'wan'" })),
            )
                .into_response();
        }
    };

    match state.jobs.create_hash_file_job(path, network).await {
        Ok(id) => Json(CreateJobResponse { id }).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn pause_job(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Ok(jid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid job id" })),
        )
            .into_response();
    };
    if state.jobs.get_job(jid).await.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "job not found" })),
        )
            .into_response();
    }
    match state.jobs.pause(jid).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn resume_job(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Ok(jid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid job id" })),
        )
            .into_response();
    };
    if state.jobs.get_job(jid).await.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "job not found" })),
        )
            .into_response();
    }
    match state.jobs.resume(jid).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn cancel_job(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Ok(jid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid job id" })),
        )
            .into_response();
    };
    if state.jobs.get_job(jid).await.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "job not found" })),
        )
            .into_response();
    }
    match state.jobs.cancel(jid).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn list_sessions(State(state): State<AppState>) -> Json<Vec<sessions::ReceiveSessionView>> {
    Json(state.sessions.list_receive_sessions().await)
}

async fn create_receive_session(
    State(state): State<AppState>,
) -> Json<sessions::ReceiveSessionView> {
    state.metrics.inc_receive_sessions_created();
    Json(state.sessions.create_receive_session().await)
}

async fn open_receive_session(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Response {
    match state.sessions.open_receive_session(&code).await {
        Ok(view) => Json(view).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn list_transfers(State(state): State<AppState>) -> Json<Vec<transfers::TransferView>> {
    Json(state.transfers.list().await)
}

#[derive(Debug, Deserialize)]
struct CreateSendTransferRequest {
    addr: String,
    code: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct CreateSendTransferResponse {
    id: Uuid,
}

async fn create_send_transfer(
    State(state): State<AppState>,
    Json(req): Json<CreateSendTransferRequest>,
) -> Response {
    let Ok(addr) = req.addr.parse() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid addr (expected ip:port)" })),
        )
            .into_response();
    };
    if req.code.len() != 6 || !req.code.chars().all(|c| c.is_ascii_digit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid code (expected 6 digits)" })),
        )
            .into_response();
    }
    let req_path = req.path.clone();
    let path = std::path::PathBuf::from(&req_path);
    if !path.is_absolute() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "path must be absolute" })),
        )
            .into_response();
    }

    state.metrics.inc_transfer_send_requests();
    match state.transfers.create_send(addr, req.code, path).await {
        Ok(id) => Json(CreateSendTransferResponse { id }).into_response(),
        Err(err) => {
            state.metrics.inc_transfer_create_failures();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response()
        }
    }
}

async fn create_send_transfer_wan(
    State(state): State<AppState>,
    Json(req): Json<CreateSendTransferRequest>,
) -> Response {
    let Ok(addr) = req.addr.parse() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid addr (expected ip:port)" })),
        )
            .into_response();
    };
    if req.code.len() != 6 || !req.code.chars().all(|c| c.is_ascii_digit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid code (expected 6 digits)" })),
        )
            .into_response();
    }
    let path = std::path::PathBuf::from(req.path);
    if !path.is_absolute() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "path must be absolute" })),
        )
            .into_response();
    }

    state.metrics.inc_transfer_send_wan_requests();
    match state.transfers.create_send_wan(addr, req.code, path).await {
        Ok(id) => Json(CreateSendTransferResponse { id }).into_response(),
        Err(err) => {
            state.metrics.inc_transfer_create_failures();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreateSendTransferByCodeRequest {
    code: String,
    path: String,
}

async fn create_send_transfer_by_code(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateSendTransferByCodeRequest>,
) -> Response {
    let auto_req_id = Uuid::new_v4();
    if req.code.len() != 6 || !req.code.chars().all(|c| c.is_ascii_digit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid code (expected 6 digits)" })),
        )
            .into_response();
    }

    let req_path = req.path.clone();
    let path = std::path::PathBuf::from(&req_path);
    if !path.is_absolute() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "path must be absolute" })),
        )
            .into_response();
    }

    let relay_token = relay_token_header(&headers);
    let turn_accelerate = headers
        .get("x-turn-accelerate")
        .and_then(|h| h.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_relay = headers
        .get("x-relay-fallback")
        .and_then(|h| h.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let auto_relay_on_fail = headers
        .get("x-relay-auto-on-fail")
        .and_then(|h| h.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    state.metrics.inc_transfer_send_auto_requests();
    if turn_accelerate {
        state.metrics.inc_auto_route_turn_requested();
    }
    if force_relay {
        state.metrics.inc_auto_route_force_relay_requests();
    }
    let turn_preflight = if turn_accelerate {
        state.metrics.inc_turn_preflight_requests();
        if let Some(token) = relay_token.as_deref() {
            match fetch_relay_turn_credentials(&state, token, 600).await {
                Ok(v) => {
                    state.metrics.inc_turn_preflight_success();
                    let ice_server_count = v
                        .get("iceServers")
                        .and_then(|x| x.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    Some(json!({
                        "requested": true,
                        "ok": true,
                        "ice_server_count": ice_server_count
                    }))
                }
                Err(e) => {
                    state.metrics.inc_turn_preflight_failures();
                    Some(json!({ "requested": true, "ok": false, "error": e }))
                }
            }
        } else {
            state.metrics.inc_turn_preflight_failures();
            Some(json!({
                "requested": true,
                "ok": false,
                "error": "missing x-relay-token (sign in first)"
            }))
        }
    } else {
        None
    };
    let candidates = if force_relay {
        Vec::new()
    } else {
        state.discovery.candidate_routes().await
    };
    let lan_candidate_count = candidates.len() as u64;
    let wan_candidate_count = candidates.iter().filter(|c| c.wan_endpoint.is_some()).count() as u64;
    state
        .metrics
        .add_auto_route_candidates(lan_candidate_count, wan_candidate_count);
    tracing::info!(
        auto_req_id = %auto_req_id,
        turn_accelerate = turn_accelerate,
        force_relay = force_relay,
        auto_relay_on_fail = auto_relay_on_fail,
        lan_candidates = lan_candidate_count,
        wan_candidates = wan_candidate_count,
        "auto-route request received"
    );
    if candidates.is_empty() {
        state.metrics.inc_auto_route_no_candidates();
        if let Some(token) = relay_token {
            state.metrics.inc_relay_fallback_attempts();
            let relay_req = RelayMeUploadRequest {
                path: req_path.clone(),
                recursive: None,
                include_hidden: None,
                max_files: None,
            };
            match relay_me_upload_with_e2ee(&state, token, relay_req).await {
                Ok(value) => {
                    state.metrics.inc_relay_fallback_success();
                    tracing::info!(
                        auto_req_id = %auto_req_id,
                        mode = "relay_fallback",
                        reason = if force_relay { "forced" } else { "no_candidates" },
                        "auto-route fallback uploaded to relay"
                    );
                    return Json(json!({
                        "mode": "relay_fallback",
                        "message": if force_relay {
                            "relay fallback forced by client"
                        } else {
                            "no LAN peers discovered; uploaded to relay instead"
                        },
                        "relay": value,
                        "turn_preflight": turn_preflight
                    }))
                    .into_response();
                }
                Err(e) => {
                    state.metrics.inc_relay_fallback_failures();
                    state.metrics.inc_transfer_create_failures();
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": format!("no peers discovered; relay fallback failed: {e}") })),
                    )
                        .into_response();
                }
            }
        }
        state.metrics.inc_transfer_create_failures();
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "no peers discovered yet (try manual addr or wait a few seconds). relay fallback requires x-relay-token." })),
        )
            .into_response();
    }

    let auto_candidates = candidates
        .into_iter()
        .map(|c| transfers::AutoRouteCandidate {
            lan_addr: c.lan_endpoint,
            wan_addr: c.wan_endpoint,
        })
        .collect::<Vec<_>>();
    match state
        .transfers
        .create_send_auto(auto_candidates, req.code, path)
        .await
    {
        Ok(id) => {
            let armed = if !force_relay && auto_relay_on_fail {
                if let Some(token) = relay_token {
                    spawn_relay_fallback_on_transfer_failure(
                        state.clone(),
                        id,
                        token,
                        req_path.clone(),
                    );
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if armed {
                state.metrics.inc_auto_route_relay_auto_armed();
            }
            Json(json!({
                "id": id,
                "mode": "auto_route",
                "route_order": if turn_accelerate { json!(["lan", "wan", "turn", "relay"]) } else { json!(["lan", "wan", "relay"]) },
                "relay_fallback_armed": armed,
                "turn_preflight": turn_preflight
            }))
            .into_response()
        }
        Err(err) => {
            state.metrics.inc_transfer_create_failures();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response()
        }
    }
}

fn spawn_relay_fallback_on_transfer_failure(
    state: AppState,
    transfer_id: Uuid,
    relay_token: String,
    path: String,
) {
    tokio::spawn(async move {
        let Some(status) = state.transfers.wait_terminal_status(transfer_id).await else {
            return;
        };
        if status != transfers::TransferStatus::Failed {
            return;
        }

        let relay_req = RelayMeUploadRequest {
            path: path.clone(),
            recursive: None,
            include_hidden: None,
            max_files: None,
        };
        state.metrics.inc_relay_fallback_attempts();
        match relay_me_upload_with_e2ee(&state, relay_token, relay_req).await {
            Ok(v) => {
                state.metrics.inc_relay_fallback_success();
                tracing::info!(
                    transfer_id = %transfer_id,
                    mode = "relay_fallback",
                    relay = %v,
                    "auto route failed; uploaded to relay"
                );
            }
            Err(e) => {
                state.metrics.inc_relay_fallback_failures();
                tracing::warn!(
                    transfer_id = %transfer_id,
                    mode = "relay_fallback",
                    error = %e,
                    "auto route failed and relay fallback also failed"
                );
            }
        }
    });
}

async fn get_transfer(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Ok(id) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid transfer id" })),
        )
            .into_response();
    };
    match state.transfers.get(id).await {
        Some(t) => Json(t).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "transfer not found" })),
        )
            .into_response(),
    }
}

async fn list_peers(State(state): State<AppState>) -> Json<Vec<discovery::PeerView>> {
    Json(state.discovery.list_peers().await)
}

async fn cancel_transfer(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Ok(id) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid transfer id" })),
        )
            .into_response();
    };
    if state.transfers.get(id).await.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "transfer not found" })),
        )
            .into_response();
    }
    match state.transfers.cancel(id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

fn relay_token_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-relay-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

fn sanitize_filename_local(name: &str) -> String {
    let base = name
        .split(['/', '\\'])
        .last()
        .unwrap_or("file.bin")
        .trim();
    if base.is_empty() {
        return "file.bin".to_string();
    }
    base.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                c
            } else {
                '_'
            }
        })
        .take(180)
        .collect()
}

fn sanitize_relative_path_local(path: &str) -> Option<std::path::PathBuf> {
    let raw = path.trim();
    if raw.is_empty() {
        return None;
    }
    let mut out = std::path::PathBuf::new();
    let mut parts = 0usize;
    for seg in raw.split(['/', '\\']) {
        let s = seg.trim();
        if s.is_empty() || s == "." || s == ".." {
            continue;
        }
        let clean = sanitize_filename_local(s);
        if clean.is_empty() || clean == "." || clean == ".." {
            continue;
        }
        out.push(clean);
        parts += 1;
        if parts >= 32 {
            break;
        }
    }
    if parts == 0 { None } else { Some(out) }
}

async fn create_relay_channel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let client = client.with_bearer_token(token);

    match client.create_channel().await {
        Ok(meta) => Json(meta).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn ensure_relay_channel(
    State(state): State<AppState>,
    Path(code): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let client = client.with_bearer_token(token);

    match client.ensure_channel(&code).await {
        Ok(meta) => Json(meta).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct RelayUploadRequest {
    code: String,
    path: String,
}

async fn relay_upload(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RelayUploadRequest>,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let client = client.with_bearer_token(token);

    let path = std::path::PathBuf::from(req.path);
    if !path.is_absolute() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "path must be absolute" })),
        )
            .into_response();
    }

    match client.upload_file(&req.code, &path).await {
        Ok(out) => Json(out).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct RelayUploadQuery {
    name: Option<String>,
}

async fn relay_upload_bytes(
    State(state): State<AppState>,
    Path(code): Path<String>,
    axum::extract::Query(q): axum::extract::Query<RelayUploadQuery>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let client = client.with_bearer_token(token);

    let max_bytes = client
        .me_plan()
        .await
        .ok()
        .and_then(|p| p.limits.max_file_bytes)
        .unwrap_or(relay::RELAY_DEFAULT_MAX_FILE_BYTES);
    if body.len() as u64 > max_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": format!("file too large for current plan (max {} bytes)", max_bytes) })),
        )
            .into_response();
    }

    let filename = q.name.unwrap_or_else(|| "file.bin".to_string());
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream");

    match client
        .upload_bytes(&code, &filename, content_type, body.to_vec())
        .await
    {
        Ok(out) => Json(out).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn relay_me_channel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let client = client.with_bearer_token(token);

    match client.me_channel().await {
        Ok(view) => Json(view).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn relay_me_plan(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c.with_bearer_token(token),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    match client.me_plan().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn relay_me_billing(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c.with_bearer_token(token),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    match client.me_billing().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct RelayTurnQuery {
    ttl: Option<u64>,
}

async fn fetch_relay_turn_credentials(
    state: &AppState,
    token: &str,
    ttl: u64,
) -> Result<serde_json::Value, String> {
    let base = state
        .relay_base_url
        .clone()
        .ok_or_else(|| "XSEND_RELAY_BASE_URL not configured".to_string())?;
    let client = relay::RelayClient::new(base)
        .map_err(|e| e.to_string())?
        .with_bearer_token(token.to_string());
    client
        .turn_credentials(ttl.clamp(60, 172800))
        .await
        .map_err(|e| e.to_string())
}

async fn relay_turn_credentials(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<RelayTurnQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    state.metrics.inc_turn_credentials_requests();
    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            state.metrics.inc_turn_credentials_failures();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let ttl = q.ttl.unwrap_or(600).clamp(60, 172800);
    match fetch_relay_turn_credentials(&state, &token, ttl).await {
        Ok(v) => {
            state.metrics.inc_turn_credentials_success();
            Json(v).into_response()
        }
        Err(e) => {
            state.metrics.inc_turn_credentials_failures();
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct RelayMeUploadRequest {
    path: String,
    #[serde(default)]
    recursive: Option<bool>,
    #[serde(default)]
    include_hidden: Option<bool>,
    #[serde(default)]
    max_files: Option<usize>,
}

struct RelayMeUploadContext {
    client: relay::RelayClient,
    channel_code: String,
    file_key: [u8; 32],
    max_plain_bytes: u64,
    max_transport_bytes: u64,
    remaining_slots: Option<usize>,
}

#[derive(Debug, Serialize)]
struct RelayBatchItemResult {
    path: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<relay::RelayFileView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn is_hidden_name(name: &str) -> bool {
    name.starts_with('.')
}

async fn collect_relay_upload_files(
    root: &std::path::Path,
    recursive: bool,
    include_hidden: bool,
    scan_cap: usize,
) -> Result<Vec<std::path::PathBuf>, String> {
    use std::collections::VecDeque;

    let mut dirs = VecDeque::new();
    dirs.push_back(root.to_path_buf());
    let mut out: Vec<std::path::PathBuf> = Vec::new();

    while let Some(dir) = dirs.pop_front() {
        let mut rd = tokio::fs::read_dir(&dir)
            .await
            .map_err(|e| format!("read dir failed ({}): {e}", dir.to_string_lossy()))?;
        loop {
            let ent = rd
                .next_entry()
                .await
                .map_err(|e| format!("read dir entry failed ({}): {e}", dir.to_string_lossy()))?;
            let Some(ent) = ent else { break };
            let p = ent.path();
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if !include_hidden && is_hidden_name(&name) {
                continue;
            }
            let ft = ent
                .file_type()
                .await
                .map_err(|e| format!("read file type failed ({}): {e}", p.to_string_lossy()))?;
            if ft.is_file() {
                out.push(p);
                if out.len() >= scan_cap {
                    out.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
                    return Ok(out);
                }
            } else if ft.is_dir() && recursive {
                dirs.push_back(p);
            }
        }
    }

    out.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    Ok(out)
}

async fn build_relay_upload_ctx(
    state: &AppState,
    token: String,
    channel_hint: Option<&relay::RelayChannelView>,
) -> Result<RelayMeUploadContext, String> {
    let Some(base) = state.relay_base_url.clone() else {
        return Err("XSEND_RELAY_BASE_URL not configured".to_string());
    };

    let client = relay::RelayClient::new(base)
        .map_err(|e| format!("invalid relay base url: {e}"))?
        .with_bearer_token(token);

    let plan = client.me_plan().await.ok();
    let max_plain_bytes = plan
        .as_ref()
        .and_then(|p| p.limits.max_file_bytes)
        .unwrap_or(relay::RELAY_DEFAULT_MAX_FILE_BYTES);
    let channel = if let Some(h) = channel_hint {
        h.clone()
    } else {
        client
            .me_channel()
            .await
            .map_err(|e| format!("fetch relay channel failed: {e}"))?
    };
    let code = channel.channel.code.clone();
    let file_key = state
        .relay_keys
        .get_or_create(&code)
        .await
        .map_err(|e| format!("prepare relay key failed: {e}"))?;
    let remaining_slots = channel
        .limits
        .as_ref()
        .and_then(|l| l.max_files)
        .map(|max| max as usize)
        .map(|max| max.saturating_sub(channel.files.len()));
    let e2ee_overhead = plan
        .as_ref()
        .and_then(|p| p.limits.e2ee_overhead_bytes)
        .unwrap_or(relay::RELAY_E2EE_OVERHEAD_BYTES);
    let max_transport_bytes = max_plain_bytes.saturating_add(e2ee_overhead);
    Ok(RelayMeUploadContext {
        client,
        channel_code: code,
        file_key,
        max_plain_bytes,
        max_transport_bytes,
        remaining_slots,
    })
}

async fn relay_me_upload_one_with_ctx(
    ctx: &RelayMeUploadContext,
    path: &std::path::Path,
    filename: Option<String>,
    relative_path: Option<String>,
) -> Result<relay::RelayUploadResult, String> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| format!("stat file failed: {e}"))?;
    if !meta.is_file() {
        return Err("path is not a regular file".to_string());
    }
    if meta.len() > ctx.max_plain_bytes {
        return Err(format!(
            "file too large for current plan (max {} bytes)",
            ctx.max_plain_bytes
        ));
    }

    let filename = filename.unwrap_or_else(|| {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(sanitize_filename_local)
            .unwrap_or_else(|| "file.bin".to_string())
    });
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| format!("read file failed: {e}"))?;

    let env = relay_e2ee::RelayFileEnvelope {
        filename: filename.clone(),
        content_type: "application/octet-stream".to_string(),
        data: bytes,
    };
    let encrypted = relay_e2ee::encrypt_file_envelope(&ctx.file_key, &env)
        .map_err(|e| format!("encrypt file failed: {e}"))?;
    if encrypted.len() as u64 > ctx.max_transport_bytes {
        return Err(
            "encrypted payload exceeds transport quota; pick a slightly smaller file".to_string(),
        );
    }

    ctx.client
        .upload_bytes_me_e2ee(
            &filename,
            "application/octet-stream",
            encrypted,
            Some(ctx.max_transport_bytes),
            relative_path.as_deref(),
        )
        .await
        .map_err(|e| format!("relay upload failed: {e}"))
}

async fn relay_me_upload_with_e2ee(
    state: &AppState,
    token: String,
    req: RelayMeUploadRequest,
) -> Result<serde_json::Value, String> {
    let path = std::path::PathBuf::from(req.path);
    if !path.is_absolute() {
        return Err("path must be absolute".to_string());
    }

    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|e| format!("stat path failed: {e}"))?;

    if meta.is_file() {
        let ctx = build_relay_upload_ctx(state, token, None).await?;
        let out = relay_me_upload_one_with_ctx(&ctx, &path, None, None).await?;
        return Ok(json!({
            "mode": "file",
            "file": out.file,
            "encrypted": true,
            "channel_code": ctx.channel_code
        }));
    }

    if !meta.is_dir() {
        return Err("path must be a regular file or directory".to_string());
    }

    let recursive = req.recursive.unwrap_or(true);
    let include_hidden = req.include_hidden.unwrap_or(false);
    let scan_cap = req.max_files.unwrap_or(1000).clamp(1, 5000);
    let mut files = collect_relay_upload_files(&path, recursive, include_hidden, scan_cap).await?;
    if files.is_empty() {
        return Err("directory has no regular files".to_string());
    }

    let ctx = build_relay_upload_ctx(state, token, None).await?;
    let mut truncated_by_slots = false;
    if let Some(slots) = ctx.remaining_slots {
        if slots == 0 {
            return Err("relay file limit reached".to_string());
        }
        if files.len() > slots {
            files.truncate(slots);
            truncated_by_slots = true;
        }
    }

    let mut uploaded = 0usize;
    let mut failed = 0usize;
    let mut stopped_on_limit = false;
    let mut results: Vec<RelayBatchItemResult> = Vec::new();

    for file in files {
        let rel_path = file
            .strip_prefix(&path)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| file.to_string_lossy().to_string());
        let rel_path = rel_path.replace('\\', "/");
        let fname = file
            .file_name()
            .and_then(|n| n.to_str())
            .map(sanitize_filename_local)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "file.bin".to_string());
        match relay_me_upload_one_with_ctx(&ctx, &file, Some(fname), Some(rel_path.clone())).await {
            Ok(out) => {
                uploaded += 1;
                results.push(RelayBatchItemResult {
                    path: rel_path,
                    status: "uploaded".to_string(),
                    file: Some(out.file),
                    error: None,
                });
            }
            Err(e) => {
                failed += 1;
                let lower = e.to_ascii_lowercase();
                let is_quota_limit = lower.contains("file limit reached")
                    || lower.contains("total storage limit reached");
                results.push(RelayBatchItemResult {
                    path: rel_path,
                    status: if is_quota_limit {
                        "stopped".to_string()
                    } else {
                        "failed".to_string()
                    },
                    file: None,
                    error: Some(e),
                });
                if is_quota_limit {
                    stopped_on_limit = true;
                    break;
                }
            }
        }
    }

    Ok(json!({
        "mode": "dir",
        "root": path.to_string_lossy().to_string(),
        "encrypted": true,
        "channel_code": ctx.channel_code,
        "summary": {
            "uploaded": uploaded,
            "failed": failed,
            "truncated_by_slots": truncated_by_slots,
            "stopped_on_limit": stopped_on_limit
        },
        "results": results
    }))
}

async fn relay_me_upload(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RelayMeUploadRequest>,
) -> Response {
    state.metrics.inc_relay_upload_requests();
    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            state.metrics.inc_relay_upload_failures();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };
    match relay_me_upload_with_e2ee(&state, token, req).await {
        Ok(v) => {
            state.metrics.inc_relay_upload_success();
            let uploaded_files = v
                .get("summary")
                .and_then(|s| s.get("uploaded"))
                .and_then(|n| n.as_u64())
                .or_else(|| {
                    if v.get("mode").and_then(|m| m.as_str()) == Some("file") {
                        Some(1)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            state.metrics.add_relay_uploaded_files(uploaded_files);
            Json(v).into_response()
        }
        Err(msg) => {
            state.metrics.inc_relay_upload_failures();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": msg })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct RelayMePullRequest {
    id: String,
}

#[derive(Debug, Serialize)]
struct RelayMePullResponse {
    save_path: String,
    filename: String,
}

fn relay_download_dir() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    home.join(".xsend").join("downloads").join("relay")
}

async fn unique_dest_path(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let base = dir.join(filename);
    if tokio::fs::metadata(&base).await.is_err() {
        return base;
    }

    let p = std::path::Path::new(filename);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = p.extension().and_then(|s| s.to_str());
    for i in 1..=999usize {
        let name = match ext {
            Some(ext) if !ext.is_empty() => format!("{stem} ({i}).{ext}"),
            _ => format!("{stem} ({i})"),
        };
        let cand = dir.join(name);
        if tokio::fs::metadata(&cand).await.is_err() {
            return cand;
        }
    }

    // Fallback: overwrite the base (should be extremely rare).
    base
}

fn decrypt_relay_downloaded_file(
    maybe_key: Option<[u8; 32]>,
    mut file: relay::RelayDownloadedFile,
) -> Result<relay::RelayDownloadedFile, String> {
    let decrypted = match maybe_key {
        Some(k) => relay_e2ee::decrypt_file_envelope(&k, &file.bytes),
        None => {
            if file.bytes.starts_with(b"XSR1") {
                return Err(
                    "encrypted file detected but no local relay key; pair your device first"
                        .to_string(),
                );
            }
            Ok(None)
        }
    };

    if let Ok(Some(env)) = decrypted {
        file.filename = sanitize_filename_local(&env.filename);
        file.bytes = env.data;
        Ok(file)
    } else if let Err(e) = decrypted {
        Err(format!("decrypt failed: {e}"))
    } else {
        Ok(file)
    }
}

async fn relay_me_pull(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RelayMePullRequest>,
) -> Response {
    state.metrics.inc_relay_pull_requests();
    let Some(base) = state.relay_base_url.clone() else {
        state.metrics.inc_relay_pull_failures();
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            state.metrics.inc_relay_pull_failures();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c,
        Err(e) => {
            state.metrics.inc_relay_pull_failures();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let client = client.with_bearer_token(token);

    let id = req.id.trim();
    if id.is_empty() {
        state.metrics.inc_relay_pull_failures();
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "missing file id" })),
        )
            .into_response();
    }

    let channel = match client.me_channel().await {
        Ok(v) => v,
        Err(e) => {
            state.metrics.inc_relay_pull_failures();
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("fetch relay channel failed: {e}") })),
            )
                .into_response();
        }
    };
    let rel_hint = channel
        .files
        .iter()
        .find(|f| f.id == id)
        .and_then(|f| f.relative_path.clone());
    let code = channel.channel.code;

    let file = match client.download_bytes_me(id).await {
        Ok(f) => f,
        Err(e) => {
            state.metrics.inc_relay_pull_failures();
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let maybe_key = state.relay_keys.get(&code).await;
    let file = match decrypt_relay_downloaded_file(maybe_key, file) {
        Ok(v) => v,
        Err(e) => {
            state.metrics.inc_relay_pull_failures();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e })),
            )
                .into_response();
        }
    };

    let dir = relay_download_dir();
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        state.metrics.inc_relay_pull_failures();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("create download dir failed: {e}") })),
        )
            .into_response();
    }
    let mut save_dir = dir.clone();
    let mut save_name = file.filename.clone();
    if let Some(rel) = rel_hint
        .as_deref()
        .and_then(sanitize_relative_path_local)
    {
        if let Some(parent) = rel.parent() {
            if !parent.as_os_str().is_empty() {
                save_dir = dir.join(parent);
            }
        }
        if let Some(name) = rel.file_name().and_then(|n| n.to_str()) {
            let n = sanitize_filename_local(name);
            if !n.is_empty() {
                save_name = n;
            }
        }
    }
    if let Err(e) = tokio::fs::create_dir_all(&save_dir).await {
        state.metrics.inc_relay_pull_failures();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("create nested dir failed: {e}") })),
        )
            .into_response();
    }
    let dest = unique_dest_path(&save_dir, &save_name).await;
    if let Err(e) = tokio::fs::write(&dest, &file.bytes).await {
        state.metrics.inc_relay_pull_failures();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("write file failed: {e}") })),
        )
            .into_response();
    }

    state.metrics.inc_relay_pull_success();
    state.metrics.add_relay_pull_files(1);
    Json(RelayMePullResponse {
        save_path: dest.to_string_lossy().to_string(),
        filename: file.filename,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
struct RelayMePullAllRequest {
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct RelayMePullAllItem {
    id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    save_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct RelayMePullAllResponse {
    save_dir: String,
    channel_code: String,
    downloaded: usize,
    failed: usize,
    items: Vec<RelayMePullAllItem>,
}

async fn relay_me_pull_all(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RelayMePullAllRequest>,
) -> Response {
    state.metrics.inc_relay_pull_requests();
    let Some(base) = state.relay_base_url.clone() else {
        state.metrics.inc_relay_pull_failures();
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };

    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            state.metrics.inc_relay_pull_failures();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };

    let client = match relay::RelayClient::new(base) {
        Ok(c) => c.with_bearer_token(token),
        Err(e) => {
            state.metrics.inc_relay_pull_failures();
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let channel = match client.me_channel().await {
        Ok(v) => v,
        Err(e) => {
            state.metrics.inc_relay_pull_failures();
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("fetch relay channel failed: {e}") })),
            )
                .into_response();
        }
    };
    let code = channel.channel.code.clone();

    let mut files = channel.files.clone();
    files.sort_by(|a, b| a.uploaded_at_ms.cmp(&b.uploaded_at_ms));
    let limit = req.limit.unwrap_or(files.len()).clamp(0, 2000);
    if files.len() > limit {
        files.truncate(limit);
    }

    let dir = relay_download_dir().join(&code);
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        state.metrics.inc_relay_pull_failures();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("create download dir failed: {e}") })),
        )
            .into_response();
    }

    let maybe_key = state.relay_keys.get(&code).await;
    let mut downloaded = 0usize;
    let mut failed = 0usize;
    let mut items: Vec<RelayMePullAllItem> = Vec::new();

    for f in files {
        let id = f.id.clone();
        let downloaded_file = match client.download_bytes_me(&id).await {
            Ok(v) => v,
            Err(e) => {
                failed += 1;
                items.push(RelayMePullAllItem {
                    id,
                    status: "failed".to_string(),
                    filename: Some(f.filename.clone()),
                    save_path: None,
                    error: Some(e.to_string()),
                });
                continue;
            }
        };
        let downloaded_file = match decrypt_relay_downloaded_file(maybe_key, downloaded_file) {
            Ok(v) => v,
            Err(e) => {
                failed += 1;
                items.push(RelayMePullAllItem {
                    id,
                    status: "failed".to_string(),
                    filename: Some(f.filename.clone()),
                    save_path: None,
                    error: Some(e),
                });
                continue;
            }
        };
        let mut save_dir = dir.clone();
        let mut save_name = downloaded_file.filename.clone();
        if let Some(rel) = f
            .relative_path
            .as_deref()
            .and_then(sanitize_relative_path_local)
        {
            if let Some(parent) = rel.parent() {
                if !parent.as_os_str().is_empty() {
                    save_dir = dir.join(parent);
                }
            }
            if let Some(name) = rel.file_name().and_then(|n| n.to_str()) {
                let n = sanitize_filename_local(name);
                if !n.is_empty() {
                    save_name = n;
                }
            }
        }
        if let Err(e) = tokio::fs::create_dir_all(&save_dir).await {
            failed += 1;
            items.push(RelayMePullAllItem {
                id,
                status: "failed".to_string(),
                filename: Some(downloaded_file.filename),
                save_path: Some(save_dir.to_string_lossy().to_string()),
                error: Some(format!("create nested dir failed: {e}")),
            });
            continue;
        }
        let dest = unique_dest_path(&save_dir, &save_name).await;
        if let Err(e) = tokio::fs::write(&dest, &downloaded_file.bytes).await {
            failed += 1;
            items.push(RelayMePullAllItem {
                id,
                status: "failed".to_string(),
                filename: Some(downloaded_file.filename),
                save_path: Some(dest.to_string_lossy().to_string()),
                error: Some(format!("write file failed: {e}")),
            });
            continue;
        }
        downloaded += 1;
        items.push(RelayMePullAllItem {
            id,
            status: "downloaded".to_string(),
            filename: Some(downloaded_file.filename),
            save_path: Some(dest.to_string_lossy().to_string()),
            error: None,
        });
    }

    if downloaded > 0 {
        state.metrics.inc_relay_pull_success();
        state.metrics.add_relay_pull_files(downloaded as u64);
    }
    if failed > 0 {
        for _ in 0..failed {
            state.metrics.inc_relay_pull_failures();
        }
    }

    Json(RelayMePullAllResponse {
        save_dir: dir.to_string_lossy().to_string(),
        channel_code: code,
        downloaded,
        failed,
        items,
    })
    .into_response()
}

#[derive(Debug, Serialize)]
struct RelayE2eeStatusResponse {
    channel_code: String,
    has_key: bool,
    key_fingerprint: Option<String>,
}

async fn relay_e2ee_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };
    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };
    let client = match relay::RelayClient::new(base) {
        Ok(c) => c.with_bearer_token(token),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let channel = match client.me_channel().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let code = channel.channel.code;
    let key = state.relay_keys.get(&code).await;
    let fp = key.map(|k| hex::encode(&k[0..8]));
    Json(RelayE2eeStatusResponse {
        channel_code: code,
        has_key: key.is_some(),
        key_fingerprint: fp,
    })
    .into_response()
}

async fn relay_e2ee_pair_start(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };
    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };
    let client = match relay::RelayClient::new(base) {
        Ok(c) => c.with_bearer_token(token),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let pubkey = relay_e2ee::x25519_public_from_secret(secret);
    let pubkey_b64 = relay_e2ee::b64url_encode(&pubkey);

    let out = match client.e2ee_pair_start(&pubkey_b64).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    if let Err(e) = state
        .relay_pair_pending
        .insert(&out.code, secret, out.expires_at_ms)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("store pair state failed: {e}") })),
        )
            .into_response();
    }

    Json(json!({
      "ok": true,
      "pair_code": out.code,
      "expires_at_ms": out.expires_at_ms
    }))
    .into_response()
}

async fn relay_e2ee_pair_send(
    State(state): State<AppState>,
    Path(code): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };
    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };
    let client = match relay::RelayClient::new(base) {
        Ok(c) => c.with_bearer_token(token),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let channel = match client.me_channel().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let my_code = channel.channel.code;
    let file_key = match state.relay_keys.get_or_create(&my_code).await {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("load local key failed: {e}") })),
            )
                .into_response();
        }
    };

    let info = match client.e2ee_pair_info(&code).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let Some(peer_pub_b64) = info.pubkey else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "pair target is not ready yet (missing receiver pubkey)" })),
        )
            .into_response();
    };

    let peer_pub = match relay_e2ee::b64url_decode(&peer_pub_b64) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("invalid receiver pubkey from relay: {e}") })),
            )
                .into_response();
        }
    };
    if peer_pub.len() != 32 {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": "invalid receiver pubkey length" })),
        )
            .into_response();
    }
    let mut peer_pub_arr = [0u8; 32];
    peer_pub_arr.copy_from_slice(&peer_pub);

    let mut sender_secret = [0u8; 32];
    OsRng.fill_bytes(&mut sender_secret);
    let sender_pub = relay_e2ee::x25519_public_from_secret(sender_secret);
    let shared = relay_e2ee::x25519_shared(sender_secret, peer_pub_arr);
    let wrap_key = match relay_e2ee::derive_pair_wrap_key(shared) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("derive wrap key failed: {e}") })),
            )
                .into_response();
        }
    };
    let (nonce, ciphertext) = match relay_e2ee::encrypt_pair_file_key(&wrap_key, &file_key) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("encrypt pair payload failed: {e}") })),
            )
                .into_response();
        }
    };

    if let Err(e) = client
        .e2ee_pair_complete(
            &code,
            &relay_e2ee::b64url_encode(&sender_pub),
            &relay_e2ee::b64url_encode(&nonce),
            &relay_e2ee::b64url_encode(&ciphertext),
        )
        .await
    {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    Json(json!({ "ok": true, "shared_channel_code": my_code }))
        .into_response()
}

async fn relay_e2ee_pair_accept(
    State(state): State<AppState>,
    Path(code): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(base) = state.relay_base_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "XSEND_RELAY_BASE_URL not configured" })),
        )
            .into_response();
    };
    let token = match relay_token_header(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "missing x-relay-token (sign in first)" })),
            )
                .into_response();
        }
    };
    let client = match relay::RelayClient::new(base) {
        Ok(c) => c.with_bearer_token(token),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let Some(secret) = state.relay_pair_pending.get_valid(&code).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "pair code not pending or already expired on this device" })),
        )
            .into_response();
    };

    let pair = match client.e2ee_pair_result(&code).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let sender_pub = match relay_e2ee::b64url_decode(&pair.sender_pubkey) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid sender pubkey: {e}") })),
            )
                .into_response();
        }
    };
    let nonce = match relay_e2ee::b64url_decode(&pair.nonce) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid nonce: {e}") })),
            )
                .into_response();
        }
    };
    let ciphertext = match relay_e2ee::b64url_decode(&pair.ciphertext) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid ciphertext: {e}") })),
            )
                .into_response();
        }
    };
    if sender_pub.len() != 32 || nonce.len() != 12 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid pair payload lengths" })),
        )
            .into_response();
    }
    let mut sender_pub_arr = [0u8; 32];
    sender_pub_arr.copy_from_slice(&sender_pub);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let shared = relay_e2ee::x25519_shared(secret, sender_pub_arr);
    let wrap_key = match relay_e2ee::derive_pair_wrap_key(shared) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("derive wrap key failed: {e}") })),
            )
                .into_response();
        }
    };
    let file_key = match relay_e2ee::decrypt_pair_file_key(&wrap_key, &nonce_arr, &ciphertext) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("decrypt pair payload failed: {e}") })),
            )
                .into_response();
        }
    };

    let channel = match client.me_channel().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let my_code = channel.channel.code;
    if let Err(e) = state.relay_keys.set(&my_code, file_key).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("save relay key failed: {e}") })),
        )
            .into_response();
    }
    state.relay_pair_pending.remove(&code).await;

    Json(json!({
      "ok": true,
      "channel_code": my_code,
      "key_fingerprint": hex::encode(&file_key[0..8])
    }))
    .into_response()
}
