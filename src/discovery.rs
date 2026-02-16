use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
#[cfg(not(target_family = "wasm"))]
use futures_util::{SinkExt, StreamExt};
use get_if_addrs::{IfAddr, get_if_addrs};
use serde::{Deserialize, Serialize};
#[cfg(not(target_family = "wasm"))]
use tokio::net::UdpSocket;
use tokio::{sync::Mutex, time};
#[cfg(not(target_family = "wasm"))]
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::warn;
use uuid::Uuid;

const DISCOVERY_PORT: u16 = 49_872;
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
const PEER_TTL: Duration = Duration::from_secs(10);
const SIGNAL_PRESENCE_KIND: &str = "xsend_discovery_v1";
const SIGNAL_RECONNECT_MIN: Duration = Duration::from_secs(1);
const SIGNAL_RECONNECT_MAX: Duration = Duration::from_secs(15);
const DEFAULT_SIGNAL_BASE_URL: &str = "https://relay.xsend.com";

#[derive(Debug, Clone, Serialize)]
pub struct PeerView {
    pub daemon_id: Uuid,
    // Legacy field kept for UI/backward compatibility; equals lan_endpoint.
    pub endpoint: String,
    pub lan_endpoint: String,
    pub wan_endpoint: Option<String>,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveryService {
    backend: DiscoveryBackend,
}

#[derive(Debug, Clone)]
enum DiscoveryBackend {
    Disabled,
    #[cfg(not(target_family = "wasm"))]
    NativeUdp(Arc<NativeUdpBackend>),
    WebSignaling(Arc<WebSignalingBackend>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryMode {
    NativeUdp,
    WebSignaling,
    Disabled,
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
struct NativeUdpBackend {
    self_id: Uuid,
    peers: Mutex<HashMap<Uuid, PeerInfo>>,
}

#[derive(Debug)]
struct WebSignalingBackend {
    peers: Mutex<HashMap<Uuid, PeerInfo>>,
    peer_ws_to_daemon: Mutex<HashMap<String, Uuid>>,
}

#[derive(Debug, Clone)]
struct PeerInfo {
    lan_endpoint: SocketAddr,
    wan_endpoint: Option<SocketAddr>,
    last_seen_ms: u64,
    // Monotonic clock for TTL calculation; immune to wall-clock jumps.
    last_seen_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscoveryMsgV1 {
    v: u8,
    daemon_id: Uuid,
    lan_port: u16,
    #[serde(default)]
    wan_port: Option<u16>,
    ts_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignalPresenceV1 {
    v: u8,
    daemon_id: Uuid,
    #[serde(default)]
    lan_endpoints: Vec<String>,
    #[serde(default)]
    wan_endpoints: Vec<String>,
    #[serde(default)]
    ts_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CandidateRoute {
    pub lan_endpoint: SocketAddr,
    pub wan_endpoint: Option<SocketAddr>,
}

impl DiscoveryMode {
    fn from_env() -> Self {
        let from_env = std::env::var("XSEND_DISCOVERY_MODE")
            .ok()
            .unwrap_or_default()
            .to_ascii_lowercase();

        match from_env.as_str() {
            "off" | "none" | "disabled" => Self::Disabled,
            "web" | "signaling" | "worker" => Self::WebSignaling,
            "udp" | "native" | "" => {
                if cfg!(target_family = "wasm") {
                    Self::WebSignaling
                } else {
                    Self::NativeUdp
                }
            }
            _ => {
                if cfg!(target_family = "wasm") {
                    Self::WebSignaling
                } else {
                    Self::NativeUdp
                }
            }
        }
    }
}

impl DiscoveryService {
    pub fn disabled() -> Self {
        Self {
            backend: DiscoveryBackend::Disabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self.backend, DiscoveryBackend::Disabled)
    }

    pub async fn start(self_id: Uuid, lan_port: u16, wan_port: u16) -> anyhow::Result<Self> {
        if lan_port == 0 && wan_port == 0 {
            return Ok(Self::disabled());
        }

        match DiscoveryMode::from_env() {
            DiscoveryMode::Disabled => Ok(Self::disabled()),
            DiscoveryMode::WebSignaling => {
                #[cfg(not(target_family = "wasm"))]
                {
                    Self::start_web_signaling(self_id, lan_port, wan_port).await
                }
                #[cfg(target_family = "wasm")]
                {
                    tracing::info!("discovery backend: web signaling (wasm placeholder)");
                    Ok(Self {
                        backend: DiscoveryBackend::WebSignaling(Arc::new(WebSignalingBackend {
                            peers: Mutex::new(HashMap::new()),
                            peer_ws_to_daemon: Mutex::new(HashMap::new()),
                        })),
                    })
                }
            }
            DiscoveryMode::NativeUdp => {
                #[cfg(not(target_family = "wasm"))]
                {
                    Self::start_native_udp(self_id, lan_port, wan_port).await
                }
                #[cfg(target_family = "wasm")]
                {
                    tracing::info!("discovery backend: web signaling (wasm fallback)");
                    Ok(Self {
                        backend: DiscoveryBackend::WebSignaling(Arc::new(WebSignalingBackend {
                            peers: Mutex::new(HashMap::new()),
                            peer_ws_to_daemon: Mutex::new(HashMap::new()),
                        })),
                    })
                }
            }
        }
    }

    #[cfg(not(target_family = "wasm"))]
    async fn start_native_udp(self_id: Uuid, lan_port: u16, wan_port: u16) -> anyhow::Result<Self> {
        let backend = Arc::new(NativeUdpBackend {
            self_id,
            peers: Mutex::new(HashMap::new()),
        });

        let sockets = match bind_discovery_sockets().await {
            Ok(v) => v,
            Err(err) => {
                warn!("discovery disabled (udp bind failed): {err:#}");
                return Ok(Self::disabled());
            }
        };

        for binding in &sockets {
            let rx_backend = Arc::clone(&backend);
            let rx_sock = Arc::clone(&binding.sock);
            tokio::spawn(async move {
                recv_loop(rx_backend, rx_sock).await;
            });
        }

        tokio::spawn(async move {
            send_loop(self_id, lan_port, wan_port, sockets).await;
        });

        tracing::info!("discovery backend: native udp");
        Ok(Self {
            backend: DiscoveryBackend::NativeUdp(backend),
        })
    }

    #[cfg(not(target_family = "wasm"))]
    async fn start_web_signaling(self_id: Uuid, lan_port: u16, wan_port: u16) -> anyhow::Result<Self> {
        let backend = Arc::new(WebSignalingBackend {
            peers: Mutex::new(HashMap::new()),
            peer_ws_to_daemon: Mutex::new(HashMap::new()),
        });

        let ws_url = build_signal_ws_url(self_id)?;
        let scope = signal_scope();
        let backend_for_task = Arc::clone(&backend);
        tokio::spawn(async move {
            run_web_signaling_loop(backend_for_task, self_id, lan_port, wan_port, ws_url, scope).await;
        });

        tracing::info!("discovery backend: web signaling");
        Ok(Self {
            backend: DiscoveryBackend::WebSignaling(backend),
        })
    }

    pub async fn list_peers(&self) -> Vec<PeerView> {
        match &self.backend {
            DiscoveryBackend::Disabled => Vec::new(),
            #[cfg(not(target_family = "wasm"))]
            DiscoveryBackend::NativeUdp(v) => list_peers_from(&v.peers).await,
            DiscoveryBackend::WebSignaling(v) => list_peers_from(&v.peers).await,
        }
    }

    pub async fn upsert_signaling_peer(
        &self,
        daemon_id: Uuid,
        lan_endpoint: SocketAddr,
        wan_endpoint: Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        let DiscoveryBackend::WebSignaling(v) = &self.backend else {
            anyhow::bail!("signaling peer updates require web signaling backend");
        };
        upsert_signaling_peer_inner(v, None, daemon_id, lan_endpoint, wan_endpoint).await;
        Ok(())
    }

    pub async fn remove_signaling_peer(&self, daemon_id: Uuid) {
        if let DiscoveryBackend::WebSignaling(v) = &self.backend {
            let mut peers = v.peers.lock().await;
            peers.remove(&daemon_id);
            let mut alias = v.peer_ws_to_daemon.lock().await;
            alias.retain(|_, id| *id != daemon_id);
        }
    }

    pub async fn candidate_endpoints(&self) -> Vec<SocketAddr> {
        self.candidate_routes()
            .await
            .into_iter()
            .map(|r| r.lan_endpoint)
            .collect()
    }

    pub async fn candidate_routes(&self) -> Vec<CandidateRoute> {
        match &self.backend {
            DiscoveryBackend::Disabled => Vec::new(),
            #[cfg(not(target_family = "wasm"))]
            DiscoveryBackend::NativeUdp(v) => candidate_routes_from(&v.peers).await,
            DiscoveryBackend::WebSignaling(v) => candidate_routes_from(&v.peers).await,
        }
    }
}

#[cfg(not(target_family = "wasm"))]
fn signal_scope() -> Option<String> {
    let raw = std::env::var("XSEND_DISCOVERY_SCOPE").ok()?;
    let scope = raw.trim();
    if scope.is_empty() {
        None
    } else {
        Some(scope.chars().take(32).collect())
    }
}

#[cfg(not(target_family = "wasm"))]
fn signal_base_url() -> String {
    std::env::var("XSEND_DISCOVERY_SIGNAL_BASE_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("XSEND_RELAY_BASE_URL")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| DEFAULT_SIGNAL_BASE_URL.to_string())
}

#[cfg(not(target_family = "wasm"))]
fn build_signal_ws_url(self_id: Uuid) -> anyhow::Result<String> {
    let base = signal_base_url();
    let base = base.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        anyhow::bail!("invalid signal base url scheme");
    };

    let url = format!(
        "{ws_base}/api/v1/realtime/auto/ws?peer_id={}&name={}",
        urlencoding::encode(&self_id.to_string()),
        urlencoding::encode("xsend-daemon")
    );
    Ok(url)
}

#[cfg(not(target_family = "wasm"))]
async fn run_web_signaling_loop(
    backend: Arc<WebSignalingBackend>,
    self_id: Uuid,
    lan_port: u16,
    wan_port: u16,
    ws_url: String,
    scope: Option<String>,
) {
    let mut backoff = SIGNAL_RECONNECT_MIN;
    loop {
        let full_url = if let Some(sc) = &scope {
            if ws_url.contains("scope=") {
                ws_url.clone()
            } else {
                format!("{}&scope={}", ws_url, urlencoding::encode(sc))
            }
        } else {
            ws_url.clone()
        };

        match connect_async(&full_url).await {
            Ok((stream, _)) => {
                tracing::info!("web signaling connected");
                backoff = SIGNAL_RECONNECT_MIN;
                if let Err(err) = run_web_signaling_session(
                    Arc::clone(&backend),
                    self_id,
                    lan_port,
                    wan_port,
                    stream,
                )
                .await
                {
                    warn!("web signaling session ended: {err:#}");
                }
            }
            Err(err) => {
                warn!("web signaling connect failed: {err:#}");
            }
        }

        time::sleep(backoff).await;
        let next_secs = (backoff.as_secs().max(1) * 2).min(SIGNAL_RECONNECT_MAX.as_secs());
        backoff = Duration::from_secs(next_secs);
    }
}

#[cfg(not(target_family = "wasm"))]
async fn run_web_signaling_session(
    backend: Arc<WebSignalingBackend>,
    self_id: Uuid,
    lan_port: u16,
    wan_port: u16,
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> anyhow::Result<()> {
    let self_peer_id = self_id.to_string();
    let (mut write, mut read) = stream.split();
    let mut known_ws_peers = HashSet::<String>::new();

    write
        .send(Message::Text(
            serde_json::json!({ "type": "list" }).to_string(),
        ))
        .await
        .context("signal ws send list")?;

    let mut announce_tick = time::interval(DISCOVERY_INTERVAL);
    let mut refresh_tick = time::interval(Duration::from_secs(8));

    loop {
        tokio::select! {
            _ = announce_tick.tick() => {
                let presence = local_presence(self_id, lan_port, wan_port);
                for ws_peer in &known_ws_peers {
                    let msg = serde_json::json!({
                        "type": "signal",
                        "to": ws_peer,
                        "kind": SIGNAL_PRESENCE_KIND,
                        "payload": presence,
                    });
                    write
                        .send(Message::Text(msg.to_string()))
                        .await
                        .context("signal ws announce send")?;
                }
            }
            _ = refresh_tick.tick() => {
                write
                    .send(Message::Text(
                        serde_json::json!({ "type": "list" }).to_string(),
                    ))
                    .await
                    .context("signal ws refresh list")?;
            }
            msg = read.next() => {
                let Some(msg) = msg else {
                    anyhow::bail!("signal ws stream closed");
                };
                let msg = msg.context("signal ws read frame")?;
                if matches!(msg, Message::Close(_)) {
                    anyhow::bail!("signal ws closed");
                }
                let text = match msg {
                    Message::Text(v) => v,
                    Message::Binary(v) => String::from_utf8(v).unwrap_or_default(),
                    _ => continue,
                };
                if text.trim().is_empty() {
                    continue;
                }
                let parsed = match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let Some(kind) = parsed.get("type").and_then(|v| v.as_str()) else {
                    continue;
                };
                match kind {
                    "welcome" | "peers" => {
                        let next = extract_ws_peers(&parsed, &self_peer_id);
                        prune_disconnected_ws_peers(&backend, &known_ws_peers, &next).await;
                        known_ws_peers = next;
                    }
                    "peer_join" => {
                        if let Some(ws_peer_id) = parsed
                            .get("peer")
                            .and_then(|v| v.get("id"))
                            .and_then(|v| v.as_str())
                            .map(|v| v.to_string())
                        {
                            if ws_peer_id != self_peer_id {
                                known_ws_peers.insert(ws_peer_id);
                            }
                        }
                    }
                    "peer_leave" => {
                        if let Some(ws_peer_id) = parsed.get("peer_id").and_then(|v| v.as_str()) {
                            known_ws_peers.remove(ws_peer_id);
                            remove_signaling_peer_by_ws_id(&backend, ws_peer_id).await;
                        }
                    }
                    "signal" => {
                        let Some(from) = parsed.get("from").and_then(|v| v.as_str()) else {
                            continue;
                        };
                        let Some(signal_kind) = parsed.get("kind").and_then(|v| v.as_str()) else {
                            continue;
                        };
                        if signal_kind != SIGNAL_PRESENCE_KIND {
                            continue;
                        }
                        let Some(payload) = parsed.get("payload") else {
                            continue;
                        };
                        let Ok(presence) = serde_json::from_value::<SignalPresenceV1>(payload.clone()) else {
                            continue;
                        };
                        if presence.v != 1 || presence.daemon_id == self_id {
                            continue;
                        }
                        let (lan_endpoint, wan_endpoint) = match select_presence_endpoints(&presence) {
                            Some(v) => v,
                            None => continue,
                        };
                        upsert_signaling_peer_inner(
                            &backend,
                            Some(from),
                            presence.daemon_id,
                            lan_endpoint,
                            wan_endpoint,
                        )
                        .await;
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(not(target_family = "wasm"))]
fn extract_ws_peers(msg: &serde_json::Value, self_peer_id: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(peers) = msg.get("peers").and_then(|v| v.as_array()) else {
        return out;
    };
    for p in peers {
        let Some(id) = p.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        if id == self_peer_id {
            continue;
        }
        out.insert(id.to_string());
    }
    out
}

#[cfg(not(target_family = "wasm"))]
async fn prune_disconnected_ws_peers(
    backend: &Arc<WebSignalingBackend>,
    prev: &HashSet<String>,
    next: &HashSet<String>,
) {
    for ws_peer_id in prev {
        if !next.contains(ws_peer_id) {
            remove_signaling_peer_by_ws_id(backend, ws_peer_id).await;
        }
    }
}

async fn upsert_signaling_peer_inner(
    backend: &WebSignalingBackend,
    ws_peer_id: Option<&str>,
    daemon_id: Uuid,
    lan_endpoint: SocketAddr,
    wan_endpoint: Option<SocketAddr>,
) {
    {
        let mut peers = backend.peers.lock().await;
        peers.insert(
            daemon_id,
            PeerInfo {
                lan_endpoint,
                wan_endpoint,
                last_seen_ms: now_ms(),
                last_seen_at: Instant::now(),
            },
        );
    }
    if let Some(ws_id) = ws_peer_id {
        let mut alias = backend.peer_ws_to_daemon.lock().await;
        alias.insert(ws_id.to_string(), daemon_id);
    }
}

async fn remove_signaling_peer_by_ws_id(backend: &WebSignalingBackend, ws_peer_id: &str) {
    let removed = {
        let mut alias = backend.peer_ws_to_daemon.lock().await;
        alias.remove(ws_peer_id)
    };
    if let Some(daemon_id) = removed {
        let mut peers = backend.peers.lock().await;
        peers.remove(&daemon_id);
    }
}

#[cfg(not(target_family = "wasm"))]
fn local_presence(self_id: Uuid, lan_port: u16, wan_port: u16) -> SignalPresenceV1 {
    SignalPresenceV1 {
        v: 1,
        daemon_id: self_id,
        lan_endpoints: local_lan_endpoints(lan_port),
        wan_endpoints: local_wan_endpoints(wan_port),
        ts_ms: now_ms(),
    }
}

#[cfg(not(target_family = "wasm"))]
fn local_lan_endpoints(port: u16) -> Vec<String> {
    if port == 0 {
        return Vec::new();
    }

    let mut out = BTreeSet::new();
    if let Ok(addrs) = get_if_addrs() {
        for iface in addrs {
            match iface.ip() {
                IpAddr::V4(v4) => {
                    if v4.is_loopback() || v4.is_link_local() {
                        continue;
                    }
                    if !v4.is_private() {
                        continue;
                    }
                    out.insert(SocketAddr::new(IpAddr::V4(v4), port).to_string());
                }
                IpAddr::V6(v6) => {
                    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                        continue;
                    }
                    out.insert(SocketAddr::new(IpAddr::V6(v6), port).to_string());
                }
            }
        }
    }

    if out.is_empty() {
        out.insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).to_string());
    }
    out.into_iter().collect()
}

#[cfg(not(target_family = "wasm"))]
fn local_wan_endpoints(port: u16) -> Vec<String> {
    if port == 0 {
        return Vec::new();
    }

    let mut out = BTreeSet::new();
    if let Ok(addrs) = get_if_addrs() {
        for iface in addrs {
            match iface.ip() {
                IpAddr::V4(v4) => {
                    if v4.is_loopback() || v4.is_link_local() {
                        continue;
                    }
                    out.insert(SocketAddr::new(IpAddr::V4(v4), port).to_string());
                }
                IpAddr::V6(v6) => {
                    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                        continue;
                    }
                    out.insert(SocketAddr::new(IpAddr::V6(v6), port).to_string());
                }
            }
        }
    }
    out.into_iter().collect()
}

fn select_presence_endpoints(presence: &SignalPresenceV1) -> Option<(SocketAddr, Option<SocketAddr>)> {
    let mut lan = first_valid_endpoint(&presence.lan_endpoints, true);
    let mut wan = first_valid_endpoint(&presence.wan_endpoints, false);

    if lan.is_none() {
        lan = wan;
    }
    lan.map(|lan_endpoint| {
        if wan == Some(lan_endpoint) {
            wan = None;
        }
        (lan_endpoint, wan)
    })
}

fn first_valid_endpoint(values: &[String], local_lan_only: bool) -> Option<SocketAddr> {
    for raw in values {
        let Ok(addr) = raw.parse::<SocketAddr>() else {
            continue;
        };
        if local_lan_only {
            if !is_discovery_eligible_ip(addr.ip()) {
                continue;
            }
        } else if !is_unicast_ip(addr.ip()) {
            continue;
        }
        return Some(addr);
    }
    None
}

fn is_unicast_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_multicast() && v4 != Ipv4Addr::BROADCAST,
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

async fn list_peers_from(peers: &Mutex<HashMap<Uuid, PeerInfo>>) -> Vec<PeerView> {
    let mut guard = peers.lock().await;
    purge_stale_peers(&mut guard, Instant::now());

    let mut out = Vec::with_capacity(guard.len());
    for (id, p) in guard.iter() {
        let lan = p.lan_endpoint.to_string();
        out.push(PeerView {
            daemon_id: *id,
            endpoint: lan.clone(),
            lan_endpoint: lan,
            wan_endpoint: p.wan_endpoint.map(|x| x.to_string()),
            last_seen_ms: p.last_seen_ms,
        });
    }
    out.sort_by_key(|p| p.last_seen_ms);
    out
}

async fn candidate_routes_from(peers: &Mutex<HashMap<Uuid, PeerInfo>>) -> Vec<CandidateRoute> {
    let mut guard = peers.lock().await;
    purge_stale_peers(&mut guard, Instant::now());
    let mut out = Vec::with_capacity(guard.len());
    for p in guard.values() {
        out.push(CandidateRoute {
            lan_endpoint: p.lan_endpoint,
            wan_endpoint: p.wan_endpoint,
        });
    }
    out
}

fn purge_stale_peers(peers: &mut HashMap<Uuid, PeerInfo>, now: Instant) {
    peers.retain(|_, p| {
        now.checked_duration_since(p.last_seen_at)
            .unwrap_or_default()
            <= PEER_TTL
    });
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug, Clone)]
struct BoundSocket {
    sock: Arc<UdpSocket>,
    targets: Vec<SocketAddr>,
}

#[cfg(not(target_family = "wasm"))]
async fn bind_discovery_sockets() -> anyhow::Result<Vec<BoundSocket>> {
    let mut out = Vec::new();

    match bind_discovery_socket_v4().await {
        Ok(sock) => {
            let targets = broadcast_targets_v4();
            if !targets.is_empty() {
                out.push(BoundSocket {
                    sock: Arc::new(sock),
                    targets,
                });
            }
        }
        Err(err) => warn!("IPv4 discovery socket unavailable: {err:#}"),
    }

    match bind_discovery_socket_v6().await {
        Ok(sock) => {
            let targets = multicast_targets_v6();
            if !targets.is_empty() {
                out.push(BoundSocket {
                    sock: Arc::new(sock),
                    targets,
                });
            }
        }
        Err(err) => warn!("IPv6 discovery socket unavailable: {err:#}"),
    }

    if out.is_empty() {
        anyhow::bail!("no discovery sockets available");
    }
    Ok(out)
}

#[cfg(not(target_family = "wasm"))]
async fn recv_loop(backend: Arc<NativeUdpBackend>, sock: Arc<UdpSocket>) {
    let mut buf = [0u8; 1500];
    loop {
        let (n, from): (usize, SocketAddr) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => return,
        };
        let msg = match serde_json::from_slice::<DiscoveryMsgV1>(&buf[..n]) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if msg.v != 1 {
            continue;
        }
        if msg.daemon_id == backend.self_id {
            continue;
        }

        let lan_endpoint = SocketAddr::new(from.ip(), msg.lan_port);
        if !is_discovery_eligible_ip(lan_endpoint.ip()) {
            continue;
        }

        let wan_endpoint = msg
            .wan_port
            .filter(|p| *p > 0)
            .map(|p| SocketAddr::new(from.ip(), p));

        let mut guard = backend.peers.lock().await;
        guard.insert(
            msg.daemon_id,
            PeerInfo {
                lan_endpoint,
                wan_endpoint,
                last_seen_ms: now_ms(),
                last_seen_at: Instant::now(),
            },
        );
    }
}

#[cfg(not(target_family = "wasm"))]
async fn send_loop(self_id: Uuid, lan_port: u16, wan_port: u16, sockets: Vec<BoundSocket>) {
    let mut tick = time::interval(DISCOVERY_INTERVAL);
    loop {
        tick.tick().await;
        let msg = DiscoveryMsgV1 {
            v: 1,
            daemon_id: self_id,
            lan_port,
            wan_port: if wan_port > 0 { Some(wan_port) } else { None },
            ts_ms: now_ms(),
        };
        let bytes = match serde_json::to_vec(&msg) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for binding in &sockets {
            for dst in &binding.targets {
                let _ = binding.sock.send_to(&bytes, dst).await;
            }
        }
    }
}

#[cfg(not(target_family = "wasm"))]
async fn bind_discovery_socket_v4() -> anyhow::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("create udp v4 socket")?;
    sock.set_reuse_address(true).ok();
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    sock.set_reuse_port(true).ok();
    sock.set_broadcast(true).ok();
    sock.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DISCOVERY_PORT).into())
        .context("bind udp v4 socket")?;
    sock.set_nonblocking(true).context("set nonblocking")?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock).context("udp v4 from std")
}

#[cfg(not(target_family = "wasm"))]
async fn bind_discovery_socket_v6() -> anyhow::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("create udp v6 socket")?;
    sock.set_reuse_address(true).ok();
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    sock.set_reuse_port(true).ok();
    sock.set_only_v6(true).ok();
    sock.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DISCOVERY_PORT).into())
        .context("bind udp v6 socket")?;
    sock.set_nonblocking(true).context("set nonblocking")?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock).context("udp v6 from std")
}

#[cfg(not(target_family = "wasm"))]
fn broadcast_targets_v4() -> Vec<SocketAddr> {
    let mut out = BTreeSet::new();
    out.insert(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::BROADCAST),
        DISCOVERY_PORT,
    ));

    if let Ok(addrs) = get_if_addrs() {
        for iface in addrs {
            let IfAddr::V4(v4) = iface.addr else {
                continue;
            };
            if v4.ip.is_loopback() || v4.ip.is_link_local() {
                continue;
            }
            if !v4.ip.is_private() {
                continue;
            }
            if let Some(bcast) = v4.broadcast {
                out.insert(SocketAddr::new(IpAddr::V4(bcast), DISCOVERY_PORT));
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(not(target_family = "wasm"))]
fn multicast_targets_v6() -> Vec<SocketAddr> {
    let mut out = BTreeSet::new();
    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    if let Ok(addrs) = get_if_addrs() {
        for iface in addrs {
            let IfAddr::V6(v6) = iface.addr else {
                continue;
            };
            if v6.ip.is_unspecified() || v6.ip.is_multicast() {
                continue;
            }
            let scope_id = interface_scope_id(&iface.name).unwrap_or(0);
            out.insert(SocketAddr::V6(SocketAddrV6::new(
                all_nodes,
                DISCOVERY_PORT,
                0,
                scope_id,
            )));
        }
    }
    if out.is_empty() {
        out.insert(SocketAddr::V6(SocketAddrV6::new(
            all_nodes,
            DISCOVERY_PORT,
            0,
            0,
        )));
    }
    out.into_iter().collect()
}

#[cfg(unix)]
fn interface_scope_id(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

#[cfg(not(unix))]
fn interface_scope_id(_name: &str) -> Option<u32> {
    None
}

fn is_discovery_eligible_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        // Allow IPv6 unicast; multicast/unspecified are not valid peer endpoints.
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligible_ip_allows_ipv6_unicast() {
        let ll: IpAddr = "fe80::1".parse().expect("ipv6 link local");
        let ula: IpAddr = "fd00::42".parse().expect("ipv6 ula");
        assert!(is_discovery_eligible_ip(ll));
        assert!(is_discovery_eligible_ip(ula));
    }

    #[test]
    fn purge_stale_uses_monotonic_instant() {
        let now = Instant::now();
        let fresh_at = now.checked_sub(Duration::from_secs(2)).unwrap_or(now);
        let stale_at = now.checked_sub(Duration::from_secs(30)).unwrap_or(now);

        let mut peers = HashMap::new();
        peers.insert(
            Uuid::new_v4(),
            PeerInfo {
                lan_endpoint: "127.0.0.1:1234".parse().expect("lan"),
                wan_endpoint: None,
                last_seen_ms: 1,
                last_seen_at: fresh_at,
            },
        );
        peers.insert(
            Uuid::new_v4(),
            PeerInfo {
                lan_endpoint: "127.0.0.1:5678".parse().expect("lan"),
                wan_endpoint: None,
                last_seen_ms: 2,
                last_seen_at: stale_at,
            },
        );

        purge_stale_peers(&mut peers, now);
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn select_presence_uses_lan_endpoint() {
        let p = SignalPresenceV1 {
            v: 1,
            daemon_id: Uuid::new_v4(),
            lan_endpoints: vec!["192.168.1.44:49160".to_string()],
            wan_endpoints: vec!["203.0.113.9:49160".to_string()],
            ts_ms: 123,
        };
        let picked = select_presence_endpoints(&p).expect("presence endpoint");
        assert_eq!(picked.0, "192.168.1.44:49160".parse::<SocketAddr>().unwrap());
        assert_eq!(
            picked.1,
            Some("203.0.113.9:49160".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn select_presence_falls_back_to_wan_when_lan_missing() {
        let p = SignalPresenceV1 {
            v: 1,
            daemon_id: Uuid::new_v4(),
            lan_endpoints: vec![],
            wan_endpoints: vec!["198.51.100.7:5000".to_string()],
            ts_ms: 123,
        };
        let picked = select_presence_endpoints(&p).expect("presence endpoint");
        assert_eq!(picked.0, "198.51.100.7:5000".parse::<SocketAddr>().unwrap());
        assert_eq!(picked.1, None);
    }
}
