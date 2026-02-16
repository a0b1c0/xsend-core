use anyhow::Context;
use get_if_addrs::get_if_addrs;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::{discovery, http, jobs, lan, metrics, relay_keys, security, sessions, transfers, wan};

const DEFAULT_RELAY_BASE_URL: &str = "https://relay.xsend.com";

#[derive(Clone, Debug)]
pub struct DaemonInfo {
    pub http_base_url: String,
    pub ui_url: String,
    pub admin_token: String,
    pub daemon_id: Uuid,
    pub lan_port: u16,
    pub lan_endpoints: Vec<String>,
    pub wan_port: u16,
    pub wan_endpoints: Vec<String>,
}

pub struct DaemonHandle {
    pub info: DaemonInfo,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl DaemonHandle {
    pub fn signal_shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    pub async fn wait(self) -> anyhow::Result<()> {
        self.join.await.context("join daemon task")?
    }

    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        self.signal_shutdown();
        self.join.await.context("join daemon task")?
    }
}

fn init_tracing() {
    // If another runtime (e.g. desktop app) already initialized tracing, don't fail.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,tower_http=warn")),
        )
        .try_init();
}

pub async fn start() -> anyhow::Result<DaemonHandle> {
    init_tracing();

    let daemon_id = Uuid::new_v4();
    let admin_token = security::generate_admin_token();
    let daemon_metrics = metrics::Metrics::new();
    let sessions = sessions::SessionManager::new(std::time::Duration::from_secs(15 * 60));
    let mut transfer_cfg = transfers::TransferManagerConfig::free_defaults();
    transfer_cfg.recovery_file = Some(default_transfer_recovery_file());
    let transfers = transfers::TransferManager::new(transfer_cfg);
    match transfers.recover_from_disk().await {
        Ok(n) if n > 0 => {
            daemon_metrics.add_transfer_recovered(n as u64);
            tracing::info!("restored {n} pending transfer(s) from recovery state");
        }
        Ok(_) => {}
        Err(err) => {
            tracing::warn!("transfer recovery skipped: {err:#}");
        }
    }
    let download_dir = default_download_dir();
    // For normal users, relay should "just work" without extra config.
    // Deploy your own relay and override with XSEND_RELAY_BASE_URL if needed.
    let relay_base_url = std::env::var("XSEND_RELAY_BASE_URL")
        .ok()
        .or_else(|| Some(DEFAULT_RELAY_BASE_URL.to_string()));
    let relay_keys = relay_keys::RelayKeyStore::open(default_relay_key_file())
        .await
        .context("open relay key store")?;
    let relay_pair_pending = relay_keys::RelayPairPendingStore::new();

    // LAN data plane listener (separate from localhost HTTP UI).
    let (lan_port, lan_endpoints) = match TcpListener::bind(("0.0.0.0", 0)).await {
        Ok(lan_listener) => {
            let lan_addr = lan_listener.local_addr().context("get lan addr")?;
            let lan_endpoints = collect_lan_endpoints(lan_addr);

            let lan_state = lan::LanState {
                daemon_id,
                sessions: sessions.clone(),
                transfers: transfers.clone(),
                download_dir: download_dir.clone(),
            };
            tokio::spawn(async move {
                if let Err(err) = lan::serve(lan_listener, lan_state).await {
                    tracing::error!("lan server stopped: {err:#}");
                }
            });

            (lan_addr.port(), lan_endpoints)
        }
        Err(err) => {
            // Some environments (sandboxes) disallow binding non-loopback.
            tracing::warn!("LAN listener disabled (bind 0.0.0.0 failed): {err}");
            (0, Vec::new())
        }
    };

    let preferred_wan_port = if lan_port > 0 { lan_port } else { 0 };
    let (wan_port, wan_endpoints) = match wan::bind_server_endpoint(
        std::net::SocketAddr::from(([0, 0, 0, 0], preferred_wan_port)),
    ) {
        Ok(endpoint) => {
            let addr = endpoint
                .local_addr()
                .context("get wan quic local addr")?;
            let wan_endpoints = collect_wan_endpoints(addr);
            let wan_state = wan::WanState {
                daemon_id,
                sessions: sessions.clone(),
                transfers: transfers.clone(),
                download_dir: download_dir.clone(),
            };
            tokio::spawn(async move {
                if let Err(err) = wan::serve(endpoint, wan_state).await {
                    tracing::error!("wan quic server stopped: {err:#}");
                }
            });
            (addr.port(), wan_endpoints)
        }
        Err(err) => {
            tracing::warn!("WAN QUIC listener disabled: {err:#}");
            (0, Vec::new())
        }
    };

    let discovery = discovery::DiscoveryService::start(daemon_id, lan_port, wan_port)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("discovery disabled: {err:#}");
            discovery::DiscoveryService::disabled()
        });

    // Spec: only listen on 127.0.0.1, and use a random port.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("bind daemon listener")?;
    let addr = listener.local_addr().context("get local addr")?;

    let state = http::AppState {
        admin_token: admin_token.clone(),
        allowed_origins: vec![
            format!("http://127.0.0.1:{}", addr.port()),
            format!("http://localhost:{}", addr.port()),
        ],
        daemon_id,
        lan_port,
        lan_endpoints: lan_endpoints.clone(),
        wan_port,
        wan_endpoints: wan_endpoints.clone(),
        jobs: jobs::JobManager::new(jobs::JobManagerConfig::free_defaults()),
        sessions,
        transfers,
        relay_base_url,
        relay_keys,
        relay_pair_pending,
        discovery,
        metrics: daemon_metrics,
    };

    let app = http::router(state);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .context("serve http")
    });

    let http_base_url = format!("http://127.0.0.1:{}", addr.port());
    let ui_url = format!("{http_base_url}/");
    Ok(DaemonHandle {
        info: DaemonInfo {
            http_base_url,
            ui_url,
            admin_token,
            daemon_id,
            lan_port,
            lan_endpoints,
            wan_port,
            wan_endpoints,
        },
        shutdown_tx: Some(shutdown_tx),
        join,
    })
}

pub async fn run() -> anyhow::Result<()> {
    let handle = start().await?;

    println!("xsend daemon listening: {}", handle.info.http_base_url);
    println!("open UI: {}", handle.info.ui_url);
    if should_print_admin_token() {
        println!("admin token (API/CLI): {}", handle.info.admin_token);
    } else {
        println!("admin token (API/CLI): hidden by default");
        println!(
            "admin token hint: {} (set XSEND_PRINT_ADMIN_TOKEN=1 to print full token)",
            mask_secret(&handle.info.admin_token)
        );
    }
    println!("daemon id: {}", handle.info.daemon_id);
    if handle.info.lan_port > 0 {
        println!("lan listen port: {}", handle.info.lan_port);
    } else {
        println!("lan listen port: disabled");
    }
    if handle.info.wan_port > 0 {
        println!("wan quic port: {}", handle.info.wan_port);
    } else {
        println!("wan quic port: disabled");
    }

    handle.wait().await
}

fn should_print_admin_token() -> bool {
    std::env::var("XSEND_PRINT_ADMIN_TOKEN")
        .ok()
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

fn mask_secret(secret: &str) -> String {
    const KEEP: usize = 4;
    if secret.len() <= KEEP * 2 {
        return "<hidden>".to_string();
    }
    let prefix = &secret[..KEEP];
    let suffix = &secret[secret.len() - KEEP..];
    format!("{prefix}...{suffix}")
}

fn default_download_dir() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    home.join(".xsend").join("downloads")
}

fn default_relay_key_file() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    home.join(".xsend").join("relay_keys.json")
}

fn default_transfer_recovery_file() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    home.join(".xsend").join("transfers_recovery.json")
}

fn collect_lan_endpoints(bind: std::net::SocketAddr) -> Vec<String> {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let port = bind.port();
    let mut out = BTreeSet::new();
    out.insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).to_string());
    out.insert(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port).to_string());

    if bind.ip().is_loopback() {
        return out.into_iter().collect();
    }

    if let Ok(addrs) = get_if_addrs() {
        for iface in addrs {
            match iface.ip() {
                IpAddr::V4(v4) => {
                    if v4.is_loopback() || v4.is_link_local() {
                        continue;
                    }
                    // Only show private LAN ranges by default.
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

    out.into_iter().collect()
}

fn collect_wan_endpoints(bind: std::net::SocketAddr) -> Vec<String> {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let port = bind.port();
    let mut out = BTreeSet::new();
    out.insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).to_string());
    out.insert(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port).to_string());

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
