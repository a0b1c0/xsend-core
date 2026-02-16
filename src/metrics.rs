use std::fmt::Write as _;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct Metrics {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    started_at_ms: u64,

    http_requests_total: AtomicU64,
    http_responses_2xx_total: AtomicU64,
    http_responses_4xx_total: AtomicU64,
    http_responses_5xx_total: AtomicU64,

    receive_sessions_created_total: AtomicU64,

    transfer_send_requests_total: AtomicU64,
    transfer_send_wan_requests_total: AtomicU64,
    transfer_send_auto_requests_total: AtomicU64,
    transfer_create_failures_total: AtomicU64,
    transfer_recovered_total: AtomicU64,
    auto_route_force_relay_requests_total: AtomicU64,
    auto_route_turn_requested_total: AtomicU64,
    auto_route_no_candidates_total: AtomicU64,
    auto_route_relay_auto_armed_total: AtomicU64,
    auto_route_candidates_lan_total: AtomicU64,
    auto_route_candidates_wan_total: AtomicU64,

    relay_fallback_attempts_total: AtomicU64,
    relay_fallback_success_total: AtomicU64,
    relay_fallback_failures_total: AtomicU64,

    turn_preflight_requests_total: AtomicU64,
    turn_preflight_success_total: AtomicU64,
    turn_preflight_failures_total: AtomicU64,
    turn_credentials_requests_total: AtomicU64,
    turn_credentials_success_total: AtomicU64,
    turn_credentials_failures_total: AtomicU64,

    relay_upload_requests_total: AtomicU64,
    relay_upload_success_total: AtomicU64,
    relay_upload_failures_total: AtomicU64,
    relay_uploaded_files_total: AtomicU64,

    relay_pull_requests_total: AtomicU64,
    relay_pull_success_total: AtomicU64,
    relay_pull_failures_total: AtomicU64,
    relay_pull_files_total: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                started_at_ms: now_ms(),

                http_requests_total: AtomicU64::new(0),
                http_responses_2xx_total: AtomicU64::new(0),
                http_responses_4xx_total: AtomicU64::new(0),
                http_responses_5xx_total: AtomicU64::new(0),

                receive_sessions_created_total: AtomicU64::new(0),

                transfer_send_requests_total: AtomicU64::new(0),
                transfer_send_wan_requests_total: AtomicU64::new(0),
                transfer_send_auto_requests_total: AtomicU64::new(0),
                transfer_create_failures_total: AtomicU64::new(0),
                transfer_recovered_total: AtomicU64::new(0),
                auto_route_force_relay_requests_total: AtomicU64::new(0),
                auto_route_turn_requested_total: AtomicU64::new(0),
                auto_route_no_candidates_total: AtomicU64::new(0),
                auto_route_relay_auto_armed_total: AtomicU64::new(0),
                auto_route_candidates_lan_total: AtomicU64::new(0),
                auto_route_candidates_wan_total: AtomicU64::new(0),

                relay_fallback_attempts_total: AtomicU64::new(0),
                relay_fallback_success_total: AtomicU64::new(0),
                relay_fallback_failures_total: AtomicU64::new(0),

                turn_preflight_requests_total: AtomicU64::new(0),
                turn_preflight_success_total: AtomicU64::new(0),
                turn_preflight_failures_total: AtomicU64::new(0),
                turn_credentials_requests_total: AtomicU64::new(0),
                turn_credentials_success_total: AtomicU64::new(0),
                turn_credentials_failures_total: AtomicU64::new(0),

                relay_upload_requests_total: AtomicU64::new(0),
                relay_upload_success_total: AtomicU64::new(0),
                relay_upload_failures_total: AtomicU64::new(0),
                relay_uploaded_files_total: AtomicU64::new(0),

                relay_pull_requests_total: AtomicU64::new(0),
                relay_pull_success_total: AtomicU64::new(0),
                relay_pull_failures_total: AtomicU64::new(0),
                relay_pull_files_total: AtomicU64::new(0),
            }),
        }
    }

    pub fn observe_http_start(&self) {
        self.inner.http_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_http_status(&self, status: u16) {
        if (200..300).contains(&status) {
            self.inner
                .http_responses_2xx_total
                .fetch_add(1, Ordering::Relaxed);
        } else if (400..500).contains(&status) {
            self.inner
                .http_responses_4xx_total
                .fetch_add(1, Ordering::Relaxed);
        } else if status >= 500 {
            self.inner
                .http_responses_5xx_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn inc_receive_sessions_created(&self) {
        self.inner
            .receive_sessions_created_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_transfer_send_requests(&self) {
        self.inner
            .transfer_send_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_transfer_send_wan_requests(&self) {
        self.inner
            .transfer_send_wan_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_transfer_send_auto_requests(&self) {
        self.inner
            .transfer_send_auto_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_transfer_create_failures(&self) {
        self.inner
            .transfer_create_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_transfer_recovered(&self, n: u64) {
        if n > 0 {
            self.inner
                .transfer_recovered_total
                .fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn inc_auto_route_force_relay_requests(&self) {
        self.inner
            .auto_route_force_relay_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auto_route_turn_requested(&self) {
        self.inner
            .auto_route_turn_requested_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auto_route_no_candidates(&self) {
        self.inner
            .auto_route_no_candidates_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auto_route_relay_auto_armed(&self) {
        self.inner
            .auto_route_relay_auto_armed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_auto_route_candidates(&self, lan: u64, wan: u64) {
        if lan > 0 {
            self.inner
                .auto_route_candidates_lan_total
                .fetch_add(lan, Ordering::Relaxed);
        }
        if wan > 0 {
            self.inner
                .auto_route_candidates_wan_total
                .fetch_add(wan, Ordering::Relaxed);
        }
    }

    pub fn inc_relay_fallback_attempts(&self) {
        self.inner
            .relay_fallback_attempts_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_fallback_success(&self) {
        self.inner
            .relay_fallback_success_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_fallback_failures(&self) {
        self.inner
            .relay_fallback_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_turn_preflight_requests(&self) {
        self.inner
            .turn_preflight_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_turn_preflight_success(&self) {
        self.inner
            .turn_preflight_success_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_turn_preflight_failures(&self) {
        self.inner
            .turn_preflight_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_turn_credentials_requests(&self) {
        self.inner
            .turn_credentials_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_turn_credentials_success(&self) {
        self.inner
            .turn_credentials_success_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_turn_credentials_failures(&self) {
        self.inner
            .turn_credentials_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_upload_requests(&self) {
        self.inner
            .relay_upload_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_upload_success(&self) {
        self.inner
            .relay_upload_success_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_upload_failures(&self) {
        self.inner
            .relay_upload_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_relay_uploaded_files(&self, n: u64) {
        if n > 0 {
            self.inner
                .relay_uploaded_files_total
                .fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn inc_relay_pull_requests(&self) {
        self.inner
            .relay_pull_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_pull_success(&self) {
        self.inner
            .relay_pull_success_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_relay_pull_failures(&self) {
        self.inner
            .relay_pull_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_relay_pull_files(&self, n: u64) {
        if n > 0 {
            self.inner
                .relay_pull_files_total
                .fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn render_prometheus(&self) -> String {
        fn v(c: &AtomicU64) -> u64 {
            c.load(Ordering::Relaxed)
        }

        let i = &self.inner;
        let mut out = String::with_capacity(2048);
        let _ = writeln!(out, "# TYPE xsend_daemon_started_at_ms gauge");
        let _ = writeln!(out, "xsend_daemon_started_at_ms {}", i.started_at_ms);

        let _ = writeln!(out, "# TYPE xsend_http_requests_total counter");
        let _ = writeln!(out, "xsend_http_requests_total {}", v(&i.http_requests_total));
        let _ = writeln!(
            out,
            "xsend_http_responses_2xx_total {}",
            v(&i.http_responses_2xx_total)
        );
        let _ = writeln!(
            out,
            "xsend_http_responses_4xx_total {}",
            v(&i.http_responses_4xx_total)
        );
        let _ = writeln!(
            out,
            "xsend_http_responses_5xx_total {}",
            v(&i.http_responses_5xx_total)
        );

        let _ = writeln!(
            out,
            "xsend_receive_sessions_created_total {}",
            v(&i.receive_sessions_created_total)
        );

        let _ = writeln!(
            out,
            "xsend_transfer_send_requests_total {}",
            v(&i.transfer_send_requests_total)
        );
        let _ = writeln!(
            out,
            "xsend_transfer_send_wan_requests_total {}",
            v(&i.transfer_send_wan_requests_total)
        );
        let _ = writeln!(
            out,
            "xsend_transfer_send_auto_requests_total {}",
            v(&i.transfer_send_auto_requests_total)
        );
        let _ = writeln!(
            out,
            "xsend_transfer_create_failures_total {}",
            v(&i.transfer_create_failures_total)
        );
        let _ = writeln!(
            out,
            "xsend_transfer_recovered_total {}",
            v(&i.transfer_recovered_total)
        );
        let _ = writeln!(
            out,
            "xsend_auto_route_force_relay_requests_total {}",
            v(&i.auto_route_force_relay_requests_total)
        );
        let _ = writeln!(
            out,
            "xsend_auto_route_turn_requested_total {}",
            v(&i.auto_route_turn_requested_total)
        );
        let _ = writeln!(
            out,
            "xsend_auto_route_no_candidates_total {}",
            v(&i.auto_route_no_candidates_total)
        );
        let _ = writeln!(
            out,
            "xsend_auto_route_relay_auto_armed_total {}",
            v(&i.auto_route_relay_auto_armed_total)
        );
        let _ = writeln!(
            out,
            "xsend_auto_route_candidates_lan_total {}",
            v(&i.auto_route_candidates_lan_total)
        );
        let _ = writeln!(
            out,
            "xsend_auto_route_candidates_wan_total {}",
            v(&i.auto_route_candidates_wan_total)
        );

        let _ = writeln!(
            out,
            "xsend_relay_fallback_attempts_total {}",
            v(&i.relay_fallback_attempts_total)
        );
        let _ = writeln!(
            out,
            "xsend_relay_fallback_success_total {}",
            v(&i.relay_fallback_success_total)
        );
        let _ = writeln!(
            out,
            "xsend_relay_fallback_failures_total {}",
            v(&i.relay_fallback_failures_total)
        );

        let _ = writeln!(
            out,
            "xsend_turn_preflight_requests_total {}",
            v(&i.turn_preflight_requests_total)
        );
        let _ = writeln!(
            out,
            "xsend_turn_preflight_success_total {}",
            v(&i.turn_preflight_success_total)
        );
        let _ = writeln!(
            out,
            "xsend_turn_preflight_failures_total {}",
            v(&i.turn_preflight_failures_total)
        );
        let _ = writeln!(
            out,
            "xsend_turn_credentials_requests_total {}",
            v(&i.turn_credentials_requests_total)
        );
        let _ = writeln!(
            out,
            "xsend_turn_credentials_success_total {}",
            v(&i.turn_credentials_success_total)
        );
        let _ = writeln!(
            out,
            "xsend_turn_credentials_failures_total {}",
            v(&i.turn_credentials_failures_total)
        );

        let _ = writeln!(
            out,
            "xsend_relay_upload_requests_total {}",
            v(&i.relay_upload_requests_total)
        );
        let _ = writeln!(
            out,
            "xsend_relay_upload_success_total {}",
            v(&i.relay_upload_success_total)
        );
        let _ = writeln!(
            out,
            "xsend_relay_upload_failures_total {}",
            v(&i.relay_upload_failures_total)
        );
        let _ = writeln!(
            out,
            "xsend_relay_uploaded_files_total {}",
            v(&i.relay_uploaded_files_total)
        );

        let _ = writeln!(
            out,
            "xsend_relay_pull_requests_total {}",
            v(&i.relay_pull_requests_total)
        );
        let _ = writeln!(
            out,
            "xsend_relay_pull_success_total {}",
            v(&i.relay_pull_success_total)
        );
        let _ = writeln!(
            out,
            "xsend_relay_pull_failures_total {}",
            v(&i.relay_pull_failures_total)
        );
        let _ = writeln!(
            out,
            "xsend_relay_pull_files_total {}",
            v(&i.relay_pull_files_total)
        );

        out
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
