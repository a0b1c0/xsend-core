use std::path::Path;

use anyhow::Context;
use rand::{Rng, rngs::OsRng};
use reqwest::header;
use serde::{Deserialize, Serialize};

pub const RELAY_DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
pub const RELAY_E2EE_OVERHEAD_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone)]
pub struct RelayClient {
    base_url: String,
    http: reqwest::Client,
    bearer_token: Option<String>,
}

impl RelayClient {
    pub fn new(base_url: String) -> anyhow::Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            anyhow::bail!("relay base url must start with http:// or https://");
        }
        Ok(Self {
            base_url,
            http: reqwest::Client::new(),
            bearer_token: None,
        })
    }

    pub fn with_bearer_token(mut self, token: String) -> Self {
        let t = token.trim().to_string();
        self.bearer_token = if t.is_empty() { None } else { Some(t) };
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(t) = &self.bearer_token {
            req.bearer_auth(t)
        } else {
            req
        }
    }

    pub async fn create_channel(&self) -> anyhow::Result<RelayChannelMeta> {
        // Client-generated short code; retry on collision.
        for _ in 0..50 {
            let code = format!("{:06}", OsRng.gen_range(0..=999_999u32));
            let url = format!("{}/api/v1/channel/{}", self.base_url, code);

            let res = self
                .auth(self.http.put(url))
                .send()
                .await
                .context("relay create channel request")?;

            if res.status().as_u16() == 409 {
                continue;
            }

            let res = res
                .error_for_status()
                .context("relay create channel status")?;
            let meta = res
                .json::<RelayChannelMeta>()
                .await
                .context("relay create channel json")?;
            return Ok(meta);
        }

        anyhow::bail!("failed to allocate channel code");
    }

    pub async fn ensure_channel(&self, code: &str) -> anyhow::Result<RelayChannelMeta> {
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("invalid code (expected 6 digits)");
        }

        let url = format!("{}/api/v1/channel/{}", self.base_url, code);
        let res = self
            .auth(self.http.put(url.clone()))
            .send()
            .await
            .context("relay ensure channel request")?;

        match res.status().as_u16() {
            201 => {
                let meta = res
                    .json::<RelayChannelMeta>()
                    .await
                    .context("relay ensure channel json")?;
                Ok(meta)
            }
            409 => {
                // Already exists; fetch meta via the list endpoint.
                let view = self
                    .auth(self.http.get(url))
                    .send()
                    .await
                    .context("relay get channel request")?
                    .error_for_status()
                    .context("relay get channel status")?
                    .json::<RelayChannelView>()
                    .await
                    .context("relay get channel json")?;
                Ok(view.channel)
            }
            _ => {
                let text = res.text().await.unwrap_or_default();
                anyhow::bail!("relay ensure channel failed: {}", text.trim());
            }
        }
    }

    pub async fn upload_file(&self, code: &str, path: &Path) -> anyhow::Result<RelayUploadResult> {
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("invalid code (expected 6 digits)");
        }

        let meta = tokio::fs::metadata(path)
            .await
            .context("stat upload file")?;
        if !meta.is_file() {
            anyhow::bail!("path is not a regular file");
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin");
        let filename = sanitize_filename(filename);

        let body = tokio::fs::read(path).await.context("read upload file")?;

        self.upload_bytes(code, &filename, "application/octet-stream", body)
            .await
    }

    pub async fn upload_bytes(
        &self,
        code: &str,
        filename: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<RelayUploadResult> {
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("invalid code (expected 6 digits)");
        }

        let filename = sanitize_filename(filename);
        let content_type = if content_type.trim().is_empty() {
            "application/octet-stream"
        } else {
            content_type.trim()
        };

        let url = format!(
            "{}/api/v1/channel/{}/files?name={}",
            self.base_url,
            code,
            urlencoding::encode(&filename)
        );

        let mut res = self
            .auth(
                self.http
                    .post(url.clone())
                    .header(reqwest::header::CONTENT_TYPE, content_type)
                    .body(body.clone()),
            )
            .send()
            .await
            .context("relay upload request")?;

        if res.status().as_u16() == 404 {
            // Code missing/expired. Create it and retry once.
            let _ = self.ensure_channel(code).await?;
            res = self
                .auth(
                    self.http
                        .post(url)
                        .header(reqwest::header::CONTENT_TYPE, content_type)
                        .body(body),
                )
                .send()
                .await
                .context("relay upload retry request")?;
        }

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay upload failed: {}", text.trim());
        }

        let out = res
            .json::<RelayUploadResult>()
            .await
            .context("relay upload json")?;
        Ok(out)
    }

    pub async fn me_channel(&self) -> anyhow::Result<RelayChannelView> {
        let url = format!("{}/api/v1/me/channel", self.base_url);
        let res = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("relay me channel request")?
            .error_for_status()
            .context("relay me channel status")?;
        let view = res
            .json::<RelayChannelView>()
            .await
            .context("relay me channel json")?;
        Ok(view)
    }

    pub async fn me_plan(&self) -> anyhow::Result<RelayMePlanResponse> {
        let url = format!("{}/api/v1/me/plan", self.base_url);
        let res = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("relay me plan request")?;
        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay me plan failed: {}", text.trim());
        }
        let out = res
            .json::<RelayMePlanResponse>()
            .await
            .context("relay me plan json")?;
        Ok(out)
    }

    pub async fn me_billing(&self) -> anyhow::Result<RelayMeBillingResponse> {
        let url = format!("{}/api/v1/me/billing", self.base_url);
        let res = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("relay me billing request")?;
        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay me billing failed: {}", text.trim());
        }
        let out = res
            .json::<RelayMeBillingResponse>()
            .await
            .context("relay me billing json")?;
        Ok(out)
    }

    pub async fn turn_credentials(&self, ttl_seconds: u64) -> anyhow::Result<serde_json::Value> {
        let ttl = ttl_seconds.clamp(60, 172800);
        let url = format!("{}/api/v1/turn/credentials?ttl={ttl}", self.base_url);
        let res = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("relay turn credentials request")?;
        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay turn credentials failed: {}", text.trim());
        }
        let out = res
            .json::<serde_json::Value>()
            .await
            .context("relay turn credentials json")?;
        Ok(out)
    }

    async fn me_max_file_bytes(&self) -> Option<u64> {
        let plan = self.me_plan().await.ok()?;
        let max = plan.limits.max_file_bytes?;
        if max > 0 { Some(max) } else { None }
    }

    pub async fn upload_file_me(&self, path: &Path) -> anyhow::Result<RelayUploadResult> {
        let meta = tokio::fs::metadata(path)
            .await
            .context("stat upload file")?;
        if !meta.is_file() {
            anyhow::bail!("path is not a regular file");
        }
        if let Some(limit) = self.me_max_file_bytes().await {
            if meta.len() > limit {
                anyhow::bail!("file too large for current plan (max {} bytes)", limit);
            }
        }

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin");
        let filename = sanitize_filename(filename);

        let body = tokio::fs::read(path).await.context("read upload file")?;
        self.upload_bytes_me(&filename, "application/octet-stream", body)
            .await
    }

    pub async fn upload_bytes_me(
        &self,
        filename: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<RelayUploadResult> {
        self.upload_bytes_me_inner(filename, content_type, body, false, None, None)
            .await
    }

    pub async fn upload_bytes_me_e2ee(
        &self,
        filename: &str,
        content_type: &str,
        body: Vec<u8>,
        max_transport_bytes: Option<u64>,
        relative_path: Option<&str>,
    ) -> anyhow::Result<RelayUploadResult> {
        self.upload_bytes_me_inner(
            filename,
            content_type,
            body,
            true,
            max_transport_bytes,
            relative_path,
        )
            .await
    }

    async fn upload_bytes_me_inner(
        &self,
        filename: &str,
        content_type: &str,
        body: Vec<u8>,
        e2ee: bool,
        max_transport_bytes: Option<u64>,
        relative_path: Option<&str>,
    ) -> anyhow::Result<RelayUploadResult> {
        let transport_limit = if let Some(v) = max_transport_bytes {
            Some(v)
        } else if e2ee {
            self.me_max_file_bytes()
                .await
                .and_then(|v| v.checked_add(RELAY_E2EE_OVERHEAD_BYTES))
        } else {
            self.me_max_file_bytes().await
        };

        if let Some(limit) = transport_limit {
            if body.len() as u64 > limit {
                anyhow::bail!("file too large for current plan (max {} bytes)", limit);
            }
        }

        let filename = sanitize_filename(filename);
        let content_type = if content_type.trim().is_empty() {
            "application/octet-stream"
        } else {
            content_type.trim()
        };

        let mut url = format!(
            "{}/api/v1/me/files?name={}",
            self.base_url,
            urlencoding::encode(&filename)
        );
        if let Some(rel) = relative_path.and_then(sanitize_relative_path) {
            url.push_str("&rel=");
            url.push_str(&urlencoding::encode(&rel));
        }

        let mut req = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
        if e2ee {
            req = req.header("x-xsend-e2ee", "1");
        }
        let res = self
            .auth(req)
            .send()
            .await
            .context("relay me upload request")?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay me upload failed: {}", text.trim());
        }

        let out = res
            .json::<RelayUploadResult>()
            .await
            .context("relay me upload json")?;
        Ok(out)
    }

    pub async fn download_bytes_me(&self, file_id: &str) -> anyhow::Result<RelayDownloadedFile> {
        let id = file_id.trim();
        if id.is_empty() {
            anyhow::bail!("missing file id");
        }

        let url = format!("{}/api/v1/me/files/{}", self.base_url, id);
        let res = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("relay me download request")?;

        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay me download failed: {}", text.trim());
        }

        let content_type = res
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let cd = res
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let filename = filename_from_content_disposition(cd).unwrap_or_else(|| "file.bin".to_string());
        let filename = sanitize_filename(&filename);

        let bytes = res.bytes().await.context("relay me download body")?;

        Ok(RelayDownloadedFile {
            filename,
            content_type,
            bytes: bytes.to_vec(),
        })
    }

    pub async fn e2ee_pair_start(&self, pubkey_b64: &str) -> anyhow::Result<RelayPairStartResponse> {
        let url = format!("{}/api/v1/e2ee/pair/start", self.base_url);
        let res = self
            .auth(self.http.post(url).json(&serde_json::json!({ "pubkey": pubkey_b64 })))
            .send()
            .await
            .context("relay e2ee pair start request")?;
        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay e2ee pair start failed: {}", text.trim());
        }
        let out = res
            .json::<RelayPairStartResponse>()
            .await
            .context("relay e2ee pair start json")?;
        Ok(out)
    }

    pub async fn e2ee_pair_info(&self, code: &str) -> anyhow::Result<RelayPairInfoResponse> {
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("invalid pair code (expected 6 digits)");
        }
        let url = format!("{}/api/v1/e2ee/pair/{}", self.base_url, code);
        let res = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("relay e2ee pair info request")?;
        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay e2ee pair info failed: {}", text.trim());
        }
        let out = res
            .json::<RelayPairInfoResponse>()
            .await
            .context("relay e2ee pair info json")?;
        Ok(out)
    }

    pub async fn e2ee_pair_complete(
        &self,
        code: &str,
        sender_pubkey: &str,
        nonce: &str,
        ciphertext: &str,
    ) -> anyhow::Result<()> {
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("invalid pair code (expected 6 digits)");
        }
        let url = format!("{}/api/v1/e2ee/pair/{}/complete", self.base_url, code);
        let res = self
            .auth(self.http.post(url).json(&serde_json::json!({
                "sender_pubkey": sender_pubkey,
                "nonce": nonce,
                "ciphertext": ciphertext
            })))
            .send()
            .await
            .context("relay e2ee pair complete request")?;
        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay e2ee pair complete failed: {}", text.trim());
        }
        Ok(())
    }

    pub async fn e2ee_pair_result(&self, code: &str) -> anyhow::Result<RelayPairCipherResponse> {
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("invalid pair code (expected 6 digits)");
        }
        let url = format!("{}/api/v1/e2ee/pair/{}/result", self.base_url, code);
        let res = self
            .auth(self.http.get(url))
            .send()
            .await
            .context("relay e2ee pair result request")?;
        if !res.status().is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("relay e2ee pair result failed: {}", text.trim());
        }
        let out = res
            .json::<RelayPairCipherResponse>()
            .await
            .context("relay e2ee pair result json")?;
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayChannelMeta {
    pub code: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayChannelView {
    pub channel: RelayChannelMeta,
    #[serde(default)]
    pub limits: Option<RelayLimitsView>,
    #[serde(default)]
    pub files: Vec<RelayFileView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayLimitsView {
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub max_files: Option<u64>,
    #[serde(default)]
    pub max_file_bytes: Option<u64>,
    #[serde(default)]
    pub max_total_bytes: Option<u64>,
    #[serde(default)]
    pub file_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub e2ee_overhead_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayUploadResult {
    pub file: RelayFileView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFileView {
    pub id: String,
    pub filename: String,
    #[serde(default)]
    pub relative_path: Option<String>,
    pub content_type: String,
    pub size_bytes: u64,
    pub uploaded_at_ms: u64,
    pub download_url: String,
}

#[derive(Debug, Clone)]
pub struct RelayDownloadedFile {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPairStartResponse {
    pub ok: bool,
    pub code: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPairInfoResponse {
    pub pair: RelayChannelMeta,
    #[serde(default)]
    pub pubkey: Option<String>,
    #[serde(default)]
    pub has_cipher: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPairCipherResponse {
    pub sender_pubkey: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayUsageDaily {
    #[serde(default)]
    pub date_key: Option<String>,
    #[serde(default)]
    pub upload_bytes: u64,
    #[serde(default)]
    pub download_bytes: u64,
    #[serde(default)]
    pub upload_files: u64,
    #[serde(default)]
    pub download_files: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayFeatureFlags {
    #[serde(default)]
    pub relay_upload: bool,
    #[serde(default)]
    pub relay_download: bool,
    #[serde(default)]
    pub relay_e2ee: bool,
    #[serde(default)]
    pub turn_accelerate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayMePlanResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub client_type: Option<String>,
    #[serde(default)]
    pub limits: RelayLimitsView,
    #[serde(default)]
    pub features: Option<RelayFeatureFlags>,
    #[serde(default)]
    pub usage_today: Option<RelayUsageDaily>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayUsageMonth {
    #[serde(default)]
    pub month_key: Option<String>,
    #[serde(default)]
    pub upload_bytes: u64,
    #[serde(default)]
    pub download_bytes: u64,
    #[serde(default)]
    pub upload_files: u64,
    #[serde(default)]
    pub download_files: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayBillingRates {
    #[serde(default)]
    pub upload_per_gb_usd: f64,
    #[serde(default)]
    pub download_per_gb_usd: f64,
    #[serde(default)]
    pub free_quota_gb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayMeBillingResponse {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub month: Option<String>,
    #[serde(default)]
    pub rates: RelayBillingRates,
    #[serde(default)]
    pub usage: RelayUsageMonth,
    #[serde(default)]
    pub free_applied_bytes: Option<u64>,
    #[serde(default)]
    pub billable_bytes: Option<u64>,
    #[serde(default)]
    pub billable_upload_bytes: Option<u64>,
    #[serde(default)]
    pub billable_download_bytes: Option<u64>,
    #[serde(default)]
    pub estimated_usd: f64,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub features: Option<RelayFeatureFlags>,
}

fn sanitize_filename(name: &str) -> String {
    let base = name.split(['/', '\\']).next_back().unwrap_or("file.bin").trim();
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

fn sanitize_relative_path(path: &str) -> Option<String> {
    let raw = path.trim();
    if raw.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for seg in raw.split(['/', '\\']) {
        let s = seg.trim();
        if s.is_empty() || s == "." || s == ".." {
            continue;
        }
        let clean: String = s
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                    c
                } else {
                    '_'
                }
            })
            .take(120)
            .collect();
        if clean.is_empty() || clean == "." || clean == ".." {
            continue;
        }
        parts.push(clean);
        if parts.len() >= 32 {
            break;
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn filename_from_content_disposition(v: &str) -> Option<String> {
    // Minimal parse: attachment; filename="foo.txt"
    for part in v.split(';') {
        let p = part.trim();
        if p.len() < 9 {
            continue;
        }
        if !p[..9].eq_ignore_ascii_case("filename=") {
            continue;
        }
        let mut rest = p[9..].trim();
        if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
            rest = &rest[1..rest.len() - 1];
        }
        if rest.is_empty() {
            return None;
        }
        return Some(rest.to_string());
    }
    None
}
