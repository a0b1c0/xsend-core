import bcrypt from "bcryptjs";

type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

interface Env {
  ASSETS: Fetcher;
  RELAY_BUCKET: R2Bucket;
  CHANNEL: DurableObjectNamespace;
  PAIR: DurableObjectNamespace;
  SIGNAL_AUTO: DurableObjectNamespace;
  XADMIN_DB: D1Database;

  // Vars are strings in Workers.
  MAX_FILES: string;
  MAX_FILE_BYTES: string;
  MAX_TOTAL_BYTES: string;
  CHANNEL_TTL_SECONDS: string;
  FILE_TTL_SECONDS: string;
  PRO_MAX_FILES?: string;
  PRO_MAX_FILE_BYTES?: string;
  PRO_MAX_TOTAL_BYTES?: string;
  PRO_FILE_TTL_SECONDS?: string;
  BILLING_UPLOAD_PER_GB_USD?: string;
  BILLING_DOWNLOAD_PER_GB_USD?: string;
  BILLING_FREE_QUOTA_GB?: string;
  E2EE_OVERHEAD_BYTES?: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_PRICE_ID?: string;
  BILLING_SUCCESS_URL?: string;
  BILLING_CANCEL_URL?: string;
  BILLING_PORTAL_RETURN_URL?: string;
  STRIPE_WEBHOOK_SECRET?: string;

  // Secrets / optional vars.
  SESSION_SECRET: string;
  SESSION_TTL_SECONDS?: string;
  TURN_KEY_ID?: string;
  TURN_KEY_SECRET?: string;
  TURN_REQUIRE_PAID?: string;
  RELAY_UPLOAD_REQUIRE_PAID?: string;
  RELAY_DOWNLOAD_REQUIRE_PAID?: string;
  RELAY_E2EE_REQUIRE_PAID?: string;
  RELAY_BATCH_REQUIRE_PAID?: string;
  AUTO_DISCOVERY_REQUIRE_PAID?: string;
  OFFLINE_MODE_REQUIRE_PAID?: string;

  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;

  // Sign in with Apple (OAuth2 + OpenID Connect)
  // Vars (strings) + one secret:
  // - APPLE_CLIENT_ID: Services ID (web) / client_id
  // - APPLE_TEAM_ID: Apple developer team id
  // - APPLE_KEY_ID: Key id for the private key
  // - APPLE_PRIVATE_KEY: .p8 private key PEM (secret)
  APPLE_CLIENT_ID?: string;
  APPLE_TEAM_ID?: string;
  APPLE_KEY_ID?: string;
  APPLE_PRIVATE_KEY?: string;
}

interface ChannelMeta {
  code: string;
  created_at_ms: number;
  expires_at_ms: number;
  owner_client_id: string;
}

interface PairMeta {
  code: string;
  created_at_ms: number;
  expires_at_ms: number;
  owner_client_id: string;
}

interface PairCipher {
  sender_pubkey_b64: string;
  nonce_b64: string;
  ciphertext_b64: string;
  created_at_ms: number;
}

interface StoredFile {
  id: string;
  filename: string;
  relative_path?: string;
  content_type: string;
  size_bytes: number;
  uploaded_at_ms: number;
  r2_key: string;
}

interface ClientRow {
  id: string;
  username: string;
  email: string | null;
  role: string | null;
  status: string | null;
  client_type: string | null;
}

interface SessionClaims {
  sub: string; // client id
  exp: number; // epoch seconds
}

interface ClientLimits {
  plan: string;
  max_files: number;
  max_file_bytes: number;
  max_total_bytes: number;
  file_ttl_seconds: number;
  source: "default" | "client_type" | "plan_override";
}

interface ClientFeatures {
  relay_upload: boolean;
  relay_download: boolean;
  relay_e2ee: boolean;
  relay_batch_upload: boolean;
  turn_accelerate: boolean;
  auto_discovery: boolean;
  offline_mode: boolean;
}

interface UsageDaily {
  date_key: string;
  upload_bytes: number;
  download_bytes: number;
  upload_files: number;
  download_files: number;
}

interface UsageMonth {
  month_key: string;
  upload_bytes: number;
  download_bytes: number;
  upload_files: number;
  download_files: number;
}

interface BillingSubscriptionRow {
  stripe_subscription_id: string;
  status: string;
  plan: string;
  current_period_start_ms: number | null;
  current_period_end_ms: number | null;
  cancel_at_period_end: boolean;
  updated_at_ms: number;
}

interface BillingInvoiceRow {
  stripe_invoice_id: string;
  status: string;
  amount_due: number;
  amount_paid: number;
  currency: string | null;
  hosted_invoice_url: string | null;
  invoice_pdf_url: string | null;
  period_start_ms: number | null;
  period_end_ms: number | null;
  created_at_ms: number | null;
  paid_at_ms: number | null;
}

interface BillingRefundRow {
  stripe_refund_id: string;
  stripe_charge_id: string | null;
  stripe_payment_intent_id: string | null;
  status: string;
  amount: number;
  currency: string | null;
  reason: string | null;
  failure_reason: string | null;
  receipt_number: string | null;
  created_at_ms: number | null;
  updated_at_ms: number;
}

interface BillingDisputeRow {
  stripe_dispute_id: string;
  stripe_charge_id: string | null;
  status: string;
  amount: number;
  currency: string | null;
  reason: string | null;
  evidence_due_by_ms: number | null;
  is_charge_refundable: boolean;
  created_at_ms: number | null;
  updated_at_ms: number;
}

const SESSION_COOKIE = "xsend_session";
const OAUTH_COOKIE = "xsend_oauth";
const CLIENT_ID_HEADER = "x-client-id";

// Ensure bcrypt salt generation uses cryptographically secure randomness (Workers provides WebCrypto).
bcrypt.setRandomFallback((len: number) => {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return Array.from(buf);
});

function corsHeaders(origin: string | null) {
  // For MVP: allow any origin (daemon UI, public page, etc.)
  const allowOrigin = origin ?? "*";
  return {
    "access-control-allow-origin": allowOrigin,
    "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
    "access-control-allow-headers": "content-type,authorization,x-filename",
    "access-control-max-age": "86400",
  };
}

function withCors(req: Request, res: Response): Response {
  const origin = req.headers.get("origin");
  const headers = new Headers(res.headers);
  const cors = corsHeaders(origin);
  for (const [k, v] of Object.entries(cors)) headers.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

function json(req: Request, value: any, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  return withCors(req, new Response(JSON.stringify(value), { ...init, headers }));
}

function err(req: Request, status: number, message: string): Response {
  return json(req, { error: message }, { status });
}

type IntEnvKey =
  | "MAX_FILES"
  | "MAX_FILE_BYTES"
  | "MAX_TOTAL_BYTES"
  | "CHANNEL_TTL_SECONDS"
  | "FILE_TTL_SECONDS"
  | "PRO_MAX_FILES"
  | "PRO_MAX_FILE_BYTES"
  | "PRO_MAX_TOTAL_BYTES"
  | "PRO_FILE_TTL_SECONDS"
  | "E2EE_OVERHEAD_BYTES";

function parseIntEnv(env: Env, key: IntEnvKey, fallback: number) {
  const raw = env[key];
  if (typeof raw !== "string" || raw.trim().length === 0) return fallback;
  const v = Number.parseInt(raw, 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

function parseFloatEnv(raw: string | undefined, fallback: number): number {
  if (typeof raw !== "string" || raw.trim().length === 0) return fallback;
  const v = Number.parseFloat(raw);
  return Number.isFinite(v) ? v : fallback;
}

function parseBoolEnv(raw: string | undefined, fallback: boolean): boolean {
  if (typeof raw !== "string" || raw.trim().length === 0) return fallback;
  const v = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  return fallback;
}

function getClientIp(request: Request): string {
  const ipDirect = request.headers.get("cf-connecting-ip");
  if (typeof ipDirect === "string" && ipDirect.trim()) return ipDirect.trim();
  const xff = request.headers.get("x-forwarded-for");
  if (typeof xff === "string" && xff.trim()) {
    const first = xff.split(",")[0]?.trim();
    if (first) return first;
  }
  return "0.0.0.0";
}

function maskIp(ip: string): string {
  if (/^[0-9.]+$/.test(ip)) {
    const p = ip.split(".");
    if (p.length === 4) return `${p[0]}.${p[1]}.${p[2]}.x`;
  }
  if (ip.includes(":")) return "ipv6";
  return "unknown";
}

function sanitizePeerId(raw: string | null | undefined): string | null {
  const s = String(raw || "").trim();
  if (!s) return null;
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(s)) return null;
  return s;
}

function sanitizePeerName(raw: string | null | undefined): string | null {
  const s = String(raw || "").trim();
  if (!s) return null;
  return s.slice(0, 64);
}

function wsDataToString(data: any): string | null {
  if (typeof data === "string") return data;
  if (data instanceof ArrayBuffer) {
    try {
      return new TextDecoder().decode(new Uint8Array(data));
    } catch (_) {
      return null;
    }
  }
  if (ArrayBuffer.isView(data)) {
    try {
      const view = data as ArrayBufferView;
      return new TextDecoder().decode(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
    } catch (_) {
      return null;
    }
  }
  return null;
}

function nowMs(): number {
  return Date.now();
}

function nowDateKey(): string {
  return new Date().toISOString().slice(0, 10);
}

function nowMonthKey(): string {
  return new Date().toISOString().slice(0, 7);
}

function parseMonthKey(raw: string | null | undefined): string | null {
  const v = String(raw || "").trim();
  if (!v) return nowMonthKey();
  if (!/^[0-9]{4}-[0-9]{2}$/.test(v)) return null;
  const year = Number.parseInt(v.slice(0, 4), 10);
  const month = Number.parseInt(v.slice(5, 7), 10);
  if (!Number.isFinite(year) || !Number.isFinite(month)) return null;
  if (year < 2000 || year > 2100) return null;
  if (month < 1 || month > 12) return null;
  return v;
}

function monthBoundsMs(monthKey: string): { start_ms: number; end_ms: number } {
  const year = Number.parseInt(monthKey.slice(0, 4), 10);
  const month = Number.parseInt(monthKey.slice(5, 7), 10);
  const start = Date.UTC(year, month - 1, 1, 0, 0, 0, 0);
  const end = month === 12 ? Date.UTC(year + 1, 0, 1, 0, 0, 0, 0) : Date.UTC(year, month, 1, 0, 0, 0, 0);
  return { start_ms: start, end_ms: end };
}

function csvEscape(v: any): string {
  if (v === null || v === undefined) return "";
  const s = String(v);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, "\"\"")}"`;
  return s;
}

function normalizePlanName(v: string | null | undefined): string {
  const s = String(v || "").trim().toLowerCase();
  if (!s) return "free";
  return s;
}

function isPaidPlan(planName: string): boolean {
  const p = normalizePlanName(planName);
  return p === "pro" || p === "paid" || p === "business" || p === "enterprise";
}

function resolveClientFeatures(env: Env, limits: ClientLimits): ClientFeatures {
  const paid = isPaidPlan(limits.plan);
  const turnRequirePaid = parseBoolEnv(env.TURN_REQUIRE_PAID, false);
  const relayUploadRequirePaid = parseBoolEnv(env.RELAY_UPLOAD_REQUIRE_PAID, false);
  const relayDownloadRequirePaid = parseBoolEnv(env.RELAY_DOWNLOAD_REQUIRE_PAID, false);
  const relayE2eeRequirePaid = parseBoolEnv(env.RELAY_E2EE_REQUIRE_PAID, false);
  const relayBatchRequirePaid = parseBoolEnv(env.RELAY_BATCH_REQUIRE_PAID, false);
  const autoDiscoveryRequirePaid = parseBoolEnv(env.AUTO_DISCOVERY_REQUIRE_PAID, false);
  const offlineModeRequirePaid = parseBoolEnv(env.OFFLINE_MODE_REQUIRE_PAID, false);
  return {
    relay_upload: relayUploadRequirePaid ? paid : true,
    relay_download: relayDownloadRequirePaid ? paid : true,
    relay_e2ee: relayE2eeRequirePaid ? paid : true,
    relay_batch_upload: relayBatchRequirePaid ? paid : true,
    turn_accelerate: turnRequirePaid ? paid : true,
    auto_discovery: autoDiscoveryRequirePaid ? paid : true,
    offline_mode: offlineModeRequirePaid ? paid : true,
  };
}

function featureDenied(
  request: Request,
  feature: keyof ClientFeatures,
  limits: ClientLimits,
  features: ClientFeatures,
  message: string,
): Response {
  return json(
    request,
    {
      error: message,
      upgrade_required: true,
      plan: limits.plan,
      feature,
      features,
    },
    { status: 402 },
  );
}

function limitsFromEnv(env: Env, paid: boolean): ClientLimits {
  if (paid) {
    return {
      plan: "pro",
      max_files: parseIntEnv(env, "PRO_MAX_FILES", 200),
      max_file_bytes: parseIntEnv(env, "PRO_MAX_FILE_BYTES", 1024 * 1024 * 1024),
      max_total_bytes: parseIntEnv(env, "PRO_MAX_TOTAL_BYTES", 200 * 1024 * 1024 * 1024),
      file_ttl_seconds: parseIntEnv(env, "PRO_FILE_TTL_SECONDS", 30 * 24 * 3600),
      source: "client_type",
    };
  }
  return {
    plan: "free",
    max_files: parseIntEnv(env, "MAX_FILES", 5),
    max_file_bytes: parseIntEnv(env, "MAX_FILE_BYTES", 10 * 1024 * 1024),
    max_total_bytes: parseIntEnv(env, "MAX_TOTAL_BYTES", 50 * 1024 * 1024),
    file_ttl_seconds: parseIntEnv(env, "FILE_TTL_SECONDS", 7 * 24 * 3600),
    source: "default",
  };
}

async function dbClientType(env: Env, clientId: string): Promise<string | null> {
  try {
    const row = (await env.XADMIN_DB.prepare("SELECT client_type FROM clients WHERE id=?1 LIMIT 1").bind(clientId).first()) as any;
    if (!row) return null;
    return typeof row.client_type === "string" ? row.client_type : null;
  } catch (_) {
    return null;
  }
}

async function dbPlanOverride(env: Env, clientId: string): Promise<Partial<ClientLimits> | null> {
  try {
    const now = nowMs();
    const row = (await env.XADMIN_DB.prepare(
      "SELECT plan, max_files, max_file_bytes, max_total_bytes, file_ttl_seconds, status, expires_at_ms FROM xsend_client_plans WHERE client_id=?1 ORDER BY updated_at_ms DESC LIMIT 1",
    )
      .bind(clientId)
      .first()) as any;
    if (!row) return null;
    const status = String(row.status || "active");
    if (status !== "active") return null;
    const exp = Number(row.expires_at_ms || 0);
    if (Number.isFinite(exp) && exp > 0 && exp <= now) return null;

    const out: Partial<ClientLimits> = { source: "plan_override" };
    if (typeof row.plan === "string" && row.plan.trim().length > 0) out.plan = normalizePlanName(row.plan);
    if (Number.isFinite(Number(row.max_files)) && Number(row.max_files) > 0) out.max_files = Number(row.max_files);
    if (Number.isFinite(Number(row.max_file_bytes)) && Number(row.max_file_bytes) > 0) out.max_file_bytes = Number(row.max_file_bytes);
    if (Number.isFinite(Number(row.max_total_bytes)) && Number(row.max_total_bytes) > 0) out.max_total_bytes = Number(row.max_total_bytes);
    if (Number.isFinite(Number(row.file_ttl_seconds)) && Number(row.file_ttl_seconds) > 0) out.file_ttl_seconds = Number(row.file_ttl_seconds);
    return out;
  } catch (_) {
    // Table may not exist yet; keep fallback behavior.
    return null;
  }
}

async function resolveClientLimits(env: Env, clientId: string, clientTypeHint?: string | null): Promise<ClientLimits> {
  const ctype = normalizePlanName(clientTypeHint || (await dbClientType(env, clientId)));
  const paidByType = isPaidPlan(ctype) || ctype.includes("pro") || ctype.includes("paid");
  let limits = limitsFromEnv(env, paidByType);
  if (paidByType) {
    limits.plan = ctype === "free" ? "pro" : ctype;
    limits.source = "client_type";
  }

  const override = await dbPlanOverride(env, clientId);
  if (override) {
    limits = {
      plan: override.plan || limits.plan,
      max_files: override.max_files || limits.max_files,
      max_file_bytes: override.max_file_bytes || limits.max_file_bytes,
      max_total_bytes: override.max_total_bytes || limits.max_total_bytes,
      file_ttl_seconds: override.file_ttl_seconds || limits.file_ttl_seconds,
      source: "plan_override",
    };
  }
  return limits;
}

async function recordUsage(
  env: Env,
  clientId: string,
  uploadBytes: number,
  downloadBytes: number,
  uploadFiles: number,
  downloadFiles: number,
): Promise<void> {
  if (!clientId) return;
  const upB = Number.isFinite(uploadBytes) && uploadBytes > 0 ? Math.floor(uploadBytes) : 0;
  const downB = Number.isFinite(downloadBytes) && downloadBytes > 0 ? Math.floor(downloadBytes) : 0;
  const upF = Number.isFinite(uploadFiles) && uploadFiles > 0 ? Math.floor(uploadFiles) : 0;
  const downF = Number.isFinite(downloadFiles) && downloadFiles > 0 ? Math.floor(downloadFiles) : 0;
  if (upB === 0 && downB === 0 && upF === 0 && downF === 0) return;

  try {
    const now = nowMs();
    const key = nowDateKey();
    await env.XADMIN_DB.prepare(
      "INSERT INTO xsend_usage_daily (client_id, date_key, upload_bytes, download_bytes, upload_files, download_files, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(client_id, date_key) DO UPDATE SET upload_bytes=upload_bytes + excluded.upload_bytes, download_bytes=download_bytes + excluded.download_bytes, upload_files=upload_files + excluded.upload_files, download_files=download_files + excluded.download_files, updated_at_ms=excluded.updated_at_ms",
    )
      .bind(clientId, key, upB, downB, upF, downF, now)
      .run();
  } catch (_) {
    // Usage metering is best effort; should not break transfer path.
  }
}

async function getUsageToday(env: Env, clientId: string): Promise<UsageDaily> {
  const empty: UsageDaily = {
    date_key: nowDateKey(),
    upload_bytes: 0,
    download_bytes: 0,
    upload_files: 0,
    download_files: 0,
  };
  try {
    const key = nowDateKey();
    const row = (await env.XADMIN_DB.prepare(
      "SELECT date_key, upload_bytes, download_bytes, upload_files, download_files FROM xsend_usage_daily WHERE client_id=?1 AND date_key=?2 LIMIT 1",
    )
      .bind(clientId, key)
      .first()) as any;
    if (!row) return empty;
    return {
      date_key: typeof row.date_key === "string" ? row.date_key : key,
      upload_bytes: Number.isFinite(Number(row.upload_bytes)) ? Number(row.upload_bytes) : 0,
      download_bytes: Number.isFinite(Number(row.download_bytes)) ? Number(row.download_bytes) : 0,
      upload_files: Number.isFinite(Number(row.upload_files)) ? Number(row.upload_files) : 0,
      download_files: Number.isFinite(Number(row.download_files)) ? Number(row.download_files) : 0,
    };
  } catch (_) {
    return empty;
  }
}

async function getUsageMonth(env: Env, clientId: string): Promise<UsageMonth> {
  return await getUsageMonthFor(env, clientId, nowMonthKey());
}

async function getUsageMonthFor(env: Env, clientId: string, monthKey: string): Promise<UsageMonth> {
  const empty: UsageMonth = {
    month_key: monthKey,
    upload_bytes: 0,
    download_bytes: 0,
    upload_files: 0,
    download_files: 0,
  };
  try {
    const row = (await env.XADMIN_DB.prepare(
      "SELECT SUM(upload_bytes) AS upload_bytes, SUM(download_bytes) AS download_bytes, SUM(upload_files) AS upload_files, SUM(download_files) AS download_files FROM xsend_usage_daily WHERE client_id=?1 AND substr(date_key,1,7)=?2",
    )
      .bind(clientId, monthKey)
      .first()) as any;
    return {
      month_key: monthKey,
      upload_bytes: Number.isFinite(Number(row?.upload_bytes)) ? Number(row.upload_bytes) : 0,
      download_bytes: Number.isFinite(Number(row?.download_bytes)) ? Number(row.download_bytes) : 0,
      upload_files: Number.isFinite(Number(row?.upload_files)) ? Number(row.upload_files) : 0,
      download_files: Number.isFinite(Number(row?.download_files)) ? Number(row.download_files) : 0,
    };
  } catch (_) {
    return empty;
  }
}

function stripeConfigured(env: Env): boolean {
  return (
    isNonEmpty(env.STRIPE_SECRET_KEY) &&
    isNonEmpty(env.STRIPE_PRICE_ID) &&
    isNonEmpty(env.BILLING_SUCCESS_URL) &&
    isNonEmpty(env.BILLING_CANCEL_URL)
  );
}

function stripeWebhookConfigured(env: Env): boolean {
  return stripeConfigured(env) && isNonEmpty(env.STRIPE_WEBHOOK_SECRET);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function parseUnixSecondsToMs(v: any): number | null {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n * 1000);
}

function stripeStatusGrantsPro(statusRaw: any): boolean {
  const s = String(statusRaw || "").trim().toLowerCase();
  return s === "active" || s === "trialing" || s === "past_due";
}

function normalizeCurrency(v: any): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim().toLowerCase();
  return s ? s : null;
}

function parseStripeSigHeader(v: string | null): { timestamp: number; v1: string[] } | null {
  if (!v) return null;
  const parts = v.split(",").map((x) => x.trim()).filter(Boolean);
  let ts = 0;
  const v1: string[] = [];
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx <= 0) continue;
    const k = p.slice(0, idx).trim();
    const val = p.slice(idx + 1).trim();
    if (k === "t") {
      const n = Number.parseInt(val, 10);
      if (Number.isFinite(n) && n > 0) ts = n;
      continue;
    }
    if (k === "v1" && /^[0-9a-fA-F]{64}$/.test(val)) {
      v1.push(val.toLowerCase());
    }
  }
  if (!ts || v1.length === 0) return null;
  return { timestamp: ts, v1 };
}

async function verifyStripeWebhookSignature(env: Env, rawBody: string, sigHeader: string | null): Promise<boolean> {
  if (!isNonEmpty(env.STRIPE_WEBHOOK_SECRET)) return false;
  const parsed = parseStripeSigHeader(sigHeader);
  if (!parsed) return false;
  const nowSec = Math.floor(Date.now() / 1000);
  const age = Math.abs(nowSec - parsed.timestamp);
  if (age > 5 * 60) return false;

  const signedPayload = `${parsed.timestamp}.${rawBody}`;
  const sig = await hmacSha256(env.STRIPE_WEBHOOK_SECRET.trim(), signedPayload);
  const got = bytesToHex(sig);
  for (const want of parsed.v1) {
    if (timingSafeEqual(got, want)) return true;
  }
  return false;
}

async function stripeApiRequest(
  env: Env,
  method: "GET" | "POST",
  path: string,
  params?: URLSearchParams,
  extraHeaders?: Record<string, string>,
): Promise<any> {
  if (!isNonEmpty(env.STRIPE_SECRET_KEY)) throw new Error("stripe not configured");
  let url = `https://api.stripe.com${path}`;
  const headers = new Headers(extraHeaders || {});
  headers.set("authorization", `Bearer ${env.STRIPE_SECRET_KEY.trim()}`);

  let body: string | undefined = undefined;
  if (method === "GET") {
    const q = params ? params.toString() : "";
    if (q) url += (url.includes("?") ? "&" : "?") + q;
  } else if (params) {
    headers.set("content-type", "application/x-www-form-urlencoded");
    body = params.toString();
  } else {
    headers.set("content-type", "application/x-www-form-urlencoded");
    body = "";
  }

  const res = await fetch(url, { method, headers, body });
  const text = await res.text().catch(() => "");
  let j: any = null;
  if (text) {
    try {
      j = JSON.parse(text);
    } catch (_) {
      j = null;
    }
  }
  if (!res.ok) {
    const msg = typeof j?.error?.message === "string" ? j.error.message : `${res.status} ${res.statusText}`;
    throw new Error(`stripe api failed (${path}): ${msg}`);
  }
  return j;
}

async function dbGetBillingCustomerByClient(env: Env, clientId: string): Promise<string | null> {
  const row = (await env.XADMIN_DB.prepare(
    "SELECT stripe_customer_id FROM xsend_billing_customers WHERE client_id=?1 LIMIT 1",
  )
    .bind(clientId)
    .first()) as any;
  if (!row || typeof row.stripe_customer_id !== "string") return null;
  return row.stripe_customer_id;
}

async function dbGetBillingClientByCustomer(env: Env, customerId: string): Promise<string | null> {
  const row = (await env.XADMIN_DB.prepare(
    "SELECT client_id FROM xsend_billing_customers WHERE stripe_customer_id=?1 LIMIT 1",
  )
    .bind(customerId)
    .first()) as any;
  if (!row || typeof row.client_id !== "string") return null;
  return row.client_id;
}

async function dbUpsertBillingCustomer(env: Env, clientId: string, customerId: string, email: string | null): Promise<void> {
  const now = nowMs();
  await env.XADMIN_DB.prepare(
    "INSERT OR REPLACE INTO xsend_billing_customers (client_id, stripe_customer_id, email, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?4)",
  )
    .bind(clientId, customerId, email, now)
    .run();
}

async function dbMarkStripeEventSeen(env: Env, eventId: string, eventType: string): Promise<boolean> {
  const existing = (await env.XADMIN_DB.prepare(
    "SELECT stripe_event_id FROM xsend_billing_events WHERE stripe_event_id=?1 LIMIT 1",
  )
    .bind(eventId)
    .first()) as any;
  if (existing) return false;

  await env.XADMIN_DB.prepare(
    "INSERT INTO xsend_billing_events (stripe_event_id, event_type, received_at_ms) VALUES (?1, ?2, ?3)",
  )
    .bind(eventId, eventType, nowMs())
    .run();
  return true;
}

async function dbUpsertBillingSubscription(
  env: Env,
  clientId: string,
  subscriptionId: string,
  status: string,
  plan: string,
  currentPeriodStartMs: number | null,
  currentPeriodEndMs: number | null,
  cancelAtPeriodEnd: boolean,
): Promise<void> {
  const now = nowMs();
  await env.XADMIN_DB.prepare(
    "INSERT INTO xsend_billing_subscriptions (stripe_subscription_id, client_id, status, plan, current_period_start_ms, current_period_end_ms, cancel_at_period_end, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(stripe_subscription_id) DO UPDATE SET client_id=?2, status=?3, plan=?4, current_period_start_ms=?5, current_period_end_ms=?6, cancel_at_period_end=?7, updated_at_ms=?8",
  )
    .bind(
      subscriptionId,
      clientId,
      status,
      plan,
      currentPeriodStartMs,
      currentPeriodEndMs,
      cancelAtPeriodEnd ? 1 : 0,
      now,
    )
    .run();
}

async function dbSetClientProPlanStatus(
  env: Env,
  clientId: string,
  active: boolean,
  startsAtMs: number | null,
  expiresAtMs: number | null,
): Promise<void> {
  const now = nowMs();
  const status = active ? "active" : "inactive";
  const effectiveExpiresAt = expiresAtMs && expiresAtMs > 0 ? expiresAtMs : active ? now + 30 * 24 * 3600 * 1000 : now;
  await env.XADMIN_DB.prepare(
    "INSERT INTO xsend_client_plans (client_id, plan, status, starts_at_ms, expires_at_ms, updated_at_ms) VALUES (?1, 'pro', ?2, ?3, ?4, ?5) ON CONFLICT(client_id, plan) DO UPDATE SET status=?2, starts_at_ms=COALESCE(?3, xsend_client_plans.starts_at_ms), expires_at_ms=?4, updated_at_ms=?5",
  )
    .bind(clientId, status, startsAtMs, effectiveExpiresAt, now)
    .run();
}

async function dbUpsertBillingInvoice(
  env: Env,
  clientId: string,
  stripeInvoiceId: string,
  stripeCustomerId: string | null,
  stripeSubscriptionId: string | null,
  status: string,
  amountDue: number,
  amountPaid: number,
  currency: string | null,
  hostedInvoiceUrl: string | null,
  invoicePdfUrl: string | null,
  periodStartMs: number | null,
  periodEndMs: number | null,
  createdAtMs: number | null,
  paidAtMs: number | null,
  stripeChargeId: string | null,
  stripePaymentIntentId: string | null,
  subtotalExcludingTax: number | null,
  taxAmount: number | null,
): Promise<void> {
  const now = nowMs();
  try {
    await env.XADMIN_DB.prepare(
      "INSERT INTO xsend_billing_invoices (stripe_invoice_id, client_id, stripe_customer_id, stripe_subscription_id, stripe_charge_id, stripe_payment_intent_id, status, amount_due, amount_paid, subtotal_excluding_tax, tax_amount, currency, hosted_invoice_url, invoice_pdf_url, period_start_ms, period_end_ms, created_at_ms, paid_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19) ON CONFLICT(stripe_invoice_id) DO UPDATE SET client_id=?2, stripe_customer_id=?3, stripe_subscription_id=?4, stripe_charge_id=?5, stripe_payment_intent_id=?6, status=?7, amount_due=?8, amount_paid=?9, subtotal_excluding_tax=?10, tax_amount=?11, currency=?12, hosted_invoice_url=?13, invoice_pdf_url=?14, period_start_ms=?15, period_end_ms=?16, created_at_ms=?17, paid_at_ms=?18, updated_at_ms=?19",
    )
      .bind(
        stripeInvoiceId,
        clientId,
        stripeCustomerId,
        stripeSubscriptionId,
        stripeChargeId,
        stripePaymentIntentId,
        status,
        amountDue,
        amountPaid,
        subtotalExcludingTax,
        taxAmount,
        currency,
        hostedInvoiceUrl,
        invoicePdfUrl,
        periodStartMs,
        periodEndMs,
        createdAtMs,
        paidAtMs,
        now,
      )
      .run();
  } catch (_) {
    // Backward-compatible fallback before enhanced migration is applied.
    await env.XADMIN_DB.prepare(
      "INSERT INTO xsend_billing_invoices (stripe_invoice_id, client_id, stripe_customer_id, stripe_subscription_id, status, amount_due, amount_paid, currency, hosted_invoice_url, invoice_pdf_url, period_start_ms, period_end_ms, created_at_ms, paid_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) ON CONFLICT(stripe_invoice_id) DO UPDATE SET client_id=?2, stripe_customer_id=?3, stripe_subscription_id=?4, status=?5, amount_due=?6, amount_paid=?7, currency=?8, hosted_invoice_url=?9, invoice_pdf_url=?10, period_start_ms=?11, period_end_ms=?12, created_at_ms=?13, paid_at_ms=?14, updated_at_ms=?15",
    )
      .bind(
        stripeInvoiceId,
        clientId,
        stripeCustomerId,
        stripeSubscriptionId,
        status,
        amountDue,
        amountPaid,
        currency,
        hostedInvoiceUrl,
        invoicePdfUrl,
        periodStartMs,
        periodEndMs,
        createdAtMs,
        paidAtMs,
        now,
      )
      .run();
  }
}

async function dbGetLatestBillingSubscription(env: Env, clientId: string): Promise<BillingSubscriptionRow | null> {
  const row = (await env.XADMIN_DB.prepare(
    "SELECT stripe_subscription_id, status, plan, current_period_start_ms, current_period_end_ms, cancel_at_period_end, updated_at_ms FROM xsend_billing_subscriptions WHERE client_id=?1 ORDER BY updated_at_ms DESC LIMIT 1",
  )
    .bind(clientId)
    .first()) as any;
  if (!row) return null;
  return {
    stripe_subscription_id: String(row.stripe_subscription_id),
    status: String(row.status || ""),
    plan: String(row.plan || "pro"),
    current_period_start_ms: Number.isFinite(Number(row.current_period_start_ms)) ? Number(row.current_period_start_ms) : null,
    current_period_end_ms: Number.isFinite(Number(row.current_period_end_ms)) ? Number(row.current_period_end_ms) : null,
    cancel_at_period_end: Number(row.cancel_at_period_end || 0) === 1,
    updated_at_ms: Number.isFinite(Number(row.updated_at_ms)) ? Number(row.updated_at_ms) : 0,
  };
}

async function dbListBillingInvoices(env: Env, clientId: string, limit: number): Promise<BillingInvoiceRow[]> {
  const lim = Math.max(1, Math.min(100, Math.floor(limit)));
  const rows = (await env.XADMIN_DB.prepare(
    "SELECT stripe_invoice_id, status, amount_due, amount_paid, currency, hosted_invoice_url, invoice_pdf_url, period_start_ms, period_end_ms, created_at_ms, paid_at_ms FROM xsend_billing_invoices WHERE client_id=?1 ORDER BY COALESCE(created_at_ms, updated_at_ms) DESC LIMIT ?2",
  )
    .bind(clientId, lim)
    .all()) as any;
  const out: BillingInvoiceRow[] = [];
  const list = Array.isArray(rows?.results) ? rows.results : [];
  for (const row of list) {
    out.push({
      stripe_invoice_id: String(row.stripe_invoice_id || ""),
      status: String(row.status || ""),
      amount_due: Number.isFinite(Number(row.amount_due)) ? Number(row.amount_due) : 0,
      amount_paid: Number.isFinite(Number(row.amount_paid)) ? Number(row.amount_paid) : 0,
      currency: typeof row.currency === "string" ? row.currency : null,
      hosted_invoice_url: typeof row.hosted_invoice_url === "string" ? row.hosted_invoice_url : null,
      invoice_pdf_url: typeof row.invoice_pdf_url === "string" ? row.invoice_pdf_url : null,
      period_start_ms: Number.isFinite(Number(row.period_start_ms)) ? Number(row.period_start_ms) : null,
      period_end_ms: Number.isFinite(Number(row.period_end_ms)) ? Number(row.period_end_ms) : null,
      created_at_ms: Number.isFinite(Number(row.created_at_ms)) ? Number(row.created_at_ms) : null,
      paid_at_ms: Number.isFinite(Number(row.paid_at_ms)) ? Number(row.paid_at_ms) : null,
    });
  }
  return out;
}

async function dbUpsertBillingChargeLink(
  env: Env,
  clientId: string,
  stripeChargeId: string,
  stripePaymentIntentId: string | null,
  sourceInvoiceId: string | null,
): Promise<void> {
  if (!stripeChargeId) return;
  const now = nowMs();
  try {
    await env.XADMIN_DB.prepare(
      "INSERT INTO xsend_billing_charge_links (stripe_charge_id, stripe_payment_intent_id, client_id, source_invoice_id, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(stripe_charge_id) DO UPDATE SET stripe_payment_intent_id=?2, client_id=?3, source_invoice_id=COALESCE(?4, xsend_billing_charge_links.source_invoice_id), updated_at_ms=?5",
    )
      .bind(stripeChargeId, stripePaymentIntentId, clientId, sourceInvoiceId, now)
      .run();
  } catch (_) {
    // Table may not exist before enhanced migration.
  }
}

async function dbResolveBillingClientByCharge(
  env: Env,
  stripeChargeId: string | null,
  stripePaymentIntentId: string | null,
): Promise<string | null> {
  try {
    if (stripeChargeId) {
      const row = (await env.XADMIN_DB.prepare(
        "SELECT client_id FROM xsend_billing_charge_links WHERE stripe_charge_id=?1 LIMIT 1",
      )
        .bind(stripeChargeId)
        .first()) as any;
      if (row && typeof row.client_id === "string" && row.client_id) return row.client_id;
    }
    if (stripePaymentIntentId) {
      const row = (await env.XADMIN_DB.prepare(
        "SELECT client_id FROM xsend_billing_charge_links WHERE stripe_payment_intent_id=?1 ORDER BY updated_at_ms DESC LIMIT 1",
      )
        .bind(stripePaymentIntentId)
        .first()) as any;
      if (row && typeof row.client_id === "string" && row.client_id) return row.client_id;
    }
    return null;
  } catch (_) {
    // Table may not exist before enhanced migration.
    return null;
  }
}

async function dbUpsertBillingRefund(
  env: Env,
  clientId: string,
  stripeRefundId: string,
  stripeChargeId: string | null,
  stripePaymentIntentId: string | null,
  status: string,
  amount: number,
  currency: string | null,
  reason: string | null,
  failureReason: string | null,
  receiptNumber: string | null,
  createdAtMs: number | null,
): Promise<void> {
  if (!stripeRefundId) return;
  const now = nowMs();
  try {
    await env.XADMIN_DB.prepare(
      "INSERT INTO xsend_billing_refunds (stripe_refund_id, client_id, stripe_charge_id, stripe_payment_intent_id, status, amount, currency, reason, failure_reason, receipt_number, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) ON CONFLICT(stripe_refund_id) DO UPDATE SET client_id=?2, stripe_charge_id=?3, stripe_payment_intent_id=?4, status=?5, amount=?6, currency=?7, reason=?8, failure_reason=?9, receipt_number=?10, created_at_ms=COALESCE(?11, xsend_billing_refunds.created_at_ms), updated_at_ms=?12",
    )
      .bind(
        stripeRefundId,
        clientId,
        stripeChargeId,
        stripePaymentIntentId,
        status,
        amount,
        currency,
        reason,
        failureReason,
        receiptNumber,
        createdAtMs,
        now,
      )
      .run();
  } catch (_) {
    // Table may not exist before enhanced migration.
  }
}

async function dbUpsertBillingDispute(
  env: Env,
  clientId: string,
  stripeDisputeId: string,
  stripeChargeId: string | null,
  status: string,
  amount: number,
  currency: string | null,
  reason: string | null,
  evidenceDueByMs: number | null,
  isChargeRefundable: boolean,
  createdAtMs: number | null,
): Promise<void> {
  if (!stripeDisputeId) return;
  const now = nowMs();
  try {
    await env.XADMIN_DB.prepare(
      "INSERT INTO xsend_billing_disputes (stripe_dispute_id, client_id, stripe_charge_id, status, amount, currency, reason, evidence_due_by_ms, is_charge_refundable, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) ON CONFLICT(stripe_dispute_id) DO UPDATE SET client_id=?2, stripe_charge_id=?3, status=?4, amount=?5, currency=?6, reason=?7, evidence_due_by_ms=?8, is_charge_refundable=?9, created_at_ms=COALESCE(?10, xsend_billing_disputes.created_at_ms), updated_at_ms=?11",
    )
      .bind(
        stripeDisputeId,
        clientId,
        stripeChargeId,
        status,
        amount,
        currency,
        reason,
        evidenceDueByMs,
        isChargeRefundable ? 1 : 0,
        createdAtMs,
        now,
      )
      .run();
  } catch (_) {
    // Table may not exist before enhanced migration.
  }
}

async function dbListBillingRefunds(env: Env, clientId: string, limit: number): Promise<BillingRefundRow[]> {
  const lim = Math.max(1, Math.min(100, Math.floor(limit)));
  const rows = (await env.XADMIN_DB.prepare(
    "SELECT stripe_refund_id, stripe_charge_id, stripe_payment_intent_id, status, amount, currency, reason, failure_reason, receipt_number, created_at_ms, updated_at_ms FROM xsend_billing_refunds WHERE client_id=?1 ORDER BY COALESCE(created_at_ms, updated_at_ms) DESC LIMIT ?2",
  )
    .bind(clientId, lim)
    .all()) as any;
  const out: BillingRefundRow[] = [];
  const list = Array.isArray(rows?.results) ? rows.results : [];
  for (const row of list) {
    out.push({
      stripe_refund_id: String(row.stripe_refund_id || ""),
      stripe_charge_id: typeof row.stripe_charge_id === "string" ? row.stripe_charge_id : null,
      stripe_payment_intent_id: typeof row.stripe_payment_intent_id === "string" ? row.stripe_payment_intent_id : null,
      status: String(row.status || ""),
      amount: Number.isFinite(Number(row.amount)) ? Number(row.amount) : 0,
      currency: typeof row.currency === "string" ? row.currency : null,
      reason: typeof row.reason === "string" ? row.reason : null,
      failure_reason: typeof row.failure_reason === "string" ? row.failure_reason : null,
      receipt_number: typeof row.receipt_number === "string" ? row.receipt_number : null,
      created_at_ms: Number.isFinite(Number(row.created_at_ms)) ? Number(row.created_at_ms) : null,
      updated_at_ms: Number.isFinite(Number(row.updated_at_ms)) ? Number(row.updated_at_ms) : 0,
    });
  }
  return out;
}

async function dbListBillingDisputes(env: Env, clientId: string, limit: number): Promise<BillingDisputeRow[]> {
  const lim = Math.max(1, Math.min(100, Math.floor(limit)));
  const rows = (await env.XADMIN_DB.prepare(
    "SELECT stripe_dispute_id, stripe_charge_id, status, amount, currency, reason, evidence_due_by_ms, is_charge_refundable, created_at_ms, updated_at_ms FROM xsend_billing_disputes WHERE client_id=?1 ORDER BY COALESCE(created_at_ms, updated_at_ms) DESC LIMIT ?2",
  )
    .bind(clientId, lim)
    .all()) as any;
  const out: BillingDisputeRow[] = [];
  const list = Array.isArray(rows?.results) ? rows.results : [];
  for (const row of list) {
    out.push({
      stripe_dispute_id: String(row.stripe_dispute_id || ""),
      stripe_charge_id: typeof row.stripe_charge_id === "string" ? row.stripe_charge_id : null,
      status: String(row.status || ""),
      amount: Number.isFinite(Number(row.amount)) ? Number(row.amount) : 0,
      currency: typeof row.currency === "string" ? row.currency : null,
      reason: typeof row.reason === "string" ? row.reason : null,
      evidence_due_by_ms: Number.isFinite(Number(row.evidence_due_by_ms)) ? Number(row.evidence_due_by_ms) : null,
      is_charge_refundable: Number(row.is_charge_refundable || 0) === 1,
      created_at_ms: Number.isFinite(Number(row.created_at_ms)) ? Number(row.created_at_ms) : null,
      updated_at_ms: Number.isFinite(Number(row.updated_at_ms)) ? Number(row.updated_at_ms) : 0,
    });
  }
  return out;
}

async function dbBillingMonthReport(
  env: Env,
  clientId: string,
  monthKey: string,
): Promise<{
  month: string;
  usage: UsageMonth;
  invoices: { count: number; amount_due: number; amount_paid: number };
  refunds: { count: number; amount_succeeded: number };
  disputes: { count: number; open_count: number; amount_open: number; amount_won: number; amount_lost: number };
}> {
  const usage = await getUsageMonthFor(env, clientId, monthKey);
  const bounds = monthBoundsMs(monthKey);
  let invRow: any = null;
  let refundRow: any = null;
  let disputeRow: any = null;
  try {
    invRow = (await env.XADMIN_DB.prepare(
      "SELECT COUNT(*) AS n, SUM(amount_due) AS amount_due, SUM(amount_paid) AS amount_paid FROM xsend_billing_invoices WHERE client_id=?1 AND created_at_ms>=?2 AND created_at_ms<?3",
    )
      .bind(clientId, bounds.start_ms, bounds.end_ms)
      .first()) as any;
  } catch (_) {}
  try {
    refundRow = (await env.XADMIN_DB.prepare(
      "SELECT COUNT(*) AS n, SUM(CASE WHEN status='succeeded' THEN amount ELSE 0 END) AS amount_succeeded FROM xsend_billing_refunds WHERE client_id=?1 AND created_at_ms>=?2 AND created_at_ms<?3",
    )
      .bind(clientId, bounds.start_ms, bounds.end_ms)
      .first()) as any;
  } catch (_) {}
  try {
    disputeRow = (await env.XADMIN_DB.prepare(
      "SELECT COUNT(*) AS n, SUM(CASE WHEN status IN ('warning_needs_response','warning_under_review','needs_response','under_review') THEN 1 ELSE 0 END) AS open_count, SUM(CASE WHEN status IN ('warning_needs_response','warning_under_review','needs_response','under_review') THEN amount ELSE 0 END) AS amount_open, SUM(CASE WHEN status='won' THEN amount ELSE 0 END) AS amount_won, SUM(CASE WHEN status='lost' THEN amount ELSE 0 END) AS amount_lost FROM xsend_billing_disputes WHERE client_id=?1 AND created_at_ms>=?2 AND created_at_ms<?3",
    )
      .bind(clientId, bounds.start_ms, bounds.end_ms)
      .first()) as any;
  } catch (_) {}

  return {
    month: monthKey,
    usage,
    invoices: {
      count: Number.isFinite(Number(invRow?.n)) ? Number(invRow.n) : 0,
      amount_due: Number.isFinite(Number(invRow?.amount_due)) ? Number(invRow.amount_due) : 0,
      amount_paid: Number.isFinite(Number(invRow?.amount_paid)) ? Number(invRow.amount_paid) : 0,
    },
    refunds: {
      count: Number.isFinite(Number(refundRow?.n)) ? Number(refundRow.n) : 0,
      amount_succeeded: Number.isFinite(Number(refundRow?.amount_succeeded)) ? Number(refundRow.amount_succeeded) : 0,
    },
    disputes: {
      count: Number.isFinite(Number(disputeRow?.n)) ? Number(disputeRow.n) : 0,
      open_count: Number.isFinite(Number(disputeRow?.open_count)) ? Number(disputeRow.open_count) : 0,
      amount_open: Number.isFinite(Number(disputeRow?.amount_open)) ? Number(disputeRow.amount_open) : 0,
      amount_won: Number.isFinite(Number(disputeRow?.amount_won)) ? Number(disputeRow.amount_won) : 0,
      amount_lost: Number.isFinite(Number(disputeRow?.amount_lost)) ? Number(disputeRow.amount_lost) : 0,
    },
  };
}

async function stripeGetSubscription(env: Env, subscriptionId: string): Promise<any> {
  return await stripeApiRequest(env, "GET", `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`);
}

async function ensureStripeCustomerForClient(env: Env, client: ClientRow): Promise<string> {
  const existing = await dbGetBillingCustomerByClient(env, client.id);
  if (existing) return existing;

  const params = new URLSearchParams();
  params.set("metadata[client_id]", client.id);
  params.set("name", client.username);
  if (client.email) params.set("email", client.email);

  const created = await stripeApiRequest(env, "POST", "/v1/customers", params, {
    "idempotency-key": `xsend-customer-${client.id}`,
  });
  const customerId = typeof created?.id === "string" ? created.id : "";
  if (!customerId) throw new Error("stripe customer creation returned no id");
  await dbUpsertBillingCustomer(env, client.id, customerId, client.email);
  return customerId;
}

function withCheckoutSessionPlaceholder(rawUrl: string): string {
  const url = String(rawUrl || "").trim();
  if (!url) return url;
  if (url.includes("{CHECKOUT_SESSION_ID}")) return url;
  try {
    const u = new URL(url);
    if (!u.searchParams.has("session_id")) u.searchParams.set("session_id", "{CHECKOUT_SESSION_ID}");
    return u.toString();
  } catch (_) {
    return url;
  }
}

async function createStripeCheckoutForClient(env: Env, client: ClientRow): Promise<{ id: string; url: string }> {
  if (!stripeConfigured(env)) throw new Error("stripe checkout is not configured");
  const customerId = await ensureStripeCustomerForClient(env, client);

  const successUrl = withCheckoutSessionPlaceholder(env.BILLING_SUCCESS_URL!.trim());
  const cancelUrl = env.BILLING_CANCEL_URL!.trim();
  const priceId = env.STRIPE_PRICE_ID!.trim();

  const params = new URLSearchParams();
  params.set("mode", "subscription");
  params.set("customer", customerId);
  params.set("client_reference_id", client.id);
  params.set("line_items[0][price]", priceId);
  params.set("line_items[0][quantity]", "1");
  params.set("allow_promotion_codes", "true");
  params.set("success_url", successUrl);
  params.set("cancel_url", cancelUrl);
  params.set("metadata[client_id]", client.id);
  params.set("metadata[plan]", "pro");
  params.set("subscription_data[metadata][client_id]", client.id);
  params.set("subscription_data[metadata][plan]", "pro");

  const session = await stripeApiRequest(env, "POST", "/v1/checkout/sessions", params);
  const sessionId = typeof session?.id === "string" ? session.id : "";
  const sessionUrl = typeof session?.url === "string" ? session.url : "";
  if (!sessionId || !sessionUrl) throw new Error("stripe checkout session creation failed");
  return { id: sessionId, url: sessionUrl };
}

function pickPortalReturnUrl(request: Request, env: Env, raw: string | null | undefined): string {
  const origin = new URL(request.url).origin;
  const fallback = isNonEmpty(env.BILLING_PORTAL_RETURN_URL) ? env.BILLING_PORTAL_RETURN_URL.trim() : `${origin}/`;
  const candidate = String(raw || "").trim();
  if (!candidate) return fallback;
  try {
    const u = new URL(candidate);
    const o = new URL(origin);
    if (u.origin !== o.origin) return fallback;
    return u.toString();
  } catch (_) {
    return fallback;
  }
}

async function createStripeBillingPortalForClient(
  request: Request,
  env: Env,
  client: ClientRow,
  returnUrlRaw?: string | null,
): Promise<{ id: string; url: string }> {
  if (!isNonEmpty(env.STRIPE_SECRET_KEY)) throw new Error("stripe is not configured");
  const customerId = await ensureStripeCustomerForClient(env, client);
  const params = new URLSearchParams();
  params.set("customer", customerId);
  params.set("return_url", pickPortalReturnUrl(request, env, returnUrlRaw));
  const session = await stripeApiRequest(env, "POST", "/v1/billing_portal/sessions", params);
  const id = typeof session?.id === "string" ? session.id : "";
  const url = typeof session?.url === "string" ? session.url : "";
  if (!id || !url) throw new Error("stripe billing portal session creation failed");
  return { id, url };
}

function summarizeSubscriptionView(sub: any): any {
  const id = typeof sub?.id === "string" ? sub.id : "";
  return {
    id,
    status: typeof sub?.status === "string" ? sub.status : "unknown",
    plan: "pro",
    cancel_at_period_end: Boolean(sub?.cancel_at_period_end),
    current_period_start_ms: parseUnixSecondsToMs(sub?.current_period_start),
    current_period_end_ms: parseUnixSecondsToMs(sub?.current_period_end),
  };
}

async function stripeListSubscriptionsForCustomer(env: Env, customerId: string): Promise<any[]> {
  const params = new URLSearchParams();
  params.set("customer", customerId);
  params.set("status", "all");
  params.set("limit", "20");
  const out = await stripeApiRequest(env, "GET", "/v1/subscriptions", params);
  return Array.isArray(out?.data) ? out.data : [];
}

async function stripeFindManagedSubscription(env: Env, clientId: string): Promise<any | null> {
  const sub = await dbGetLatestBillingSubscription(env, clientId);
  if (sub?.stripe_subscription_id) {
    try {
      return await stripeGetSubscription(env, sub.stripe_subscription_id);
    } catch (_) {
      // Try customer-based lookup below.
    }
  }
  const customerId = await dbGetBillingCustomerByClient(env, clientId);
  if (!customerId) return null;
  const list = await stripeListSubscriptionsForCustomer(env, customerId);
  if (list.length === 0) return null;
  const rank = (s: any): number => {
    const status = String(s?.status || "").toLowerCase();
    if (status === "active" || status === "trialing") return 3;
    if (status === "past_due" || status === "unpaid") return 2;
    if (status === "incomplete" || status === "incomplete_expired") return 1;
    return 0;
  };
  list.sort((a, b) => {
    const ra = rank(a);
    const rb = rank(b);
    if (rb !== ra) return rb - ra;
    const be = Number(b?.current_period_end || 0);
    const ae = Number(a?.current_period_end || 0);
    return be - ae;
  });
  return list[0] || null;
}

async function stripeUpdateSubscriptionCancelAtPeriodEnd(
  env: Env,
  subId: string,
  cancelAtPeriodEnd: boolean,
): Promise<any> {
  const params = new URLSearchParams();
  params.set("cancel_at_period_end", cancelAtPeriodEnd ? "true" : "false");
  return await stripeApiRequest(env, "POST", `/v1/subscriptions/${encodeURIComponent(subId)}`, params);
}

function billingReportToCsv(report: {
  month: string;
  usage: UsageMonth;
  invoices: { count: number; amount_due: number; amount_paid: number };
  refunds: { count: number; amount_succeeded: number };
  disputes: { count: number; open_count: number; amount_open: number; amount_won: number; amount_lost: number };
}): string {
  const lines: string[] = [];
  lines.push(
    [
      "month",
      "upload_bytes",
      "download_bytes",
      "upload_files",
      "download_files",
      "invoice_count",
      "invoice_amount_due_cents",
      "invoice_amount_paid_cents",
      "refund_count",
      "refund_succeeded_amount_cents",
      "dispute_count",
      "dispute_open_count",
      "dispute_open_amount_cents",
      "dispute_won_amount_cents",
      "dispute_lost_amount_cents",
    ].join(","),
  );
  lines.push(
    [
      csvEscape(report.month),
      csvEscape(report.usage.upload_bytes),
      csvEscape(report.usage.download_bytes),
      csvEscape(report.usage.upload_files),
      csvEscape(report.usage.download_files),
      csvEscape(report.invoices.count),
      csvEscape(report.invoices.amount_due),
      csvEscape(report.invoices.amount_paid),
      csvEscape(report.refunds.count),
      csvEscape(report.refunds.amount_succeeded),
      csvEscape(report.disputes.count),
      csvEscape(report.disputes.open_count),
      csvEscape(report.disputes.amount_open),
      csvEscape(report.disputes.amount_won),
      csvEscape(report.disputes.amount_lost),
    ].join(","),
  );
  return lines.join("\n") + "\n";
}

function stripeInvoicePeriodMs(inv: any): { start: number | null; end: number | null } {
  const directStart = parseUnixSecondsToMs(inv?.period_start);
  const directEnd = parseUnixSecondsToMs(inv?.period_end);
  if (directStart || directEnd) return { start: directStart, end: directEnd };

  const lines = inv?.lines?.data;
  if (!Array.isArray(lines) || lines.length === 0) return { start: null, end: null };
  const first = lines[0];
  const p = first?.period || {};
  return {
    start: parseUnixSecondsToMs(p?.start),
    end: parseUnixSecondsToMs(p?.end),
  };
}

async function applySubscriptionToPlan(env: Env, clientId: string, sub: any): Promise<void> {
  const subscriptionId = typeof sub?.id === "string" ? sub.id : "";
  if (!subscriptionId) return;

  const status = String(sub?.status || "").trim().toLowerCase();
  const plan = "pro";
  const currentPeriodStartMs = parseUnixSecondsToMs(sub?.current_period_start);
  const currentPeriodEndMs = parseUnixSecondsToMs(sub?.current_period_end);
  const cancelAtPeriodEnd = Boolean(sub?.cancel_at_period_end);
  const active = stripeStatusGrantsPro(status);

  await dbUpsertBillingSubscription(
    env,
    clientId,
    subscriptionId,
    status || "unknown",
    plan,
    currentPeriodStartMs,
    currentPeriodEndMs,
    cancelAtPeriodEnd,
  );
  await dbSetClientProPlanStatus(env, clientId, active, currentPeriodStartMs, currentPeriodEndMs);
}

function stripeObjectMetadataClientId(obj: any): string | null {
  const a = obj?.metadata?.client_id;
  if (typeof a === "string" && a.trim()) return a.trim();
  const b = obj?.client_reference_id;
  if (typeof b === "string" && b.trim()) return b.trim();
  return null;
}

async function resolveStripeEventClientId(env: Env, obj: any): Promise<string | null> {
  const fromMeta = stripeObjectMetadataClientId(obj);
  if (fromMeta) return fromMeta;
  const customerId = typeof obj?.customer === "string" ? obj.customer : "";
  if (customerId) {
    const mapped = await dbGetBillingClientByCustomer(env, customerId);
    if (mapped) return mapped;
  }
  return null;
}

async function handleStripeWebhookEvent(env: Env, event: any): Promise<void> {
  const type = typeof event?.type === "string" ? event.type : "";
  const obj = event?.data?.object || null;
  if (!obj || !type) return;

  if (type === "checkout.session.completed" || type === "checkout.session.async_payment_succeeded") {
    const clientId = await resolveStripeEventClientId(env, obj);
    const customerId = typeof obj?.customer === "string" ? obj.customer : "";
    const customerEmail = typeof obj?.customer_details?.email === "string" ? obj.customer_details.email : null;
    if (clientId && customerId) {
      await dbUpsertBillingCustomer(env, clientId, customerId, customerEmail);
    }
    const subId = typeof obj?.subscription === "string" ? obj.subscription : "";
    if (clientId && subId) {
      const sub = await stripeGetSubscription(env, subId);
      await applySubscriptionToPlan(env, clientId, sub);
    }
    return;
  }

  if (type === "customer.subscription.created" || type === "customer.subscription.updated" || type === "customer.subscription.deleted") {
    const clientId = await resolveStripeEventClientId(env, obj);
    const customerId = typeof obj?.customer === "string" ? obj.customer : "";
    if (!clientId) return;
    if (customerId) await dbUpsertBillingCustomer(env, clientId, customerId, null);
    await applySubscriptionToPlan(env, clientId, obj);
    return;
  }

  if (
    type === "invoice.paid" ||
    type === "invoice.updated" ||
    type === "invoice.finalized" ||
    type === "invoice.payment_failed" ||
    type === "invoice.payment_succeeded"
  ) {
    const clientId = await resolveStripeEventClientId(env, obj);
    if (!clientId) return;

    const invoiceId = typeof obj?.id === "string" ? obj.id : "";
    if (!invoiceId) return;
    const customerId = typeof obj?.customer === "string" ? obj.customer : null;
    if (customerId) await dbUpsertBillingCustomer(env, clientId, customerId, null);

    const subId = typeof obj?.subscription === "string" ? obj.subscription : null;
    const amountDue = Number.isFinite(Number(obj?.amount_due)) ? Number(obj.amount_due) : 0;
    const amountPaid = Number.isFinite(Number(obj?.amount_paid)) ? Number(obj.amount_paid) : 0;
    const status = typeof obj?.status === "string" ? obj.status : type;
    const hostedInvoiceUrl = typeof obj?.hosted_invoice_url === "string" ? obj.hosted_invoice_url : null;
    const invoicePdfUrl = typeof obj?.invoice_pdf === "string" ? obj.invoice_pdf : null;
    const currency = normalizeCurrency(obj?.currency);
    const stripeChargeId = typeof obj?.charge === "string" ? obj.charge : null;
    const stripePaymentIntentId = typeof obj?.payment_intent === "string" ? obj.payment_intent : null;
    const subtotalExcludingTax = Number.isFinite(Number(obj?.subtotal_excluding_tax))
      ? Number(obj.subtotal_excluding_tax)
      : Number.isFinite(Number(obj?.total_excluding_tax))
        ? Number(obj.total_excluding_tax)
        : null;
    const taxAmount = Number.isFinite(Number(obj?.tax))
      ? Number(obj.tax)
      : Array.isArray(obj?.total_taxes)
        ? obj.total_taxes.reduce((acc: number, t: any) => acc + (Number.isFinite(Number(t?.amount)) ? Number(t.amount) : 0), 0)
        : null;
    const createdAtMs = parseUnixSecondsToMs(obj?.created);
    const paidAtMs = parseUnixSecondsToMs(obj?.status_transitions?.paid_at);
    const period = stripeInvoicePeriodMs(obj);

    await dbUpsertBillingInvoice(
      env,
      clientId,
      invoiceId,
      customerId,
      subId,
      status,
      amountDue,
      amountPaid,
      currency,
      hostedInvoiceUrl,
      invoicePdfUrl,
      period.start,
      period.end,
      createdAtMs,
      paidAtMs,
      stripeChargeId,
      stripePaymentIntentId,
      subtotalExcludingTax,
      taxAmount,
    );
    if (stripeChargeId) {
      await dbUpsertBillingChargeLink(env, clientId, stripeChargeId, stripePaymentIntentId, invoiceId);
    }

    if (subId && (type === "invoice.paid" || type === "invoice.payment_succeeded")) {
      const sub = await stripeGetSubscription(env, subId);
      await applySubscriptionToPlan(env, clientId, sub);
    }
    return;
  }

  if (type === "charge.refunded" || type === "charge.refund.updated" || type.startsWith("refund.")) {
    const baseClientId = await resolveStripeEventClientId(env, obj);
    const baseChargeId = type.startsWith("charge.") && typeof obj?.id === "string" ? obj.id : null;
    const basePaymentIntent = typeof obj?.payment_intent === "string" ? obj.payment_intent : null;
    const refunds: any[] = (() => {
      if (type.startsWith("refund.")) return [obj];
      const arr = obj?.refunds?.data;
      return Array.isArray(arr) ? arr : [];
    })();

    for (const r of refunds) {
      const refundId = typeof r?.id === "string" ? r.id : "";
      if (!refundId) continue;
      const chargeId = typeof r?.charge === "string" ? r.charge : baseChargeId;
      const paymentIntentId = typeof r?.payment_intent === "string" ? r.payment_intent : basePaymentIntent;
      let clientId = baseClientId;
      if (!clientId) clientId = await dbResolveBillingClientByCharge(env, chargeId, paymentIntentId);
      if (!clientId) continue;

      const status = typeof r?.status === "string" ? r.status : type;
      const amount = Number.isFinite(Number(r?.amount)) ? Number(r.amount) : 0;
      const currency = normalizeCurrency(r?.currency || obj?.currency);
      const reason = typeof r?.reason === "string" ? r.reason : null;
      const failureReason = typeof r?.failure_reason === "string" ? r.failure_reason : null;
      const receiptNumber = typeof r?.receipt_number === "string" ? r.receipt_number : null;
      const createdAtMs = parseUnixSecondsToMs(r?.created);
      await dbUpsertBillingRefund(
        env,
        clientId,
        refundId,
        chargeId,
        paymentIntentId,
        status,
        amount,
        currency,
        reason,
        failureReason,
        receiptNumber,
        createdAtMs,
      );
      if (chargeId) await dbUpsertBillingChargeLink(env, clientId, chargeId, paymentIntentId, null);
    }
    return;
  }

  if (type.startsWith("charge.dispute.")) {
    const disputeId = typeof obj?.id === "string" ? obj.id : "";
    if (!disputeId) return;
    const chargeId = typeof obj?.charge === "string" ? obj.charge : null;
    let clientId = await resolveStripeEventClientId(env, obj);
    if (!clientId) clientId = await dbResolveBillingClientByCharge(env, chargeId, null);
    if (!clientId) return;

    const status = typeof obj?.status === "string" ? obj.status : type;
    const amount = Number.isFinite(Number(obj?.amount)) ? Number(obj.amount) : 0;
    const currency = normalizeCurrency(obj?.currency);
    const reason = typeof obj?.reason === "string" ? obj.reason : null;
    const evidenceDueByMs = parseUnixSecondsToMs(obj?.evidence_details?.due_by);
    const isChargeRefundable = Boolean(obj?.is_charge_refundable);
    const createdAtMs = parseUnixSecondsToMs(obj?.created);
    await dbUpsertBillingDispute(
      env,
      clientId,
      disputeId,
      chargeId,
      status,
      amount,
      currency,
      reason,
      evidenceDueByMs,
      isChargeRefundable,
      createdAtMs,
    );
    if (chargeId) await dbUpsertBillingChargeLink(env, clientId, chargeId, null, null);
    return;
  }
}

async function stripeWebhookHandler(request: Request, env: Env): Promise<Response> {
  if (!stripeWebhookConfigured(env)) return err(request, 501, "stripe webhook not configured");

  const rawBody = await request.text().catch(() => "");
  if (!rawBody) return err(request, 400, "missing webhook body");

  const sigHeader = request.headers.get("stripe-signature");
  const ok = await verifyStripeWebhookSignature(env, rawBody, sigHeader);
  if (!ok) return err(request, 400, "invalid stripe signature");

  let event: any = null;
  try {
    event = JSON.parse(rawBody);
  } catch (_) {
    return err(request, 400, "invalid webhook json");
  }

  const eventId = typeof event?.id === "string" ? event.id : "";
  const eventType = typeof event?.type === "string" ? event.type : "";
  if (!eventId || !eventType) return err(request, 400, "invalid webhook event");

  const firstSeen = await dbMarkStripeEventSeen(env, eventId, eventType);
  if (!firstSeen) return json(request, { ok: true, duplicate: true });

  await handleStripeWebhookEvent(env, event);
  return json(request, { ok: true, received: true });
}

function isValidCode(code: string): boolean {
  // Keep codes short and easy to type. Numeric-only.
  return /^[0-9]{6}$/.test(code);
}

function randomCode6(): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  const n = buf[0] % 1_000_000;
  return String(n).padStart(6, "0");
}

function uuidv7(): string {
  // Minimal UUIDv7 generator (time-ordered). Matches the style used in xadmin DB.
  const ts = BigInt(Date.now()); // ms
  const rand = new Uint8Array(10);
  crypto.getRandomValues(rand);

  const b = new Uint8Array(16);
  b[0] = Number((ts >> 40n) & 0xffn);
  b[1] = Number((ts >> 32n) & 0xffn);
  b[2] = Number((ts >> 24n) & 0xffn);
  b[3] = Number((ts >> 16n) & 0xffn);
  b[4] = Number((ts >> 8n) & 0xffn);
  b[5] = Number(ts & 0xffn);

  // 0b0111xxxx => version 7 + 4 random bits.
  b[6] = 0x70 | (rand[0] & 0x0f);
  b[7] = rand[1];

  // 0b10xxxxxx => variant RFC4122.
  b[8] = 0x80 | (rand[2] & 0x3f);
  b[9] = rand[3];
  b[10] = rand[4];
  b[11] = rand[5];
  b[12] = rand[6];
  b[13] = rand[7];
  b[14] = rand[8];
  b[15] = rand[9];

  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function sanitizeFilename(name: string): string {
  // Strip path, keep ASCII-ish.
  const base = name.split(/[\\/]/).pop() || "file.bin";
  const trimmed = base.trim();
  if (!trimmed) return "file.bin";
  return trimmed.replace(/[^a-zA-Z0-9.\-_\s]/g, "_").slice(0, 180);
}

function sanitizeRelativePath(pathRaw: string | null): string | null {
  if (!pathRaw) return null;
  const raw = String(pathRaw).trim();
  if (!raw) return null;
  const out: string[] = [];
  for (const segRaw of raw.split(/[\\/]+/)) {
    const seg = segRaw.trim();
    if (!seg || seg === "." || seg === "..") continue;
    const clean = seg.replace(/[^a-zA-Z0-9.\-_\s]/g, "_").trim().slice(0, 120);
    if (!clean || clean === "." || clean === "..") continue;
    out.push(clean);
    if (out.length >= 32) break;
  }
  if (out.length === 0) return null;
  return out.join("/");
}

function contentDisposition(filename: string): string {
  // ASCII fallback; avoids tricky RFC5987 handling for MVP.
  const safe = filename.replace(/["\\]/g, "_");
  return `attachment; filename="${safe}"`;
}

function parseCookieHeader(v: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!v) return out;
  const parts = v.split(";");
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = val;
  }
  return out;
}

function b64urlFromBytes(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(s: string): Uint8Array | null {
  try {
    let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch (_) {
    return null;
  }
}

function b64urlToBytesLen(s: string, wantLen: number): Uint8Array | null {
  const b = b64urlToBytes(String(s || ""));
  if (!b) return null;
  return b.length === wantLen ? b : null;
}

function b64urlFromString(s: string): string {
  return b64urlFromBytes(new TextEncoder().encode(s));
}

function b64urlToString(s: string): string | null {
  const bytes = b64urlToBytes(s);
  if (!bytes) return null;
  try {
    return new TextDecoder().decode(bytes);
  } catch (_) {
    return null;
  }
}

function bearerToken(req: Request): string | null {
  const h = req.headers.get("authorization");
  if (!h) return null;
  const m = h.match(/^\s*Bearer\s+(.+)\s*$/i);
  return m ? m[1] : null;
}

async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return new Uint8Array(sig);
}

function randomB64Url(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return b64urlFromBytes(buf);
}

async function sha256B64Url(s: string): Promise<string> {
  const enc = new TextEncoder();
  const dig = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return b64urlFromBytes(new Uint8Array(dig));
}

async function createSignedCookieValue(env: Env, obj: any): Promise<string> {
  const payload = b64urlFromString(JSON.stringify(obj));
  const sig = await hmacSha256(env.SESSION_SECRET, payload);
  return `${payload}.${b64urlFromBytes(sig)}`;
}

async function verifySignedCookieValue(env: Env, token: string): Promise<any | null> {
  const t = String(token || "").trim();
  const parts = t.split(".");
  if (parts.length !== 2) return null;
  const payload = parts[0];
  const want = parts[1];
  const sig = await hmacSha256(env.SESSION_SECRET, payload);
  const got = b64urlFromBytes(sig);
  if (got !== want) return null;
  const payloadStr = b64urlToString(payload);
  if (!payloadStr) return null;
  try {
    return JSON.parse(payloadStr);
  } catch (_) {
    return null;
  }
}

async function createSessionToken(env: Env, claims: SessionClaims): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlFromString(JSON.stringify(header));
  const p = b64urlFromString(JSON.stringify(claims));
  const data = `${h}.${p}`;
  const sig = await hmacSha256(env.SESSION_SECRET, data);
  return `${data}.${b64urlFromBytes(sig)}`;
}

async function verifySessionToken(env: Env, token: string): Promise<SessionClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const data = `${parts[0]}.${parts[1]}`;
  const want = parts[2];
  const sig = await hmacSha256(env.SESSION_SECRET, data);
  const got = b64urlFromBytes(sig);
  if (got !== want) return null;
  const payloadStr = b64urlToString(parts[1]);
  if (!payloadStr) return null;
  let payload: any;
  try {
    payload = JSON.parse(payloadStr);
  } catch (_) {
    return null;
  }
  if (!payload || typeof payload !== "object") return null;
  if (typeof payload.sub !== "string" || typeof payload.exp !== "number") return null;
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) return null;
  return { sub: payload.sub, exp: payload.exp };
}

function parseSessionTtlSeconds(env: Env): number {
  const raw = env.SESSION_TTL_SECONDS;
  if (!raw) return 7 * 24 * 3600;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 60 ? n : 7 * 24 * 3600;
}

async function authClientId(req: Request, env: Env): Promise<string | null> {
  const b = bearerToken(req);
  if (b) {
    // Heuristic: our JWT has dots; client tokens don't.
    if (b.includes(".")) {
      const claims = await verifySessionToken(env, b);
      return claims ? claims.sub : null;
    }

    const row = (await env.XADMIN_DB.prepare(
      "SELECT client_id, status, deleted_at, expires_at FROM client_tokens WHERE key=?1 LIMIT 1",
    )
      .bind(b)
      .first()) as any;
    if (!row) return null;
    if (row.deleted_at !== null && row.deleted_at !== undefined) return null;
    if (String(row.status || "") !== "active") return null;
    const exp = Number(row.expires_at || 0);
    if (Number.isFinite(exp) && exp > 0 && exp <= Date.now()) return null;
    return String(row.client_id);
  }

  const cookies = parseCookieHeader(req.headers.get("cookie"));
  const t = cookies[SESSION_COOKIE];
  if (t) {
    const claims = await verifySessionToken(env, t);
    return claims ? claims.sub : null;
  }

  return null;
}

async function requireAuth(req: Request, env: Env): Promise<{ client_id: string } | Response> {
  const clientId = await authClientId(req, env);
  if (!clientId) return err(req, 401, "unauthorized");
  return { client_id: clientId };
}

async function dbGetClientByIdentifier(env: Env, identRaw: string): Promise<(ClientRow & { password_hash: string | null }) | null> {
  const ident = identRaw.trim();
  if (!ident) return null;
  const row = (await env.XADMIN_DB.prepare(
    "SELECT id, username, email, role, status, client_type, password_hash, deleted_at FROM clients WHERE (username=?1 OR email=?1) LIMIT 1",
  )
    .bind(ident)
    .first()) as any;
  if (!row) return null;
  if (row.deleted_at !== null && row.deleted_at !== undefined) return null;
  return {
    id: String(row.id),
    username: String(row.username),
    email: row.email ? String(row.email) : null,
    role: row.role ? String(row.role) : null,
    status: row.status ? String(row.status) : null,
    client_type: row.client_type ? String(row.client_type) : null,
    password_hash: row.password_hash ? String(row.password_hash) : null,
  };
}

async function dbUsernameExists(env: Env, usernameRaw: string): Promise<boolean> {
  const username = usernameRaw.trim();
  if (!username) return false;
  const row = (await env.XADMIN_DB.prepare(
    "SELECT id, deleted_at FROM clients WHERE username=?1 LIMIT 1",
  )
    .bind(username)
    .first()) as any;
  if (!row) return false;
  if (row.deleted_at !== null && row.deleted_at !== undefined) return false;
  return true;
}

async function dbCreateClient(env: Env, username: string, email: string | null, passwordHash: string): Promise<ClientRow> {
  const id = uuidv7();
  const nowMs = Date.now();
  await env.XADMIN_DB.prepare(
    "INSERT INTO clients (id, username, password_hash, email, role, status, created_at, last_login_at, client_type) VALUES (?1, ?2, ?3, ?4, 'user', 'active', (strftime('%s','now')), ?5, 'xsend')",
  )
    .bind(id, username, passwordHash, email, nowMs)
    .run();

  return { id, username, email, role: "user", status: "active", client_type: "xsend" };
}

async function dbCreateClientOAuth(env: Env, username: string, email: string | null): Promise<ClientRow> {
  const id = uuidv7();
  const nowMs = Date.now();
  await env.XADMIN_DB.prepare(
    "INSERT INTO clients (id, username, password_hash, email, role, status, created_at, last_login_at, client_type) VALUES (?1, ?2, NULL, ?3, 'user', 'active', (strftime('%s','now')), ?4, 'xsend')",
  )
    .bind(id, username, email, nowMs)
    .run();
  return { id, username, email, role: "user", status: "active", client_type: "xsend" };
}

async function dbGetClientById(env: Env, id: string): Promise<ClientRow | null> {
  const row = (await env.XADMIN_DB.prepare(
    "SELECT id, username, email, role, status, client_type, deleted_at FROM clients WHERE id=?1 LIMIT 1",
  )
    .bind(id)
    .first()) as any;
  if (!row) return null;
  if (row.deleted_at !== null && row.deleted_at !== undefined) return null;
  return {
    id: String(row.id),
    username: String(row.username),
    email: row.email ? String(row.email) : null,
    role: row.role ? String(row.role) : null,
    status: row.status ? String(row.status) : null,
    client_type: row.client_type ? String(row.client_type) : null,
  };
}

async function dbGetIdentity(env: Env, provider: string, subject: string): Promise<{ client_id: string; email: string | null } | null> {
  const row = (await env.XADMIN_DB.prepare(
    "SELECT client_id, email FROM xsend_client_identities WHERE provider=?1 AND subject=?2 LIMIT 1",
  )
    .bind(provider, subject)
    .first()) as any;
  if (!row) return null;
  return { client_id: String(row.client_id), email: row.email ? String(row.email) : null };
}

async function dbUpsertIdentity(env: Env, provider: string, subject: string, clientId: string, email: string | null): Promise<void> {
  const now = Date.now();
  await env.XADMIN_DB.prepare(
    "INSERT INTO xsend_client_identities (provider, subject, client_id, email, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?5) ON CONFLICT(provider, subject) DO UPDATE SET client_id=?3, email=?4, updated_at_ms=?5",
  )
    .bind(provider, subject, clientId, email, now)
    .run();
}

async function dbAllocateUsername(env: Env, desired: string): Promise<string> {
  let base = String(desired || "").trim();
  if (!base) base = "xsend";
  if (base.length > 64) base = base.slice(0, 64);
  if (!(await dbUsernameExists(env, base))) return base;

  const prefix = base.length > 52 ? base.slice(0, 52) : base;
  for (let i = 0; i < 20; i++) {
    const cand = `${prefix}-${randomCode6()}`;
    if (!(await dbUsernameExists(env, cand))) return cand;
  }
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}

async function dbUpsertUserChannel(env: Env, clientId: string, code: string): Promise<void> {
  const now = Date.now();
  await env.XADMIN_DB.prepare(
    "INSERT INTO xsend_relay_channels (client_id, code, updated_at_ms) VALUES (?1, ?2, ?3) ON CONFLICT(client_id) DO UPDATE SET code=?2, updated_at_ms=?3",
  )
    .bind(clientId, code, now)
    .run();
}

async function dbGetUserChannel(env: Env, clientId: string): Promise<string | null> {
  const row = (await env.XADMIN_DB.prepare("SELECT code FROM xsend_relay_channels WHERE client_id=?1 LIMIT 1")
    .bind(clientId)
    .first()) as any;
  if (!row || !row.code) return null;
  const code = String(row.code);
  return isValidCode(code) ? code : null;
}

async function doInternalCreate(env: Env, code: string, clientId: string): Promise<Response> {
  const ttl = parseIntEnv(env, "CHANNEL_TTL_SECONDS", 900);
  const id = env.CHANNEL.idFromName(code);
  const stub = env.CHANNEL.get(id);
  return await stub.fetch("https://do/__internal/create", {
    method: "POST",
    headers: { "content-type": "application/json", [CLIENT_ID_HEADER]: clientId },
    body: JSON.stringify({ code, ttl_seconds: ttl }),
  });
}

async function ensureUserChannel(env: Env, clientId: string): Promise<string> {
  const existing = await dbGetUserChannel(env, clientId);
  if (existing) {
    const res = await doInternalCreate(env, existing, clientId);
    if (res.status === 201 || res.status === 409) return existing;
    if (res.status === 403) {
      // Someone else owns it (or legacy unowned); allocate a new one.
    } else {
      const text = await res.text().catch(() => "");
      throw new Error(`relay ensure channel failed: ${res.status} ${text.trim()}`);
    }
  }

  for (let i = 0; i < 50; i++) {
    const code = randomCode6();
    const res = await doInternalCreate(env, code, clientId);
    if (res.status === 201 || res.status === 409) {
      await dbUpsertUserChannel(env, clientId, code);
      return code;
    }
    if (res.status === 403) continue;
    if (res.status === 409) continue;
    const text = await res.text().catch(() => "");
    throw new Error(`relay allocate channel failed: ${res.status} ${text.trim()}`);
  }
  throw new Error("failed to allocate channel code");
}

function setCookie(headers: Headers, name: string, value: string, maxAgeSeconds: number): void {
  // workers.dev is HTTPS; set Secure.
  headers.append(
    "set-cookie",
    `${name}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`,
  );
}

function clearCookie(headers: Headers, name: string): void {
  headers.append("set-cookie", `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

type OAuthProvider = "google" | "github" | "apple";

function isNonEmpty(v: string | undefined | null): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function oauthConfigured(env: Env, p: OAuthProvider): boolean {
  if (p === "google") return isNonEmpty(env.GOOGLE_CLIENT_ID) && isNonEmpty(env.GOOGLE_CLIENT_SECRET);
  if (p === "github") return isNonEmpty(env.GITHUB_CLIENT_ID) && isNonEmpty(env.GITHUB_CLIENT_SECRET);
  if (p === "apple") {
    return (
      isNonEmpty(env.APPLE_CLIENT_ID) &&
      isNonEmpty(env.APPLE_TEAM_ID) &&
      isNonEmpty(env.APPLE_KEY_ID) &&
      isNonEmpty(env.APPLE_PRIVATE_KEY)
    );
  }
  return false;
}

function oauthRedirectUri(origin: string, p: OAuthProvider): string {
  return `${origin}/api/v1/auth/oauth/${p}/callback`;
}

async function oauthStart(request: Request, env: Env, p: OAuthProvider): Promise<Response> {
  if (!oauthConfigured(env, p)) return err(request, 501, `${p} oauth not configured`);
  const url = new URL(request.url);
  const origin = url.origin;

  const state = randomB64Url(16);
  const verifier = randomB64Url(32);
  const challenge = await sha256B64Url(verifier);
  const exp = Math.floor(Date.now() / 1000) + 600;

  const cookieValue = await createSignedCookieValue(env, { p, state, verifier, exp });

  const headers = new Headers();
  setCookie(headers, OAUTH_COOKIE, cookieValue, 600);

  const redir = oauthRedirectUri(origin, p);
  let authUrl: URL;
  if (p === "google") {
    authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.searchParams.set("client_id", env.GOOGLE_CLIENT_ID!.trim());
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("prompt", "select_account");
  } else if (p === "github") {
    authUrl = new URL("https://github.com/login/oauth/authorize");
    authUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID!.trim());
    authUrl.searchParams.set("scope", "read:user user:email");
  } else {
    authUrl = new URL("https://appleid.apple.com/auth/authorize");
    authUrl.searchParams.set("client_id", env.APPLE_CLIENT_ID!.trim());
    // Apple supports "name email"; name is only returned the first time.
    // Keep it minimal; email is the important one for username allocation.
    authUrl.searchParams.set("scope", "email");
    // Use query so our callback can be a GET (we still accept POST too).
    authUrl.searchParams.set("response_mode", "query");
  }
  authUrl.searchParams.set("redirect_uri", redir);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  headers.set("location", authUrl.toString());
  return new Response(null, { status: 302, headers });
}

async function exchangeGoogle(env: Env, code: string, verifier: string, redirectUri: string): Promise<{ access_token: string }> {
  const params = new URLSearchParams();
  params.set("client_id", env.GOOGLE_CLIENT_ID!.trim());
  params.set("client_secret", env.GOOGLE_CLIENT_SECRET!.trim());
  params.set("code", code);
  params.set("code_verifier", verifier);
  params.set("redirect_uri", redirectUri);
  params.set("grant_type", "authorization_code");
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const j = (await res.json().catch(() => null)) as any;
  if (!res.ok) {
    const msg = j && j.error ? String(j.error) : `${res.status} ${res.statusText}`;
    throw new Error(`google token exchange failed: ${msg}`);
  }
  const accessToken = typeof j?.access_token === "string" ? j.access_token : "";
  if (!accessToken) throw new Error("google token exchange returned no access_token");
  return { access_token: accessToken };
}

async function googleUserInfo(accessToken: string): Promise<{ subject: string; email: string | null; username: string }> {
  const res = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  const j = (await res.json().catch(() => null)) as any;
  if (!res.ok) {
    const msg = j && j.error ? String(j.error) : `${res.status} ${res.statusText}`;
    throw new Error(`google userinfo failed: ${msg}`);
  }
  const subject = typeof j?.sub === "string" ? j.sub : "";
  const email = typeof j?.email === "string" ? j.email : null;
  const username = email ? email : subject ? `google:${subject}` : "google-user";
  if (!subject) throw new Error("google userinfo returned no sub");
  return { subject, email, username };
}

async function exchangeGitHub(env: Env, code: string, verifier: string, redirectUri: string, state: string): Promise<{ access_token: string }> {
  const params = new URLSearchParams();
  params.set("client_id", env.GITHUB_CLIENT_ID!.trim());
  params.set("client_secret", env.GITHUB_CLIENT_SECRET!.trim());
  params.set("code", code);
  params.set("redirect_uri", redirectUri);
  params.set("state", state);
  params.set("code_verifier", verifier);
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const j = (await res.json().catch(() => null)) as any;
  if (!res.ok) {
    const msg = j && j.error_description ? String(j.error_description) : `${res.status} ${res.statusText}`;
    throw new Error(`github token exchange failed: ${msg}`);
  }
  const accessToken = typeof j?.access_token === "string" ? j.access_token : "";
  if (!accessToken) throw new Error("github token exchange returned no access_token");
  return { access_token: accessToken };
}

async function gitHubUserInfo(accessToken: string): Promise<{ subject: string; email: string | null; username: string }> {
  const userRes = await fetch("https://api.github.com/user", {
    headers: { authorization: `Bearer ${accessToken}`, "user-agent": "xsend-relay" },
  });
  const user = (await userRes.json().catch(() => null)) as any;
  if (!userRes.ok) {
    const msg = user && user.message ? String(user.message) : `${userRes.status} ${userRes.statusText}`;
    throw new Error(`github user failed: ${msg}`);
  }
  const subject = user && (typeof user.id === "number" || typeof user.id === "string") ? String(user.id) : "";
  const login = user && typeof user.login === "string" ? user.login : "";
  if (!subject) throw new Error("github user returned no id");

  let email: string | null = null;
  const emailsRes = await fetch("https://api.github.com/user/emails", {
    headers: { authorization: `Bearer ${accessToken}`, "user-agent": "xsend-relay", accept: "application/vnd.github+json" },
  });
  const emails = (await emailsRes.json().catch(() => null)) as any;
  if (emailsRes.ok && Array.isArray(emails)) {
    const primary = emails.find((e) => e && e.primary && e.verified && typeof e.email === "string");
    const any = emails.find((e) => e && typeof e.email === "string");
    email = primary ? String(primary.email) : any ? String(any.email) : null;
  }

  const username = login ? login : `github:${subject}`;
  return { subject, email, username };
}

function pemToDer(pem: string): ArrayBuffer {
  const cleaned = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "")
    .trim();
  const bin = atob(cleaned);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function ecdsaSigToJose(sig: Uint8Array, size: number): Uint8Array {
  // WebCrypto ECDSA signatures are usually raw (r||s). Some runtimes return DER.
  // JWT (JWS) for ES256 requires the raw format.
  if (sig.length === size * 2) return sig;

  // Minimal DER parser: 30 xx 02 xx r 02 xx s
  let i = 0;
  if (sig[i++] !== 0x30) throw new Error("invalid der (seq)");
  const seqLen = sig[i++];
  if (seqLen + 2 !== sig.length && !(seqLen === 0x81 && sig[i++] + 3 === sig.length)) {
    // best-effort; tolerate long form length
  }
  if (sig[i++] !== 0x02) throw new Error("invalid der (int r)");
  const rLen = sig[i++];
  const r = sig.slice(i, i + rLen);
  i += rLen;
  if (sig[i++] !== 0x02) throw new Error("invalid der (int s)");
  const sLen = sig[i++];
  const s = sig.slice(i, i + sLen);

  const out = new Uint8Array(size * 2);
  const rTrim = r[0] === 0x00 ? r.slice(1) : r;
  const sTrim = s[0] === 0x00 ? s.slice(1) : s;
  if (rTrim.length > size || sTrim.length > size) throw new Error("invalid der (int too large)");
  out.set(rTrim, size - rTrim.length);
  out.set(sTrim, size * 2 - sTrim.length);
  return out;
}

async function signJwtEs256(privateKeyPem: string, header: any, payload: any): Promise<string> {
  const h = b64urlFromString(JSON.stringify(header));
  const p = b64urlFromString(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPem),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(signingInput)),
  );
  const joseSig = ecdsaSigToJose(sig, 32);
  return `${signingInput}.${b64urlFromBytes(joseSig)}`;
}

function decodeJwt(token: string): { header: any; payload: any; signing_input: string; signature: Uint8Array } {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("invalid jwt");
  const [h, p, s] = parts;
  const headerStr = b64urlToString(h);
  const payloadStr = b64urlToString(p);
  const sig = b64urlToBytes(s);
  if (!headerStr || !payloadStr || !sig) throw new Error("invalid jwt encoding");
  let header: any;
  let payload: any;
  try {
    header = JSON.parse(headerStr);
    payload = JSON.parse(payloadStr);
  } catch (_) {
    throw new Error("invalid jwt json");
  }
  return { header, payload, signing_input: `${h}.${p}`, signature: sig };
}

let gAppleJwksCache: { fetched_at_ms: number; keys: any[] } | null = null;

async function fetchAppleJwks(): Promise<any[]> {
  const now = Date.now();
  if (gAppleJwksCache && now - gAppleJwksCache.fetched_at_ms < 6 * 3600 * 1000 && gAppleJwksCache.keys.length > 0) {
    return gAppleJwksCache.keys;
  }
  const res = await fetch("https://appleid.apple.com/auth/keys", { method: "GET" });
  const j = (await res.json().catch(() => null)) as any;
  if (!res.ok || !j || !Array.isArray(j.keys)) throw new Error("apple jwks fetch failed");
  gAppleJwksCache = { fetched_at_ms: now, keys: j.keys };
  return j.keys;
}

async function verifyAppleIdToken(env: Env, idToken: string): Promise<{ subject: string; email: string | null; username: string }> {
  const { header, payload, signing_input, signature } = decodeJwt(idToken);
  const alg = typeof header?.alg === "string" ? header.alg : "";
  const kid = typeof header?.kid === "string" ? header.kid : "";
  if (alg !== "RS256") throw new Error("apple id_token alg not RS256");
  if (!kid) throw new Error("apple id_token missing kid");

  const now = Math.floor(Date.now() / 1000);
  const iss = typeof payload?.iss === "string" ? payload.iss : "";
  const aud = payload?.aud;
  const exp = typeof payload?.exp === "number" ? payload.exp : 0;
  const sub = typeof payload?.sub === "string" ? payload.sub : "";
  const email = typeof payload?.email === "string" ? payload.email : null;
  if (iss !== "https://appleid.apple.com") throw new Error("apple id_token invalid issuer");
  if (!exp || exp <= now) throw new Error("apple id_token expired");
  const clientId = env.APPLE_CLIENT_ID!.trim();
  const audOk =
    (typeof aud === "string" && aud === clientId) || (Array.isArray(aud) && aud.some((x) => typeof x === "string" && x === clientId));
  if (!audOk) throw new Error("apple id_token invalid audience");
  if (!sub) throw new Error("apple id_token missing sub");

  let keys = await fetchAppleJwks();
  let jwk = keys.find((k) => k && typeof k === "object" && k.kid === kid);
  if (!jwk) {
    // Retry once with a forced refresh (key rotation).
    gAppleJwksCache = null;
    keys = await fetchAppleJwks();
    jwk = keys.find((k) => k && typeof k === "object" && k.kid === kid);
  }
  if (!jwk) throw new Error("apple jwk not found");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signature,
    new TextEncoder().encode(signing_input),
  );
  if (!ok) throw new Error("apple id_token signature invalid");

  const username = email ? email : `apple:${sub}`;
  return { subject: sub, email, username };
}

async function exchangeApple(env: Env, code: string, verifier: string, redirectUri: string): Promise<{ id_token: string }> {
  const now = Math.floor(Date.now() / 1000);
  // Apple allows client_secret JWTs up to 6 months, but short-lived is fine.
  const clientSecret = await signJwtEs256(
    env.APPLE_PRIVATE_KEY!.trim(),
    { alg: "ES256", kid: env.APPLE_KEY_ID!.trim(), typ: "JWT" },
    {
      iss: env.APPLE_TEAM_ID!.trim(),
      iat: now,
      exp: now + 10 * 60,
      aud: "https://appleid.apple.com",
      sub: env.APPLE_CLIENT_ID!.trim(),
    },
  );

  const params = new URLSearchParams();
  params.set("client_id", env.APPLE_CLIENT_ID!.trim());
  params.set("client_secret", clientSecret);
  params.set("code", code);
  params.set("grant_type", "authorization_code");
  params.set("redirect_uri", redirectUri);
  params.set("code_verifier", verifier);
  const res = await fetch("https://appleid.apple.com/auth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const j = (await res.json().catch(() => null)) as any;
  if (!res.ok) {
    const msg = j && j.error ? String(j.error) : `${res.status} ${res.statusText}`;
    throw new Error(`apple token exchange failed: ${msg}`);
  }
  const idToken = typeof j?.id_token === "string" ? j.id_token : "";
  if (!idToken) throw new Error("apple token exchange returned no id_token");
  return { id_token: idToken };
}

async function oauthCallbackParams(request: Request): Promise<{ code: string; state: string; error: string }> {
  const url = new URL(request.url);
  let code = url.searchParams.get("code") || "";
  let state = url.searchParams.get("state") || "";
  let error = url.searchParams.get("error") || "";

  if ((!code || !state) && request.method === "POST") {
    const ct = request.headers.get("content-type") || "";
    if (ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data")) {
      const fd = await request.formData().catch(() => null);
      if (fd) {
        code = String(fd.get("code") || "");
        state = String(fd.get("state") || "");
        error = String(fd.get("error") || "");
      }
    }
  }
  return { code, state, error };
}

async function oauthCallback(request: Request, env: Env, ctx: ExecutionContext, p: OAuthProvider): Promise<Response> {
  if (!oauthConfigured(env, p)) return err(request, 501, `${p} oauth not configured`);
  const url = new URL(request.url);
  const origin = url.origin;

  const { code, state, error } = await oauthCallbackParams(request);
  if (error) return err(request, 400, `oauth error: ${error}`);
  if (!code || !state) return err(request, 400, "missing oauth parameters");

  const cookies = parseCookieHeader(request.headers.get("cookie"));
  const raw = cookies[OAUTH_COOKIE];
  if (!raw) return err(request, 400, "missing oauth cookie");
  const data = await verifySignedCookieValue(env, raw);
  if (!data || typeof data !== "object") return err(request, 400, "invalid oauth cookie");

  const exp = typeof (data as any).exp === "number" ? (data as any).exp : 0;
  const now = Math.floor(Date.now() / 1000);
  if (!exp || exp <= now) return err(request, 400, "oauth cookie expired");

  const cookieProvider = (data as any).p;
  const cookieState = (data as any).state;
  const verifier = (data as any).verifier;
  if (cookieProvider !== p) return err(request, 400, "oauth provider mismatch");
  if (cookieState !== state) return err(request, 400, "oauth state mismatch");
  if (typeof verifier !== "string" || verifier.length < 10) return err(request, 400, "invalid oauth verifier");

  const redirectUri = oauthRedirectUri(origin, p);
  let subject = "";
  let email: string | null = null;
  let username = "";

  if (p === "google") {
    const tok = await exchangeGoogle(env, code, verifier, redirectUri);
    const info = await googleUserInfo(tok.access_token);
    subject = info.subject;
    email = info.email;
    username = info.username;
  } else if (p === "github") {
    const tok = await exchangeGitHub(env, code, verifier, redirectUri, state);
    const info = await gitHubUserInfo(tok.access_token);
    subject = info.subject;
    email = info.email;
    username = info.username;
  } else {
    const tok = await exchangeApple(env, code, verifier, redirectUri);
    const info = await verifyAppleIdToken(env, tok.id_token);
    subject = info.subject;
    email = info.email;
    username = info.username;
  }

  const providerKey = p;
  const existing = await dbGetIdentity(env, providerKey, subject);
  let user: ClientRow | null = null;
  if (existing) {
    user = await dbGetClientById(env, existing.client_id);
  }
  if (!user) {
    const uname = await dbAllocateUsername(env, username || (email || `${p}:${subject}`));
    user = await dbCreateClientOAuth(env, uname, email);
  }

  await dbUpsertIdentity(env, providerKey, subject, user.id, email);

  // Best-effort last_login_at update + fill email if missing.
  ctx.waitUntil(
    env.XADMIN_DB.prepare("UPDATE clients SET last_login_at=?1, email=COALESCE(email, ?2), client_type=COALESCE(client_type, 'xsend') WHERE id=?3")
      .bind(Date.now(), email, user.id)
      .run()
      .then(() => {})
      .catch(() => {}),
  );

  const ttl = parseSessionTtlSeconds(env);
  const tokenNow = Math.floor(Date.now() / 1000);
  const sessionToken = await createSessionToken(env, { sub: user.id, exp: tokenNow + ttl });
  const headers = new Headers();
  setCookie(headers, SESSION_COOKIE, sessionToken, ttl);
  clearCookie(headers, OAUTH_COOKIE);
  headers.set("location", `${origin}/`);
  return new Response(null, { status: 302, headers });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      if (request.method === "OPTIONS") {
        return withCors(request, new Response(null, { status: 204 }));
      }

      const url = new URL(request.url);

      if (url.pathname === "/api/v1/health") {
        return json(request, { ok: true });
      }

      if (url.pathname === "/api/v1/realtime/auto/info" && request.method === "GET") {
        const autoRequirePaid = parseBoolEnv(env.AUTO_DISCOVERY_REQUIRE_PAID, false);
        if (autoRequirePaid) {
          const auth = await requireAuth(request, env);
          if (auth instanceof Response) return auth;
          const limits = await resolveClientLimits(env, auth.client_id);
          const features = resolveClientFeatures(env, limits);
          if (!features.auto_discovery) {
            return featureDenied(request, "auto_discovery", limits, features, "auto discovery requires paid plan");
          }
        }
        const ip = getClientIp(request);
        const scopeRaw = String(url.searchParams.get("scope") || "").trim();
        const scope = scopeRaw ? scopeRaw.slice(0, 32) : "";
        return json(request, {
          ok: true,
          mode: "auto_discovery",
          public_ip_hint: maskIp(ip),
          scope: scope || null,
          ws_path: "/api/v1/realtime/auto/ws",
          notes: "Clients with the same public IP and same scope join the same signaling room. Session setup requires explicit requester/receiver authorization.",
        });
      }

      if (url.pathname === "/api/v1/realtime/auto/ws" && request.method === "GET") {
        const autoRequirePaid = parseBoolEnv(env.AUTO_DISCOVERY_REQUIRE_PAID, false);
        if (autoRequirePaid) {
          const auth = await requireAuth(request, env);
          if (auth instanceof Response) return auth;
          const limits = await resolveClientLimits(env, auth.client_id);
          const features = resolveClientFeatures(env, limits);
          if (!features.auto_discovery) {
            return featureDenied(request, "auto_discovery", limits, features, "auto discovery requires paid plan");
          }
        }
        const ip = getClientIp(request);
        const scopeRaw = String(url.searchParams.get("scope") || "").trim();
        const scope = scopeRaw ? scopeRaw.slice(0, 32) : "";
        const roomName = scope ? `auto:${ip}:${scope}` : `auto:${ip}`;
        const id = env.SIGNAL_AUTO.idFromName(roomName);
        const stub = env.SIGNAL_AUTO.get(id);
        const fwdUrl = new URL("https://do/ws");
        const peerId = sanitizePeerId(url.searchParams.get("peer_id"));
        const name = sanitizePeerName(url.searchParams.get("name"));
        if (peerId) fwdUrl.searchParams.set("peer_id", peerId);
        if (name) fwdUrl.searchParams.set("name", name);
        const fwdReq = new Request(fwdUrl.toString(), request);
        return await stub.fetch(fwdReq);
      }

      if (url.pathname === "/api/v1/billing/stripe/webhook" && request.method === "POST") {
        return await stripeWebhookHandler(request, env);
      }

      if (url.pathname === "/api/v1/auth/providers" && request.method === "GET") {
        return json(request, {
          google: oauthConfigured(env, "google"),
          github: oauthConfigured(env, "github"),
          apple: oauthConfigured(env, "apple"),
        });
      }

      const oauthStartMatch = url.pathname.match(/^\/api\/v1\/auth\/oauth\/(google|github|apple)\/start$/);
      if (oauthStartMatch && request.method === "GET") {
        const p = oauthStartMatch[1] as OAuthProvider;
        return await oauthStart(request, env, p);
      }

      const oauthCbMatch = url.pathname.match(/^\/api\/v1\/auth\/oauth\/(google|github|apple)\/callback$/);
      if (oauthCbMatch && (request.method === "GET" || request.method === "POST")) {
        const p = oauthCbMatch[1] as OAuthProvider;
        return await oauthCallback(request, env, ctx, p);
      }

      if (url.pathname === "/api/v1/auth/register" && request.method === "POST") {
        const body = (await request.json().catch(() => null)) as any;
        const username = typeof body?.username === "string" ? body.username.trim() : "";
        const email = typeof body?.email === "string" ? body.email.trim() : "";
        const password = typeof body?.password === "string" ? body.password : "";

        if (!username || username.length < 3 || username.length > 64) {
          return err(request, 400, "invalid username");
        }
        if (password.length < 8 || password.length > 200) {
          return err(request, 400, "invalid password");
        }

        if (await dbUsernameExists(env, username)) {
          return err(request, 409, "username already exists");
        }

        const hash = await bcrypt.hash(password, 10);
        const user = await dbCreateClient(env, username, email || null, hash);

        const ttl = parseSessionTtlSeconds(env);
        const now = Math.floor(Date.now() / 1000);
        const token = await createSessionToken(env, { sub: user.id, exp: now + ttl });
        const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
        setCookie(headers, SESSION_COOKIE, token, ttl);
        return withCors(
          request,
          new Response(JSON.stringify({ ok: true, token, user }), { status: 201, headers }),
        );
      }

      if (url.pathname === "/api/v1/auth/login" && request.method === "POST") {
        const body = (await request.json().catch(() => null)) as any;
        const ident = typeof body?.identifier === "string" ? body.identifier : typeof body?.username === "string" ? body.username : "";
        const password = typeof body?.password === "string" ? body.password : "";
        const row = await dbGetClientByIdentifier(env, ident);
        if (!row) return err(request, 401, "invalid credentials");
        if (String(row.status || "active") !== "active") return err(request, 403, "account disabled");
        if (!row.password_hash) return err(request, 401, "password not set for this account");

        const ok = await bcrypt.compare(password, row.password_hash);
        if (!ok) return err(request, 401, "invalid credentials");

        // Best-effort last_login_at update (ms).
        ctx.waitUntil(
          env.XADMIN_DB.prepare("UPDATE clients SET last_login_at=?1, client_type=COALESCE(client_type, 'xsend') WHERE id=?2")
            .bind(Date.now(), row.id)
            .run()
            .then(() => {})
            .catch(() => {}),
        );

        const user: ClientRow = {
          id: row.id,
          username: row.username,
          email: row.email,
          role: row.role,
          status: row.status,
          client_type: row.client_type,
        };
        const ttl = parseSessionTtlSeconds(env);
        const now = Math.floor(Date.now() / 1000);
        const token = await createSessionToken(env, { sub: row.id, exp: now + ttl });
        const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
        setCookie(headers, SESSION_COOKIE, token, ttl);
        return withCors(request, new Response(JSON.stringify({ ok: true, token, user }), { status: 200, headers }));
      }

      if (url.pathname === "/api/v1/auth/logout" && request.method === "POST") {
        const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
        clearCookie(headers, SESSION_COOKIE);
        return withCors(request, new Response(JSON.stringify({ ok: true }), { status: 200, headers }));
      }

      if (url.pathname === "/api/v1/auth/me" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const row = (await env.XADMIN_DB.prepare(
          "SELECT id, username, email, role, status, client_type, deleted_at FROM clients WHERE id=?1 LIMIT 1",
        )
          .bind(auth.client_id)
          .first()) as any;
        if (!row || (row.deleted_at !== null && row.deleted_at !== undefined)) return err(request, 401, "unauthorized");
        const user: ClientRow = {
          id: String(row.id),
          username: String(row.username),
          email: row.email ? String(row.email) : null,
          role: row.role ? String(row.role) : null,
          status: row.status ? String(row.status) : null,
          client_type: row.client_type ? String(row.client_type) : null,
        };
        const limits = await resolveClientLimits(env, user.id, user.client_type);
        const usage_today = await getUsageToday(env, user.id);
        const limitsOut = {
          ...limits,
          e2ee_overhead_bytes: parseIntEnv(env, "E2EE_OVERHEAD_BYTES", 16 * 1024),
        };
        const features = resolveClientFeatures(env, limits);
        return json(request, { ok: true, user, limits: limitsOut, features, usage_today });
      }

      if (url.pathname === "/api/v1/me/plan" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const row = (await env.XADMIN_DB.prepare(
          "SELECT id, username, email, role, status, client_type, deleted_at FROM clients WHERE id=?1 LIMIT 1",
        )
          .bind(auth.client_id)
          .first()) as any;
        if (!row || (row.deleted_at !== null && row.deleted_at !== undefined)) return err(request, 401, "unauthorized");

        const clientType = row.client_type ? String(row.client_type) : null;
        const limits = await resolveClientLimits(env, String(row.id), clientType);
        const usage_today = await getUsageToday(env, String(row.id));
        const limitsOut = {
          ...limits,
          e2ee_overhead_bytes: parseIntEnv(env, "E2EE_OVERHEAD_BYTES", 16 * 1024),
        };
        const features = resolveClientFeatures(env, limits);
        return json(request, {
          ok: true,
          plan: limits.plan,
          client_type: clientType,
          limits: limitsOut,
          features,
          usage_today,
        });
      }

      if (url.pathname === "/api/v1/me/billing" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limits = await resolveClientLimits(env, auth.client_id);
        const features = resolveClientFeatures(env, limits);
        const monthUsage = await getUsageMonth(env, auth.client_id);
        const uploadBytes = Math.max(0, monthUsage.upload_bytes);
        const downloadBytes = Math.max(0, monthUsage.download_bytes);
        const totalBytes = uploadBytes + downloadBytes;

        const uploadRate = Math.max(0, parseFloatEnv(env.BILLING_UPLOAD_PER_GB_USD, 0.12));
        const downloadRate = Math.max(0, parseFloatEnv(env.BILLING_DOWNLOAD_PER_GB_USD, 0.05));
        const freeQuotaGb = Math.max(0, parseFloatEnv(env.BILLING_FREE_QUOTA_GB, 0.05));

        const bytesPerGb = 1024 * 1024 * 1024;
        const freeBytes = Math.floor(freeQuotaGb * bytesPerGb);
        // User-friendly policy: free quota offsets upload first, then download.
        const freeAfterUpload = Math.max(0, freeBytes - uploadBytes);
        const billableUpload = Math.max(0, uploadBytes - freeBytes);
        const billableDownload = Math.max(0, downloadBytes - freeAfterUpload);
        const billableBytes = billableUpload + billableDownload;
        const freeAppliedBytes = Math.max(0, totalBytes - billableBytes);

        const estUsd = (billableUpload / bytesPerGb) * uploadRate + (billableDownload / bytesPerGb) * downloadRate;
        let subscription: BillingSubscriptionRow | null = null;
        let recentInvoices: BillingInvoiceRow[] = [];
        let recentRefunds: BillingRefundRow[] = [];
        let recentDisputes: BillingDisputeRow[] = [];
        try {
          subscription = await dbGetLatestBillingSubscription(env, auth.client_id);
          recentInvoices = await dbListBillingInvoices(env, auth.client_id, 5);
          recentRefunds = await dbListBillingRefunds(env, auth.client_id, 5);
          recentDisputes = await dbListBillingDisputes(env, auth.client_id, 5);
        } catch (_) {
          // Billing schema may not be migrated yet.
        }

        return json(request, {
          ok: true,
          month: monthUsage.month_key,
          rates: {
            upload_per_gb_usd: uploadRate,
            download_per_gb_usd: downloadRate,
            free_quota_gb: freeQuotaGb,
          },
          usage: monthUsage,
          free_applied_bytes: freeAppliedBytes,
          billable_bytes: billableBytes,
          billable_upload_bytes: billableUpload,
          billable_download_bytes: billableDownload,
          estimated_usd: Number(estUsd.toFixed(4)),
          stripe: {
            configured: stripeConfigured(env),
            portal_configured: isNonEmpty(env.STRIPE_SECRET_KEY),
          },
          subscription: subscription
            ? {
                id: subscription.stripe_subscription_id,
                status: subscription.status,
                plan: subscription.plan,
                current_period_start_ms: subscription.current_period_start_ms,
                current_period_end_ms: subscription.current_period_end_ms,
                cancel_at_period_end: subscription.cancel_at_period_end,
                updated_at_ms: subscription.updated_at_ms,
              }
            : null,
          recent_invoices: recentInvoices,
          recent_refunds: recentRefunds,
          recent_disputes: recentDisputes,
          report_url_template: "/api/v1/me/billing/report?month=YYYY-MM&format=csv",
          plan: limits.plan,
          features,
        });
      }

      if (url.pathname === "/api/v1/me/billing/invoices" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limitRaw = url.searchParams.get("limit") || "20";
        const limit = Number.parseInt(limitRaw, 10);
        const lim = Number.isFinite(limit) ? limit : 20;
        try {
          const invoices = await dbListBillingInvoices(env, auth.client_id, lim);
          return json(request, { ok: true, invoices });
        } catch (e: any) {
          return err(request, 500, e?.message || "billing invoices unavailable");
        }
      }

      if (url.pathname === "/api/v1/me/billing/refunds" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limitRaw = url.searchParams.get("limit") || "20";
        const limit = Number.parseInt(limitRaw, 10);
        const lim = Number.isFinite(limit) ? limit : 20;
        try {
          const refunds = await dbListBillingRefunds(env, auth.client_id, lim);
          return json(request, { ok: true, refunds });
        } catch (e: any) {
          return err(request, 500, e?.message || "billing refunds unavailable");
        }
      }

      if (url.pathname === "/api/v1/me/billing/disputes" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limitRaw = url.searchParams.get("limit") || "20";
        const limit = Number.parseInt(limitRaw, 10);
        const lim = Number.isFinite(limit) ? limit : 20;
        try {
          const disputes = await dbListBillingDisputes(env, auth.client_id, lim);
          return json(request, { ok: true, disputes });
        } catch (e: any) {
          return err(request, 500, e?.message || "billing disputes unavailable");
        }
      }

      if (url.pathname === "/api/v1/me/billing/report" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const monthKey = parseMonthKey(url.searchParams.get("month"));
        if (!monthKey) return err(request, 400, "invalid month, expected YYYY-MM");
        const format = String(url.searchParams.get("format") || "json").trim().toLowerCase();
        let report:
          | {
              month: string;
              usage: UsageMonth;
              invoices: { count: number; amount_due: number; amount_paid: number };
              refunds: { count: number; amount_succeeded: number };
              disputes: { count: number; open_count: number; amount_open: number; amount_won: number; amount_lost: number };
            }
          | null = null;
        try {
          report = await dbBillingMonthReport(env, auth.client_id, monthKey);
        } catch (e: any) {
          return err(request, 500, e?.message || "billing report unavailable");
        }
        if (format === "csv") {
          const headers = new Headers();
          headers.set("content-type", "text/csv; charset=utf-8");
          headers.set("content-disposition", `attachment; filename="xsend-billing-${monthKey}.csv"`);
          return withCors(request, new Response(billingReportToCsv(report), { status: 200, headers }));
        }
        return json(request, { ok: true, report });
      }

      if (url.pathname === "/api/v1/me/billing/checkout" && request.method === "POST") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        if (!stripeConfigured(env)) return err(request, 501, "stripe checkout not configured");

        const client = await dbGetClientById(env, auth.client_id);
        if (!client) return err(request, 401, "unauthorized");
        try {
          const checkout = await createStripeCheckoutForClient(env, client);
          return json(request, {
            ok: true,
            checkout_url: checkout.url,
            checkout_session_id: checkout.id,
          });
        } catch (e: any) {
          return err(request, 502, e?.message || "stripe checkout failed");
        }
      }

      if (url.pathname === "/api/v1/me/billing/portal" && request.method === "POST") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        if (!isNonEmpty(env.STRIPE_SECRET_KEY)) return err(request, 501, "stripe is not configured");
        const client = await dbGetClientById(env, auth.client_id);
        if (!client) return err(request, 401, "unauthorized");
        const body = (await request.json().catch(() => null)) as any;
        const returnUrlRaw = typeof body?.return_url === "string" ? body.return_url : null;
        try {
          const portal = await createStripeBillingPortalForClient(request, env, client, returnUrlRaw);
          return json(request, { ok: true, portal_url: portal.url, portal_session_id: portal.id });
        } catch (e: any) {
          return err(request, 502, e?.message || "stripe billing portal failed");
        }
      }

      if (
        (url.pathname === "/api/v1/me/billing/subscription/cancel" || url.pathname === "/api/v1/me/billing/subscription/resume") &&
        request.method === "POST"
      ) {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        if (!isNonEmpty(env.STRIPE_SECRET_KEY)) return err(request, 501, "stripe is not configured");
        const wantCancel = url.pathname.endsWith("/cancel");
        let sub: any = null;
        try {
          sub = await stripeFindManagedSubscription(env, auth.client_id);
        } catch (e: any) {
          return err(request, 502, e?.message || "failed to find subscription");
        }
        const subId = typeof sub?.id === "string" ? sub.id : "";
        if (!subId) return err(request, 404, "subscription not found");
        const status = String(sub?.status || "").toLowerCase();
        if (!wantCancel && status === "canceled") {
          return err(request, 409, "subscription already canceled; create a new checkout");
        }

        try {
          const updated = await stripeUpdateSubscriptionCancelAtPeriodEnd(env, subId, wantCancel);
          await applySubscriptionToPlan(env, auth.client_id, updated);
          return json(request, {
            ok: true,
            action: wantCancel ? "cancel_at_period_end" : "resume",
            subscription: summarizeSubscriptionView(updated),
          });
        } catch (e: any) {
          return err(request, 502, e?.message || "subscription update failed");
        }
      }

      if (url.pathname === "/api/v1/me/channel" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limits = await resolveClientLimits(env, auth.client_id);
        const features = resolveClientFeatures(env, limits);
        if (!features.relay_download) {
          return featureDenied(request, "relay_download", limits, features, "relay channel listing requires paid plan");
        }
        const code = await ensureUserChannel(env, auth.client_id);
        const id = env.CHANNEL.idFromName(code);
        const stub = env.CHANNEL.get(id);
        const res = await stub.fetch("https://do/", { method: "GET", headers: { [CLIENT_ID_HEADER]: auth.client_id } });
        return withCors(request, res);
      }

      const meFileMatch = url.pathname.match(/^\/api\/v1\/me\/files(?:\/([0-9a-fA-F-]{16,64}))?$/);
      if (meFileMatch) {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limits = await resolveClientLimits(env, auth.client_id);
        const features = resolveClientFeatures(env, limits);
        const fileId = meFileMatch[1];
        if (request.method === "POST" && !features.relay_upload) {
          return featureDenied(request, "relay_upload", limits, features, "relay upload requires paid plan");
        }
        if (request.method === "GET" && !features.relay_download) {
          return featureDenied(request, "relay_download", limits, features, "relay download requires paid plan");
        }
        if (request.method === "DELETE" && !features.relay_upload) {
          return featureDenied(request, "relay_upload", limits, features, "relay delete requires paid plan");
        }
        if (request.method === "POST" && url.searchParams.get("rel") && !features.relay_batch_upload) {
          return featureDenied(
            request,
            "relay_batch_upload",
            limits,
            features,
            "relay folder/batch upload requires paid plan",
          );
        }
        const code = await ensureUserChannel(env, auth.client_id);
        const id = env.CHANNEL.idFromName(code);
        const stub = env.CHANNEL.get(id);
        const forwardUrl = new URL(request.url);
        forwardUrl.pathname = fileId ? `/files/${fileId}` : "/files";
        const headers = new Headers(request.headers);
        headers.set(CLIENT_ID_HEADER, auth.client_id);
        // Preserve query (?name=...) for POST /files
        const forwarded = new Request(forwardUrl.toString(), request);
        const fwdReq = new Request(forwarded, { headers });
        const res = await stub.fetch(fwdReq);
        return withCors(request, res);
      }

      if (url.pathname === "/api/v1/turn/credentials" && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        if (!env.TURN_KEY_ID || !env.TURN_KEY_SECRET) return err(request, 501, "turn not configured");
        const limits = await resolveClientLimits(env, auth.client_id);
        const features = resolveClientFeatures(env, limits);
        if (!features.turn_accelerate) {
          return json(
            request,
            {
              error: "turn acceleration requires paid plan",
              upgrade_required: true,
              plan: limits.plan,
              features,
            },
            { status: 402 },
          );
        }

        const ttlRaw = url.searchParams.get("ttl") || "3600";
        const ttl = Math.min(172800, Math.max(60, Number.parseInt(ttlRaw, 10) || 3600));
        const res = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate`, {
          method: "POST",
          headers: { authorization: `Bearer ${env.TURN_KEY_SECRET}`, "content-type": "application/json" },
          body: JSON.stringify({ ttl }),
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          return err(request, 502, `turn credential generation failed (${res.status}): ${text.trim()}`);
        }
        const data = (await res.json().catch(() => null)) as any;
        const urls = Array.isArray(data?.iceServers?.urls) ? data.iceServers.urls.filter((u: any) => typeof u === "string") : [];
        const filtered = urls.filter((u: string) => !u.includes(":53"));
        const username = typeof data?.iceServers?.username === "string" ? data.iceServers.username : "";
        const credential = typeof data?.iceServers?.credential === "string" ? data.iceServers.credential : "";
        if (!username || !credential || filtered.length === 0) {
          return err(request, 502, "turn returned invalid credentials");
        }
        return json(request, {
          iceServers: [
            { urls: "stun:stun.cloudflare.com:3478" },
            { urls: filtered, username, credential, credentialType: "password" },
          ],
        });
      }

      if (url.pathname === "/api/v1/e2ee/pair/start" && request.method === "POST") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limits = await resolveClientLimits(env, auth.client_id);
        const features = resolveClientFeatures(env, limits);
        if (!features.relay_e2ee) {
          return featureDenied(request, "relay_e2ee", limits, features, "relay e2ee pairing requires paid plan");
        }
        const body = (await request.json().catch(() => null)) as any;
        const pubkey = typeof body?.pubkey === "string" ? body.pubkey.trim() : "";
        if (!b64urlToBytesLen(pubkey, 32)) return err(request, 400, "invalid pubkey (expected base64url 32 bytes)");

        const ttlSeconds = 10 * 60;
        for (let i = 0; i < 50; i++) {
          const code = randomCode6();
          const id = env.PAIR.idFromName(code);
          const stub = env.PAIR.get(id);
          const res = await stub.fetch("https://do/__internal/create", {
            method: "POST",
            headers: { "content-type": "application/json", [CLIENT_ID_HEADER]: auth.client_id },
            body: JSON.stringify({ code, ttl_seconds: ttlSeconds }),
          });
          if (res.status === 201) {
            const meta = (await res.json().catch(() => null)) as any;
            const res2 = await stub.fetch("https://do/pub", {
              method: "POST",
              headers: { "content-type": "application/json", [CLIENT_ID_HEADER]: auth.client_id },
              body: JSON.stringify({ pubkey_b64: pubkey }),
            });
            if (!res2.ok) {
              const t = await res2.text().catch(() => "");
              return err(request, 502, `pair pubkey store failed: ${res2.status} ${t.trim()}`);
            }
            return json(request, { ok: true, code, expires_at_ms: Number(meta?.expires_at_ms || 0) }, { status: 201 });
          }
          if (res.status === 409 || res.status === 403) continue;
          const t = await res.text().catch(() => "");
          return err(request, 502, `pair create failed: ${res.status} ${t.trim()}`);
        }
        return err(request, 500, "failed to allocate pair code");
      }

      const pairInfoMatch = url.pathname.match(/^\/api\/v1\/e2ee\/pair\/([0-9]{6})$/);
      if (pairInfoMatch && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limits = await resolveClientLimits(env, auth.client_id);
        const features = resolveClientFeatures(env, limits);
        if (!features.relay_e2ee) {
          return featureDenied(request, "relay_e2ee", limits, features, "relay e2ee pairing requires paid plan");
        }
        const code = pairInfoMatch[1];
        const id = env.PAIR.idFromName(code);
        const stub = env.PAIR.get(id);
        const res = await stub.fetch("https://do/", { method: "GET", headers: { [CLIENT_ID_HEADER]: auth.client_id } });
        return withCors(request, res);
      }

      const pairCompleteMatch = url.pathname.match(/^\/api\/v1\/e2ee\/pair\/([0-9]{6})\/complete$/);
      if (pairCompleteMatch && request.method === "POST") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limits = await resolveClientLimits(env, auth.client_id);
        const features = resolveClientFeatures(env, limits);
        if (!features.relay_e2ee) {
          return featureDenied(request, "relay_e2ee", limits, features, "relay e2ee pairing requires paid plan");
        }
        const code = pairCompleteMatch[1];
        const body = (await request.json().catch(() => null)) as any;
        const senderPub = typeof body?.sender_pubkey === "string" ? body.sender_pubkey.trim() : "";
        const nonce = typeof body?.nonce === "string" ? body.nonce.trim() : "";
        const cipher = typeof body?.ciphertext === "string" ? body.ciphertext.trim() : "";
        if (!b64urlToBytesLen(senderPub, 32)) return err(request, 400, "invalid sender_pubkey");
        if (!b64urlToBytesLen(nonce, 12)) return err(request, 400, "invalid nonce");
        if (!b64urlToBytes(cipher)) return err(request, 400, "invalid ciphertext");

        const id = env.PAIR.idFromName(code);
        const stub = env.PAIR.get(id);
        const res = await stub.fetch("https://do/cipher", {
          method: "POST",
          headers: { "content-type": "application/json", [CLIENT_ID_HEADER]: auth.client_id },
          body: JSON.stringify({ sender_pubkey_b64: senderPub, nonce_b64: nonce, ciphertext_b64: cipher }),
        });
        return withCors(request, res);
      }

      const pairResultMatch = url.pathname.match(/^\/api\/v1\/e2ee\/pair\/([0-9]{6})\/result$/);
      if (pairResultMatch && request.method === "GET") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const limits = await resolveClientLimits(env, auth.client_id);
        const features = resolveClientFeatures(env, limits);
        if (!features.relay_e2ee) {
          return featureDenied(request, "relay_e2ee", limits, features, "relay e2ee pairing requires paid plan");
        }
        const code = pairResultMatch[1];
        const id = env.PAIR.idFromName(code);
        const stub = env.PAIR.get(id);
        const res = await stub.fetch("https://do/cipher", { method: "GET", headers: { [CLIENT_ID_HEADER]: auth.client_id } });
        return withCors(request, res);
      }

      if (url.pathname === "/api/v1/channel" && request.method === "POST") {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const ttl = parseIntEnv(env, "CHANNEL_TTL_SECONDS", 900);
        for (let i = 0; i < 50; i++) {
          const code = randomCode6();
          const id = env.CHANNEL.idFromName(code);
          const stub = env.CHANNEL.get(id);
          const res = await stub.fetch("https://do/__internal/create", {
            method: "POST",
            headers: { "content-type": "application/json", [CLIENT_ID_HEADER]: auth.client_id },
            body: JSON.stringify({ code, ttl_seconds: ttl }),
          });
          if (res.status === 201) {
            const body = await res.json();
            return json(request, body, { status: 201 });
          }
          if (res.status === 409 || res.status === 403) continue;
          return withCors(request, res);
        }
        return err(request, 500, "failed to allocate channel code");
      }

      const m = url.pathname.match(/^\/api\/v1\/channel\/([0-9]{6})(?:\/(.*))?$/);
      if (m) {
        const auth = await requireAuth(request, env);
        if (auth instanceof Response) return auth;
        const code = m[1];
        const rest = m[2] || "";
        const id = env.CHANNEL.idFromName(code);
        const stub = env.CHANNEL.get(id);

        // Create with client-supplied code: PUT /api/v1/channel/<code>
        if (request.method === "PUT" && rest === "") {
          const ttl = parseIntEnv(env, "CHANNEL_TTL_SECONDS", 900);
          const res = await stub.fetch("https://do/__internal/create", {
            method: "POST",
            headers: { "content-type": "application/json", [CLIENT_ID_HEADER]: auth.client_id },
            body: JSON.stringify({ code, ttl_seconds: ttl }),
          });
          return withCors(request, res);
        }

        // Forward to DO.
        const forwardUrl = new URL(request.url);
        forwardUrl.pathname = "/" + rest;
        const headers = new Headers(request.headers);
        headers.set(CLIENT_ID_HEADER, auth.client_id);
        const forwarded = new Request(forwardUrl.toString(), request);
        const fwdReq = new Request(forwarded, { headers });
        const res = await stub.fetch(fwdReq);
        return withCors(request, res);
      }

      // Static assets (public page).
      const asset = await env.ASSETS.fetch(request);
      if (asset.status !== 404) return asset;
      return new Response("Not Found", { status: 404 });
    } catch (e: any) {
      return err(request, 500, e?.message || "internal error");
    }
  },
};

type SignalPeer = {
  id: string;
  ws: WebSocket;
  name: string | null;
  joined_at_ms: number;
};

export class SignalAutoDO {
  private state: DurableObjectState;
  private env: Env;
  private peers: Map<string, SignalPeer>;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.peers = new Map();
  }

  private peerList(): Array<{ id: string; name: string | null; joined_at_ms: number }> {
    const out: Array<{ id: string; name: string | null; joined_at_ms: number }> = [];
    for (const p of this.peers.values()) {
      out.push({ id: p.id, name: p.name, joined_at_ms: p.joined_at_ms });
    }
    out.sort((a, b) => a.joined_at_ms - b.joined_at_ms);
    return out;
  }

  private send(ws: WebSocket, msg: Record<string, JsonValue>): void {
    try {
      ws.send(JSON.stringify(msg));
    } catch (_) {
      // Ignore transient websocket send failures.
    }
  }

  private broadcast(msg: Record<string, JsonValue>, exceptId?: string): void {
    for (const [id, p] of this.peers.entries()) {
      if (exceptId && id === exceptId) continue;
      this.send(p.ws, msg);
    }
  }

  private removePeer(peerId: string): void {
    const old = this.peers.get(peerId);
    if (!old) return;
    this.peers.delete(peerId);
    this.broadcast({ type: "peer_leave", peer_id: peerId, ts_ms: Date.now() });
  }

  private onMessage(peerId: string, evt: MessageEvent): void {
    const raw = wsDataToString((evt as any).data);
    if (!raw) return;
    let msg: any = null;
    try {
      msg = JSON.parse(raw);
    } catch (_) {
      return;
    }
    if (!msg || typeof msg !== "object") return;
    const t = typeof msg.type === "string" ? msg.type : "";
    const sender = this.peers.get(peerId);
    if (!sender) return;

    if (t === "ping") {
      this.send(sender.ws, { type: "pong", ts_ms: Date.now() });
      return;
    }

    if (t === "list") {
      this.send(sender.ws, { type: "peers", peers: this.peerList(), ts_ms: Date.now() });
      return;
    }

    if (t === "meta") {
      const name = sanitizePeerName(typeof msg.name === "string" ? msg.name : null);
      sender.name = name;
      this.broadcast(
        {
          type: "peer_update",
          peer: { id: sender.id, name: sender.name, joined_at_ms: sender.joined_at_ms },
          ts_ms: Date.now(),
        },
        sender.id,
      );
      return;
    }

    if (t === "signal") {
      const to = sanitizePeerId(typeof msg.to === "string" ? msg.to : null);
      if (!to) return;
      const target = this.peers.get(to);
      if (!target) {
        this.send(sender.ws, { type: "error", error: "peer_not_found", to, ts_ms: Date.now() });
        return;
      }
      const kind = typeof msg.kind === "string" ? msg.kind : null;
      const payload: JsonValue = msg.payload === undefined ? null : (msg.payload as JsonValue);
      this.send(target.ws, {
        type: "signal",
        from: sender.id,
        kind,
        payload,
        ts_ms: Date.now(),
      });
      return;
    }
  }

  private attachPeer(peerId: string, ws: WebSocket, name: string | null): void {
    const peer: SignalPeer = {
      id: peerId,
      ws,
      name,
      joined_at_ms: Date.now(),
    };
    this.peers.set(peerId, peer);

    ws.addEventListener("message", (evt) => this.onMessage(peerId, evt));
    ws.addEventListener("close", () => this.removePeer(peerId));
    ws.addEventListener("error", () => this.removePeer(peerId));
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request.headers.get("origin")) });
    }

    const url = new URL(request.url);
    if (url.pathname === "/health" && request.method === "GET") {
      return new Response(
        JSON.stringify({ ok: true, peers: this.peers.size }),
        { status: 200, headers: { "content-type": "application/json; charset=utf-8" } },
      );
    }

    if (url.pathname !== "/ws" || request.method !== "GET") {
      return new Response(JSON.stringify({ error: "not found" }), {
        status: 404,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    const upgrade = String(request.headers.get("upgrade") || "").toLowerCase();
    if (upgrade !== "websocket") {
      return new Response(JSON.stringify({ error: "expected websocket upgrade" }), {
        status: 426,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    let peerId = sanitizePeerId(url.searchParams.get("peer_id")) || crypto.randomUUID();
    if (this.peers.has(peerId)) peerId = `${peerId.slice(0, 48)}-${randomCode6()}`;
    const peerName = sanitizePeerName(url.searchParams.get("name"));

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    this.attachPeer(peerId, server, peerName);

    this.send(server, {
      type: "welcome",
      self_id: peerId,
      peers: this.peerList(),
      ts_ms: Date.now(),
    });
    this.broadcast(
      {
        type: "peer_join",
        peer: { id: peerId, name: peerName, joined_at_ms: Date.now() },
        ts_ms: Date.now(),
      },
      peerId,
    );
    return new Response(null, { status: 101, webSocket: client });
  }
}

export class ChannelDO {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request.headers.get("origin")) });
    }

    const clientId = request.headers.get(CLIENT_ID_HEADER);
    if (!clientId) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/__internal/create" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as any;
      const code = typeof body?.code === "string" ? body.code : "";
      const ttlSeconds = typeof body?.ttl_seconds === "number" ? body.ttl_seconds : 900;
      if (!isValidCode(code)) return new Response(JSON.stringify({ error: "invalid code" }), { status: 400 });

      const now = Date.now();
      const existing = await this.state.storage.get<ChannelMeta>("meta");
      if (existing && now < existing.expires_at_ms) {
        if (existing.owner_client_id !== clientId) {
          return new Response(JSON.stringify({ error: "channel owned by another user" }), {
            status: 403,
            headers: { "content-type": "application/json; charset=utf-8" },
          });
        }
        // Ensure alarms are set even for legacy channels created before alarms existed.
        await this.state.storage.setAlarm(existing.expires_at_ms).catch(() => {});
        return new Response(JSON.stringify({ error: "channel already exists" }), {
          status: 409,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }

      // Clean any old data (expired channel reuse).
      if (existing) {
        await this.state.storage.deleteAlarm().catch(() => {});
        const files = await this.state.storage.list<StoredFile>({ prefix: "f:" });
        const keys = Array.from(files.values()).map((f) => f.r2_key);
        if (keys.length > 0) {
          await this.env.RELAY_BUCKET.delete(keys);
        }
        await this.state.storage.deleteAll();
      }

      const meta: ChannelMeta = {
        code,
        created_at_ms: now,
        expires_at_ms: now + ttlSeconds * 1000,
        owner_client_id: clientId,
      };
      await this.state.storage.put("meta", meta);
      await this.state.storage.setAlarm(meta.expires_at_ms).catch(() => {});
      return new Response(JSON.stringify(meta), { status: 201, headers: { "content-type": "application/json" } });
    }

    const meta = await this.state.storage.get<ChannelMeta>("meta");
    if (!meta) return new Response(JSON.stringify({ error: "channel not found" }), { status: 404 });
    const now = Date.now();
    if (meta.owner_client_id !== clientId) {
      return new Response(JSON.stringify({ error: "forbidden" }), {
        status: 403,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    const limits = await resolveClientLimits(this.env, meta.owner_client_id);
    const fileTtlSeconds = limits.file_ttl_seconds;
    const fileTtlMs = fileTtlSeconds * 1000;

    // Prune expired files and keep the channel expiry aligned with the last unexpired file.
    const filesMap = await this.state.storage.list<StoredFile>({ prefix: "f:" });
    const expiredStorageKeys: string[] = [];
    const expiredR2Keys: string[] = [];
    const liveFiles: StoredFile[] = [];

    let nextAlarmAtMs = meta.expires_at_ms;
    let channelExpiresAtMs = meta.expires_at_ms;
    let minFileExp = Number.POSITIVE_INFINITY;
    let maxFileExp = 0;

    for (const f of filesMap.values()) {
      if (!f || typeof f.uploaded_at_ms !== "number" || typeof f.id !== "string" || typeof f.r2_key !== "string") {
        continue;
      }
      const expAt = f.uploaded_at_ms + fileTtlMs;
      if (now >= expAt) {
        expiredStorageKeys.push(`f:${f.id}`);
        expiredR2Keys.push(f.r2_key);
        continue;
      }
      liveFiles.push(f);
      if (expAt < minFileExp) minFileExp = expAt;
      if (expAt > maxFileExp) maxFileExp = expAt;
    }

    if (expiredR2Keys.length > 0) {
      await this.env.RELAY_BUCKET.delete(expiredR2Keys).catch(() => {});
    }
    if (expiredStorageKeys.length > 0) {
      await this.state.storage.delete(expiredStorageKeys).catch(() => {});
    }

    if (liveFiles.length > 0) {
      channelExpiresAtMs = maxFileExp;
      nextAlarmAtMs = Number.isFinite(minFileExp) ? minFileExp : maxFileExp;
    }

    if (meta.expires_at_ms !== channelExpiresAtMs) {
      meta.expires_at_ms = channelExpiresAtMs;
      await this.state.storage.put("meta", meta);
    }

    if (nextAlarmAtMs > now) {
      await this.state.storage.setAlarm(nextAlarmAtMs).catch(() => {});
    }

    if (now >= meta.expires_at_ms) {
      // Channel expired: clear everything so retention is enforced even if nobody visits the channel.
      const allFiles = await this.state.storage.list<StoredFile>({ prefix: "f:" });
      const keys = Array.from(allFiles.values()).map((f) => f.r2_key);
      if (keys.length > 0) {
        await this.env.RELAY_BUCKET.delete(keys).catch(() => {});
      }
      await this.state.storage.deleteAlarm().catch(() => {});
      await this.state.storage.deleteAll();
      return new Response(JSON.stringify({ error: "channel expired" }), { status: 404 });
    }

    if (path === "/" && request.method === "GET") {
      const maxFiles = limits.max_files;
      const maxBytes = limits.max_file_bytes;
      const maxTotalBytes = limits.max_total_bytes;
      const list = liveFiles.slice().sort((a, b) => a.uploaded_at_ms - b.uploaded_at_ms);
      const totalBytes = list.reduce((acc, f) => acc + (Number.isFinite(f.size_bytes) ? f.size_bytes : 0), 0);
      return new Response(
        JSON.stringify({
          channel: meta,
          limits: {
            plan: limits.plan,
            source: limits.source,
            max_files: maxFiles,
            max_file_bytes: maxBytes,
            max_total_bytes: maxTotalBytes,
            file_ttl_seconds: fileTtlSeconds,
            e2ee_overhead_bytes: parseIntEnv(this.env, "E2EE_OVERHEAD_BYTES", 16 * 1024),
          },
          usage: { file_count: list.length, total_bytes: totalBytes },
          files: list.map((f) => ({
            id: f.id,
            filename: f.filename,
            relative_path: f.relative_path || null,
            content_type: f.content_type,
            size_bytes: f.size_bytes,
            uploaded_at_ms: f.uploaded_at_ms,
            expires_at_ms: f.uploaded_at_ms + fileTtlMs,
            download_url: `/api/v1/channel/${meta.code}/files/${f.id}`,
          })),
        }),
        { headers: { "content-type": "application/json; charset=utf-8" } },
      );
    }

    if (path === "/files" && request.method === "POST") {
      const maxFiles = limits.max_files;
      const maxBytes = limits.max_file_bytes;
      const maxTotalBytes = limits.max_total_bytes;
      const e2eeHeader = (request.headers.get("x-xsend-e2ee") || "").trim().toLowerCase();
      const e2eeUpload = e2eeHeader === "1" || e2eeHeader === "true" || e2eeHeader === "yes";
      const e2eeOverhead = parseIntEnv(this.env, "E2EE_OVERHEAD_BYTES", 16 * 1024);
      const maxTransportBytes = e2eeUpload ? maxBytes + Math.max(0, e2eeOverhead) : maxBytes;

      const nameParam = url.searchParams.get("name") || "file.bin";
      const filename = sanitizeFilename(nameParam);
      const relativePath = sanitizeRelativePath(url.searchParams.get("rel"));
      const contentType = request.headers.get("content-type") || "application/octet-stream";

      const contentLengthHeader = request.headers.get("content-length");
      if (contentLengthHeader) {
        const n = Number.parseInt(contentLengthHeader, 10);
        if (Number.isFinite(n) && n > maxTransportBytes) {
          return new Response(JSON.stringify({ error: "file too large" }), { status: 413 });
        }
      }

      if (liveFiles.length >= maxFiles) {
        return new Response(JSON.stringify({ error: "file limit reached" }), { status: 403 });
      }

      const buf = await request.arrayBuffer();
      if (buf.byteLength > maxTransportBytes) {
        return new Response(JSON.stringify({ error: "file too large" }), { status: 413 });
      }

      const currentTotal = liveFiles.reduce((acc, f) => acc + (Number.isFinite(f.size_bytes) ? f.size_bytes : 0), 0);
      if (currentTotal + buf.byteLength > maxTotalBytes) {
        return new Response(JSON.stringify({ error: "total storage limit reached" }), { status: 403 });
      }

      const id = crypto.randomUUID();
      const r2Key = `ch/${meta.code}/${id}`;
      await this.env.RELAY_BUCKET.put(r2Key, buf, {
        httpMetadata: { contentType },
        customMetadata: { filename, uploadedAt: new Date().toISOString() },
      });

      const uploadedAtMs = Date.now();
      const f: StoredFile = {
        id,
        filename,
        relative_path: relativePath || undefined,
        content_type: contentType,
        size_bytes: buf.byteLength,
        uploaded_at_ms: uploadedAtMs,
        r2_key: r2Key,
      };
      await this.state.storage.put(`f:${id}`, f);
      await recordUsage(this.env, meta.owner_client_id, buf.byteLength, 0, 1, 0);

      // Update channel expiry/alarm based on the earliest/latest file expiry.
      const newFiles = liveFiles.concat([f]);
      let newMinExp = Number.POSITIVE_INFINITY;
      let newMaxExp = 0;
      for (const it of newFiles) {
        const expAt = it.uploaded_at_ms + fileTtlMs;
        if (expAt < newMinExp) newMinExp = expAt;
        if (expAt > newMaxExp) newMaxExp = expAt;
      }
      meta.expires_at_ms = newMaxExp;
      await this.state.storage.put("meta", meta);
      if (Number.isFinite(newMinExp) && newMinExp > Date.now()) {
        await this.state.storage.setAlarm(newMinExp).catch(() => {});
      }

      return new Response(
        JSON.stringify({
          file: {
            id: f.id,
            filename: f.filename,
            relative_path: f.relative_path || null,
            content_type: f.content_type,
            size_bytes: f.size_bytes,
            uploaded_at_ms: f.uploaded_at_ms,
            expires_at_ms: f.uploaded_at_ms + fileTtlMs,
            download_url: `/api/v1/channel/${meta.code}/files/${f.id}`,
          },
        }),
        { status: 201, headers: { "content-type": "application/json; charset=utf-8" } },
      );
    }

    const fileMatch = path.match(/^\/files\/([0-9a-fA-F-]{16,64})$/);
    if (fileMatch && (request.method === "GET" || request.method === "HEAD")) {
      const id = fileMatch[1];
      const f = await this.state.storage.get<StoredFile>(`f:${id}`);
      if (!f) return new Response("Not Found", { status: 404 });

      const expAt = typeof f.uploaded_at_ms === "number" ? f.uploaded_at_ms + fileTtlMs : 0;
      if (expAt > 0 && Date.now() >= expAt) {
        await this.env.RELAY_BUCKET.delete(f.r2_key).catch(() => {});
        await this.state.storage.delete(`f:${id}`).catch(() => {});
        return new Response("Not Found", { status: 404 });
      }

      const obj = await this.env.RELAY_BUCKET.get(f.r2_key);
      if (!obj) {
        // If the object is gone (e.g. lifecycle), clean up metadata.
        await this.state.storage.delete(`f:${id}`).catch(() => {});
        return new Response("Not Found", { status: 404 });
      }

      const headers = new Headers();
      obj.writeHttpMetadata(headers);
      headers.set("etag", obj.httpEtag);
      headers.set("cache-control", "no-store");
      headers.set("content-type", f.content_type || "application/octet-stream");
      headers.set("content-disposition", contentDisposition(f.filename));

      if (request.method === "HEAD") return new Response(null, { status: 200, headers });
      await recordUsage(this.env, meta.owner_client_id, 0, f.size_bytes, 0, 1);
      return new Response(obj.body, { status: 200, headers });
    }

    if (fileMatch && request.method === "DELETE") {
      const id = fileMatch[1];
      const f = await this.state.storage.get<StoredFile>(`f:${id}`);
      if (!f) return new Response("Not Found", { status: 404 });
      await this.env.RELAY_BUCKET.delete(f.r2_key);
      await this.state.storage.delete(`f:${id}`);
      return new Response(null, { status: 204 });
    }

    return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  }

  async alarm(): Promise<void> {
    try {
      const meta = await this.state.storage.get<ChannelMeta>("meta");
      if (!meta) return;

      const now = Date.now();
      const limits = await resolveClientLimits(this.env, meta.owner_client_id);
      const fileTtlSeconds = limits.file_ttl_seconds;
      const fileTtlMs = fileTtlSeconds * 1000;

      const filesMap = await this.state.storage.list<StoredFile>({ prefix: "f:" });
      const expiredStorageKeys: string[] = [];
      const expiredR2Keys: string[] = [];
      const liveFiles: StoredFile[] = [];

      let minFileExp = Number.POSITIVE_INFINITY;
      let maxFileExp = 0;

      for (const f of filesMap.values()) {
        if (!f || typeof f.uploaded_at_ms !== "number" || typeof f.id !== "string" || typeof f.r2_key !== "string") {
          continue;
        }
        const expAt = f.uploaded_at_ms + fileTtlMs;
        if (now >= expAt) {
          expiredStorageKeys.push(`f:${f.id}`);
          expiredR2Keys.push(f.r2_key);
          continue;
        }
        liveFiles.push(f);
        if (expAt < minFileExp) minFileExp = expAt;
        if (expAt > maxFileExp) maxFileExp = expAt;
      }

      if (expiredR2Keys.length > 0) {
        await this.env.RELAY_BUCKET.delete(expiredR2Keys).catch(() => {});
      }
      if (expiredStorageKeys.length > 0) {
        await this.state.storage.delete(expiredStorageKeys).catch(() => {});
      }

      if (liveFiles.length === 0) {
        if (now >= meta.expires_at_ms) {
          // Nothing left; fully clear the DO state.
          await this.state.storage.deleteAlarm().catch(() => {});
          await this.state.storage.deleteAll();
          return;
        }
        // Keep an idle alarm so stale empty channels are eventually reclaimed.
        if (meta.expires_at_ms > now) {
          await this.state.storage.setAlarm(meta.expires_at_ms).catch(() => {});
        }
        return;
      }

      // Keep channel expiry aligned with the last file expiry.
      meta.expires_at_ms = maxFileExp;
      await this.state.storage.put("meta", meta);
      const nextAlarmAtMs = Number.isFinite(minFileExp) ? minFileExp : maxFileExp;
      if (nextAlarmAtMs > now) {
        await this.state.storage.setAlarm(nextAlarmAtMs).catch(() => {});
      } else {
        await this.state.storage.setAlarm(now + 1000).catch(() => {});
      }
    } catch (_) {
      // Best-effort cleanup; ignore errors.
    }
  }
}

export class PairDO {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request.headers.get("origin")) });
    }

    const clientId = request.headers.get(CLIENT_ID_HEADER);
    if (!clientId) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/__internal/create" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as any;
      const code = typeof body?.code === "string" ? body.code : "";
      const ttlSeconds = typeof body?.ttl_seconds === "number" ? body.ttl_seconds : 600;
      if (!isValidCode(code)) return new Response(JSON.stringify({ error: "invalid code" }), { status: 400 });

      const now = Date.now();
      const existing = await this.state.storage.get<PairMeta>("meta");
      if (existing && now < existing.expires_at_ms) {
        if (existing.owner_client_id !== clientId) {
          return new Response(JSON.stringify({ error: "pair owned by another user" }), {
            status: 403,
            headers: { "content-type": "application/json; charset=utf-8" },
          });
        }
        await this.state.storage.setAlarm(existing.expires_at_ms).catch(() => {});
        return new Response(JSON.stringify({ error: "pair already exists" }), {
          status: 409,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }

      // Clean any old data.
      if (existing) {
        await this.state.storage.deleteAlarm().catch(() => {});
        await this.state.storage.deleteAll();
      }

      const meta: PairMeta = {
        code,
        created_at_ms: now,
        expires_at_ms: now + ttlSeconds * 1000,
        owner_client_id: clientId,
      };
      await this.state.storage.put("meta", meta);
      await this.state.storage.setAlarm(meta.expires_at_ms).catch(() => {});
      return new Response(JSON.stringify(meta), { status: 201, headers: { "content-type": "application/json" } });
    }

    const meta = await this.state.storage.get<PairMeta>("meta");
    if (!meta) return new Response(JSON.stringify({ error: "pair not found" }), { status: 404 });
    const now = Date.now();
    if (now >= meta.expires_at_ms) {
      await this.state.storage.deleteAlarm().catch(() => {});
      await this.state.storage.deleteAll();
      return new Response(JSON.stringify({ error: "pair expired" }), { status: 404 });
    }
    if (meta.owner_client_id !== clientId) {
      return new Response(JSON.stringify({ error: "forbidden" }), {
        status: 403,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    if (path === "/" && request.method === "GET") {
      const pub = (await this.state.storage.get<string>("pub")) || null;
      const cipher = (await this.state.storage.get<PairCipher>("cipher")) || null;
      return new Response(
        JSON.stringify({
          pair: { code: meta.code, created_at_ms: meta.created_at_ms, expires_at_ms: meta.expires_at_ms },
          pubkey: pub,
          has_cipher: !!cipher,
        }),
        { headers: { "content-type": "application/json; charset=utf-8" } },
      );
    }

    if (path === "/pub" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as any;
      const pubkey = typeof body?.pubkey_b64 === "string" ? body.pubkey_b64.trim() : "";
      if (!b64urlToBytesLen(pubkey, 32)) {
        return new Response(JSON.stringify({ error: "invalid pubkey" }), {
          status: 400,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }
      await this.state.storage.put("pub", pubkey);
      return new Response(JSON.stringify({ ok: true }), { status: 201, headers: { "content-type": "application/json" } });
    }

    if (path === "/cipher" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as any;
      const senderPub = typeof body?.sender_pubkey_b64 === "string" ? body.sender_pubkey_b64.trim() : "";
      const nonce = typeof body?.nonce_b64 === "string" ? body.nonce_b64.trim() : "";
      const cipher = typeof body?.ciphertext_b64 === "string" ? body.ciphertext_b64.trim() : "";
      if (!b64urlToBytesLen(senderPub, 32)) {
        return new Response(JSON.stringify({ error: "invalid sender_pubkey" }), {
          status: 400,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }
      if (!b64urlToBytesLen(nonce, 12)) {
        return new Response(JSON.stringify({ error: "invalid nonce" }), {
          status: 400,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }
      if (!b64urlToBytes(cipher)) {
        return new Response(JSON.stringify({ error: "invalid ciphertext" }), {
          status: 400,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }

      const c: PairCipher = {
        sender_pubkey_b64: senderPub,
        nonce_b64: nonce,
        ciphertext_b64: cipher,
        created_at_ms: Date.now(),
      };
      await this.state.storage.put("cipher", c);
      return new Response(JSON.stringify({ ok: true }), { status: 201, headers: { "content-type": "application/json" } });
    }

    if (path === "/cipher" && request.method === "GET") {
      const c = await this.state.storage.get<PairCipher>("cipher");
      if (!c) return new Response(JSON.stringify({ error: "not ready" }), { status: 404 });
      return new Response(
        JSON.stringify({
          sender_pubkey: c.sender_pubkey_b64,
          nonce: c.nonce_b64,
          ciphertext: c.ciphertext_b64,
        }),
        { headers: { "content-type": "application/json; charset=utf-8" } },
      );
    }

    return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  }

  async alarm(): Promise<void> {
    try {
      await this.state.storage.deleteAlarm().catch(() => {});
      await this.state.storage.deleteAll();
    } catch (_) {}
  }
}
