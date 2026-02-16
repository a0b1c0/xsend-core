function $(id) {
  return document.getElementById(id);
}

function setErr(msg) {
  const el = $("err");
  if (!el) return;
  el.textContent = msg ? String(msg) : "";
}

function fmtBytes(n) {
  if (!Number.isFinite(n)) return "?";
  const units = ["B", "KiB", "MiB", "GiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = v >= 10 || i === 0 ? 0 : 1;
  return `${v.toFixed(digits)} ${units[i]}`;
}

function fmtUsd(n) {
  if (!Number.isFinite(n)) return "-";
  return `$${Number(n).toFixed(4)}`;
}

function fmtTs(ms) {
  if (!ms) return "-";
  try {
    return new Date(ms).toLocaleString();
  } catch (_) {
    return "-";
  }
}

let gUser = null;
let gProviders = { google: false, github: false, apple: false };

async function api(method, path, body, headers) {
  const h = Object.assign({}, headers || {});
  const init = { method, headers: h, credentials: "same-origin" };
  if (body !== undefined) init.body = body;

  const res = await fetch(path, init);
  if (res.status === 401) {
    gUser = null;
    renderAccount();
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch (_) {}
    throw new Error(msg);
  }
  return res;
}

async function apiJson(method, path, obj) {
  return await api(method, path, JSON.stringify(obj), { "content-type": "application/json" });
}

function renderAccount() {
  const st = $("acctStatus");
  if (st) st.textContent = gUser ? `signed in as ${gUser.username}` : "signed out";

  const myCode = $("myCode");
  if (myCode) myCode.textContent = "-";

  const canUse = !!gUser;
  if ($("upload")) $("upload").disabled = !canUse;
  if ($("refresh")) $("refresh").disabled = !canUse;
  if ($("logout")) $("logout").disabled = !canUse;
  if ($("billingCheckout")) $("billingCheckout").disabled = !canUse;
  if ($("billingPortal")) $("billingPortal").disabled = !canUse;
  if ($("billingCancel")) $("billingCancel").disabled = !canUse;
  if ($("billingResume")) $("billingResume").disabled = !canUse;
  if ($("billingReportCsv")) $("billingReportCsv").disabled = !canUse;

  if ($("oauthGoogle")) $("oauthGoogle").disabled = !gProviders.google;
  if ($("oauthGitHub")) $("oauthGitHub").disabled = !gProviders.github;
  if ($("oauthApple")) $("oauthApple").disabled = !gProviders.apple;
  if ($("oauthHint")) {
    const parts = [];
    if (gProviders.google) parts.push("Google");
    if (gProviders.github) parts.push("GitHub");
    if (gProviders.apple) parts.push("Apple");
    $("oauthHint").textContent = parts.length > 0 ? `Enabled: ${parts.join(", ")}` : "OAuth providers are not configured yet.";
  }
}

function clearRelayView() {
  if ($("status")) $("status").textContent = "-";
  if ($("expires")) $("expires").textContent = "-";
  if ($("plan")) $("plan").textContent = "-";
  if ($("usageToday")) $("usageToday").textContent = "-";
  if ($("usageMonth")) $("usageMonth").textContent = "-";
  if ($("billingEst")) $("billingEst").textContent = "-";
  if ($("billingSub")) $("billingSub").textContent = "-";
  if ($("limits")) $("limits").textContent = "-";
  if ($("uploadHint")) $("uploadHint").textContent = "-";
  if ($("billingHint")) $("billingHint").textContent = "-";
  const root = $("fileList");
  if (root) root.textContent = "";
  if ($("count")) $("count").textContent = "0";
  const inv = $("invoiceList");
  if (inv) inv.textContent = "";
  if ($("invoiceCount")) $("invoiceCount").textContent = "0";
  const rf = $("refundList");
  if (rf) rf.textContent = "";
  if ($("refundCount")) $("refundCount").textContent = "0";
  const dp = $("disputeList");
  if (dp) dp.textContent = "";
  if ($("disputeCount")) $("disputeCount").textContent = "0";
}

function renderFiles(files) {
  const root = $("fileList");
  if (!root) return;
  root.textContent = "";

  if (!files || files.length === 0) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "No files.";
    root.appendChild(p);
    if ($("count")) $("count").textContent = "0";
    return;
  }

  if ($("count")) $("count").textContent = String(files.length);

  for (const f of files) {
    const el = document.createElement("div");
    el.className = "file";

    const top = document.createElement("div");
    top.className = "topline";

    const name = document.createElement("div");
    name.className = "name";
    const a = document.createElement("a");
    a.href = f.download_url;
    const displayName = f && f.relative_path ? String(f.relative_path) : String(f.filename || "file.bin");
    a.textContent = displayName;
    a.setAttribute("download", String(f.filename || "file.bin"));
    name.appendChild(a);

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${fmtBytes(f.size_bytes)} | ${f.content_type || "application/octet-stream"} | ${fmtTs(
      f.uploaded_at_ms,
    )}`;

    top.appendChild(name);
    top.appendChild(meta);

    const actions = document.createElement("div");
    actions.style.marginTop = "10px";
    actions.style.display = "flex";
    actions.style.gap = "10px";
    actions.style.flexWrap = "wrap";

    const del = document.createElement("button");
    del.className = "danger";
    del.textContent = "Delete";
    del.onclick = async () => {
      setErr("");
      try {
        await api("DELETE", `/api/v1/me/files/${encodeURIComponent(f.id)}`);
        await refreshMyRelay();
      } catch (e) {
        setErr(e.message);
      }
    };

    actions.appendChild(del);

    el.appendChild(top);
    el.appendChild(actions);
    root.appendChild(el);
  }
}

function renderInvoices(invoices) {
  const root = $("invoiceList");
  if (!root) return;
  root.textContent = "";

  const list = Array.isArray(invoices) ? invoices : [];
  if ($("invoiceCount")) $("invoiceCount").textContent = String(list.length);
  if (list.length === 0) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "No invoices yet.";
    root.appendChild(p);
    return;
  }

  for (const inv of list) {
    const el = document.createElement("div");
    el.className = "file";

    const top = document.createElement("div");
    top.className = "topline";

    const name = document.createElement("div");
    name.className = "name";
    const id = inv && inv.stripe_invoice_id ? String(inv.stripe_invoice_id) : "invoice";
    const link = inv && inv.hosted_invoice_url ? String(inv.hosted_invoice_url) : inv && inv.invoice_pdf_url ? String(inv.invoice_pdf_url) : "";
    if (link) {
      const a = document.createElement("a");
      a.href = link;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = id;
      name.appendChild(a);
    } else {
      name.textContent = id;
    }

    const meta = document.createElement("div");
    meta.className = "meta";
    const status = inv && inv.status ? String(inv.status) : "unknown";
    const amount = Number.isFinite(Number(inv && inv.amount_paid)) ? Number(inv.amount_paid) : Number(inv && inv.amount_due) || 0;
    const currency = inv && inv.currency ? String(inv.currency).toUpperCase() : "USD";
    const created = inv && inv.created_at_ms ? fmtTs(inv.created_at_ms) : "-";
    meta.textContent = `${status} | ${(amount / 100).toFixed(2)} ${currency} | ${created}`;

    top.appendChild(name);
    top.appendChild(meta);
    el.appendChild(top);
    root.appendChild(el);
  }
}

function renderRefunds(refunds) {
  const root = $("refundList");
  if (!root) return;
  root.textContent = "";

  const list = Array.isArray(refunds) ? refunds : [];
  if ($("refundCount")) $("refundCount").textContent = String(list.length);
  if (list.length === 0) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "No refunds.";
    root.appendChild(p);
    return;
  }

  for (const rf of list) {
    const el = document.createElement("div");
    el.className = "file";

    const top = document.createElement("div");
    top.className = "topline";

    const name = document.createElement("div");
    name.className = "name";
    name.textContent = rf && rf.stripe_refund_id ? String(rf.stripe_refund_id) : "refund";

    const meta = document.createElement("div");
    meta.className = "meta";
    const status = rf && rf.status ? String(rf.status) : "unknown";
    const amount = Number.isFinite(Number(rf && rf.amount)) ? Number(rf.amount) : 0;
    const currency = rf && rf.currency ? String(rf.currency).toUpperCase() : "USD";
    const created = rf && rf.created_at_ms ? fmtTs(rf.created_at_ms) : "-";
    meta.textContent = `${status} | ${(amount / 100).toFixed(2)} ${currency} | ${created}`;

    top.appendChild(name);
    top.appendChild(meta);
    el.appendChild(top);
    root.appendChild(el);
  }
}

function renderDisputes(disputes) {
  const root = $("disputeList");
  if (!root) return;
  root.textContent = "";

  const list = Array.isArray(disputes) ? disputes : [];
  if ($("disputeCount")) $("disputeCount").textContent = String(list.length);
  if (list.length === 0) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "No disputes.";
    root.appendChild(p);
    return;
  }

  for (const dp of list) {
    const el = document.createElement("div");
    el.className = "file";

    const top = document.createElement("div");
    top.className = "topline";

    const name = document.createElement("div");
    name.className = "name";
    name.textContent = dp && dp.stripe_dispute_id ? String(dp.stripe_dispute_id) : "dispute";

    const meta = document.createElement("div");
    meta.className = "meta";
    const status = dp && dp.status ? String(dp.status) : "unknown";
    const amount = Number.isFinite(Number(dp && dp.amount)) ? Number(dp.amount) : 0;
    const currency = dp && dp.currency ? String(dp.currency).toUpperCase() : "USD";
    const created = dp && dp.created_at_ms ? fmtTs(dp.created_at_ms) : "-";
    meta.textContent = `${status} | ${(amount / 100).toFixed(2)} ${currency} | ${created}`;

    top.appendChild(name);
    top.appendChild(meta);
    el.appendChild(top);
    root.appendChild(el);
  }
}

async function loadProviders() {
  try {
    const res = await api("GET", "/api/v1/auth/providers");
    const j = await res.json();
    gProviders = {
      google: !!(j && j.google),
      github: !!(j && j.github),
      apple: !!(j && j.apple),
    };
  } catch (_) {
    gProviders = { google: false, github: false, apple: false };
  }
  renderAccount();
}

async function loadMe() {
  try {
    const res = await api("GET", "/api/v1/auth/me");
    const j = await res.json();
    gUser = j && j.user ? j.user : null;
  } catch (_) {
    gUser = null;
  }
  renderAccount();
}

async function refreshMyRelay() {
  if (!gUser) {
    clearRelayView();
    return;
  }
  let plan = null;
  let billing = null;
  try {
    const pr = await api("GET", "/api/v1/me/plan");
    plan = await pr.json();
  } catch (_) {
    plan = null;
  }
  try {
    const br = await api("GET", "/api/v1/me/billing");
    billing = await br.json();
  } catch (_) {
    billing = null;
  }
  const res = await api("GET", "/api/v1/me/channel");
  const j = await res.json();

  if ($("status")) $("status").textContent = `open (${j.channel.code})`;
  if ($("expires")) $("expires").textContent = fmtTs(j.channel.expires_at_ms);
  if ($("plan")) $("plan").textContent = plan && plan.plan ? String(plan.plan) : "-";
  if ($("usageToday")) {
    const u = plan && plan.usage_today ? plan.usage_today : null;
    if (u) {
      $("usageToday").textContent = `${fmtBytes(u.upload_bytes || 0)} up, ${fmtBytes(u.download_bytes || 0)} down`;
    } else {
      $("usageToday").textContent = "-";
    }
  }
  if ($("usageMonth")) {
    const u = billing && billing.usage ? billing.usage : null;
    if (u) {
      $("usageMonth").textContent = `${fmtBytes(u.upload_bytes || 0)} up, ${fmtBytes(u.download_bytes || 0)} down`;
    } else {
      $("usageMonth").textContent = "-";
    }
  }
  if ($("billingEst")) {
    $("billingEst").textContent =
      billing && Number.isFinite(billing.estimated_usd) ? fmtUsd(billing.estimated_usd) : "-";
  }
  if ($("billingSub")) {
    const sub = billing && billing.subscription ? billing.subscription : null;
    if (sub) {
      const status = sub.status ? String(sub.status) : "unknown";
      const periodEnd = sub.current_period_end_ms ? fmtTs(sub.current_period_end_ms) : "-";
      $("billingSub").textContent = `${status} (until ${periodEnd})`;
    } else {
      $("billingSub").textContent = "free";
    }
  }
  if ($("billingHint")) {
    const stripeCfg = !!(billing && billing.stripe && billing.stripe.configured);
    const portalCfg = !!(billing && billing.stripe && billing.stripe.portal_configured);
    const sub = billing && billing.subscription ? billing.subscription : null;
    const feats = (plan && plan.features) || (billing && billing.features) || null;
    const turnMsg = feats
      ? feats.turn_accelerate
        ? "TURN acceleration: enabled."
        : "TURN acceleration: requires paid plan."
      : "";
    const canCancel = !!sub && !sub.cancel_at_period_end;
    const canResume = !!sub && !!sub.cancel_at_period_end && String(sub.status || "").toLowerCase() !== "canceled";
    const baseHint = stripeCfg
      ? "Upgrade enables paid plan limits immediately after Stripe webhook confirmation."
      : "Stripe checkout not configured in this environment.";
    const gateHints = [];
    if (feats) {
      if (feats.relay_upload === false) gateHints.push("relay upload: paid");
      if (feats.relay_download === false) gateHints.push("relay download: paid");
      if (feats.relay_e2ee === false) gateHints.push("relay e2ee: paid");
      if (feats.relay_batch_upload === false) gateHints.push("relay batch upload: paid");
      if (feats.auto_discovery === false) gateHints.push("auto-discovery: paid");
      if (feats.offline_mode === false) gateHints.push("offline mode: paid");
    }
    const gateMsg = gateHints.length > 0 ? `Feature gates: ${gateHints.join(", ")}.` : "";
    $("billingHint").textContent = [baseHint, turnMsg, gateMsg].filter((v) => !!v).join(" ");
    const canUpload = !feats || feats.relay_upload !== false;
    const canDownload = !feats || feats.relay_download !== false;
    if ($("upload")) $("upload").disabled = !canUpload;
    if ($("refresh")) $("refresh").disabled = !canDownload;
    if ($("billingCheckout")) $("billingCheckout").disabled = !stripeCfg;
    if ($("billingPortal")) $("billingPortal").disabled = !portalCfg;
    if ($("billingCancel")) $("billingCancel").disabled = !canCancel;
    if ($("billingResume")) $("billingResume").disabled = !canResume;
    if ($("billingReportCsv")) $("billingReportCsv").disabled = false;
  }
  if ($("limits")) {
    const parts = [];
    if (j && j.limits) {
      if (Number.isFinite(j.limits.max_files)) parts.push(`${j.limits.max_files} files`);
      if (Number.isFinite(j.limits.max_file_bytes)) parts.push(`${fmtBytes(j.limits.max_file_bytes)} each`);
      if (Number.isFinite(j.limits.max_total_bytes)) parts.push(`${fmtBytes(j.limits.max_total_bytes)} total`);
      if (Number.isFinite(j.limits.file_ttl_seconds)) {
        const days = Math.round(j.limits.file_ttl_seconds / 86400);
        if (days > 0) parts.push(`stored ${days} day${days === 1 ? "" : "s"}`);
      }
    }
    $("limits").textContent = parts.length > 0 ? parts.join(", ") : "-";
  }
  if ($("uploadHint")) $("uploadHint").textContent = "Upload to your relay (auto-clears after retention)";
  if ($("myCode")) $("myCode").textContent = `code ${j.channel.code}`;
  renderFiles(j.files);
  renderInvoices(billing && billing.recent_invoices ? billing.recent_invoices : []);
  renderRefunds(billing && billing.recent_refunds ? billing.recent_refunds : []);
  renderDisputes(billing && billing.recent_disputes ? billing.recent_disputes : []);
}

async function login() {
  const ident = ($("identifier").value || "").trim();
  const pw = $("password").value || "";
  if (!ident) throw new Error("missing username/email");
  if (!pw) throw new Error("missing password");
  await apiJson("POST", "/api/v1/auth/login", { identifier: ident, password: pw });
  await loadMe();
  await refreshMyRelay();
}

async function register() {
  const ident = ($("identifier").value || "").trim();
  const pw = $("password").value || "";
  if (!ident) throw new Error("missing username");
  if (!pw) throw new Error("missing password");
  await apiJson("POST", "/api/v1/auth/register", { username: ident, password: pw });
  await loadMe();
  await refreshMyRelay();
}

async function logout() {
  setErr("");
  try {
    await api("POST", "/api/v1/auth/logout");
  } catch (_) {}
  gUser = null;
  renderAccount();
  clearRelayView();
}

async function uploadFiles() {
  if (!gUser) throw new Error("sign in first");
  const input = $("files");
  const files = input && input.files ? Array.from(input.files) : [];
  if (files.length === 0) throw new Error("no files selected");

  for (const f of files) {
    const url = `/api/v1/me/files?name=${encodeURIComponent(f.name || "file.bin")}`;
    const res = await api("POST", url, await f.arrayBuffer(), {
      "content-type": f.type || "application/octet-stream",
    });
    await res.arrayBuffer().catch(() => null);
  }

  if (input) input.value = "";
  await refreshMyRelay();
}

async function startBillingCheckout() {
  if (!gUser) throw new Error("sign in first");
  const res = await api("POST", "/api/v1/me/billing/checkout", JSON.stringify({}), {
    "content-type": "application/json",
  });
  const j = await res.json().catch(() => null);
  const checkoutUrl = j && j.checkout_url ? String(j.checkout_url) : "";
  if (!checkoutUrl) throw new Error("checkout URL missing");
  location.href = checkoutUrl;
}

async function openBillingPortal() {
  if (!gUser) throw new Error("sign in first");
  const res = await api("POST", "/api/v1/me/billing/portal", JSON.stringify({}), {
    "content-type": "application/json",
  });
  const j = await res.json().catch(() => null);
  const portalUrl = j && j.portal_url ? String(j.portal_url) : "";
  if (!portalUrl) throw new Error("portal URL missing");
  location.href = portalUrl;
}

async function updateSubscription(action) {
  if (!gUser) throw new Error("sign in first");
  const path = action === "resume" ? "/api/v1/me/billing/subscription/resume" : "/api/v1/me/billing/subscription/cancel";
  await api("POST", path, JSON.stringify({}), {
    "content-type": "application/json",
  });
  await refreshMyRelay();
}

function defaultReportMonth() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

async function exportBillingCsv() {
  if (!gUser) throw new Error("sign in first");
  const month = defaultReportMonth();
  const res = await api("GET", `/api/v1/me/billing/report?month=${encodeURIComponent(month)}&format=csv`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `xsend-billing-${month}.csv`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    a.remove();
  }, 0);
}

function setup() {
  renderAccount();
  clearRelayView();

  if ($("login")) {
    $("login").onclick = async () => {
      setErr("");
      try {
        await login();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("register")) {
    $("register").onclick = async () => {
      setErr("");
      try {
        await register();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("logout")) $("logout").onclick = () => logout();

  if ($("refresh")) {
    $("refresh").onclick = async () => {
      setErr("");
      try {
        await refreshMyRelay();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("upload")) {
    $("upload").onclick = async () => {
      setErr("");
      try {
        await uploadFiles();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("billingCheckout")) {
    $("billingCheckout").onclick = async () => {
      setErr("");
      try {
        await startBillingCheckout();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("billingPortal")) {
    $("billingPortal").onclick = async () => {
      setErr("");
      try {
        await openBillingPortal();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("billingCancel")) {
    $("billingCancel").onclick = async () => {
      setErr("");
      try {
        await updateSubscription("cancel");
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("billingResume")) {
    $("billingResume").onclick = async () => {
      setErr("");
      try {
        await updateSubscription("resume");
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("billingReportCsv")) {
    $("billingReportCsv").onclick = async () => {
      setErr("");
      try {
        await exportBillingCsv();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("oauthGoogle")) {
    $("oauthGoogle").onclick = () => {
      setErr("");
      if (!$("oauthGoogle").disabled) location.href = "/api/v1/auth/oauth/google/start";
    };
  }

  if ($("oauthGitHub")) {
    $("oauthGitHub").onclick = () => {
      setErr("");
      if (!$("oauthGitHub").disabled) location.href = "/api/v1/auth/oauth/github/start";
    };
  }

  if ($("oauthApple")) {
    $("oauthApple").onclick = () => {
      setErr("");
      if (!$("oauthApple").disabled) location.href = "/api/v1/auth/oauth/apple/start";
    };
  }

  Promise.resolve()
    .then(() => loadProviders())
    .then(() => loadMe())
    .then(() => refreshMyRelay())
    .catch((e) => setErr(e.message));
}

setup();
