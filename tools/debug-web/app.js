function $(id) {
  return document.getElementById(id);
}

function setErr(msg) {
  $("err").textContent = msg ? String(msg) : "";
}

function formatBytes(n) {
  if (!Number.isFinite(n)) return "?";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = v >= 10 || i === 0 ? 0 : 1;
  return `${v.toFixed(digits)} ${units[i]}`;
}

function formatUsd(v) {
  if (!Number.isFinite(v)) return "-";
  return `$${Number(v).toFixed(4)}`;
}

async function apiFetch(path, init) {
  const headers = Object.assign({}, (init && init.headers) || {});
  if (init && init.body && !headers["Content-Type"] && typeof init.body === "string") {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, Object.assign({}, init || {}, { headers, credentials: "same-origin" }));
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch (_) { }
    throw new Error(msg);
  }
  return res;
}

function statusClass(s) {
  if (s === "running") return "running";
  if (s === "paused") return "paused";
  if (s === "failed") return "failed";
  if (s === "completed") return "completed";
  if (s === "canceled") return "canceled";
  return "";
}

function pct(done, total) {
  if (!total || total <= 0) return 0;
  return Math.max(0, Math.min(100, (done / total) * 100));
}

function formatTs(ms) {
  if (!ms) return "-";
  try {
    return new Date(ms).toLocaleString();
  } catch (_) {
    return "-";
  }
}

let gRelayBase = null;
let gRelayToken = localStorage.getItem("xsend_relay_token") || "";
let gRelayMe = null;
let gRelayMeLastCheckMs = 0;
let gRelayE2eeLastCheckMs = 0;
let gRelayPlanLastCheckMs = 0;
let gRelayTurnLastCheckMs = 0;
let gRelayFeatures = null;
let gPicker = {
  open: false,
  targetId: null,
  roots: null,
  currentPath: null,
};

function setRelayToken(t) {
  gRelayToken = String(t || "").trim();
  if (gRelayToken) localStorage.setItem("xsend_relay_token", gRelayToken);
  else localStorage.removeItem("xsend_relay_token");
  gRelayE2eeLastCheckMs = 0;
  gRelayPlanLastCheckMs = 0;
  gRelayTurnLastCheckMs = 0;
  gRelayFeatures = null;
}

function setRelayCloudLink() {
  const el = $("relayCloudLink");
  if (!el) return;
  const base = gRelayBase;
  if (!base || base === "-") {
    el.textContent = "-";
    return;
  }
  const url = String(base).replace(/\/+$/, "") + "/";
  el.innerHTML = `<a href="${url}" target="_blank" rel="noreferrer">${url}</a>`;
}

function relaySetStatus(msg) {
  if ($("relayStatus")) $("relayStatus").textContent = msg ? String(msg) : "-";
}

function relaySetPairHint(msg) {
  if ($("relayPairHint")) $("relayPairHint").textContent = msg ? String(msg) : "-";
}

function relayClearPlanBillingTurn() {
  if ($("relayPlan")) $("relayPlan").textContent = "-";
  if ($("relayUsageToday")) $("relayUsageToday").textContent = "-";
  if ($("relayBillingMonth")) $("relayBillingMonth").textContent = "-";
  if ($("relayBillingEstimate")) $("relayBillingEstimate").textContent = "-";
  if ($("relayTurnStatus")) $("relayTurnStatus").textContent = "-";
  applyRelayFeatureGateUI(null);
}

function relayClearE2eeStatus() {
  if ($("relayE2eeChannel")) $("relayE2eeChannel").textContent = "-";
  if ($("relayE2eeHasKey")) $("relayE2eeHasKey").textContent = "-";
  if ($("relayE2eeFp")) $("relayE2eeFp").textContent = "-";
  relaySetPairHint("-");
}

function applyRelayFeatureGateUI(features) {
  const f = features || null;
  const canUpload = !f || f.relay_upload !== false;
  const canDownload = !f || f.relay_download !== false;
  const canE2ee = !f || f.relay_e2ee !== false;
  const canBatch = !f || f.relay_batch_upload !== false;
  const canTurn = !f || f.turn_accelerate !== false;

  if ($("relayUploadPath")) $("relayUploadPath").disabled = !canUpload;
  if ($("relayPullAll")) $("relayPullAll").disabled = !canDownload;
  if ($("relayListRefresh")) $("relayListRefresh").disabled = !canDownload;
  if ($("relayPairStart")) $("relayPairStart").disabled = !canE2ee;
  if ($("relayPairSend")) $("relayPairSend").disabled = !canE2ee;
  if ($("relayPairAccept")) $("relayPairAccept").disabled = !canE2ee;
  if ($("sendTurnAccel")) $("sendTurnAccel").disabled = !canTurn;
  if ($("relayPath")) $("relayPath").placeholder = canBatch ? "/Users/you/Downloads/file.bin" : "paid plan required for folder/batch";
}

function relayPairCodeValue() {
  const el = $("relayPairCode");
  const code = ((el ? el.value : "") || "").replace(/\D+/g, "").slice(0, 6);
  if (el) el.value = code;
  return code;
}

async function relayRefreshE2eeStatus(force) {
  if (!gRelayToken) {
    relayClearE2eeStatus();
    return;
  }
  const now = Date.now();
  if (!force && now - gRelayE2eeLastCheckMs < 15_000) return;
  gRelayE2eeLastCheckMs = now;

  const res = await apiFetch("/api/v1/relay/e2ee/status", {
    method: "GET",
    headers: { "x-relay-token": gRelayToken },
  });
  const view = await res.json();
  if ($("relayE2eeChannel")) $("relayE2eeChannel").textContent = view.channel_code || "-";
  if ($("relayE2eeHasKey")) $("relayE2eeHasKey").textContent = view.has_key ? "present" : "missing";
  if ($("relayE2eeFp")) $("relayE2eeFp").textContent = view.key_fingerprint || "-";
}

async function relayApiFetch(path, init) {
  const base = gRelayBase;
  if (!base) throw new Error("relay base not configured");
  if (!gRelayToken) throw new Error("please sign in first");
  const url = `${String(base).replace(/\/+$/, "")}${path}`;
  const headers = Object.assign({}, (init && init.headers) || {});
  headers["authorization"] = `Bearer ${gRelayToken}`;
  const res = await fetch(url, Object.assign({}, init || {}, { headers }));
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch (_) { }
    if (res.status === 401) {
      setRelayToken("");
      gRelayMe = null;
      relaySetStatus("signed out");
    }
    throw new Error(msg);
  }
  return res;
}

async function relayCheckMe(force) {
  const base = gRelayBase;
  if (!base) return;
  if (!gRelayToken) {
    gRelayMe = null;
    relaySetStatus("signed out");
    relayClearE2eeStatus();
    relayClearPlanBillingTurn();
    return;
  }
  const now = Date.now();
  if (!force && now - gRelayMeLastCheckMs < 30_000) return;
  gRelayMeLastCheckMs = now;
  try {
    const res = await relayApiFetch("/api/v1/auth/me");
    const j = await res.json();
    gRelayMe = j && j.user ? j.user : null;
    if (gRelayMe && gRelayMe.username) relaySetStatus(`signed in as ${gRelayMe.username}`);
    else relaySetStatus("signed in");
  } catch (e) {
    relaySetStatus(`sign in required (${e.message})`);
    relayClearPlanBillingTurn();
  }
}

async function relayRefreshPlanBilling(force) {
  if (!gRelayToken) {
    relayClearPlanBillingTurn();
    return;
  }
  const now = Date.now();
  if (!force && now - gRelayPlanLastCheckMs < 20_000) return;
  gRelayPlanLastCheckMs = now;

  try {
    const planRes = await apiFetch("/api/v1/relay/me/plan", {
      method: "GET",
      headers: { "x-relay-token": gRelayToken },
    });
    const plan = await planRes.json();
    gRelayFeatures = plan && plan.features ? plan.features : null;
    applyRelayFeatureGateUI(gRelayFeatures);
    const limits = (plan && plan.limits) || {};
    const planName = plan && plan.plan ? String(plan.plan) : "-";
    const limitStr = [];
    if (Number.isFinite(limits.max_files)) limitStr.push(`${limits.max_files} files`);
    if (Number.isFinite(limits.max_file_bytes)) limitStr.push(`${formatBytes(limits.max_file_bytes)} each`);
    if (Number.isFinite(limits.max_total_bytes)) limitStr.push(`${formatBytes(limits.max_total_bytes)} total`);
    if ($("relayPlan")) {
      $("relayPlan").textContent = limitStr.length > 0 ? `${planName} (${limitStr.join(", ")})` : planName;
    }
    if ($("relayUsageToday")) {
      const u = plan && plan.usage_today ? plan.usage_today : null;
      if (u) $("relayUsageToday").textContent = `${formatBytes(u.upload_bytes || 0)} up, ${formatBytes(u.download_bytes || 0)} down`;
      else $("relayUsageToday").textContent = "-";
    }
  } catch (_) {
    gRelayFeatures = null;
    applyRelayFeatureGateUI(null);
    if ($("relayPlan")) $("relayPlan").textContent = "-";
    if ($("relayUsageToday")) $("relayUsageToday").textContent = "-";
  }

  try {
    const billRes = await apiFetch("/api/v1/relay/me/billing", {
      method: "GET",
      headers: { "x-relay-token": gRelayToken },
    });
    const bill = await billRes.json();
    if ($("relayBillingMonth")) {
      const u = bill && bill.usage ? bill.usage : null;
      if (u) {
        $("relayBillingMonth").textContent = `${formatBytes(u.upload_bytes || 0)} up, ${formatBytes(u.download_bytes || 0)} down`;
      } else {
        $("relayBillingMonth").textContent = "-";
      }
    }
    if ($("relayBillingEstimate")) {
      const val = bill && Number.isFinite(bill.estimated_usd) ? bill.estimated_usd : 0;
      $("relayBillingEstimate").textContent = formatUsd(val);
    }
  } catch (_) {
    if ($("relayBillingMonth")) $("relayBillingMonth").textContent = "-";
    if ($("relayBillingEstimate")) $("relayBillingEstimate").textContent = "-";
  }
}

async function relayRefreshTurn(force) {
  if (!gRelayToken) {
    if ($("relayTurnStatus")) $("relayTurnStatus").textContent = "-";
    return;
  }
  if (gRelayFeatures && gRelayFeatures.turn_accelerate === false) {
    if ($("relayTurnStatus")) $("relayTurnStatus").textContent = "paid plan required";
    return;
  }
  const now = Date.now();
  if (!force && now - gRelayTurnLastCheckMs < 60_000) return;
  gRelayTurnLastCheckMs = now;
  try {
    const res = await apiFetch("/api/v1/relay/turn/credentials?ttl=600", {
      method: "GET",
      headers: { "x-relay-token": gRelayToken },
    });
    const j = await res.json();
    const servers = j && Array.isArray(j.iceServers) ? j.iceServers.length : 0;
    if ($("relayTurnStatus")) $("relayTurnStatus").textContent = servers > 0 ? `ready (${servers} ICE entries)` : "configured";
  } catch (e) {
    if ($("relayTurnStatus")) $("relayTurnStatus").textContent = `unavailable (${e.message})`;
  }
}

async function relayLogin(kind) {
  const base = gRelayBase;
  if (!base) throw new Error("relay base not configured");
  const ident = ($("relayIdent") ? $("relayIdent").value : "").trim();
  const pw = $("relayPassword") ? $("relayPassword").value : "";
  if (!ident) throw new Error("missing username/email");
  if (!pw) throw new Error("missing password");

  const url = `${String(base).replace(/\/+$/, "")}/api/v1/auth/${kind === "register" ? "register" : "login"}`;
  const payload = kind === "register" ? { username: ident, password: pw } : { identifier: ident, password: pw };
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      if (j && j.error) msg = j.error;
    } catch (_) { }
    throw new Error(msg);
  }
  const j = await res.json();
  if (!j || !j.token) throw new Error("login failed (missing token)");
  setRelayToken(j.token);
  await relayCheckMe(true);
}

async function relayLogout() {
  setRelayToken("");
  gRelayMe = null;
  relaySetStatus("signed out");
  relayClearE2eeStatus();
  relayClearPlanBillingTurn();
}

function showPicker(show) {
  const b = $("pickerBackdrop");
  if (!b) return;
  if (show) b.classList.add("show");
  else b.classList.remove("show");
}

function setPickerPath(p) {
  gPicker.currentPath = p;
  if ($("pickerPath")) $("pickerPath").textContent = p || "-";
}

function renderPickerList(entries) {
  const root = $("pickerList");
  if (!root) return;
  root.textContent = "";

  if (!entries || entries.length === 0) {
    const d = document.createElement("div");
    d.className = "muted";
    d.textContent = "Empty.";
    root.appendChild(d);
    return;
  }

  for (const e of entries) {
    const it = document.createElement("div");
    it.className = "item";

    const left = document.createElement("div");
    left.className = "name";
    left.textContent = e.name || "(unnamed)";

    const right = document.createElement("div");
    right.className = "hint";
    const kind = e.kind === "dir" ? "dir" : "file";
    right.textContent = kind;

    it.appendChild(left);
    it.appendChild(right);

    it.onclick = async () => {
      setErr("");
      try {
        if (e.kind === "dir") {
          await pickerOpenPath(e.path);
          return;
        }
        if (!gPicker.targetId) return;
        const input = $(gPicker.targetId);
        if (input) input.value = e.path;
        pickerClose();
      } catch (err) {
        setErr(err.message);
      }
    };

    root.appendChild(it);
  }
}

async function pickerLoadRoots() {
  if (gPicker.roots) return gPicker.roots;
  const res = await apiFetch("/api/v1/fs/roots");
  const roots = await res.json();
  gPicker.roots = roots || [];
  return gPicker.roots;
}

async function pickerOpenPath(path) {
  setPickerPath(path);
  const res = await apiFetch(`/api/v1/fs/list?path=${encodeURIComponent(path)}`);
  const entries = await res.json();
  renderPickerList(entries);
}

async function pickerOpenRoots() {
  const roots = await pickerLoadRoots();
  const entries = (roots || []).map((r) => ({
    name: r.name,
    path: r.path,
    kind: "dir",
  }));
  setPickerPath("(roots)");
  renderPickerList(entries);
}

function pickerClose() {
  gPicker.open = false;
  gPicker.targetId = null;
  showPicker(false);
}

async function pickerOpen(targetId) {
  gPicker.open = true;
  gPicker.targetId = targetId;
  showPicker(true);
  await pickerOpenRoots();
}

function renderJobs(jobs) {
  const root = $("jobs");
  root.textContent = "";

  if (!jobs || jobs.length === 0) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "No jobs yet.";
    root.appendChild(p);
    return;
  }

  for (const j of jobs) {
    const wrap = document.createElement("div");
    wrap.className = "job";

    const head = document.createElement("div");
    head.className = "head";
    const left = document.createElement("div");
    left.innerHTML = `<div class="id">${j.id}</div>`;
    const st = document.createElement("div");
    st.className = `status ${statusClass(j.status)}`;
    st.textContent = j.status;
    head.appendChild(left);
    head.appendChild(st);

    const path = document.createElement("div");
    path.className = "path";
    path.textContent = j.path;

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${formatBytes(j.bytes_done)} / ${formatBytes(j.bytes_total)} | chunks ${j.chunks_done
      }/${j.total_chunks} | streams ${j.allocated_streams}/${j.desired_streams}`;

    const bar = document.createElement("div");
    bar.className = "bar";
    const fill = document.createElement("div");
    fill.style.width = `${pct(j.bytes_done, j.bytes_total).toFixed(1)}%`;
    bar.appendChild(fill);

    const foot = document.createElement("div");
    foot.className = "foot";

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "8px";
    actions.style.flexWrap = "wrap";

    const btnPause = document.createElement("button");
    btnPause.className = "small";
    btnPause.textContent = "Pause";
    btnPause.onclick = async () => {
      setErr("");
      try {
        await apiFetch(`/api/v1/jobs/${j.id}/pause`, { method: "POST" });
      } catch (e) {
        setErr(e.message);
      }
      await refresh();
    };

    const btnResume = document.createElement("button");
    btnResume.className = "small";
    btnResume.textContent = "Resume";
    btnResume.onclick = async () => {
      setErr("");
      try {
        await apiFetch(`/api/v1/jobs/${j.id}/resume`, { method: "POST" });
      } catch (e) {
        setErr(e.message);
      }
      await refresh();
    };

    const btnCancel = document.createElement("button");
    btnCancel.className = "small danger";
    btnCancel.textContent = "Cancel";
    btnCancel.onclick = async () => {
      setErr("");
      try {
        await apiFetch(`/api/v1/jobs/${j.id}/cancel`, { method: "POST" });
      } catch (e) {
        setErr(e.message);
      }
      await refresh();
    };

    actions.appendChild(btnPause);
    actions.appendChild(btnResume);
    actions.appendChild(btnCancel);

    const extra = document.createElement("div");
    extra.className = "meta";
    if (j.status === "completed" && j.file_hash_blake3_hex) {
      extra.textContent = `file blake3: ${j.file_hash_blake3_hex}`;
    } else if (j.status === "failed" && j.error) {
      extra.textContent = `error: ${j.error}`;
    } else {
      extra.textContent = "";
    }

    foot.appendChild(actions);
    foot.appendChild(extra);

    wrap.appendChild(head);
    wrap.appendChild(path);
    wrap.appendChild(meta);
    wrap.appendChild(bar);
    wrap.appendChild(foot);

    root.appendChild(wrap);
  }
}

function renderTransfers(transfers) {
  const root = $("transfers");
  root.textContent = "";

  if (!transfers || transfers.length === 0) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "No transfers yet.";
    root.appendChild(p);
    return;
  }

  for (const t of transfers) {
    const wrap = document.createElement("div");
    wrap.className = "job";

    const head = document.createElement("div");
    head.className = "head";
    const left = document.createElement("div");
    left.innerHTML = `<div class="id">${t.id}</div>`;
    const st = document.createElement("div");
    st.className = `status ${statusClass(t.status)}`;
    st.textContent = `${t.dir} ${t.status}`;
    head.appendChild(left);
    head.appendChild(st);

    const path = document.createElement("div");
    path.className = "path";
    const title = t.filename ? t.filename : "(unknown file)";
    const remote = t.remote ? ` | ${t.remote}` : "";
    path.textContent = `${title}${remote}`;

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${formatBytes(t.bytes_done)} / ${formatBytes(t.bytes_total)} | chunks ${t.chunks_done
      }/${t.total_chunks}`;

    const bar = document.createElement("div");
    bar.className = "bar";
    const fill = document.createElement("div");
    fill.style.width = `${pct(t.bytes_done, t.bytes_total).toFixed(1)}%`;
    bar.appendChild(fill);

    const foot = document.createElement("div");
    foot.className = "foot";

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "8px";
    actions.style.flexWrap = "wrap";

    const btnCancel = document.createElement("button");
    btnCancel.className = "small danger";
    btnCancel.textContent = "Cancel";
    btnCancel.disabled = !(t.status === "queued" || t.status === "running");
    btnCancel.onclick = async () => {
      setErr("");
      try {
        await apiFetch(`/api/v1/transfers/${t.id}/cancel`, { method: "POST" });
      } catch (e) {
        setErr(e.message);
      }
      await refresh();
    };
    actions.appendChild(btnCancel);

    const extra = document.createElement("div");
    extra.className = "meta";
    if (t.status === "failed" && t.error) {
      extra.textContent = `error: ${t.error}`;
    } else if (t.dir === "receive" && t.status === "completed" && t.save_path) {
      extra.textContent = `saved: ${t.save_path}`;
    } else {
      extra.textContent = "";
    }

    foot.appendChild(actions);
    foot.appendChild(extra);

    wrap.appendChild(head);
    wrap.appendChild(path);
    wrap.appendChild(meta);
    wrap.appendChild(bar);
    wrap.appendChild(foot);

    root.appendChild(wrap);
  }
}

function renderRelayFiles(view) {
  const root = $("relayFilesList");
  if (!root) return;
  root.textContent = "";

  const files = view && Array.isArray(view.files) ? view.files : [];
  if (files.length === 0) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "No files.";
    root.appendChild(p);
    return;
  }

  for (const f of files.slice().sort((a, b) => (b.uploaded_at_ms || 0) - (a.uploaded_at_ms || 0))) {
    const wrap = document.createElement("div");
    wrap.className = "job";

    const head = document.createElement("div");
    head.className = "head";
    const left = document.createElement("div");
    left.innerHTML = `<div class="id">${f.id}</div>`;
    const st = document.createElement("div");
    st.className = "status completed";
    st.textContent = "cloud";
    head.appendChild(left);
    head.appendChild(st);

    const path = document.createElement("div");
    path.className = "path";
    path.textContent = f.filename || "(unnamed)";

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${formatBytes(f.size_bytes)} | ${formatTs(f.uploaded_at_ms)}`;

    const foot = document.createElement("div");
    foot.className = "foot";

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "8px";
    actions.style.flexWrap = "wrap";

    const btnPull = document.createElement("button");
    btnPull.className = "small primary";
    btnPull.textContent = "Pull to this computer";
    btnPull.onclick = async () => {
      setErr("");
      if (!gRelayToken) return setErr("sign in first");
      try {
        relaySetStatus("downloading...");
        const res = await apiFetch("/api/v1/relay/me/pull", {
          method: "POST",
          headers: { "x-relay-token": gRelayToken },
          body: JSON.stringify({ id: f.id }),
        });
        const out = await res.json();
        relaySetStatus(`saved: ${out.save_path}`);
        await relayRefreshPlanBilling(true);
      } catch (e) {
        relaySetStatus("-");
        setErr(e.message);
      }
    };
    actions.appendChild(btnPull);

    const extra = document.createElement("div");
    extra.className = "meta";
    extra.textContent = "";

    foot.appendChild(actions);
    foot.appendChild(extra);

    wrap.appendChild(head);
    wrap.appendChild(path);
    wrap.appendChild(meta);
    wrap.appendChild(foot);

    root.appendChild(wrap);
  }
}

async function relayRefreshList() {
  if (!gRelayToken) throw new Error("sign in first");
  const res = await apiFetch("/api/v1/relay/me/channel", {
    method: "GET",
    headers: { "x-relay-token": gRelayToken },
  });
  const view = await res.json();
  renderRelayFiles(view);
}

function fmtPeers(peers) {
  if (!peers || peers.length === 0) return "-";
  // show LAN/WAN endpoints seen from discovery.
  return peers
    .slice()
    .sort((a, b) => (b.last_seen_ms || 0) - (a.last_seen_ms || 0))
    .map((p) => {
      const lan = p.lan_endpoint || p.endpoint || "-";
      const wan = p.wan_endpoint || null;
      return wan ? `lan ${lan} | wan ${wan}` : `lan ${lan}`;
    })
    .join(", ");
}

async function refresh() {
  try {
    const infoRes = await apiFetch("/api/v1/info");
    const info = await infoRes.json();
    $("version").textContent = `v${info.version}`;
    if ($("daemonId")) $("daemonId").textContent = info.daemon_id;
    if ($("lanPort")) $("lanPort").textContent = String(info.lan_port);
    if ($("lanEndpoints")) $("lanEndpoints").textContent = (info.lan_endpoints || []).join(", ");
    if ($("wanPort")) $("wanPort").textContent = String(info.wan_port || 0);
    if ($("wanEndpoints")) $("wanEndpoints").textContent = (info.wan_endpoints || []).join(", ");
    gRelayBase = info.relay_base_url || null;
    if ($("relayBase")) $("relayBase").textContent = gRelayBase || "-";
    setRelayCloudLink();
    // Don't hammer the relay; relayCheckMe() throttles internally.
    relayCheckMe(false).catch(() => { });
    relayRefreshE2eeStatus(false).catch(() => { });
    relayRefreshPlanBilling(false).catch(() => { });
    relayRefreshTurn(false).catch(() => { });
    $("runningJobs").textContent = String(info.stats.running_jobs);
    $("queuedJobs").textContent = String(info.stats.queued_jobs);
    $("runningStreams").textContent = String(info.stats.running_streams);
    $("limits").textContent = `${info.stats.running_streams}/${info.stats.global_stream_limit} streams, ${info.stats.running_jobs}/${info.stats.max_running_jobs} jobs`;

    const sessRes = await apiFetch("/api/v1/sessions");
    const sessions = await sessRes.json();
    const pending = (sessions || [])
      .slice()
      .sort((a, b) => (b.created_at_ms || 0) - (a.created_at_ms || 0))
      .find((s) => s.status === "pending");
    if (pending) {
      $("receiveCode").textContent = pending.code;
      $("receiveExpires").textContent = formatTs(pending.expires_at_ms);
    }

    const tRes = await apiFetch("/api/v1/transfers");
    const transfers = await tRes.json();
    renderTransfers(transfers);

    if ($("peersList")) {
      try {
        const pRes = await apiFetch("/api/v1/peers");
        const peers = await pRes.json();
        $("peersList").textContent = fmtPeers(peers);
      } catch (_) {
        $("peersList").textContent = "-";
      }
    }

    const jobsRes = await apiFetch("/api/v1/jobs");
    const jobs = await jobsRes.json();
    renderJobs(jobs);
  } catch (e) {
    setErr(e.message);
  }
}

function setup() {
  $("create").onclick = async () => {
    setErr("");
    const path = $("path").value.trim();
    const network = $("network").value;
    if (!path) {
      setErr("missing file path");
      return;
    }
    try {
      await apiFetch("/api/v1/jobs", {
        method: "POST",
        body: JSON.stringify({ path, network }),
      });
      $("path").value = "";
      await refresh();
    } catch (e) {
      setErr(e.message);
    }
  };

  $("createReceive").onclick = async () => {
    setErr("");
    try {
      const res = await apiFetch("/api/v1/sessions/receive", { method: "POST" });
      const s = await res.json();
      $("receiveCode").textContent = s.code;
      $("receiveExpires").textContent = formatTs(s.expires_at_ms);
      $("sendCode").value = s.code;
    } catch (e) {
      setErr(e.message);
    }
  };

  if ($("openReceive")) {
    $("openReceive").onclick = async () => {
      setErr("");
      const code = ($("receiveCodeInput").value || "").trim();
      if (!/^[0-9]{6}$/.test(code)) return setErr("invalid code (expected 6 digits)");
      try {
        const res = await apiFetch(`/api/v1/sessions/receive/${code}`, { method: "POST" });
        const s = await res.json();
        $("receiveCode").textContent = s.code;
        $("receiveExpires").textContent = formatTs(s.expires_at_ms);
        $("sendCode").value = s.code;
      } catch (e) {
        setErr(e.message);
      }
      await refresh();
    };
  }

  $("sendBtn").onclick = async () => {
    setErr("");
    const addr = $("sendAddr").value.trim();
    const code = $("sendCode").value.trim();
    const path = $("sendPath").value.trim();
    if (!addr) return setErr("missing receiver addr");
    if (!code) return setErr("missing code");
    if (!path) return setErr("missing file path");
    try {
      await apiFetch("/api/v1/transfers/send", {
        method: "POST",
        body: JSON.stringify({ addr, code, path }),
      });
      $("sendPath").value = "";
      await refresh();
    } catch (e) {
      setErr(e.message);
    }
  };

  if ($("sendWanBtn")) {
    $("sendWanBtn").onclick = async () => {
      setErr("");
      const addr = $("sendAddr").value.trim();
      const code = $("sendCode").value.trim();
      const path = $("sendPath").value.trim();
      if (!addr) return setErr("missing receiver addr");
      if (!code) return setErr("missing code");
      if (!path) return setErr("missing file path");
      try {
        await apiFetch("/api/v1/transfers/send_wan", {
          method: "POST",
          body: JSON.stringify({ addr, code, path }),
        });
        $("sendPath").value = "";
        await refresh();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("sendAutoBtn")) {
    $("sendAutoBtn").onclick = async () => {
      setErr("");
      const code = $("sendCode").value.trim();
      const path = $("sendPath").value.trim();
      if (!code) return setErr("missing code");
      if (!path) return setErr("missing file path");
      try {
        const headers = {};
        if (gRelayToken) headers["x-relay-token"] = gRelayToken;
        if ($("sendAutoRelayOnFail")) {
          headers["x-relay-auto-on-fail"] = $("sendAutoRelayOnFail").checked ? "1" : "0";
        }
        if ($("sendTurnAccel") && $("sendTurnAccel").checked) {
          headers["x-turn-accelerate"] = "1";
        }
        const res = await apiFetch("/api/v1/transfers/send_by_code", {
          method: "POST",
          headers,
          body: JSON.stringify({ code, path }),
        });
        await res.json().catch(() => null);
        $("sendPath").value = "";
        await refresh();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("sendBrowse")) {
    $("sendBrowse").onclick = async () => {
      setErr("");
      try {
        await pickerOpen("sendPath");
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("pathBrowse")) {
    $("pathBrowse").onclick = async () => {
      setErr("");
      try {
        await pickerOpen("path");
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("pickerClose")) $("pickerClose").onclick = () => pickerClose();
  if ($("pickerBackdrop")) {
    $("pickerBackdrop").onclick = (e) => {
      if (e.target && e.target.id === "pickerBackdrop") pickerClose();
    };
  }

  if ($("pickerHome")) $("pickerHome").onclick = async () => pickerOpenRoots().catch((e) => setErr(e.message));
  if ($("pickerUp")) {
    $("pickerUp").onclick = async () => {
      const p = gPicker.currentPath;
      if (!p || p === "(roots)") return;
      const idx = p.replace(/\/+$/, "").lastIndexOf("/");
      if (idx <= 0) return pickerOpenRoots();
      const parent = p.slice(0, idx);
      await pickerOpenPath(parent);
    };
  }

  if ($("relayLogin")) {
    $("relayLogin").onclick = async () => {
      setErr("");
      const btn = $("relayLogin");
      const prev = btn ? btn.textContent : "Sign in";
      try {
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Signing in...";
        }
        await relayLogin("login");
        await relayRefreshPlanBilling(true);
        await relayRefreshTurn(true);
        await relayRefreshList();
      } catch (e) {
        setErr(e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = prev;
        }
      }
    };
  }

  if ($("relayRegister")) {
    $("relayRegister").onclick = async () => {
      setErr("");
      const btn = $("relayRegister");
      const prev = btn ? btn.textContent : "Create account";
      try {
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Creating...";
        }
        await relayLogin("register");
        await relayRefreshPlanBilling(true);
        await relayRefreshTurn(true);
        await relayRefreshList();
      } catch (e) {
        setErr(e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = prev;
        }
      }
    };
  }

  if ($("relayLogout")) {
    $("relayLogout").onclick = async () => {
      setErr("");
      try {
        await relayLogout();
        renderRelayFiles({ files: [] });
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("relayPathBrowse")) {
    $("relayPathBrowse").onclick = async () => {
      setErr("");
      try {
        await pickerOpen("relayPath");
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("relayUploadPath")) {
    $("relayUploadPath").onclick = async () => {
      setErr("");
      const path = ($("relayPath") ? $("relayPath").value : "").trim();
      if (!path) return setErr("missing local file path");
      if (!gRelayToken) return setErr("sign in first");

      const btn = $("relayUploadPath");
      const prev = btn ? btn.textContent : "Upload to cloud";
      try {
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Uploading...";
        }

        relaySetStatus("uploading...");
        const res = await apiFetch("/api/v1/relay/me/upload", {
          method: "POST",
          headers: { "x-relay-token": gRelayToken },
          body: JSON.stringify({ path, recursive: true }),
        });
        const out = await res.json();
        if (out && out.mode === "dir") {
          const s = out.summary || {};
          relaySetStatus(
            `folder uploaded: ${Number(s.uploaded || 0)} success, ${Number(s.failed || 0)} failed${s.stopped_on_limit ? " (stopped by quota)" : ""
            }`,
          );
          if (Array.isArray(out.results)) {
            const firstErr = out.results.find((r) => r && r.error);
            if (firstErr && firstErr.error) {
              setErr(`partial failure: ${firstErr.path || ""} -> ${firstErr.error}`);
            }
          }
        } else {
          relaySetStatus(`uploaded ${out.file ? out.file.filename : "file"}`);
        }
        if ($("relayPath")) $("relayPath").value = "";
        await relayRefreshPlanBilling(true);
        await relayRefreshList();
      } catch (e) {
        relaySetStatus("-");
        setErr(e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = prev;
        }
      }
    };
  }

  if ($("relayListRefresh")) {
    $("relayListRefresh").onclick = async () => {
      setErr("");
      try {
        await relayRefreshList();
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("relayPullAll")) {
    $("relayPullAll").onclick = async () => {
      setErr("");
      if (!gRelayToken) return setErr("sign in first");
      const btn = $("relayPullAll");
      const prev = btn ? btn.textContent : "Pull all";
      try {
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Pulling...";
        }
        relaySetStatus("downloading all...");
        const res = await apiFetch("/api/v1/relay/me/pull_all", {
          method: "POST",
          headers: { "x-relay-token": gRelayToken },
          body: JSON.stringify({}),
        });
        const out = await res.json();
        relaySetStatus(
          `pull all done: ${Number(out.downloaded || 0)} downloaded, ${Number(out.failed || 0)} failed (dir: ${out.save_dir || "-"
          })`,
        );
        if (Array.isArray(out.items)) {
          const firstErr = out.items.find((it) => it && it.error);
          if (firstErr && firstErr.error) {
            setErr(`pull partial failure: ${firstErr.id || ""} -> ${firstErr.error}`);
          }
        }
        await relayRefreshPlanBilling(true);
      } catch (e) {
        relaySetStatus("-");
        setErr(e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = prev;
        }
      }
    };
  }

  if ($("relayTurnCheck")) {
    $("relayTurnCheck").onclick = async () => {
      setErr("");
      try {
        await relayRefreshTurn(true);
      } catch (e) {
        setErr(e.message);
      }
    };
  }

  if ($("relayPairCode")) {
    $("relayPairCode").addEventListener("input", () => {
      relayPairCodeValue();
    });
  }

  if ($("relayPairStart")) {
    $("relayPairStart").onclick = async () => {
      setErr("");
      if (!gRelayToken) return setErr("sign in first");
      const btn = $("relayPairStart");
      const prev = btn ? btn.textContent : "Start pair";
      try {
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Starting...";
        }
        const res = await apiFetch("/api/v1/relay/e2ee/pair/start", {
          method: "POST",
          headers: { "x-relay-token": gRelayToken },
        });
        const j = await res.json();
        if ($("relayPairCode")) $("relayPairCode").value = j.pair_code || "";
        relaySetPairHint(
          `pair code ${j.pair_code || "-"} (expires ${formatTs(j.expires_at_ms)})`,
        );
        await relayRefreshE2eeStatus(true);
      } catch (e) {
        setErr(e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = prev;
        }
      }
    };
  }

  if ($("relayPairSend")) {
    $("relayPairSend").onclick = async () => {
      setErr("");
      if (!gRelayToken) return setErr("sign in first");
      const code = relayPairCodeValue();
      if (!/^[0-9]{6}$/.test(code)) return setErr("invalid pair code (expected 6 digits)");
      const btn = $("relayPairSend");
      const prev = btn ? btn.textContent : "Send key";
      try {
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Sending...";
        }
        await apiFetch(`/api/v1/relay/e2ee/pair/${encodeURIComponent(code)}/send`, {
          method: "POST",
          headers: { "x-relay-token": gRelayToken },
        });
        relaySetPairHint(`key sent for pair code ${code}, receiver can now accept`);
        await relayRefreshE2eeStatus(true);
      } catch (e) {
        setErr(e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = prev;
        }
      }
    };
  }

  if ($("relayPairAccept")) {
    $("relayPairAccept").onclick = async () => {
      setErr("");
      if (!gRelayToken) return setErr("sign in first");
      const code = relayPairCodeValue();
      if (!/^[0-9]{6}$/.test(code)) return setErr("invalid pair code (expected 6 digits)");
      const btn = $("relayPairAccept");
      const prev = btn ? btn.textContent : "Accept key";
      try {
        if (btn) {
          btn.disabled = true;
          btn.textContent = "Accepting...";
        }
        const res = await apiFetch(`/api/v1/relay/e2ee/pair/${encodeURIComponent(code)}/accept`, {
          method: "POST",
          headers: { "x-relay-token": gRelayToken },
        });
        const j = await res.json();
        relaySetPairHint(`key imported (fingerprint ${j.key_fingerprint || "-"})`);
        await relayRefreshE2eeStatus(true);
      } catch (e) {
        setErr(e.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = prev;
        }
      }
    };
  }

  refresh();
  setInterval(refresh, 1000);
}

setup();
