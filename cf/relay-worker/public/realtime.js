(function () {
  "use strict";

  const CHUNK_BYTES = 64 * 1024;
  const SEND_BUFFER_LIMIT = CHUNK_BYTES * 8;
  const AUTO_RECONNECT_MS = 2000;
  const AUTO_REDIAL_MS = 700;
  const OFFLINE_ICE_GATHER_MS = 900;
  const WASM_INIT_TIMEOUT_MS = 5000;
  const PAKO_INIT_TIMEOUT_MS = 5000;
  const GZIP_TIMEOUT_MS = 500;
  const RTC_STEP_TIMEOUT_MS = 3000;
  const OFFLINE_PREWARM_DELAY_MS = 300;
  const CODE_PREFIX_V3 = "XSO3.";
  const CODE_PREFIX_V2 = "XSO2.";
  const CODE_PREFIX_LEGACY = "XSO1.";
  const CODE_SHARD_CHAR_LIMIT = 900;
  const CODE_SHARD_MAX_PARTS = 24;
  const AUTO_CONNECT_WAIT_MS = 7000;
  const AUTO_CONNECT_WAIT_TURN_MS = 9000;

  function $(id) {
    return document.getElementById(id);
  }

  function nowTs() {
    return new Date().toLocaleTimeString();
  }

  function setText(id, text) {
    const el = $(id);
    if (!el) return;
    el.textContent = text == null ? "" : String(text);
  }

  function setVal(id, text) {
    const el = $(id);
    if (!el) return;
    el.value = text == null ? "" : String(text);
  }

  function getVal(id) {
    const el = $(id);
    if (!el) return "";
    return typeof el.value === "string" ? el.value : "";
  }

  function safeStorageGet(key, fallback) {
    try {
      const v = localStorage.getItem(key);
      return v == null || v === "" ? fallback : v;
    } catch (_) {
      return fallback;
    }
  }

  function safeStorageSet(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (_) {
      // ignore
    }
  }

  function randomHex(bytesLen) {
    const bytes = new Uint8Array(bytesLen);
    crypto.getRandomValues(bytes);
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out;
  }

  function randomPeerId() {
    if (typeof crypto.randomUUID === "function") {
      return crypto.randomUUID().replace(/-/g, "").slice(0, 20);
    }
    return randomHex(10);
  }

  function randomTransferId() {
    return randomHex(8);
  }

  function defaultDeviceName() {
    const platform = (navigator.platform || "device").split(" ")[0] || "device";
    return `${platform}-${randomHex(2)}`;
  }

  function fmtBytes(n) {
    const num = Number(n);
    if (!Number.isFinite(num)) return "?";
    const units = ["B", "KiB", "MiB", "GiB"];
    let v = num;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    const digits = v >= 10 || i === 0 ? 0 : 1;
    return `${v.toFixed(digits)} ${units[i]}`;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function withTimeout(promise, ms, label) {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(label || `timeout ${ms}ms`)), ms);
      Promise.resolve(promise).then(
        (v) => {
          clearTimeout(t);
          resolve(v);
        },
        (e) => {
          clearTimeout(t);
          reject(e);
        },
      );
    });
  }

  function loadScript(src, timeoutMs, readyCheck) {
    const isReady = () => {
      if (typeof readyCheck === "function") {
        try {
          return !!readyCheck();
        } catch (_) {
          return false;
        }
      }
      return false;
    };

    if (isReady()) {
      return Promise.resolve(true);
    }

    return withTimeout(
      new Promise((resolve, reject) => {
        const exist = document.querySelector(`script[src="${src}"]`);
        if (exist && (exist.dataset.loaded === "1" || isReady())) {
          resolve(true);
          return;
        }

        let poll = null;
        const cleanup = () => {
          if (poll) {
            clearInterval(poll);
            poll = null;
          }
        };

        const finishOk = () => {
          cleanup();
          resolve(true);
        };
        const finishErr = (e) => {
          cleanup();
          reject(e);
        };

        const s = exist || document.createElement("script");
        if (!exist) {
          s.src = src;
          s.async = true;
          s.dataset.loaded = "0";
          document.head.appendChild(s);
        }
        s.onload = () => {
          s.dataset.loaded = "1";
          finishOk();
        };
        s.onerror = () => finishErr(new Error(`failed to load script: ${src}`));

        if (typeof readyCheck === "function") {
          poll = setInterval(() => {
            if (isReady()) {
              finishOk();
            }
          }, 80);
        }
      }),
      timeoutMs,
      `script load timeout: ${src}`,
    );
  }

  function getFastQrBindgen() {
    if (typeof window.wasm_bindgen === "function") {
      return window.wasm_bindgen;
    }
    try {
      if (typeof wasm_bindgen === "function") {
        return wasm_bindgen;
      }
    } catch (_) {
      // ignore lexical lookup errors
    }
    return null;
  }

  async function ensurePako() {
    if (state.codec.pako) return state.codec.pako;
    if (state.codec.pakoLoading) return state.codec.pakoLoading;
    state.codec.pakoLoading = (async () => {
      if (!window.pako) {
        await loadScript("/vendor/pako/pako.min.js", PAKO_INIT_TIMEOUT_MS, () => !!window.pako);
      }
      if (!window.pako) {
        throw new Error("pako codec unavailable");
      }
      state.codec.pako = window.pako;
      return state.codec.pako;
    })().catch((err) => {
      state.codec.pakoLoading = null;
      throw err;
    });
    return state.codec.pakoLoading;
  }

  function bytesToBase64Url(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 1) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlToBytes(raw) {
    const b64 = String(raw || "")
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function splitCodeShards(singleCode) {
    const text = String(singleCode || "").trim();
    if (!text) return [];
    if (text.length <= CODE_SHARD_CHAR_LIMIT) return [text];

    const payloadPerPart = Math.max(64, CODE_SHARD_CHAR_LIMIT - 16);
    const total = Math.ceil(text.length / payloadPerPart);
    if (total > CODE_SHARD_MAX_PARTS) {
      throw new Error(`offline code too long (${text.length} chars, ${total} parts); use copy/paste`);
    }

    const out = [];
    for (let i = 0; i < total; i += 1) {
      const start = i * payloadPerPart;
      const end = Math.min(text.length, start + payloadPerPart);
      const chunk = text.slice(start, end);
      out.push(`${CODE_PREFIX_V3}${i + 1}/${total}.${chunk}`);
    }
    return out;
  }

  function parseCodeShard(line) {
    const raw = String(line || "").trim();
    const m = raw.match(/^XSO3\.(\d+)\/(\d+)\.(.+)$/);
    if (!m) return null;
    const idx = Number.parseInt(m[1], 10);
    const total = Number.parseInt(m[2], 10);
    if (!Number.isFinite(idx) || !Number.isFinite(total) || idx < 1 || total < 1 || idx > total) {
      return null;
    }
    return { idx, total, chunk: m[3] };
  }

  function normalizeShardText(text) {
    return String(text || "")
      .split(/\r?\n/g)
      .map((v) => v.trim())
      .filter((v) => v.length > 0);
  }

  function mergeScannedCode(existingText, scannedRaw) {
    const scanned = String(scannedRaw || "").trim();
    if (!scanned) {
      return { text: String(existingText || ""), shard: false, complete: false, done: 0, total: 0 };
    }

    const scannedPart = parseCodeShard(scanned);
    if (!scannedPart) {
      return { text: scanned, shard: false, complete: true, done: 1, total: 1 };
    }

    const seen = new Map();
    for (const line of normalizeShardText(existingText)) {
      const part = parseCodeShard(line);
      if (!part) continue;
      if (part.total !== scannedPart.total) continue;
      if (!seen.has(part.idx)) seen.set(part.idx, part.chunk);
    }
    seen.set(scannedPart.idx, scannedPart.chunk);

    const total = scannedPart.total;
    const lines = [];
    for (let i = 1; i <= total; i += 1) {
      const chunk = seen.get(i);
      if (!chunk) continue;
      lines.push(`${CODE_PREFIX_V3}${i}/${total}.${chunk}`);
    }
    return {
      text: lines.join("\n"),
      shard: true,
      complete: seen.size >= total,
      done: seen.size,
      total,
    };
  }

  function joinCodeShards(rawText) {
    const lines = normalizeShardText(rawText);
    if (lines.length === 0) {
      throw new Error("empty code");
    }
    if (lines.length === 1 && !lines[0].startsWith(CODE_PREFIX_V3)) {
      return lines[0];
    }

    const parts = [];
    for (const line of lines) {
      const p = parseCodeShard(line);
      if (!p) {
        throw new Error("mixed shard/non-shard code; keep only XSO3 parts");
      }
      parts.push(p);
    }
    if (parts.length === 0) {
      throw new Error("invalid shard code");
    }

    const total = parts[0].total;
    if (total > CODE_SHARD_MAX_PARTS) {
      throw new Error(`too many shards (${total})`);
    }
    for (const p of parts) {
      if (p.total !== total) {
        throw new Error("shard total mismatch");
      }
    }

    const byIdx = new Map();
    for (const p of parts) {
      byIdx.set(p.idx, p.chunk);
    }
    if (byIdx.size < total) {
      throw new Error(`incomplete shards (${byIdx.size}/${total})`);
    }

    let merged = "";
    for (let i = 1; i <= total; i += 1) {
      const chunk = byIdx.get(i);
      if (!chunk) throw new Error(`missing shard ${i}/${total}`);
      merged += chunk;
    }
    return merged;
  }

  function extractSdpFingerprint(sdp) {
    const text = typeof sdp === "string" ? sdp : "";
    if (!text) return null;
    const m = text.match(/^a=fingerprint:[^\s]+\s+([0-9a-fA-F:]+)\s*$/m);
    if (!m) return null;
    const raw = m[1].toUpperCase().replace(/[^0-9A-F]/g, "");
    if (raw.length < 16) return null;
    const grouped = [];
    for (let i = 0; i < raw.length; i += 2) {
      grouped.push(raw.slice(i, i + 2));
    }
    return grouped.join(":");
  }

  function shortFingerprint(fp) {
    const v = String(fp || "").trim();
    if (!v) return "-";
    const parts = v.split(":");
    if (parts.length <= 8) return v;
    return `${parts.slice(0, 8).join(":")}...`;
  }

  async function gzipBytes(input) {
    if (typeof CompressionStream === "function") {
      try {
        const cs = new CompressionStream("gzip");
        const writer = cs.writable.getWriter();
        await writer.write(input);
        await writer.close();
        const ab = await new Response(cs.readable).arrayBuffer();
        return new Uint8Array(ab);
      } catch (_) {
        // fall through to pako
      }
    }
    try {
      const pako = await ensurePako();
      const out = pako.gzip(input);
      return out instanceof Uint8Array ? out : new Uint8Array(out);
    } catch (_) {
      return null;
    }
  }

  async function gunzipBytes(input) {
    if (typeof DecompressionStream === "function") {
      try {
        const ds = new DecompressionStream("gzip");
        const writer = ds.writable.getWriter();
        await writer.write(input);
        await writer.close();
        const ab = await new Response(ds.readable).arrayBuffer();
        return new Uint8Array(ab);
      } catch (_) {
        // fall through to pako
      }
    }
    const pako = await ensurePako();
    const out = pako.ungzip(input);
    return out instanceof Uint8Array ? out : new Uint8Array(out);
  }

  async function encodeSdpCode(desc) {
    if (!desc || typeof desc.type !== "string" || typeof desc.sdp !== "string") {
      throw new Error("invalid description");
    }
    const payload = JSON.stringify({ v: 2, t: desc.type, sdp: desc.sdp });
    const rawBytes = new TextEncoder().encode(payload);
    const gzBytes = await withTimeout(gzipBytes(rawBytes), GZIP_TIMEOUT_MS, "gzip timeout").catch(() => null);
    const useGzip = !!(gzBytes && gzBytes.length > 0 && gzBytes.length < rawBytes.length);
    const codec = useGzip ? "g" : "r";
    const body = useGzip ? gzBytes : rawBytes;
    const single = `${CODE_PREFIX_V2}${codec}.${bytesToBase64Url(body)}`;
    const shards = splitCodeShards(single);
    return shards.join("\n");
  }

  async function decodeSdpCode(code, expectedType) {
    const raw = joinCodeShards(code);
    let obj = null;

    if (raw.startsWith(CODE_PREFIX_V2)) {
      const body = raw.slice(CODE_PREFIX_V2.length);
      const split = body.indexOf(".");
      if (split <= 0) {
        throw new Error("invalid code payload");
      }
      const codec = body.slice(0, split);
      const data = body.slice(split + 1);
      let bytes = base64UrlToBytes(data);
      if (codec === "g") {
        bytes = await gunzipBytes(bytes);
      } else if (codec !== "r") {
        throw new Error("unknown code codec");
      }
      try {
        obj = JSON.parse(new TextDecoder().decode(bytes));
      } catch (_) {
        throw new Error("invalid code payload");
      }
    } else if (raw.startsWith(CODE_PREFIX_LEGACY)) {
      const body = raw.slice(CODE_PREFIX_LEGACY.length);
      try {
        obj = JSON.parse(new TextDecoder().decode(base64UrlToBytes(body)));
      } catch (_) {
        throw new Error("invalid code payload");
      }
    } else {
      throw new Error(`invalid code prefix; expected ${CODE_PREFIX_V3}/${CODE_PREFIX_V2} or ${CODE_PREFIX_LEGACY}`);
    }

    if (!obj || typeof obj.t !== "string" || typeof obj.sdp !== "string") {
      throw new Error("invalid code structure");
    }
    if (expectedType && obj.t !== expectedType) {
      throw new Error(`expected ${expectedType} code, got ${obj.t}`);
    }
    return { type: obj.t, sdp: obj.sdp };
  }

  function compactOfflineSdp(desc) {
    if (!desc || typeof desc.type !== "string" || typeof desc.sdp !== "string") {
      return desc;
    }
    const lines = desc.sdp.replace(/\r\n/g, "\n").split("\n");
    const out = [];
    let hostCandidates = 0;

    for (const line of lines) {
      if (!line) continue;
      if (line.startsWith("a=end-of-candidates")) continue;
      if (line.startsWith("a=ice-options:trickle")) continue;
      if (line.startsWith("a=candidate:")) {
        if (line.indexOf(" typ host ") >= 0) {
          out.push(line);
          hostCandidates += 1;
        }
        continue;
      }
      out.push(line);
    }

    if (hostCandidates === 0) {
      return desc;
    }

    let sdp = out.join("\r\n");
    if (!sdp.endsWith("\r\n")) {
      sdp += "\r\n";
    }
    return { type: desc.type, sdp };
  }

  const state = {
    mode: "auto",
    peerId: safeStorageGet("xsend.rt.peer_id", randomPeerId()),
    peerName: safeStorageGet("xsend.rt.peer_name", defaultDeviceName()),
    scope: safeStorageGet("xsend.rt.scope", ""),
    features: null,

    auto: {
      running: false,
      ws: null,
      reconnectTimer: null,
      redialTimers: new Map(),
      peers: new Map(),
      sessions: new Map(),
      selfId: null,
      selectedPeerId: null,
      iceServers: null,
    },

    offline: {
      pc: null,
      dc: null,
      role: null,
      incoming: null,
      sending: false,
      fpLocal: null,
      fpRemote: null,
      fpConfirmed: false,
    },

    scan: {
      active: false,
      stream: null,
      rafId: null,
      targetId: null,
      detector: null,
    },

    qr: {
      mod: null,
      loading: null,
    },
    codec: {
      pako: null,
      pakoLoading: null,
    },
  };

  function setRtErr(msg) {
    setText("rtErr", msg ? String(msg) : "");
  }

  function setRtStatus(msg) {
    setText("rtStatus", msg ? `${msg} @ ${nowTs()}` : "idle");
  }

  function setTransferStatus(msg) {
    setText("rtTransferStatus", msg || "no transfer");
  }

  function setModeBadge() {
    setText("rtModeBadge", state.mode === "auto" ? "Auto-Discovery" : "Offline Mode");
  }

  function setModeButtons() {
    const autoBtn = $("rtModeAuto");
    const offBtn = $("rtModeOffline");
    if (autoBtn) autoBtn.className = state.mode === "auto" ? "primary" : "";
    if (offBtn) offBtn.className = state.mode === "offline" ? "primary" : "";
    if (autoBtn) autoBtn.disabled = false;
    if (offBtn) offBtn.disabled = false;
    const feats = state.features || null;
    if (autoBtn && feats && feats.auto_discovery === false) {
      autoBtn.disabled = true;
    }
    if (offBtn && feats && feats.offline_mode === false) {
      offBtn.disabled = true;
    }
  }

  async function refreshFeatureGates() {
    try {
      const res = await fetch("/api/v1/me/plan", { method: "GET", credentials: "same-origin" });
      if (!res.ok) {
        state.features = null;
        return;
      }
      const j = await res.json().catch(() => null);
      state.features = j && j.features ? j.features : null;
    } catch (_) {
      state.features = null;
    }
    setModeButtons();
    const feats = state.features || null;
    if (feats && feats.auto_discovery === false && state.mode === "auto") {
      switchMode("offline");
      setRtErr("auto discovery requires paid plan");
    }
  }

  function setSelectedPeer(peerId) {
    state.auto.selectedPeerId = peerId || null;
    setText("rtSelectedPeer", state.auto.selectedPeerId || "-");
    renderPeers();
  }

  function addReceivedFile(entry) {
    const root = $("rtReceivedList");
    if (!root) return;

    const card = document.createElement("div");
    card.className = "file";

    const top = document.createElement("div");
    top.className = "topline";

    const name = document.createElement("div");
    name.className = "name";
    const a = document.createElement("a");
    a.href = entry.url;
    a.download = entry.name;
    a.textContent = entry.name;
    name.appendChild(a);

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${fmtBytes(entry.size)} | from ${entry.from} | ${entry.mode} | ${nowTs()}`;

    top.appendChild(name);
    top.appendChild(meta);
    card.appendChild(top);
    root.prepend(card);
  }

  function clearQrBox(id, hint) {
    const box = $(id);
    if (!box) return;
    box.textContent = "";
    if (hint) {
      const span = document.createElement("span");
      span.className = "mini";
      span.textContent = hint;
      box.appendChild(span);
    }
  }

  async function loadFastQrWasm() {
    if (state.qr.mod) return state.qr.mod;
    if (state.qr.loading) return state.qr.loading;
    state.qr.loading = (async () => {
      if (!getFastQrBindgen()) {
        await loadScript("/vendor/fast_qr_nomod/fast_qr.js", WASM_INIT_TIMEOUT_MS, () => !!getFastQrBindgen());
      }
      const bindgen = getFastQrBindgen();
      if (!bindgen) {
        throw new Error("fast_qr loader unavailable");
      }
      const wasmUrl = new URL("/vendor/fast_qr_nomod/fast_qr_bg.wasm", location.origin);
      await withTimeout(bindgen(wasmUrl), WASM_INIT_TIMEOUT_MS, "init wasm timeout");
      state.qr.mod = bindgen;
      return state.qr.mod;
    })().catch((err) => {
      state.qr.loading = null;
      throw err;
    });
    return state.qr.loading;
  }

  function prewarmOfflineCodecs() {
    loadFastQrWasm().catch(() => null);
    ensurePako().catch(() => null);
  }

  async function renderQr(id, text) {
    const box = $(id);
    if (!box) return false;
    box.textContent = "";

    const lines = normalizeShardText(text);
    if (lines.length === 0) {
      clearQrBox(id, "No code");
      return false;
    }

    try {
      const fastQr = await loadFastQrWasm();
      let idx = 0;
      for (const raw of lines) {
        idx += 1;
        let opts = new fastQr.SvgOptions();
        opts = opts.shape(fastQr.Shape.Square);
        opts = opts.margin(8);
        opts = opts.module_color("#000000");
        opts = opts.background_color("#ffffff");
        opts = opts.ecl(fastQr.ECL.L);

        const svg = fastQr.qr_svg(raw, opts);
        if (!svg || svg.indexOf("<svg") === -1) {
          throw new Error("empty svg");
        }

        const partWrap = document.createElement("div");
        partWrap.style.display = "grid";
        partWrap.style.gap = "6px";
        partWrap.style.justifyItems = "center";
        partWrap.style.padding = "6px";
        if (lines.length > 1) {
          const label = document.createElement("div");
          label.className = "mini";
          label.textContent = `Part ${idx}/${lines.length}`;
          partWrap.appendChild(label);
        }

        const wrapper = document.createElement("div");
        wrapper.innerHTML = svg;
        const svgEl = wrapper.querySelector("svg");
        if (!svgEl) throw new Error("svg parse failed");
        svgEl.setAttribute("width", "300");
        svgEl.setAttribute("height", "300");
        svgEl.setAttribute("preserveAspectRatio", "xMidYMid meet");
        partWrap.appendChild(svgEl);
        box.appendChild(partWrap);
      }
      return true;
    } catch (e) {
      const errMsg = e && e.message ? String(e.message) : String(e || "unknown qr error");
      const tooLong = /too long|capacity|overflow|out of range|data length/i.test(errMsg);
      if (tooLong) {
        const totalChars = lines.reduce((acc, v) => acc + v.length, 0);
        clearQrBox(id, `QR too large (${totalChars} chars). Use copy/paste code.`);
      } else {
        clearQrBox(id, `QR failed: ${errMsg}`);
      }
      setRtErr(`qr error: ${errMsg}`);
      return false;
    }
  }

  function sanitizePeer(peer) {
    if (!peer || typeof peer.id !== "string") return null;
    return {
      id: peer.id,
      name: typeof peer.name === "string" && peer.name.trim() ? peer.name.trim() : null,
      joined_at_ms: Number(peer.joined_at_ms) || Date.now(),
    };
  }

  function peerDisplayName(peer) {
    if (!peer) return "unknown";
    return peer.name || `peer-${peer.id.slice(0, 8)}`;
  }

  function getSession(peerId) {
    return state.auto.sessions.get(peerId) || null;
  }

  function sessionConnectionState(session) {
    if (!session || !session.pc) return "idle";
    return session.pc.connectionState || session.pc.iceConnectionState || "new";
  }

  function classifyCandidateAddress(ipLike) {
    const raw = String(ipLike || "").trim().toLowerCase();
    if (!raw) return "unknown";
    if (raw === "localhost" || raw.startsWith("127.")) return "lan";
    if (raw.startsWith("10.") || raw.startsWith("192.168.") || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(raw)) return "lan";
    if (raw === "::1" || raw.startsWith("fc") || raw.startsWith("fd") || raw.startsWith("fe80:")) return "lan";
    return "wan";
  }

  async function detectSessionTransport(session) {
    if (!session || !session.pc || typeof session.pc.getStats !== "function") return;
    try {
      const stats = await session.pc.getStats();
      const byId = new Map();
      let selectedPair = null;
      let transport = null;

      stats.forEach((v) => {
        if (!v || typeof v !== "object" || !v.id) return;
        byId.set(v.id, v);
        if (v.type === "transport") transport = v;
      });

      if (transport && transport.selectedCandidatePairId) {
        selectedPair = byId.get(transport.selectedCandidatePairId) || null;
      }
      if (!selectedPair) {
        stats.forEach((v) => {
          if (selectedPair) return;
          if (!v || typeof v !== "object") return;
          if (v.type === "candidate-pair" && (v.selected || v.nominated) && v.state === "succeeded") {
            selectedPair = v;
          }
        });
      }

      if (!selectedPair) {
        session.transport = session.turnForced ? "turn" : "unknown";
        return;
      }

      const local = byId.get(selectedPair.localCandidateId);
      const remote = byId.get(selectedPair.remoteCandidateId);
      const localType = String((local && local.candidateType) || "");
      const remoteType = String((remote && remote.candidateType) || "");
      const localIp = String((local && (local.ip || local.address)) || "");
      const remoteIp = String((remote && (remote.ip || remote.address)) || "");

      if (localType === "relay" || remoteType === "relay") {
        session.transport = "turn";
      } else {
        const addrClass = [classifyCandidateAddress(localIp), classifyCandidateAddress(remoteIp)];
        session.transport = addrClass.every((v) => v === "lan") ? "lan" : "wan";
      }
    } catch (_) {
      session.transport = session.turnForced ? "turn" : "unknown";
    }
  }

  function describeTransport(session) {
    if (!session) return "idle";
    const t = String(session.transport || "");
    if (t === "turn") return "turn relay";
    if (t === "lan") return "lan p2p";
    if (t === "wan") return "wan p2p";
    if (session.turnForced) return "turn negotiating";
    return "p2p negotiating";
  }

  function updateSessionFingerprints(session) {
    if (!session || !session.pc) return;
    const local = extractSdpFingerprint(session.pc.localDescription && session.pc.localDescription.sdp);
    const remote = extractSdpFingerprint(session.pc.remoteDescription && session.pc.remoteDescription.sdp);
    const changed = local !== session.fpLocal || remote !== session.fpRemote;
    session.fpLocal = local;
    session.fpRemote = remote;
    if (changed) {
      session.fpConfirmed = false;
    }
  }

  function fingerprintSummary(local, remote, confirmed) {
    if (!local && !remote) return "fp: -";
    const loc = shortFingerprint(local);
    const rem = shortFingerprint(remote);
    return `fp ${loc} / ${rem} (${confirmed ? "verified" : "verify"})`;
  }

  function confirmFingerprint(localFp, remoteFp, label) {
    const local = shortFingerprint(localFp);
    const remote = shortFingerprint(remoteFp);
    const ok = window.confirm(
      [
        `Verify DTLS fingerprint with ${label || "peer"}.`,
        "",
        `Local:  ${local}`,
        `Remote: ${remote}`,
        "",
        "Confirm only if both devices display the same pair.",
      ].join("\n"),
    );
    return !!ok;
  }

  function ensureSessionFingerprintConfirmed(session, label) {
    updateSessionFingerprints(session);
    if (!session.fpLocal || !session.fpRemote) {
      throw new Error("fingerprint is not ready yet; wait for handshake");
    }
    if (session.fpConfirmed) return;
    if (!confirmFingerprint(session.fpLocal, session.fpRemote, label)) {
      throw new Error("fingerprint verification is required before sending files");
    }
    session.fpConfirmed = true;
  }

  function renderPeers() {
    const root = $("rtPeers");
    if (!root) return;
    root.textContent = "";

    const list = Array.from(state.auto.peers.values())
      .filter((p) => p && p.id && p.id !== state.auto.selfId)
      .sort((a, b) => (a.joined_at_ms || 0) - (b.joined_at_ms || 0));

    if (list.length === 0) {
      const empty = document.createElement("div");
      empty.className = "muted";
      empty.textContent = state.auto.running ? "No peers yet. Open this page on another device in the same WiFi." : "Auto-discovery is stopped.";
      root.appendChild(empty);
      return;
    }

    for (const peer of list) {
      const row = document.createElement("div");
      row.className = `peer${state.auto.selectedPeerId === peer.id ? " active" : ""}`;

      const line1 = document.createElement("div");
      line1.style.display = "flex";
      line1.style.justifyContent = "space-between";
      line1.style.gap = "8px";
      line1.style.flexWrap = "wrap";

      const left = document.createElement("div");
      left.textContent = peerDisplayName(peer);

      const right = document.createElement("div");
      right.className = "badge";
      right.textContent = peer.id;

      line1.appendChild(left);
      line1.appendChild(right);

      const line2 = document.createElement("div");
      line2.className = "mini";
      const sess = getSession(peer.id);
      const stateText = sessionConnectionState(sess);
      const transportText = describeTransport(sess);
      const fpText = sess
        ? fingerprintSummary(sess.fpLocal, sess.fpRemote, !!sess.fpConfirmed)
        : "fp: -";
      line2.textContent = `state: ${stateText} | route: ${transportText} | ${fpText}`;

      const actions = document.createElement("div");
      actions.style.display = "flex";
      actions.style.gap = "8px";
      actions.style.flexWrap = "wrap";

      const sel = document.createElement("button");
      sel.textContent = "Select";
      sel.onclick = () => setSelectedPeer(peer.id);

      const con = document.createElement("button");
      con.className = "primary";
      con.textContent = "Connect";
      con.onclick = async () => {
        setRtErr("");
        setSelectedPeer(peer.id);
        try {
          await connectAutoPeer(peer.id, true);
        } catch (e) {
          setRtErr(e && e.message ? e.message : "connect failed");
        }
      };

      const dis = document.createElement("button");
      dis.className = "danger";
      dis.textContent = "Disconnect";
      dis.onclick = () => closeAutoSession(peer.id, true);

      const verify = document.createElement("button");
      verify.textContent = "Verify FP";
      verify.disabled = !sess || !sess.fpLocal || !sess.fpRemote;
      verify.onclick = () => {
        if (!sess) return;
        setRtErr("");
        try {
          ensureSessionFingerprintConfirmed(sess, peerDisplayName(peer));
          setRtStatus(`fingerprint verified for ${peerDisplayName(peer)}`);
          renderPeers();
        } catch (e) {
          setRtErr(e && e.message ? e.message : "fingerprint verify failed");
        }
      };

      actions.appendChild(sel);
      actions.appendChild(con);
      actions.appendChild(dis);
      actions.appendChild(verify);

      row.onclick = (evt) => {
        const target = evt && evt.target;
        if (target && target.tagName === "BUTTON") return;
        setSelectedPeer(peer.id);
      };

      row.appendChild(line1);
      row.appendChild(line2);
      row.appendChild(actions);
      root.appendChild(row);
    }
  }

  async function maybeLoadTurnIceServers() {
    if (state.auto.iceServers) return state.auto.iceServers;

    const base = [{ urls: "stun:stun.cloudflare.com:3478" }, { urls: "stun:stun.l.google.com:19302" }];
    try {
      const res = await fetch("/api/v1/turn/credentials?ttl=3600", { method: "GET", credentials: "same-origin" });
      if (!res.ok) {
        state.auto.iceServers = base;
        return state.auto.iceServers;
      }
      const j = await res.json().catch(() => null);
      const list = Array.isArray(j && (j.iceServers || j.ice_servers)) ? (j.iceServers || j.ice_servers) : [];
      if (list.length > 0) {
        state.auto.iceServers = list;
        return state.auto.iceServers;
      }
    } catch (_) {
      // ignore
    }

    state.auto.iceServers = base;
    return state.auto.iceServers;
  }

  async function createAutoSession(peerId, forceRelay) {
    const existing = getSession(peerId);
    if (existing) return existing;

    const polite = !!(state.auto.selfId && state.auto.selfId < peerId);
    const iceServers = await maybeLoadTurnIceServers();
    const rtcCfg = { iceServers, iceCandidatePoolSize: 4 };
    if (forceRelay) {
      rtcCfg.iceTransportPolicy = "relay";
    }
    const pc = new RTCPeerConnection(rtcCfg);

    const session = {
      peerId,
      polite,
      pc,
      dc: null,
      makingOffer: false,
      ignoreOffer: false,
      pendingIce: [],
      incoming: null,
      sending: false,
      turnForced: !!forceRelay,
      transport: forceRelay ? "turn" : "unknown",
      fpLocal: null,
      fpRemote: null,
      fpConfirmed: false,
    };

    pc.onconnectionstatechange = () => {
      const st = sessionConnectionState(session);
      setRtStatus(`auto peer ${peerId.slice(0, 8)}: ${st}`);
      if (st === "connected") {
        detectSessionTransport(session).then(() => renderPeers());
      }
      if (st === "failed" || st === "closed") {
        if (!session.turnForced) {
          closeAutoSession(peerId, true);
          setRtStatus(`p2p failed with ${peerId.slice(0, 8)}; retry via TURN`);
          scheduleAutoRedial(peerId, AUTO_REDIAL_MS, true);
        } else {
          closeAutoSession(peerId, true);
          setRtStatus(`TURN failed with ${peerId.slice(0, 8)}; relay fallback available`);
        }
      }
      renderPeers();
    };

    pc.onicecandidate = (evt) => {
      if (!evt || !evt.candidate) return;
      sendAutoSignal(peerId, "ice", evt.candidate.toJSON ? evt.candidate.toJSON() : evt.candidate);
    };

    pc.ondatachannel = (evt) => {
      if (!evt || !evt.channel) return;
      attachAutoDataChannel(session, evt.channel);
    };

    state.auto.sessions.set(peerId, session);
    return session;
  }

  function closeAutoSession(peerId, keepPeer) {
    const session = getSession(peerId);
    if (session) {
      try {
        if (session.dc) session.dc.close();
      } catch (_) {
        // ignore
      }
      try {
        session.pc.close();
      } catch (_) {
        // ignore
      }
      state.auto.sessions.delete(peerId);
    }

    if (!keepPeer) {
      state.auto.peers.delete(peerId);
      if (state.auto.selectedPeerId === peerId) setSelectedPeer(null);
    }

    renderPeers();
  }

  function scheduleAutoRedial(peerId, delayMs, forceRelay) {
    if (!state.auto.running || state.mode !== "auto") return;
    if (state.auto.redialTimers.has(peerId)) return;
    const t = setTimeout(() => {
      state.auto.redialTimers.delete(peerId);
      connectAutoPeer(peerId, false, { forceRelay: !!forceRelay }).catch(() => {
        // ignore redial errors; manual connect remains available.
      });
    }, Math.max(100, Number(delayMs) || AUTO_REDIAL_MS));
    state.auto.redialTimers.set(peerId, t);
  }

  function closeAllAutoSessions() {
    const ids = Array.from(state.auto.sessions.keys());
    for (const id of ids) {
      closeAutoSession(id, true);
    }
    for (const t of state.auto.redialTimers.values()) {
      clearTimeout(t);
    }
    state.auto.redialTimers.clear();
  }

  async function waitChannelDrain(dc) {
    while (dc.readyState === "open" && dc.bufferedAmount > SEND_BUFFER_LIMIT) {
      await sleep(16);
    }
  }

  function sendControl(dc, payload) {
    dc.send(JSON.stringify(payload));
  }

  function toArrayBuffer(data) {
    if (data instanceof ArrayBuffer) return Promise.resolve(data);
    if (ArrayBuffer.isView(data)) {
      const view = data;
      return Promise.resolve(view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength));
    }
    if (data instanceof Blob) return data.arrayBuffer();
    return Promise.resolve(null);
  }

  function applyIncomingMeta(target, msg, fromLabel) {
    const id = typeof msg.id === "string" ? msg.id : randomTransferId();
    const size = Number(msg.size);
    target.incoming = {
      id,
      name: typeof msg.name === "string" && msg.name ? msg.name : `file-${id}`,
      type: typeof msg.mime === "string" && msg.mime ? msg.mime : "application/octet-stream",
      expected: Number.isFinite(size) && size >= 0 ? size : null,
      received: 0,
      chunks: [],
    };
    setTransferStatus(`Receiving ${target.incoming.name} from ${fromLabel}...`);
  }

  function maybeFinalizeIncoming(target, msg, modeLabel, fromLabel) {
    if (!target.incoming) return;
    const incoming = target.incoming;
    const doneId = typeof msg.id === "string" ? msg.id : incoming.id;
    if (doneId !== incoming.id) return;

    const blob = new Blob(incoming.chunks, { type: incoming.type || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    addReceivedFile({
      mode: modeLabel,
      from: fromLabel,
      name: incoming.name,
      size: incoming.received,
      url,
    });
    setTransferStatus(`Received ${incoming.name} (${fmtBytes(incoming.received)}) from ${fromLabel}`);
    target.incoming = null;
  }

  function applyIncomingChunk(target, chunk, fromLabel) {
    if (!target.incoming) return;
    target.incoming.chunks.push(chunk);
    target.incoming.received += chunk.byteLength;
    const exp = target.incoming.expected;
    if (Number.isFinite(exp) && exp > 0) {
      const pct = Math.min(100, Math.floor((target.incoming.received / exp) * 100));
      setTransferStatus(`Receiving ${target.incoming.name} from ${fromLabel}: ${pct}%`);
    } else {
      setTransferStatus(`Receiving ${target.incoming.name} from ${fromLabel}: ${fmtBytes(target.incoming.received)}`);
    }
  }

  function attachAutoDataChannel(session, channel) {
    session.dc = channel;
    channel.binaryType = "arraybuffer";

    channel.onopen = () => {
      setSelectedPeer(session.peerId);
      setRtStatus(`data channel open with ${session.peerId.slice(0, 8)}`);
      renderPeers();
    };

    channel.onclose = () => {
      setRtStatus(`data channel closed with ${session.peerId.slice(0, 8)}`);
      renderPeers();
    };

    channel.onerror = () => {
      const pc = session.pc;
      setRtErr(
        `data channel error (${session.peerId.slice(0, 8)}), pc=${pc.connectionState}/${pc.iceConnectionState}, sig=${pc.signalingState}`,
      );
      if (pc.connectionState !== "connected") {
        scheduleAutoRedial(session.peerId, AUTO_REDIAL_MS, session.turnForced);
      }
    };

    channel.onmessage = async (evt) => {
      const payload = evt ? evt.data : null;
      if (typeof payload === "string") {
        let msg = null;
        try {
          msg = JSON.parse(payload);
        } catch (_) {
          return;
        }
        if (!msg || typeof msg !== "object") return;
        if (msg.t === "meta") {
          applyIncomingMeta(session, msg, session.peerId);
          return;
        }
        if (msg.t === "done") {
          maybeFinalizeIncoming(session, msg, "auto", session.peerId);
        }
        return;
      }

      const chunk = await toArrayBuffer(payload);
      if (!chunk) return;
      applyIncomingChunk(session, chunk, session.peerId);
    };
  }

  async function sendFileViaChannel(channel, target, file, modeLabel) {
    if (!channel || channel.readyState !== "open") {
      throw new Error("data channel is not open");
    }

    if (target.sending) {
      throw new Error("a transfer is already running on this channel");
    }

    const transferId = randomTransferId();
    target.sending = true;
    try {
      sendControl(channel, {
        t: "meta",
        id: transferId,
        name: file.name || "file.bin",
        size: Number(file.size) || 0,
        mime: file.type || "application/octet-stream",
      });

      let offset = 0;
      while (offset < file.size) {
        if (channel.readyState !== "open") throw new Error("channel closed during send");
        await waitChannelDrain(channel);
        const end = Math.min(file.size, offset + CHUNK_BYTES);
        const chunk = await file.slice(offset, end).arrayBuffer();
        channel.send(chunk);
        offset = end;
        const pct = file.size > 0 ? Math.min(100, Math.floor((offset / file.size) * 100)) : 100;
        setTransferStatus(`${modeLabel}: sending ${file.name} ${pct}%`);
      }

      sendControl(channel, { t: "done", id: transferId });
      setTransferStatus(`${modeLabel}: sent ${file.name} (${fmtBytes(file.size)})`);
    } finally {
      target.sending = false;
    }
  }

  async function sendFiles(channel, target, files, modeLabel) {
    for (const file of files) {
      await sendFileViaChannel(channel, target, file, modeLabel);
    }
  }

  function sendAutoSignal(to, kind, payload) {
    const ws = state.auto.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(
      JSON.stringify({
        type: "signal",
        to,
        kind,
        payload: payload == null ? null : payload,
      }),
    );
  }

  async function drainPendingIce(session) {
    if (!session.pendingIce || session.pendingIce.length === 0) return;
    const items = session.pendingIce.splice(0, session.pendingIce.length);
    for (const c of items) {
      try {
        await session.pc.addIceCandidate(c);
      } catch (_) {
        // ignore stale candidates
      }
    }
  }

  async function createAndSendOffer(session) {
    if (session.makingOffer) return;
    if (session.pc.signalingState !== "stable") return;

    session.makingOffer = true;
    try {
      const offer = await session.pc.createOffer();
      await session.pc.setLocalDescription(offer);
      updateSessionFingerprints(session);
      sendAutoSignal(session.peerId, "offer", session.pc.localDescription);
    } finally {
      session.makingOffer = false;
    }
  }

  async function connectAutoPeer(peerId, manual, opts) {
    if (!peerId) throw new Error("select a peer first");
    if (!state.auto.running) throw new Error("auto-discovery is not running");
    const forceRelay = !!(opts && opts.forceRelay);
    const existing = getSession(peerId);
    if (existing && forceRelay && !existing.turnForced) {
      closeAutoSession(peerId, true);
    }
    const session = await createAutoSession(peerId, forceRelay);
    const st = sessionConnectionState(session);

    if (session.dc && session.dc.readyState === "open" && st === "connected") {
      if (manual) setRtStatus(`already connected to ${peerId.slice(0, 8)}`);
      renderPeers();
      return;
    }
    if (session.pc.signalingState === "have-local-offer") {
      if (manual) setRtStatus(`offer already pending to ${peerId.slice(0, 8)}`);
      renderPeers();
      return;
    }

    if (!session.dc || session.dc.readyState === "closing" || session.dc.readyState === "closed") {
      const dc = session.pc.createDataChannel("xsend-file", { ordered: true });
      attachAutoDataChannel(session, dc);
    }

    await createAndSendOffer(session);
    if (manual) {
      setRtStatus(`${forceRelay ? "TURN" : "p2p"} offer sent to ${peerId.slice(0, 8)}`);
    }
    renderPeers();
  }

  async function onAutoSignal(from, kind, payload) {
    if (!from || typeof from !== "string") return;
    const session = await createAutoSession(from);

    if (kind === "offer") {
      if (!payload || payload.type !== "offer" || typeof payload.sdp !== "string") return;
      if (
        session.pc.remoteDescription &&
        session.pc.remoteDescription.type === "offer" &&
        session.pc.remoteDescription.sdp === payload.sdp
      ) {
        return;
      }
      const offerCollision = session.makingOffer || session.pc.signalingState !== "stable";
      session.ignoreOffer = !session.polite && offerCollision;
      if (session.ignoreOffer) return;

      if (offerCollision) {
        try {
          await session.pc.setLocalDescription({ type: "rollback" });
        } catch (_) {
          // ignore rollback errors
        }
      }

      await session.pc.setRemoteDescription(new RTCSessionDescription(payload));
      await drainPendingIce(session);
      const answer = await session.pc.createAnswer();
      await session.pc.setLocalDescription(answer);
      updateSessionFingerprints(session);
      sendAutoSignal(from, "answer", session.pc.localDescription);
      setRtStatus(`answered ${from.slice(0, 8)}`);
      renderPeers();
      return;
    }

    if (kind === "answer") {
      if (!payload || payload.type !== "answer" || typeof payload.sdp !== "string") return;
      if (session.pc.remoteDescription && session.pc.remoteDescription.type === "answer") {
        return;
      }
      if (session.pc.signalingState !== "have-local-offer") {
        return;
      }
      await session.pc.setRemoteDescription(new RTCSessionDescription(payload));
      await drainPendingIce(session);
      updateSessionFingerprints(session);
      setRtStatus(`answer applied from ${from.slice(0, 8)}`);
      renderPeers();
      return;
    }

    if (kind === "ice") {
      if (!payload) return;
      let cand = null;
      try {
        cand = new RTCIceCandidate(payload);
      } catch (_) {
        return;
      }
      if (!session.pc.remoteDescription) {
        session.pendingIce.push(cand);
        return;
      }
      try {
        await session.pc.addIceCandidate(cand);
      } catch (_) {
        // ignore
      }
    }
  }

  function setAutoPanels() {
    const autoPanel = $("rtAutoPanel");
    const offPanel = $("rtOfflinePanel");
    if (autoPanel) autoPanel.classList.toggle("hidden", state.mode !== "auto");
    if (offPanel) offPanel.classList.toggle("hidden", state.mode !== "offline");
  }

  function autoReconnect() {
    if (!state.auto.running || state.mode !== "auto") return;
    if (state.auto.reconnectTimer) clearTimeout(state.auto.reconnectTimer);
    state.auto.reconnectTimer = setTimeout(() => {
      state.auto.reconnectTimer = null;
      openAutoSocket().catch((e) => setRtErr(e && e.message ? e.message : "auto reconnect failed"));
    }, AUTO_RECONNECT_MS);
  }

  async function openAutoSocket() {
    if (!state.auto.running || state.mode !== "auto") return;

    const qs = new URLSearchParams();
    if (state.scope) qs.set("scope", state.scope);

    const infoRes = await fetch(`/api/v1/realtime/auto/info?${qs.toString()}`, {
      method: "GET",
      credentials: "same-origin",
    }).catch(() => null);
    if (infoRes && !infoRes.ok) {
      let msg = `auto discovery unavailable (${infoRes.status})`;
      const j = await infoRes.json().catch(() => null);
      if (j && j.error) msg = String(j.error);
      throw new Error(msg);
    }

    if (state.auto.ws) {
      try {
        state.auto.ws.close();
      } catch (_) {
        // ignore
      }
      state.auto.ws = null;
    }

    const proto = location.protocol === "https:" ? "wss" : "ws";
    const params = new URLSearchParams();
    params.set("peer_id", state.peerId);
    if (state.peerName) params.set("name", state.peerName);
    if (state.scope) params.set("scope", state.scope);

    const wsUrl = `${proto}://${location.host}/api/v1/realtime/auto/ws?${params.toString()}`;
    setRtStatus("connecting signaling...");

    const ws = new WebSocket(wsUrl);
    state.auto.ws = ws;

    ws.onopen = () => {
      setRtStatus("auto-discovery connected");
      ws.send(JSON.stringify({ type: "list" }));
      ws.send(JSON.stringify({ type: "meta", name: state.peerName || null }));
    };

    ws.onmessage = (evt) => {
      let msg = null;
      try {
        msg = JSON.parse(evt.data);
      } catch (_) {
        return;
      }
      if (!msg || typeof msg !== "object") return;

      if (msg.type === "welcome") {
        state.auto.selfId = typeof msg.self_id === "string" ? msg.self_id : state.peerId;
        setText("rtSelfId", state.auto.selfId || "-");
        state.auto.peers.clear();
        const peers = Array.isArray(msg.peers) ? msg.peers : [];
        for (const p of peers) {
          const sp = sanitizePeer(p);
          if (!sp) continue;
          state.auto.peers.set(sp.id, sp);
        }
        renderPeers();
        maybeAutoConnectAny();
        return;
      }

      if (msg.type === "peers") {
        const peers = Array.isArray(msg.peers) ? msg.peers : [];
        state.auto.peers.clear();
        for (const p of peers) {
          const sp = sanitizePeer(p);
          if (!sp) continue;
          state.auto.peers.set(sp.id, sp);
        }
        renderPeers();
        maybeAutoConnectAny();
        return;
      }

      if (msg.type === "peer_join") {
        const sp = sanitizePeer(msg.peer);
        if (sp) {
          state.auto.peers.set(sp.id, sp);
          renderPeers();
          maybeAutoConnectPeer(sp.id);
        }
        return;
      }

      if (msg.type === "peer_update") {
        const sp = sanitizePeer(msg.peer);
        if (sp) {
          const old = state.auto.peers.get(sp.id) || sp;
          state.auto.peers.set(sp.id, {
            id: sp.id,
            name: sp.name,
            joined_at_ms: old.joined_at_ms || sp.joined_at_ms,
          });
          renderPeers();
        }
        return;
      }

      if (msg.type === "peer_leave") {
        const peerId = typeof msg.peer_id === "string" ? msg.peer_id : "";
        if (!peerId) return;
        closeAutoSession(peerId, false);
        renderPeers();
        return;
      }

      if (msg.type === "signal") {
        const from = typeof msg.from === "string" ? msg.from : "";
        const kind = typeof msg.kind === "string" ? msg.kind : "";
        onAutoSignal(from, kind, msg.payload).catch((e) => setRtErr(e && e.message ? e.message : "signal handling failed"));
      }
    };

    ws.onclose = () => {
      if (state.auto.ws === ws) state.auto.ws = null;
      setRtStatus("auto-discovery disconnected");
      autoReconnect();
    };

    ws.onerror = () => {
      setRtErr("auto-discovery websocket error");
    };
  }

  function stopAutoSocket() {
    state.auto.running = false;
    if (state.auto.reconnectTimer) {
      clearTimeout(state.auto.reconnectTimer);
      state.auto.reconnectTimer = null;
    }
    if (state.auto.ws) {
      try {
        state.auto.ws.close();
      } catch (_) {
        // ignore
      }
      state.auto.ws = null;
    }
    closeAllAutoSessions();
  }

  function shouldAutoDial(peerId) {
    if (!peerId || peerId === state.auto.selfId) return false;
    if (!state.auto.selfId) return false;
    return state.auto.selfId > peerId;
  }

  function maybeAutoConnectPeer(peerId) {
    if (!state.auto.running || state.mode !== "auto") return;
    if (!shouldAutoDial(peerId)) return;
    const existing = getSession(peerId);
    if (existing) {
      const st = sessionConnectionState(existing);
      if (st !== "failed" && st !== "closed") return;
    }
    connectAutoPeer(peerId, false).catch(() => {
      // ignore auto connect failures; user can connect manually.
    });
  }

  function maybeAutoConnectAny() {
    const peers = Array.from(state.auto.peers.values())
      .map((p) => p.id)
      .filter((id) => !!id && id !== state.auto.selfId);
    for (const id of peers) {
      maybeAutoConnectPeer(id);
    }
  }

  function startAutoDiscovery() {
    const feats = state.features || null;
    if (feats && feats.auto_discovery === false) {
      setRtErr("auto discovery requires paid plan");
      return;
    }
    state.auto.running = true;
    setRtStatus("starting auto-discovery");
    openAutoSocket().catch((e) => setRtErr(e && e.message ? e.message : "failed to start auto-discovery"));
  }

  function stopAutoDiscovery() {
    stopAutoSocket();
    state.auto.peers.clear();
    state.auto.selfId = null;
    setText("rtSelfId", "-");
    setSelectedPeer(null);
    renderPeers();
    setRtStatus("auto-discovery stopped");
  }

  function closeOfflineSession() {
    if (state.offline.dc) {
      try {
        state.offline.dc.close();
      } catch (_) {
        // ignore
      }
    }
    if (state.offline.pc) {
      try {
        state.offline.pc.close();
      } catch (_) {
        // ignore
      }
    }
    state.offline.pc = null;
    state.offline.dc = null;
    state.offline.role = null;
    state.offline.incoming = null;
    state.offline.fpLocal = null;
    state.offline.fpRemote = null;
    state.offline.fpConfirmed = false;
    setText("rtOfflineFp", "fingerprint: -");
  }

  function updateOfflineFingerprints() {
    const pc = state.offline.pc;
    if (!pc) {
      state.offline.fpLocal = null;
      state.offline.fpRemote = null;
      state.offline.fpConfirmed = false;
      setText("rtOfflineFp", "fingerprint: -");
      return;
    }
    const local = extractSdpFingerprint(pc.localDescription && pc.localDescription.sdp);
    const remote = extractSdpFingerprint(pc.remoteDescription && pc.remoteDescription.sdp);
    const changed = local !== state.offline.fpLocal || remote !== state.offline.fpRemote;
    state.offline.fpLocal = local;
    state.offline.fpRemote = remote;
    if (changed) state.offline.fpConfirmed = false;
    setText(
      "rtOfflineFp",
      `fingerprint: ${fingerprintSummary(state.offline.fpLocal, state.offline.fpRemote, state.offline.fpConfirmed)}`,
    );
  }

  function ensureOfflineFingerprintConfirmed() {
    if (!state.offline.fpLocal || !state.offline.fpRemote) {
      throw new Error("offline fingerprint is not ready yet");
    }
    if (state.offline.fpConfirmed) return;
    if (!confirmFingerprint(state.offline.fpLocal, state.offline.fpRemote, "offline peer")) {
      throw new Error("offline fingerprint verification is required before sending");
    }
    state.offline.fpConfirmed = true;
    updateOfflineFingerprints();
  }

  function attachOfflineDataChannel(dc) {
    state.offline.dc = dc;
    dc.binaryType = "arraybuffer";

    dc.onopen = () => {
      setRtStatus("offline channel connected");
      updateOfflineFingerprints();
    };

    dc.onclose = () => {
      setRtStatus("offline channel closed");
    };

    dc.onerror = () => {
      setRtErr("offline data channel error");
    };

    dc.onmessage = async (evt) => {
      const payload = evt ? evt.data : null;
      if (typeof payload === "string") {
        let msg = null;
        try {
          msg = JSON.parse(payload);
        } catch (_) {
          return;
        }
        if (!msg || typeof msg !== "object") return;
        if (msg.t === "meta") {
          applyIncomingMeta(state.offline, msg, "offline-peer");
          return;
        }
        if (msg.t === "done") {
          maybeFinalizeIncoming(state.offline, msg, "offline", "offline-peer");
        }
        return;
      }

      const chunk = await toArrayBuffer(payload);
      if (!chunk) return;
      applyIncomingChunk(state.offline, chunk, "offline-peer");
    };
  }

  async function waitIceGatheringDone(pc, timeoutMs) {
    if (pc.iceGatheringState === "complete") return;
    await new Promise((resolve) => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        pc.removeEventListener("icegatheringstatechange", onState);
        resolve();
      };
      const onState = () => {
        if (pc.iceGatheringState === "complete") finish();
      };
      pc.addEventListener("icegatheringstatechange", onState);
      setTimeout(finish, timeoutMs);
    });
  }

  function createOfflinePc(role) {
    const pc = new RTCPeerConnection({ iceServers: [] });
    pc.onconnectionstatechange = () => {
      setRtStatus(`offline rtc ${pc.connectionState}`);
    };
    pc.ondatachannel = (evt) => {
      if (role === "answer") {
        attachOfflineDataChannel(evt.channel);
      }
    };
    state.offline.pc = pc;
    state.offline.role = role;
    state.offline.fpConfirmed = false;
    updateOfflineFingerprints();
    return pc;
  }

  async function createOfflineOffer() {
    setRtStatus("creating offer...");
    closeOfflineSession();
    clearQrBox("rtOfferQr", "Preparing...");
    setVal("rtOfferCodeOut", "");
    const warmQr = loadFastQrWasm().catch(() => null);
    const warmPako = ensurePako().catch(() => null);

    const pc = createOfflinePc("offer");
    const dc = pc.createDataChannel("xsend-file", { ordered: true });
    attachOfflineDataChannel(dc);

    const offer = await withTimeout(pc.createOffer(), RTC_STEP_TIMEOUT_MS, "create offer timeout");
    await withTimeout(pc.setLocalDescription(offer), RTC_STEP_TIMEOUT_MS, "set local description timeout").catch(() => null);
    await waitIceGatheringDone(pc, OFFLINE_ICE_GATHER_MS);
    await warmPako;
    await warmQr;
    const local = pc.localDescription || offer;
    const compact = compactOfflineSdp(local);
    const code = await encodeSdpCode(compact);
    setVal("rtOfferCodeOut", code);
    updateOfflineFingerprints();
    setRtStatus(`offer code ready (${code.length} chars)`);
    const ok = await renderQr("rtOfferQr", code);
    setRtStatus(ok ? "offer QR ready" : "offer code ready (QR unavailable)");
  }

  async function createOfflineAnswer() {
    setRtStatus("creating answer...");
    const offerCode = getVal("rtOfferCodeIn").trim();
    if (!offerCode) throw new Error("paste or scan offer code first");
    const warmQr = loadFastQrWasm().catch(() => null);
    const warmPako = ensurePako().catch(() => null);

    const offer = await decodeSdpCode(offerCode, "offer");
    closeOfflineSession();
    clearQrBox("rtAnswerQr", "Preparing...");
    setVal("rtAnswerCodeOut", "");

    const pc = createOfflinePc("answer");
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await withTimeout(pc.createAnswer(), RTC_STEP_TIMEOUT_MS, "create answer timeout");
    await withTimeout(pc.setLocalDescription(answer), RTC_STEP_TIMEOUT_MS, "set local description timeout").catch(() => null);
    await waitIceGatheringDone(pc, OFFLINE_ICE_GATHER_MS);
    await warmPako;
    await warmQr;
    const local = pc.localDescription || answer;
    const compact = compactOfflineSdp(local);
    const code = await encodeSdpCode(compact);
    setVal("rtAnswerCodeOut", code);
    updateOfflineFingerprints();
    setRtStatus(`answer code ready (${code.length} chars)`);
    const ok = await renderQr("rtAnswerQr", code);
    setRtStatus(ok ? "answer QR ready" : "answer code ready (QR unavailable)");
  }

  async function applyOfflineAnswer() {
    const pc = state.offline.pc;
    if (!pc || state.offline.role !== "offer") {
      throw new Error("create offer first on sender side");
    }

    if (pc.remoteDescription && pc.remoteDescription.type === "answer" && pc.signalingState === "stable") {
      setRtStatus("answer already applied");
      return;
    }
    if (pc.signalingState !== "have-local-offer") {
      throw new Error(`cannot apply answer in state: ${pc.signalingState}. reset and create offer again`);
    }

    const answerCode = getVal("rtAnswerCodeIn").trim();
    if (!answerCode) throw new Error("paste or scan answer code first");
    const answer = await decodeSdpCode(answerCode, "answer");

    await pc.setRemoteDescription(new RTCSessionDescription(answer));
    updateOfflineFingerprints();
    setRtStatus("answer applied; waiting for offline channel open");
  }

  async function startScan(targetId) {
    if (!("mediaDevices" in navigator) || !navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== "function") {
      throw new Error("camera is not available in this browser");
    }
    if (typeof window.BarcodeDetector !== "function") {
      throw new Error("BarcodeDetector is not supported; use copy/paste code");
    }

    stopScan();

    const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
    const stream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: { ideal: "environment" },
      },
      audio: false,
    });

    const wrap = $("rtScanWrap");
    const video = $("rtScanVideo");
    if (!video) throw new Error("scan video element missing");

    state.scan.active = true;
    state.scan.stream = stream;
    state.scan.targetId = targetId;
    state.scan.detector = detector;

    if (wrap) wrap.classList.remove("hidden");

    video.srcObject = stream;
    await video.play().catch(() => null);

    const loop = async () => {
      if (!state.scan.active || !video || !state.scan.detector) return;
      try {
        const codes = await state.scan.detector.detect(video);
        if (Array.isArray(codes) && codes.length > 0) {
          const rawValue = codes[0] && typeof codes[0].rawValue === "string" ? codes[0].rawValue.trim() : "";
          if (rawValue) {
            const current = state.scan.targetId ? getVal(state.scan.targetId) : "";
            const merged = mergeScannedCode(current, rawValue);
            if (state.scan.targetId) setVal(state.scan.targetId, merged.text);
            if (!merged.shard || merged.complete) {
              stopScan();
              setRtStatus(merged.shard ? `QR scanned (${merged.done}/${merged.total})` : "QR scanned");
              return;
            }
            setRtStatus(`QR shard scanned (${merged.done}/${merged.total}); keep scanning`);
          }
        }
      } catch (_) {
        // Ignore intermittent detector failures.
      }
      state.scan.rafId = requestAnimationFrame(loop);
    };

    state.scan.rafId = requestAnimationFrame(loop);
  }

  function stopScan() {
    if (state.scan.rafId) {
      cancelAnimationFrame(state.scan.rafId);
      state.scan.rafId = null;
    }

    if (state.scan.stream) {
      for (const t of state.scan.stream.getTracks()) {
        try {
          t.stop();
        } catch (_) {
          // ignore
        }
      }
      state.scan.stream = null;
    }

    const video = $("rtScanVideo");
    if (video) {
      video.pause();
      video.srcObject = null;
    }

    const wrap = $("rtScanWrap");
    if (wrap) wrap.classList.add("hidden");

    state.scan.active = false;
    state.scan.targetId = null;
    state.scan.detector = null;
  }

  function switchMode(mode) {
    const next = mode === "offline" ? "offline" : "auto";
    if (state.mode === next) return;
    const feats = state.features || null;
    if (next === "auto" && feats && feats.auto_discovery === false) {
      setRtErr("auto discovery requires paid plan");
      return;
    }
    if (next === "offline" && feats && feats.offline_mode === false) {
      setRtErr("offline mode requires paid plan");
      return;
    }

    state.mode = next;
    setModeBadge();
    setModeButtons();
    setAutoPanels();
    setRtErr("");

    if (state.mode === "auto") {
      closeOfflineSession();
      stopScan();
      startAutoDiscovery();
    } else {
      prewarmOfflineCodecs();
      stopAutoDiscovery();
      setRtStatus("offline mode");
    }
  }

  async function waitAutoChannelOpen(peerId, timeoutMs) {
    const timeout = Math.max(300, Number(timeoutMs) || AUTO_CONNECT_WAIT_MS);
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const session = getSession(peerId);
      if (session && session.dc && session.dc.readyState === "open") {
        return session;
      }
      await sleep(120);
    }
    throw new Error("timed out waiting for data channel");
  }

  async function ensureAutoSessionReady(peerId) {
    let session = getSession(peerId);
    if (session && session.dc && session.dc.readyState === "open") {
      return session;
    }

    await connectAutoPeer(peerId, false, { forceRelay: false });
    try {
      session = await waitAutoChannelOpen(peerId, AUTO_CONNECT_WAIT_MS);
      return session;
    } catch (_) {
      setRtStatus(`p2p connect timeout with ${peerId.slice(0, 8)}; retry via TURN`);
    }

    await connectAutoPeer(peerId, false, { forceRelay: true });
    session = await waitAutoChannelOpen(peerId, AUTO_CONNECT_WAIT_TURN_MS);
    return session;
  }

  async function relayFallbackUploadFiles(files, reasonLabel) {
    const list = Array.isArray(files) ? files : [];
    if (list.length === 0) return false;

    const meRes = await fetch("/api/v1/auth/me", { method: "GET", credentials: "same-origin" }).catch(() => null);
    if (!meRes || !meRes.ok) {
      throw new Error("TURN/P2P failed; sign in first to use relay fallback");
    }
    const me = await meRes.json().catch(() => null);
    if (!me || !me.user) {
      throw new Error("TURN/P2P failed; sign in first to use relay fallback");
    }

    const chRes = await fetch("/api/v1/me/channel", { method: "GET", credentials: "same-origin" });
    if (!chRes.ok) {
      const text = await chRes.text().catch(() => "");
      throw new Error(`relay fallback channel failed (${chRes.status}): ${text.trim()}`);
    }
    const ch = await chRes.json().catch(() => null);
    const relayCode = ch && ch.channel && ch.channel.code ? String(ch.channel.code) : "-";

    let uploaded = 0;
    for (const file of list) {
      const name = file && file.name ? String(file.name) : "file.bin";
      const qs = new URLSearchParams();
      qs.set("name", name);
      const upRes = await fetch(`/api/v1/me/files?${qs.toString()}`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/octet-stream" },
        body: file,
      });
      if (!upRes.ok) {
        const text = await upRes.text().catch(() => "");
        throw new Error(`relay upload failed (${upRes.status}): ${text.trim()}`);
      }
      uploaded += 1;
    }

    setTransferStatus(
      `relay fallback uploaded ${uploaded} file(s), code ${relayCode}${reasonLabel ? ` (${reasonLabel})` : ""}`,
    );
    return true;
  }

  async function sendAutoSelectedFiles() {
    const peerId = state.auto.selectedPeerId;
    if (!peerId) throw new Error("select a peer first");

    const input = $("rtAutoFiles");
    const files = input && input.files ? Array.from(input.files) : [];
    if (files.length === 0) throw new Error("select files first");

    const session = await ensureAutoSessionReady(peerId).catch(async () => {
      await relayFallbackUploadFiles(files, "auto-connect failed");
      if (input) input.value = "";
      return null;
    });
    if (!session) return;

    try {
      ensureSessionFingerprintConfirmed(session, peerDisplayName(state.auto.peers.get(peerId)));
      await sendFiles(session.dc, session, files, `auto:${peerId.slice(0, 8)}`);
      if (input) input.value = "";
    } catch (e) {
      await relayFallbackUploadFiles(files, e && e.message ? String(e.message) : "p2p send failed");
      if (input) input.value = "";
    }
  }

  async function sendOfflineSelectedFiles() {
    const dc = state.offline.dc;
    const input = $("rtOfflineFiles");
    const files = input && input.files ? Array.from(input.files) : [];
    if (files.length === 0) throw new Error("select files first");
    if (!dc || dc.readyState !== "open") {
      await relayFallbackUploadFiles(files, "offline channel unavailable");
      if (input) input.value = "";
      return;
    }

    ensureOfflineFingerprintConfirmed();
    try {
      await sendFiles(dc, state.offline, files, "offline");
      if (input) input.value = "";
    } catch (e) {
      await relayFallbackUploadFiles(files, e && e.message ? String(e.message) : "offline send failed");
      if (input) input.value = "";
    }
  }

  function setupEvents() {
    const modeAuto = $("rtModeAuto");
    const modeOffline = $("rtModeOffline");
    const nameInput = $("rtDeviceName");
    const scopeInput = $("rtScope");

    if (modeAuto) {
      modeAuto.onclick = () => switchMode("auto");
    }
    if (modeOffline) {
      modeOffline.onclick = () => switchMode("offline");
    }

    if (nameInput) {
      nameInput.onchange = () => {
        const v = getVal("rtDeviceName").trim().slice(0, 32);
        state.peerName = v || defaultDeviceName();
        setVal("rtDeviceName", state.peerName);
        safeStorageSet("xsend.rt.peer_name", state.peerName);

        if (state.mode === "auto") {
          const ws = state.auto.ws;
          if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "meta", name: state.peerName || null }));
          } else {
            openAutoSocket().catch(() => {
              // ignore restart failures here
            });
          }
        }
      };
    }

    if (scopeInput) {
      scopeInput.onchange = () => {
        const v = getVal("rtScope").trim().slice(0, 32);
        state.scope = v;
        safeStorageSet("xsend.rt.scope", state.scope);
        if (state.mode === "auto") {
          stopAutoDiscovery();
          startAutoDiscovery();
        }
      };
    }

    const startBtn = $("rtStartAuto");
    if (startBtn) {
      startBtn.onclick = () => {
        setRtErr("");
        startAutoDiscovery();
      };
    }

    const stopBtn = $("rtStopAuto");
    if (stopBtn) {
      stopBtn.onclick = () => {
        setRtErr("");
        stopAutoDiscovery();
      };
    }

    const refreshBtn = $("rtRefreshPeers");
    if (refreshBtn) {
      refreshBtn.onclick = () => {
        const ws = state.auto.ws;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "list" }));
        }
      };
    }

    const connectBtn = $("rtConnectPeer");
    if (connectBtn) {
      connectBtn.onclick = async () => {
        setRtErr("");
        try {
          await connectAutoPeer(state.auto.selectedPeerId, true);
        } catch (e) {
          setRtErr(e && e.message ? e.message : "connect failed");
        }
      };
    }

    const disconnectBtn = $("rtDisconnectPeer");
    if (disconnectBtn) {
      disconnectBtn.onclick = () => {
        if (!state.auto.selectedPeerId) return;
        closeAutoSession(state.auto.selectedPeerId, true);
      };
    }

    const sendAutoBtn = $("rtSendAuto");
    if (sendAutoBtn) {
      sendAutoBtn.onclick = async () => {
        setRtErr("");
        try {
          await sendAutoSelectedFiles();
        } catch (e) {
          setRtErr(e && e.message ? e.message : "send failed");
        }
      };
    }

    const createOfferBtn = $("rtCreateOffer");
    if (createOfferBtn) {
      createOfferBtn.onclick = async () => {
        setRtErr("");
        try {
          await createOfflineOffer();
        } catch (e) {
          setRtErr(e && e.message ? e.message : "create offer failed");
        }
      };
    }

    const createAnswerBtn = $("rtCreateAnswer");
    if (createAnswerBtn) {
      createAnswerBtn.onclick = async () => {
        setRtErr("");
        try {
          await createOfflineAnswer();
        } catch (e) {
          setRtErr(e && e.message ? e.message : "create answer failed");
        }
      };
    }

    const applyAnswerBtn = $("rtApplyAnswer");
    if (applyAnswerBtn) {
      applyAnswerBtn.onclick = async () => {
        setRtErr("");
        try {
          await applyOfflineAnswer();
        } catch (e) {
          setRtErr(e && e.message ? e.message : "apply answer failed");
        }
      };
    }

    const resetOfflineBtn = $("rtResetOffline");
    if (resetOfflineBtn) {
      resetOfflineBtn.onclick = () => {
        closeOfflineSession();
        stopScan();
        setRtStatus("offline session reset");
      };
    }

    const verifyOfflineBtn = $("rtVerifyOfflineFp");
    if (verifyOfflineBtn) {
      verifyOfflineBtn.onclick = () => {
        setRtErr("");
        try {
          ensureOfflineFingerprintConfirmed();
          setRtStatus("offline fingerprint verified");
        } catch (e) {
          setRtErr(e && e.message ? e.message : "offline fingerprint verification failed");
        }
      };
    }

    const scanOfferBtn = $("rtScanOffer");
    if (scanOfferBtn) {
      scanOfferBtn.onclick = async () => {
        setRtErr("");
        try {
          await startScan("rtOfferCodeIn");
        } catch (e) {
          setRtErr(e && e.message ? e.message : "scan failed");
        }
      };
    }

    const scanAnswerBtn = $("rtScanAnswer");
    if (scanAnswerBtn) {
      scanAnswerBtn.onclick = async () => {
        setRtErr("");
        try {
          await startScan("rtAnswerCodeIn");
        } catch (e) {
          setRtErr(e && e.message ? e.message : "scan failed");
        }
      };
    }

    const stopScanBtn = $("rtStopScan");
    if (stopScanBtn) {
      stopScanBtn.onclick = () => stopScan();
    }

    const sendOfflineBtn = $("rtSendOffline");
    if (sendOfflineBtn) {
      sendOfflineBtn.onclick = async () => {
        setRtErr("");
        try {
          await sendOfflineSelectedFiles();
        } catch (e) {
          setRtErr(e && e.message ? e.message : "offline send failed");
        }
      };
    }
  }

  function registerServiceWorker() {
    if (!("serviceWorker" in navigator)) return;
    navigator.serviceWorker.register("/sw.js").catch(() => {
      // ignore service worker registration failures in unsupported contexts.
    });
  }

  function installErrorHooks() {
    if (window.__xsendRtErrHooksInstalled) return;
    window.__xsendRtErrHooksInstalled = true;

    window.addEventListener("error", (ev) => {
      const msg = ev && ev.message ? String(ev.message) : "unknown script error";
      setRtErr(`js error: ${msg}`);
    });

    window.addEventListener("unhandledrejection", (ev) => {
      const reason = ev && ev.reason;
      const msg = reason && reason.message ? String(reason.message) : String(reason || "unhandled rejection");
      setRtErr(`promise error: ${msg}`);
    });
  }

  function initValues() {
    setVal("rtDeviceName", state.peerName);
    setVal("rtScope", state.scope);
    setModeBadge();
    setModeButtons();
    setAutoPanels();
    setText("rtSelfId", "-");
    setText("rtSelectedPeer", "-");
    setTransferStatus("no transfer");
    setText("rtOfflineFp", "fingerprint: -");
    clearQrBox("rtOfferQr", "Offer QR will appear here");
    clearQrBox("rtAnswerQr", "Answer QR will appear here");
    renderPeers();
  }

  function init() {
    if (!$("rtModeAuto")) return;
    state.peerId = state.peerId || randomPeerId();
    state.peerName = state.peerName || defaultDeviceName();

    installErrorHooks();

    safeStorageSet("xsend.rt.peer_id", state.peerId);
    safeStorageSet("xsend.rt.peer_name", state.peerName);
    safeStorageSet("xsend.rt.scope", state.scope);

    initValues();
    setupEvents();
    refreshFeatureGates().catch(() => null);
    registerServiceWorker();
    setTimeout(() => prewarmOfflineCodecs(), OFFLINE_PREWARM_DELAY_MS);

    state.mode = "auto";
    setModeBadge();
    setModeButtons();
    setAutoPanels();
    startAutoDiscovery();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
