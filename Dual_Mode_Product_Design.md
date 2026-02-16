# xSend Dual-Mode Product Design

Updated: 2026-02-16

## 1. Goal

Under the constraint of "no app installation, browser-only access to `xsend.com`", provide a dual-mode transfer experience:

1. Default mode: Auto-Discovery
2. Fallback mode: Offline Direct

Core requirements:

- Frictionless default: open the page and immediately see connectable devices
- Works without internet: end-to-end direct transfer must still work on a fully offline LAN
- Security first: end-to-end encryption with minimal server visibility

## 2. Mode One: Auto-Discovery (Default)

### 2.1 User Flow

Scenario: phone and laptop are on the same Wi-Fi, with internet access.

1. Both sides open `xsend.com`
2. Browser Wasm/JS connects to Worker signaling
3. Signaling assigns a room by shared public IP (optional scope)
4. Both sides complete WebRTC negotiation automatically
5. The page shows nearby peers directly; user clicks and sends files

Result: file data prefers LAN P2P, while signaling control flows through the Worker.

### 2.2 Current Backend Baseline (Implemented)

- Worker auto-discovery signaling APIs:
  - `GET /api/v1/realtime/auto/info`
  - `GET /api/v1/realtime/auto/ws`
- Durable Object: `SignalAutoDO`
- Message types:
  - Uplink: `ping` / `list` / `meta` / `signal`
  - Downlink: `welcome` / `peers` / `peer_join` / `peer_leave` / `peer_update` / `signal`

## 3. Mode Two: Offline Direct (Offline Mode)

### 3.1 User Flow

Scenario: airplane, basement, fully offline LAN, or users who do not trust public signaling.

1. User switches to "Offline Mode"
2. Sender creates a local session and generates QR/short code (connection descriptor + ephemeral public key)
3. Receiver clicks "Scan" and uses camera scanning
4. Both browsers complete local session negotiation and key confirmation
5. Establish P2P data channel and transfer files

Result: no dependency on public signaling servers, fully offline path.

### 3.2 Technical Constraints

- In a fully offline state, first-load web access is unavailable; requires one of:
  - already-open page kept alive without refresh, or
  - PWA offline shell (Service Worker + pre-cached core assets)
- QR payload size must be controlled strictly (recommended compression + chunking)

## 4. Security Design (Shared by Both Modes)

- Session-level ephemeral keys (regenerated for every connection)
- E2EE:
  - key exchange: X25519
  - KDF: HKDF-SHA256
  - data encryption: ChaCha20-Poly1305
- Fingerprint confirmation:
  - show short fingerprint on first connection (4-6 words or 12-char short code) for MITM resistance
- Minimal logging:
  - signaling layer records only required diagnostics, no persisted SDP/file content

## 5. Routing Strategy (Browser Side)

Recommended order:

1. Same-network direct connection (WebRTC host candidate)
2. TURN for complex networks (tiered by plan if needed)
3. Fallback to R2 Relay when all P2P attempts fail (authenticated users)

Notes:

- TURN is a data-plane relay, not just handshake assistance
- Capability tiering can happen at TURN stage; Relay remains final availability fallback

## 6. Delivery Breakdown

P0 (Completed):

- Auto-discovery signaling backend (Worker + DO) is online

P1 (Completed, baseline):

- Browser auto-discovery UI (peer list, auto dial, manual connect)
- WebRTC DataChannel file transfer (chunking, progress, send/receive lists)

P2 (Completed, baseline):

- Offline Mode:
  - local offer/answer encoding (`XSO2`, with gzip payload support)
  - QR generation (`fast_qr` WebAssembly) and camera scan (`BarcodeDetector` when available)
  - Service Worker offline shell (reusable offline after first online load)

P3 (Completed):

- Fingerprint confirmation UI (both Auto and Offline before send)
- Offline code compression/chunking (`XSO3` fragment aggregation + QR fragment scan reassembly)
- Unified fallback path: `P2P -> TURN (forced relay ICE) -> Relay upload`

## 7. Acceptance Criteria

- Auto-Discovery mode:
  - two devices on same network discover each other and start transfer within 30 seconds
- Offline mode:
  - transfer can be established without any public network dependency
- Security:
  - file content and keys are never stored on servers in plaintext
- Stability:
  - fallback behavior is reliable under unstable network conditions
