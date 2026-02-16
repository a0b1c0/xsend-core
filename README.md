# xSend (Spec v3.1 MVP Skeleton)

This repository currently contains a minimal daemon skeleton based on
`Rust_File_Transfer_Final_Spec_v3_1.md`:

- Daemon binds to `127.0.0.1` on a random port
- Generates an admin token at startup
- Serves a localhost Web UI
- Provides a simple job queue with free-tier limits (max 5 running jobs, global 16 streams)
- LAN direct transfer (TCP) with:
  - 6-digit receive code for session matching
  - X25519 + HKDF-SHA256 + ChaCha20-Poly1305 (application-layer E2EE)
  - 2MiB chunking + per-chunk BLAKE3 + final file BLAKE3 verification
- Transfer queue (max 5 concurrent transfers)
- Pending send transfers are persisted and auto-restored after daemon restart (`~/.xsend/transfers_recovery.json`)
- `send_by_code` supports relay fallback when LAN peers are unavailable (requires relay sign-in token)
- Built-in Prometheus-style daemon metrics at `GET /api/v1/metrics` (admin local API)

## Run

```bash
cargo run
```

It prints a local URL like:

- `open UI: http://127.0.0.1:<port>/`

The UI sets an `HttpOnly` cookie automatically, so you don't need to paste tokens.
For API/CLI use, set `XSEND_PRINT_ADMIN_TOKEN=1` if you need the full token in stdout.
By default startup logs only print a masked token hint.

## Discovery Backend Modes

Discovery now supports dual backends:

- `native` (default on native builds): UDP LAN discovery (IPv4 broadcast + IPv6 multicast)
- `web`: Cloudflare Worker signaling (`/api/v1/realtime/auto/ws`) for browser/Wasm-compatible discovery wiring
- `off`: disable discovery

Use env vars:

```bash
XSEND_DISCOVERY_MODE=web cargo run
```

- Optional `XSEND_DISCOVERY_SIGNAL_BASE_URL` overrides signaling base (falls back to `XSEND_RELAY_BASE_URL`, then default public relay)
- Optional `XSEND_DISCOVERY_SCOPE` pins clients into a smaller signaling room scope

## Quick LAN Test (Same Machine)

1. Start daemon A: `cargo run`
2. Start daemon B in another terminal: `cargo run`
3. Open daemon B UI, click `Create receive code`, note:
   - `lan port`
   - `receive code`
4. Open daemon A UI:
   - `Receiver addr`: `127.0.0.1:<lan_port_from_B>`
   - `Code`: `<receive_code_from_B>`
   - `Absolute file path`: pick a file
   - Click `Send file`

Received files are saved under `~/.xsend/downloads` on the receiver.

## Cloud Relay (R2 Transfer Station)

This repo includes a Cloudflare Worker that provides a simple relay station (free tier: max 5 files
per relay, each <= 10MiB, total <= 50MiB, stored for 7 days):

- `/Users/minhu/Rust/xsend/cf/relay-worker`

It serves a public page where users sign in, then upload/download, backed by R2 + Durable Objects.
OAuth (Google/GitHub/Apple) can be enabled via Worker vars/secrets.
Stripe checkout/webhook + invoice/refund/dispute persistence APIs are included for paid plan activation and reconciliation export.
Browser "dual-mode" shape (Auto-Discovery + Offline Mode) design is documented in `/Users/minhu/Rust/xsend/Dual_Mode_Product_Design.md`.

Public page now also includes a no-login "Quick Link" section:

- Auto-Discovery: same-WiFi peers auto-discover and WebRTC-connect
- Offline Mode: local offer/answer code flow with QR generate/scan helpers

## Desktop (Tauri 2)

A minimal Tauri 2 desktop wrapper is included:

- `/Users/minhu/Rust/xsend/desktop`

It starts the local daemon and opens the daemon UI inside a WebView (no manual port/token copy).

## API (requires `Authorization: Bearer <token>`)

- `GET /api/v1/info`
- `GET /api/v1/metrics`
- `GET /api/v1/jobs`
- `POST /api/v1/jobs` body: `{ "path": "/absolute/path", "network": "lan" | "wan" }`
- `POST /api/v1/jobs/:id/pause`
- `POST /api/v1/jobs/:id/resume`
- `POST /api/v1/jobs/:id/cancel`
- `GET /api/v1/sessions`
- `POST /api/v1/sessions/receive`
- `GET /api/v1/transfers`
- `POST /api/v1/transfers/send` body: `{ "addr": "ip:port", "code": "123456", "path": "/absolute/path" }`
- `POST /api/v1/transfers/send_wan` body: `{ "addr": "ip:port", "code": "123456", "path": "/absolute/path" }` (QUIC data plane)
- `POST /api/v1/transfers/send_by_code` body: `{ "code": "123456", "path": "/absolute/path" }`
  - route order: `LAN -> WAN -> Relay`
  - optional header: `x-relay-token: <jwt>`
  - optional header: `x-relay-fallback: 1` (force cloud fallback for this request)
  - optional header: `x-relay-auto-on-fail: 1` (default `1`; when direct transfer fails, auto upload to relay in background)
  - optional header: `x-turn-accelerate: 1` (optional TURN preflight check; does not carry file data yet)
- `GET /api/v1/relay/me/plan` (requires `x-relay-token`)
- `GET /api/v1/relay/me/billing` (requires `x-relay-token`)
- `GET /api/v1/relay/turn/credentials?ttl=600` (requires `x-relay-token`)
- `POST /api/v1/relay/me/upload` body:
  - file: `{ "path": "/absolute/file" }`
  - folder batch: `{ "path": "/absolute/dir", "recursive": true, "include_hidden": false }`
  - folder mode preserves relative directory structure when pulling back to local
- `POST /api/v1/relay/me/pull_all` body: `{}` (downloads current channel files to local relay download dir)
- `GET /api/v1/transfers/:id`
- `POST /api/v1/transfers/:id/cancel`
