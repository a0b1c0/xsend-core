# Rust Cross-Platform File Transfer System

## Architecture Spec v3.2 (Implemented Baseline + Gap List)

Updated: 2026-02-16

--------------------------------------------------------------------------

## 1. Document Scope

This version is not an idealized target list. It is the implementation baseline reflected by the current repository.
The purpose is to keep the design document aligned with shipped code and to make open gaps explicit.

--------------------------------------------------------------------------

## 2. Current System Architecture (Implemented)

- Core language: Rust
- Local resident service: `xsend` daemon
- Local UI: localhost Web UI (served by daemon)
- Desktop wrapper: Tauri 2.0 (starts daemon and embeds WebView)
- Cloud relay: Cloudflare Worker + Durable Objects + R2 + D1

Key boundaries:

- Control plane HTTP: listens only on `127.0.0.1` random port
- LAN data plane TCP: listens on `0.0.0.0` random port (for direct LAN transfer)

--------------------------------------------------------------------------

## 3. Transfer Path Status (By Actual Implementation)

Implemented:

- LAN direct transfer (custom TCP protocol)
- WAN direct transfer (QUIC data plane)
- Cloud relay (R2 relay channel per authenticated user)
- Relay file end-to-end encryption (local encrypt upload, local decrypt download)
- Baseline auto-routing: `LAN -> WAN`, with automatic Relay fallback on failure (requires auth token)
- Browser auto-discovery signaling backend baseline (Worker `SignalAutoDO` + WebSocket)
- Browser auto-discovery frontend (no-login peer discovery + WebRTC DataChannel transfer)
- Browser Offline Mode baseline (offer/answer code, QR generate/scan, offline shell)

Not yet implemented:

- TURN as an actual file data-plane relay
- TURN-integrated automatic data-plane routing (currently TURN preflight + credentials only)
- Offline-code compression/chunking and fingerprint confirmation were baseline only and later expanded

Notes:

- TURN is still not carrying real file streams in the current core daemon pipeline.
- `send_by_code` already supports automatic background Relay fallback after direct-transfer failure (`x-relay-auto-on-fail`).

--------------------------------------------------------------------------

## 4. Cryptography and Security (Current)

LAN transfer:

- X25519 key exchange
- HKDF-SHA256 session key derivation
- ChaCha20-Poly1305 encrypted data frames
- Per-chunk BLAKE3 + final file BLAKE3 verification

Relay transfer:

- 32-byte local file key maintained per relay channel
- Encrypted file envelope header: `XSR1`
- File encryption: ChaCha20-Poly1305
- Device pairing: X25519 + HKDF + ChaCha20-Poly1305 wrapping of file key

Local control plane security:

- Admin token generated at daemon startup
- HttpOnly cookie auto-issued on first UI access
- API requires admin token (Bearer or cookie)
- Origin allowlist validation

--------------------------------------------------------------------------

## 5. Free-Tier Policy (Current)

Relay (R2 station) limits:

- Max file count: 5
- Max single file size: 10 MiB
- Max total storage: 50 MiB
- Retention: 7 days
- File type: unrestricted

Cleanup mechanism:

- Durable Object timed cleanup via `alarm()`
- Lazy cleanup on access
- Expired object and metadata deletion in sync

--------------------------------------------------------------------------

## 6. Account and Login (Current)

Implemented:

- Username/password registration and login
- Logged-in users do not need manual relay code input (`/api/v1/me/channel` auto-assigned)
- `clients.client_type` written/backfilled as `xsend`

OAuth code status:

- Google: implemented; configured in current environment
- GitHub: implemented; not configured in current environment
- Apple: implemented; not configured in current environment

--------------------------------------------------------------------------

## 7. API Status Summary

daemon local APIs (subset):

- `GET /api/v1/info`
- `POST /api/v1/sessions/receive`
- `POST /api/v1/transfers/send_by_code`
- `POST /api/v1/transfers/send_wan`
- `POST /api/v1/relay/me/upload`
- `POST /api/v1/relay/me/pull_all`
- `GET /api/v1/relay/e2ee/status`
- `POST /api/v1/relay/e2ee/pair/start`
- `POST /api/v1/relay/e2ee/pair/:code/send`
- `POST /api/v1/relay/e2ee/pair/:code/accept`

worker cloud APIs (subset):

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/providers`
- `GET /api/v1/me/channel`
- `POST /api/v1/me/files?name=...`
- `GET /api/v1/me/files/:id`
- `GET /api/v1/me/billing/invoices`
- `GET /api/v1/me/billing/refunds`
- `GET /api/v1/me/billing/disputes`
- `GET /api/v1/me/billing/report?month=YYYY-MM&format=json|csv`
- `POST /api/v1/me/billing/checkout`
- `POST /api/v1/me/billing/portal`
- `GET /api/v1/realtime/auto/info`
- `GET /api/v1/realtime/auto/ws`
- `POST /api/v1/me/billing/subscription/cancel`
- `POST /api/v1/me/billing/subscription/resume`
- `GET /api/v1/turn/credentials`
- `POST /api/v1/billing/stripe/webhook`
- `POST /api/v1/e2ee/pair/start`
- `GET /api/v1/e2ee/pair/:code`
- `POST /api/v1/e2ee/pair/:code/complete`
- `GET /api/v1/e2ee/pair/:code/result`

--------------------------------------------------------------------------

## 8. Completion Checklist

Completed:

- Local daemon startup on random port with automatic UI attach
- 6-digit receive code and LAN auto-discovery send flow (`send_by_code`)
- WAN QUIC send path (`/api/v1/transfers/send_wan`)
- `send_by_code` route order `LAN -> WAN`, with automatic Relay fallback on failure (configurable)
- Relay authenticated upload/download without manual code
- Relay free-tier quotas and 7-day auto cleanup
- Relay E2EE pairing and encrypted/decrypted file stream support
- TURN credentials API available
- Quota tier parsing by `client_type/plan` (free/pro)
- Daily/monthly usage metering and billing estimate API (`/api/v1/me/billing`) with UI surface
- Stripe baseline billing loop (Checkout + webhook signature verification + subscription/invoice persistence)
- Stripe enhanced billing loop (Billing Portal, subscription cancel/resume, refund/dispute persistence, monthly reconciliation export)
- E2EE upload ciphertext overhead channel (`x-xsend-e2ee` + configurable overhead) with dynamic quota precheck
- Relay directory batch upload and channel batch pull (relative directory structure preserved)
- D1 migration sequence extension (`0001` to `0004`) and one-step migration script (`scripts/apply-migrations.sh`)
- Crash recovery for send tasks (daemon restart auto-recovers unfinished send/send_wan/send_by_code tasks)
- Baseline observability (`/api/v1/metrics` Prometheus text metrics + key flow counters)
- Feature gate baseline (plan-based features, supports `TURN_REQUIRE_PAID` for paid TURN credentials gating)
- Browser dual-mode page (Auto-Discovery + Offline Mode) with end-to-end local send/receive loop
- Service Worker offline shell (reusable after first online load)
- Tauri 2.0 desktop shell project

Completed in the latest baseline pass:

- TURN data-channel integration at browser layer (Auto-Discovery adds forced TURN relay-ICE redial path)
- Unified automatic route fallback to `P2P -> TURN -> Relay` (Relay fallback when TURN fails)
- Dual-mode security enhancements (connection fingerprint confirmation, offline code compression/chunking, QR fragment assembly)
- Free/paid capability gating down to feature level (upload/download/e2ee/batch/auto-discovery/offline)
- Observability enhancement (auto-route dimension metrics + structured route logs)

--------------------------------------------------------------------------

## 9. Suggested Next Phase Order (Non-Blocking Enhancements)

P0:

- TURN channel stability stress tests (complex NAT, mobile network switching)

P1:

- Complete tax granularity (multi-rate/region rules) and dispute automation strategy
- Complete GitHub/Apple production configuration and callback validation

P2:

- Stronger crash recovery and cross-restart resume behavior
- Full folder-mode and batch-task UX completion
- Add dashboards, log aggregation, and alerting strategy

--------------------------------------------------------------------------

## END
