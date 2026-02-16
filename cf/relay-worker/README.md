# xsend relay worker (Cloudflare Workers + R2 + Durable Objects)

This is a minimal "transfer station" (relay) for xsend:

- Public web page: **sign in**, then upload/download files (no manual code entry)
- Free-tier limits: **max 5 files per relay**, **each <= 10MiB**, **total <= 50MiB**, **stored for 7 days**, file type unrestricted
- Storage: R2 (objects), Durable Object (per-code metadata + quota enforcement)
- Auth/users: Cloudflare D1 (xadmin DB) `clients` + `xsend_client_identities`
- Tier limits: resolved per user via `clients.client_type` and optional `xsend_client_plans`

## Local Dev

```bash
cd cf/relay-worker
npm install
npm run dev
```

Then open the printed local URL.

## Deploy

1. Ensure Wrangler is authenticated:
```bash
npx wrangler whoami
```

2. Create an R2 bucket:
```bash
npx wrangler r2 bucket create xsend-relay
```

3. Deploy:
```bash
npm run deploy
```

## D1 Schema Migration

Apply the baseline xsend relay schema (identities/channels/plans/usage):

```bash
npx wrangler d1 execute xadmin-db-v2 --file ./migrations/0001_xsend_relay_schema.sql
```

For existing databases that do not yet have `clients.client_type`, run:

```bash
npx wrangler d1 execute xadmin-db-v2 --file ./migrations/0002_clients_client_type_backfill.sql
```

Apply billing schema (Stripe customer/subscription/invoice/event tables):

```bash
npx wrangler d1 execute xadmin-db-v2 --file ./migrations/0003_xsend_billing_schema.sql
```

Apply billing enhanced schema (charge mapping + refund/dispute persistence):

```bash
npx wrangler d1 execute xadmin-db-v2 --file ./migrations/0004_xsend_billing_enhanced.sql
```

Or apply all migrations in order:

```bash
./scripts/apply-migrations.sh xadmin-db-v2 remote
```

Use `local` as the second arg for local dev DB:

```bash
./scripts/apply-migrations.sh xadmin-db-v2 local
```

## OAuth (optional)

OAuth buttons are shown in the UI, but will be disabled until configured.

### Google / GitHub

- Vars (in `wrangler.jsonc`): `GOOGLE_CLIENT_ID`, `GITHUB_CLIENT_ID`
- Secrets: `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_SECRET`

### Apple

- Vars (in `wrangler.jsonc`): `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID`
- Secret: `APPLE_PRIVATE_KEY` (the `.p8` PEM)

## Stripe Billing (optional)

Set the following vars/secrets:

- Vars: `STRIPE_PRICE_ID`, `BILLING_SUCCESS_URL`, `BILLING_CANCEL_URL`, `BILLING_PORTAL_RETURN_URL` (optional)
- Secrets: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`

Webhook endpoint:

- `POST /api/v1/billing/stripe/webhook`

## Realtime (Browser Auto-Discovery)

These endpoints support the browser-only "Auto-Discovery" mode:

- `GET /api/v1/realtime/auto/info` -> returns mode metadata and ws path
- `GET /api/v1/realtime/auto/ws` -> websocket signaling channel

Rooming policy:

- Worker groups peers by public IP (`CF-Connecting-IP`) and optional `scope` query.
- Clients under the same public IP + scope share the same signaling room.

WebSocket query params:

- `peer_id` (optional, `[a-zA-Z0-9_-]{1,64}`)
- `name` (optional, display name, max 64 chars)
- `scope` (only on `/auto/ws`; max 32 chars, used in room partition)

Signal messages:

- Client -> server:
  - `{ "type": "ping" }`
  - `{ "type": "list" }`
  - `{ "type": "meta", "name": "Alice" }`
  - `{ "type": "signal", "to": "<peer_id>", "kind": "connect_request|connect_otp_required|connect_otp_submit|connect_grant|connect_reject|offer|answer|ice", "payload": {...} }`
- Server -> client:
  - `welcome`, `peers`, `peer_join`, `peer_leave`, `peer_update`, `signal`, `pong`, `error`

Offline mode note:

- The fully offline QR/scan mode is a browser-side flow and does not require these endpoints.
- Public page (`/`) includes "Quick Link (No Login)" with:
  - Auto-Discovery peer list with explicit request/authorization handshake before WebRTC session setup
  - Offline offer/answer code flow (supports `XSO3` shard codes + QR part scan stitching)
  - Fingerprint confirmation before sending files (first-connection anti-MITM check)
  - Auto route fallback policy: P2P -> TURN (forced relay ICE) -> Relay upload (signed-in users)
  - Service Worker shell (`/sw.js`) for first-load-then-offline usage

## API

- `POST /api/v1/channel` -> create a new code
- `GET /api/v1/channel/<code>` -> list files
- `POST /api/v1/channel/<code>/files?name=...` -> upload (raw body)
- `POST /api/v1/channel/<code>/files?name=...&rel=dir/sub/file.ext` -> upload with relative path metadata
- `GET /api/v1/channel/<code>/files/<fileId>` -> download
- `DELETE /api/v1/channel/<code>/files/<fileId>` -> delete

## Logged-in API

- `GET /api/v1/auth/me`
- `GET /api/v1/me/plan` -> resolved plan limits + feature flags + today's usage
- `GET /api/v1/me/billing` -> monthly usage + estimated cost
- `GET /api/v1/me/billing/invoices` -> invoice list for current user
- `GET /api/v1/me/billing/refunds` -> refund list for current user
- `GET /api/v1/me/billing/disputes` -> dispute list for current user
- `GET /api/v1/me/billing/report?month=YYYY-MM&format=json|csv` -> monthly reconciliation report/export
- `POST /api/v1/me/billing/checkout` -> create Stripe Checkout Session
- `POST /api/v1/me/billing/portal` -> create Stripe Billing Portal session
- `POST /api/v1/me/billing/subscription/cancel` -> set `cancel_at_period_end=true`
- `POST /api/v1/me/billing/subscription/resume` -> set `cancel_at_period_end=false`
- `GET /api/v1/me/channel` -> allocate/ensure your relay (6-digit) and list files
- `POST /api/v1/me/files?name=...` -> upload
- `GET /api/v1/me/files/<fileId>` -> download
- `DELETE /api/v1/me/files/<fileId>` -> delete

## E2EE Pairing API (for relay client key exchange)

- `POST /api/v1/e2ee/pair/start` body: `{ "pubkey": "<base64url 32-byte x25519 pubkey>" }`
- `GET /api/v1/e2ee/pair/<code>` -> get pair status + receiver pubkey
- `POST /api/v1/e2ee/pair/<code>/complete` body:
  `{ "sender_pubkey": "...", "nonce": "<base64url 12 bytes>", "ciphertext": "..." }`
- `GET /api/v1/e2ee/pair/<code>/result` -> fetch encrypted sender key bundle

All pairing records are ephemeral and expire automatically (10 minutes).

## Tiered Limits

Default free tier comes from:

- `MAX_FILES`
- `MAX_FILE_BYTES`
- `MAX_TOTAL_BYTES`
- `FILE_TTL_SECONDS`

Paid/default pro tier comes from:

- `PRO_MAX_FILES`
- `PRO_MAX_FILE_BYTES`
- `PRO_MAX_TOTAL_BYTES`
- `PRO_FILE_TTL_SECONDS`

Billing defaults come from:

- `BILLING_UPLOAD_PER_GB_USD`
- `BILLING_DOWNLOAD_PER_GB_USD`
- `BILLING_FREE_QUOTA_GB`

E2EE transport allowance (for ciphertext overhead) comes from:

- `E2EE_OVERHEAD_BYTES` (default 16384)

Feature gating:

- `TURN_REQUIRE_PAID`:
  - `0` (default): any logged-in user can request TURN credentials
  - `1`: only paid plan users can request TURN credentials (`/api/v1/turn/credentials` returns `402` for free)
- `RELAY_UPLOAD_REQUIRE_PAID`:
  - `0` (default): any logged-in user can upload
  - `1`: `POST /api/v1/me/files` requires paid plan
- `RELAY_DOWNLOAD_REQUIRE_PAID`:
  - `0` (default): any logged-in user can list/download relay files
  - `1`: `GET /api/v1/me/channel` and `GET /api/v1/me/files*` require paid plan
- `RELAY_E2EE_REQUIRE_PAID`:
  - `0` (default): relay E2EE pair APIs are available to all logged-in users
  - `1`: `/api/v1/e2ee/pair/*` requires paid plan
- `RELAY_BATCH_REQUIRE_PAID`:
  - `0` (default): folder/batch upload is available
  - `1`: upload with `rel=...` (batch/folder mode) requires paid plan
- `AUTO_DISCOVERY_REQUIRE_PAID`:
  - `0` (default): quick-link auto discovery works without login
  - `1`: `/api/v1/realtime/auto/info|ws` requires signed-in paid users
- `OFFLINE_MODE_REQUIRE_PAID`:
  - `0` (default): offline mode is enabled by default in feature flags
  - `1`: paid-only offline-mode flag is returned from `/api/v1/me/plan`

Per-user overrides can be stored in `xsend_client_plans` (highest `updated_at_ms`, active, not expired).
