-- xsend relay schema baseline
-- Safe to run on a clean database or an existing xadmin DB where core tables already exist.

PRAGMA foreign_keys = ON;

-- Note:
-- Existing xadmin deployments should already include `clients.client_type`.
-- If your clients table does not have this column, add it manually before running app logic:
--   ALTER TABLE clients ADD COLUMN client_type TEXT;

CREATE TABLE IF NOT EXISTS xsend_client_identities (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  client_id TEXT NOT NULL,
  email TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS idx_xsend_identities_client_id
  ON xsend_client_identities(client_id);

CREATE TABLE IF NOT EXISTS xsend_relay_channels (
  client_id TEXT PRIMARY KEY,
  code TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_xsend_relay_channels_code
  ON xsend_relay_channels(code);

CREATE TABLE IF NOT EXISTS xsend_client_plans (
  client_id TEXT NOT NULL,
  plan TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  max_files INTEGER,
  max_file_bytes INTEGER,
  max_total_bytes INTEGER,
  file_ttl_seconds INTEGER,
  starts_at_ms INTEGER,
  expires_at_ms INTEGER,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (client_id, plan)
);

CREATE INDEX IF NOT EXISTS idx_xsend_client_plans_active
  ON xsend_client_plans(client_id, status, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS xsend_usage_daily (
  client_id TEXT NOT NULL,
  date_key TEXT NOT NULL,
  upload_bytes INTEGER NOT NULL DEFAULT 0,
  download_bytes INTEGER NOT NULL DEFAULT 0,
  upload_files INTEGER NOT NULL DEFAULT 0,
  download_files INTEGER NOT NULL DEFAULT 0,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (client_id, date_key)
);

CREATE INDEX IF NOT EXISTS idx_xsend_usage_daily_date
  ON xsend_usage_daily(date_key);
