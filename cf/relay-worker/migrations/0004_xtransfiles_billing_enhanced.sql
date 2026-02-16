-- xsend billing enhanced schema
-- Apply after 0003_xsend_billing_schema.sql

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS xsend_billing_charge_links (
  stripe_charge_id TEXT PRIMARY KEY,
  stripe_payment_intent_id TEXT,
  client_id TEXT NOT NULL,
  source_invoice_id TEXT,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_charge_links_client
  ON xsend_billing_charge_links(client_id, updated_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_charge_links_payment_intent
  ON xsend_billing_charge_links(stripe_payment_intent_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS xsend_billing_refunds (
  stripe_refund_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  stripe_charge_id TEXT,
  stripe_payment_intent_id TEXT,
  status TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 0,
  currency TEXT,
  reason TEXT,
  failure_reason TEXT,
  receipt_number TEXT,
  created_at_ms INTEGER,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_refunds_client
  ON xsend_billing_refunds(client_id, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_refunds_charge
  ON xsend_billing_refunds(stripe_charge_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS xsend_billing_disputes (
  stripe_dispute_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  stripe_charge_id TEXT,
  status TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 0,
  currency TEXT,
  reason TEXT,
  evidence_due_by_ms INTEGER,
  is_charge_refundable INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_disputes_client
  ON xsend_billing_disputes(client_id, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_disputes_charge
  ON xsend_billing_disputes(stripe_charge_id, updated_at_ms DESC);
