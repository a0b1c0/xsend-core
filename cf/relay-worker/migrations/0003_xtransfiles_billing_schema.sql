-- xsend billing schema (Stripe checkout/webhook/invoice persistence)
-- Apply after 0001_xsend_relay_schema.sql

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS xsend_billing_customers (
  client_id TEXT PRIMARY KEY,
  stripe_customer_id TEXT NOT NULL UNIQUE,
  email TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_xsend_billing_customers_customer
  ON xsend_billing_customers(stripe_customer_id);

CREATE TABLE IF NOT EXISTS xsend_billing_subscriptions (
  stripe_subscription_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  status TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'pro',
  current_period_start_ms INTEGER,
  current_period_end_ms INTEGER,
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_subscriptions_client
  ON xsend_billing_subscriptions(client_id, updated_at_ms DESC);

CREATE TABLE IF NOT EXISTS xsend_billing_invoices (
  stripe_invoice_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  status TEXT NOT NULL,
  amount_due INTEGER NOT NULL DEFAULT 0,
  amount_paid INTEGER NOT NULL DEFAULT 0,
  currency TEXT,
  hosted_invoice_url TEXT,
  invoice_pdf_url TEXT,
  period_start_ms INTEGER,
  period_end_ms INTEGER,
  created_at_ms INTEGER,
  paid_at_ms INTEGER,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_invoices_client
  ON xsend_billing_invoices(client_id, created_at_ms DESC);

CREATE TABLE IF NOT EXISTS xsend_billing_events (
  stripe_event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  received_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_xsend_billing_events_type_time
  ON xsend_billing_events(event_type, received_at_ms DESC);
