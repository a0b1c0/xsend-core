-- xsend client_type backfill for existing xadmin databases.
--
-- Run this script ONCE on environments where `clients.client_type` does not exist yet.
-- If the column already exists, skip this script.

ALTER TABLE clients ADD COLUMN client_type TEXT;

UPDATE clients
SET client_type = 'xsend'
WHERE client_type IS NULL OR trim(client_type) = '';
