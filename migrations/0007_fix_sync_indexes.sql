-- 0007_fix_sync_indexes.sql
-- Fixes sync compatibility for expenses and tariffs
ALTER TABLE expenses ADD COLUMN updated_at TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tariffs_tenant_code ON tariffs (tenant_id, code);
