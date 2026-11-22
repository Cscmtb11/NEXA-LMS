-- ==========================================================
-- Migration 0003: Multi-Tenant Architecture & Demo Data Removal
-- ==========================================================

-- 1. Create Tenants Table
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  plan TEXT NOT NULL DEFAULT 'PRO',
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at TEXT NOT NULL
);

-- Seed Default Primary Organization / Tenant
INSERT OR IGNORE INTO tenants (id, name, slug, plan, status, created_at)
VALUES ('default', 'Al-Jawahira Neuro Workstation', 'al-jawahira', 'ENTERPRISE', 'ACTIVE', datetime('now'));

-- 2. Add tenant_id to all operational tables
ALTER TABLE users ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE facility_settings ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE reporting_doctors ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE tariffs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE patients ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE referral_partners ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE referral_payouts ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE ledger_entries ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE expenses ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

-- 3. Create Tenant Performance Indices
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_patients_tenant ON patients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_doctors_tenant ON reporting_doctors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tariffs_tenant ON tariffs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_referrals_tenant ON referral_partners(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant ON ledger_entries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_expenses_tenant ON expenses(tenant_id);

-- 4. Purge All Mock Demo Data (Fresh SaaS Zero State)
DELETE FROM patients;
DELETE FROM ledger_entries;
DELETE FROM referral_payouts;
DELETE FROM referral_partners;
DELETE FROM expenses;
