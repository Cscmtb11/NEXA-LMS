-- ==========================================================
-- Migration 0006: Add Address column to Patients Table
-- ==========================================================

ALTER TABLE patients ADD COLUMN address TEXT;
