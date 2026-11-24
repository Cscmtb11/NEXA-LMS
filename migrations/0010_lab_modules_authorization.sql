-- ==========================================================
-- Migration 0010: Tenant Module Authorization (Clinical, Patho, Biochem, Neuro)
-- ==========================================================

-- Add modules column to tenants table
-- Stored as comma-separated list of enabled modules: NEURO,CLINICAL,PATHO,BIOCHEM
ALTER TABLE tenants ADD COLUMN modules TEXT DEFAULT 'NEURO,CLINICAL,PATHO,BIOCHEM';

-- Update existing default tenant to have all modules enabled
UPDATE tenants SET modules = 'NEURO,CLINICAL,PATHO,BIOCHEM' WHERE modules IS NULL OR modules = '';
