-- ==========================================================
-- Migration 0005: First Login Password Change Requirement & Tracking
-- ==========================================================

ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN password_changed_at TEXT;
