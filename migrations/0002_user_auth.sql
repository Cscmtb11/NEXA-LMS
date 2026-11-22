-- ==========================================================
-- Migration 0002: User Authentication & Role Management
-- ==========================================================

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'TECHNICIAN', -- 'ADMIN', 'DOCTOR', 'TECHNICIAN'
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  last_login_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);

-- Default Pre-Seeded Users
INSERT OR IGNORE INTO users (id, username, email, full_name, role, password_hash, password_salt, status, created_at)
VALUES 
(
  'USR_ADMIN',
  'admin',
  'admin@aljawahira.com',
  'Al-Jawahira Administrator',
  'ADMIN',
  '1a82233d9d94ee1bda69664ef3278c26f1b492c2231989cbeac811d5c352ede4',
  'salt_admin_2026',
  'ACTIVE',
  datetime('now')
),
(
  'USR_DOC_RAYEES',
  'dr.rayees',
  'rayees@aljawahira.com',
  'Dr. Rayees Ahmad Tarray',
  'DOCTOR',
  '8d3839986ad7e38be81f094b9598b0b0c3f499ea1234bf1e070021ce40bf9064',
  'salt_doc_2026',
  'ACTIVE',
  datetime('now')
),
(
  'USR_TECH_KULGAM',
  'tech.kulgam',
  'tech@aljawahira.com',
  'Clinical Technologist Desk',
  'TECHNICIAN',
  '2214da9a419272ca44eda2ba0e777cb8b1ed5fafb021f5058999d22fe04cef14',
  'salt_tech_2026',
  'ACTIVE',
  datetime('now')
);
