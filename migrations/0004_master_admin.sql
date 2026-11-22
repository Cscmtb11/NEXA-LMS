-- Migration 0004: Seed Master Platform Administrator for SpringNexa
-- Master Login: admin@springnexa.in
-- Initial Password: SpringNexa@2026

INSERT INTO users (id, tenant_id, username, email, full_name, role, password_hash, password_salt, status, created_at)
VALUES (
  'USR_MASTER_SPRINGNEXA',
  'master',
  'admin@springnexa.in',
  'admin@springnexa.in',
  'SpringNexa Master Administrator',
  'SUPER_ADMIN',
  'e9057183404b5c21282997f8549f125f6c4a344f883b9efc46a5026f75df7b52',
  'salt_springnexa_master',
  'ACTIVE',
  datetime('now')
)
ON CONFLICT(username) DO UPDATE SET
  email = excluded.email,
  full_name = excluded.full_name,
  role = 'SUPER_ADMIN',
  password_hash = excluded.password_hash,
  password_salt = excluded.password_salt,
  status = 'ACTIVE';
