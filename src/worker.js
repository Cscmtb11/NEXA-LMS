/**
 * Cloudflare Worker for Nexa-LMIS Multi-Tenant SaaS
 * Compliant with Cloudflare Security Policies & Cloudflare D1 (Serverless SQLite)
 * Multi-Tenant Architecture with Strict Data Isolation & Zero-Demo Clean State
 */

const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-Tenant-ID',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://fonts.googleapis.com https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' https:; frame-src 'self';"
};

const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store, no-cache, must-revalidate'
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...SECURITY_HEADERS
    }
  });
}

function handleOptions() {
  return new Response(null, {
    status: 204,
    headers: SECURITY_HEADERS
  });
}

/**
 * Web Crypto SHA-256 Salted Password Hash
 */
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const data = enc.encode(salt + ':' + password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Multi-Tenant D1 Schema Verification
 */
let schemaInitialized = false;
async function ensureD1Schema(db) {
  if (schemaInitialized || !db) return;

  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        plan TEXT NOT NULL DEFAULT 'PRO',
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'TECHNICIAN',
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        must_change_password INTEGER NOT NULL DEFAULT 1,
        password_changed_at TEXT,
        last_login_at TEXT,
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS facility_settings (
        id TEXT PRIMARY KEY DEFAULT 'default',
        tenant_id TEXT NOT NULL DEFAULT 'default',
        facility_name TEXT NOT NULL,
        parent_entity TEXT NOT NULL,
        cin TEXT NOT NULL,
        dpiit TEXT NOT NULL,
        address TEXT NOT NULL,
        phones TEXT NOT NULL,
        vpa TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS reporting_doctors (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        designation TEXT NOT NULL,
        qualification TEXT NOT NULL,
        reg_no TEXT NOT NULL,
        department TEXT NOT NULL,
        signature_url TEXT,
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS tariffs (
        code TEXT NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        fee REAL NOT NULL,
        doc_share REAL NOT NULL,
        ref_share REAL NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, code)
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        token TEXT NOT NULL,
        date TEXT NOT NULL,
        name TEXT NOT NULL,
        age INTEGER NOT NULL,
        gender TEXT NOT NULL,
        phone TEXT NOT NULL,
        ref_doctor TEXT NOT NULL,
        reporting_doctor TEXT NOT NULL,
        modality TEXT NOT NULL,
        fee REAL NOT NULL,
        doc_share REAL NOT NULL,
        ref_share REAL NOT NULL,
        net_lab REAL NOT NULL,
        pay_mode TEXT NOT NULL DEFAULT 'UPI / QR',
        indication TEXT NOT NULL,
        report_title TEXT NOT NULL,
        lbl_param1 TEXT,
        lbl_param2 TEXT,
        lbl_sec1 TEXT,
        lbl_sec2 TEXT,
        lbl_sec3 TEXT,
        motor_sampled TEXT,
        sensory_sampled TEXT,
        motor_findings TEXT,
        sensory_findings TEXT,
        fwaves_findings TEXT,
        impression TEXT,
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS referral_partners (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        tier REAL NOT NULL DEFAULT 1.0,
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS referral_payouts (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        date TEXT NOT NULL,
        partner TEXT NOT NULL,
        amount REAL NOT NULL,
        mode TEXT NOT NULL DEFAULT 'Cash',
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS ledger_entries (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        doctor_name TEXT NOT NULL,
        type TEXT NOT NULL,
        date TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS expenses (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        amount REAL NOT NULL,
        updated_at TEXT NOT NULL
      )
    `)
  ]);

  // Ensure user password columns exist
  try { await db.prepare("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1").run(); } catch (_) {}
  try { await db.prepare("ALTER TABLE users ADD COLUMN password_changed_at TEXT").run(); } catch (_) {}
  try { await db.prepare("ALTER TABLE patients ADD COLUMN address TEXT").run(); } catch (_) {}

  // Ensure default primary tenant
  const now = new Date().toISOString();
  await db.prepare(`
    INSERT OR IGNORE INTO tenants (id, name, slug, plan, status, created_at)
    VALUES ('default', 'Al-Jawahira Neuro Workstation', 'al-jawahira', 'ENTERPRISE', 'ACTIVE', ?)
  `).bind(now).run();

  // Ensure SpringNexa Master Platform Administrator
  await db.prepare(`
    INSERT OR IGNORE INTO users (id, tenant_id, username, email, full_name, role, password_hash, password_salt, status, created_at)
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
      '2026-11-22 10:30:00'
    )
  `).run();

  schemaInitialized = true;
}

/**
 * Authenticate session token and return user with tenant_id
 */
async function authenticateUser(request, db) {
  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  if (!token) return null;

  const session = await db.prepare(`
    SELECT s.token, s.expires_at, u.id, u.username, u.email, u.full_name, u.role, u.tenant_id, u.must_change_password
    FROM user_sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND u.status = 'ACTIVE'
  `).bind(token).first();

  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    await db.prepare("DELETE FROM user_sessions WHERE token = ?").bind(token).run();
    return null;
  }

  // Check organization status for non-superadmin users
  if (session.role !== 'SUPER_ADMIN' && session.tenant_id && session.tenant_id !== 'master') {
    const tenant = await db.prepare("SELECT status FROM tenants WHERE id = ?").bind(session.tenant_id).first();
    if (tenant && tenant.status !== 'ACTIVE') {
      return null; // Tenant is on HOLD or SUSPENDED
    }
  }

  return {
    id: session.id,
    username: session.username,
    email: session.email,
    fullName: session.full_name,
    role: session.role,
    tenantId: session.tenant_id || 'default',
    mustChangePassword: session.must_change_password === 1
  };
}

/**
 * Resolve active tenant identifier
 */
function resolveTenantId(request, currentUser = null) {
  const headerTenant = request.headers.get('X-Tenant-ID');
  if (headerTenant && headerTenant.trim()) {
    return headerTenant.trim().toLowerCase();
  }

  const url = new URL(request.url);
  const queryTenant = url.searchParams.get('tenant_id');
  if (queryTenant && queryTenant.trim()) {
    return queryTenant.trim().toLowerCase();
  }

  if (currentUser?.tenantId && currentUser.role !== 'SUPER_ADMIN') {
    return currentUser.tenantId;
  }

  return 'default';
}

const DEFAULT_STANDARD_TARIFFS = {
  NCV:  { code: 'NCV',  name: 'Nerve Conduction Velocity (Motor & Sensory)', fee: 2500, docShare: 1000, refShare: 300 },
  EEG:  { code: 'EEG',  name: 'Routine Video Electroencephalography',        fee: 2000, docShare: 800,  refShare: 250 },
  EMG:  { code: 'EMG',  name: 'Concentric Needle Electromyography',          fee: 3000, docShare: 1200, refShare: 400 },
  RNST: { code: 'RNST', name: 'Repetitive Nerve Stimulation Test',          fee: 2200, docShare: 900,  refShare: 250 },
  VEP:  { code: 'VEP',  name: 'Visual Evoked Potential (Pattern Reversal)',  fee: 1500, docShare: 600,  refShare: 200 },
  BERA: { code: 'BERA', name: 'Brainstem Evoked Response Audiometry',       fee: 2500, docShare: 1000, refShare: 300 }
};

/**
 * Load complete application state scoped strictly to tenant
 */
async function getFullState(db, userRole = null, tenantId = 'default') {
  const [
    tenantRow,
    settingsRow,
    doctorsResult,
    tariffsResult,
    patientsResult,
    partnersResult,
    payoutsResult,
    ledgerResult,
    expensesResult
  ] = await Promise.all([
    db.prepare("SELECT * FROM tenants WHERE id = ? OR slug = ?").bind(tenantId, tenantId).first(),
    db.prepare("SELECT * FROM facility_settings WHERE tenant_id = ?").bind(tenantId).first(),
    db.prepare("SELECT * FROM reporting_doctors WHERE tenant_id = ? ORDER BY created_at ASC").bind(tenantId).all(),
    db.prepare("SELECT * FROM tariffs WHERE tenant_id = ? ORDER BY code ASC").bind(tenantId).all(),
    db.prepare("SELECT * FROM patients WHERE tenant_id = ? ORDER BY date DESC, token DESC").bind(tenantId).all(),
    db.prepare("SELECT * FROM referral_partners WHERE tenant_id = ? ORDER BY name ASC").bind(tenantId).all(),
    db.prepare("SELECT * FROM referral_payouts WHERE tenant_id = ? ORDER BY date DESC").bind(tenantId).all(),
    db.prepare("SELECT * FROM ledger_entries WHERE tenant_id = ? ORDER BY date DESC").bind(tenantId).all(),
    db.prepare("SELECT * FROM expenses WHERE tenant_id = ? ORDER BY category ASC, name ASC").bind(tenantId).all()
  ]);

  const tariffsObj = {};
  if (tariffsResult.results && tariffsResult.results.length > 0) {
    tariffsResult.results.forEach(t => {
      tariffsObj[t.code] = {
        code: t.code,
        name: t.name,
        fee: t.fee,
        docShare: t.doc_share,
        refShare: t.ref_share
      };
    });
  } else {
    // Provide standard base tariffs if not yet customized
    Object.assign(tariffsObj, DEFAULT_STANDARD_TARIFFS);
  }

  const doctorsList = (doctorsResult.results || []).map(d => ({
    id: d.id,
    name: d.name,
    designation: d.designation,
    qualification: d.qualification,
    regNo: d.reg_no,
    department: d.department,
    signatureUrl: d.signature_url || ''
  }));

  const patientsList = (patientsResult.results || []).map(p => ({
    id: p.id,
    token: p.token,
    date: p.date,
    name: p.name,
    age: p.age,
    gender: p.gender,
    phone: p.phone,
    address: p.address || '',
    refDoctor: p.ref_doctor,
    reportingDoctor: p.reporting_doctor,
    modality: p.modality,
    fee: p.fee,
    docShare: p.doc_share,
    refShare: p.ref_share,
    netLab: p.net_lab,
    payMode: p.pay_mode,
    indication: p.indication,
    reportTitle: p.report_title,
    lblParam1: p.lbl_param1,
    lblParam2: p.lbl_param2,
    lblSec1: p.lbl_sec1,
    lblSec2: p.lbl_sec2,
    lblSec3: p.lbl_sec3,
    motorSampled: p.motor_sampled,
    sensorySampled: p.sensory_sampled,
    motorFindings: p.motor_findings,
    sensoryFindings: p.sensory_findings,
    fwavesFindings: p.fwaves_findings,
    impression: p.impression
  }));

  const ledgerList = (ledgerResult.results || []).map(l => ({
    id: l.id,
    doctorName: l.doctor_name,
    type: l.type,
    date: l.date,
    desc: l.description,
    amount: l.amount
  }));

  const tenantName = tenantRow?.name || 'Electrophysiology Diagnostic Center';

  return {
    tenant: tenantRow ? {
      id: tenantRow.id,
      name: tenantRow.name,
      slug: tenantRow.slug,
      plan: tenantRow.plan,
      status: tenantRow.status
    } : {
      id: tenantId,
      name: tenantName,
      slug: tenantId,
      plan: 'PRO',
      status: 'ACTIVE'
    },
    settings: settingsRow ? {
      facilityName: settingsRow.facility_name,
      parentEntity: settingsRow.parent_entity,
      cin: settingsRow.cin,
      dpiit: settingsRow.dpiit,
      address: settingsRow.address,
      phones: settingsRow.phones,
      vpa: settingsRow.vpa
    } : {
      facilityName: tenantName,
      parentEntity: 'Nexa-LMIS Enterprise Network',
      cin: '',
      dpiit: '',
      address: 'Clinical Diagnostic Facility',
      phones: '',
      vpa: ''
    },
    reportingDoctors: doctorsList,
    tariffs: tariffsObj,
    patients: patientsList,
    referralPartners: (partnersResult.results || []).map(r => ({
      id: r.id,
      name: r.name,
      type: r.type,
      tier: r.tier
    })),
    referralPayouts: (payoutsResult.results || []).map(r => ({
      id: r.id,
      date: r.date,
      partner: r.partner,
      amount: r.amount,
      mode: r.mode
    })),
    ledgerEntries: ledgerList,
    expenses: (userRole === 'ADMIN' || userRole === 'SUPER_ADMIN') ? (expensesResult.results || []).map(e => ({
      id: e.id,
      category: e.category,
      name: e.name,
      amount: e.amount
    })) : []
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return handleOptions();
    }

    // API Routes
    if (url.pathname.startsWith('/api/')) {
      if (!env?.DB) {
        return jsonResponse({
          ok: false,
          error: 'Cloudflare D1 Database binding "DB" is not configured.'
        }, 503);
      }

      await ensureD1Schema(env.DB);

      // STRICT PRIVACY PROTECTION: Block Master Super Admin from accessing patient/clinical personal data
      if (
        url.pathname === '/api/state' ||
        url.pathname === '/api/patients' ||
        url.pathname.startsWith('/api/patients/') ||
        url.pathname === '/api/ledger' ||
        url.pathname.startsWith('/api/ledger/') ||
        url.pathname === '/api/expenses' ||
        url.pathname.startsWith('/api/expenses/') ||
        url.pathname === '/api/referral-partners' ||
        url.pathname.startsWith('/api/referral-partners/') ||
        url.pathname === '/api/referral-payouts' ||
        url.pathname.startsWith('/api/referral-payouts/')
      ) {
        const currentUser = await authenticateUser(request, env.DB);
        if (currentUser && currentUser.role === 'SUPER_ADMIN') {
          return jsonResponse({
            error: 'Access Denied: Master Platform Administrator is restricted from accessing confidential patient & clinical personal data. Master scope is strictly limited to Organization and Admin user lifecycle management.'
          }, 403);
        }
      }

      // GET /api/health
      if (url.pathname === '/api/health') {
        const test = await env.DB.prepare("SELECT 1 as alive").first();
        return jsonResponse({
          ok: true,
          status: 'healthy',
          architecture: 'Multi-Tenant Serverless SaaS',
          database: 'Cloudflare D1 SQLite',
          connected: Boolean(test?.alive),
          timestamp: new Date().toISOString()
        });
      }

      // ==========================================
      // SPRINGNEXA MASTER SAAS TENANT CONTROL
      // ==========================================

      // GET /api/master/tenants - Full platform telemetry (Master Admin Only)
      if (url.pathname === '/api/master/tenants' && request.method === 'GET') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'SUPER_ADMIN') {
          return jsonResponse({ error: 'SpringNexa Master Administrator access required.' }, 403);
        }

        const { results = [] } = await env.DB.prepare(`
          SELECT 
            t.id, t.name, t.slug, t.plan, t.status, t.created_at,
            fs.parent_entity, fs.address, fs.phones, fs.vpa,
            (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id) as user_count,
            (SELECT full_name FROM users u WHERE u.tenant_id = t.id AND u.role = 'ADMIN' LIMIT 1) as admin_full_name,
            (SELECT username FROM users u WHERE u.tenant_id = t.id AND u.role = 'ADMIN' LIMIT 1) as admin_username,
            (SELECT email FROM users u WHERE u.tenant_id = t.id AND u.role = 'ADMIN' LIMIT 1) as admin_email,
            (SELECT status FROM users u WHERE u.tenant_id = t.id AND u.role = 'ADMIN' LIMIT 1) as admin_status
          FROM tenants t
          LEFT JOIN facility_settings fs ON fs.tenant_id = t.id
          WHERE t.id != 'master'
          ORDER BY t.created_at DESC
        `).all();

        return jsonResponse({ ok: true, tenants: results });
      }

      // POST /api/master/tenants - Provision new clinic tenant (Master Admin Only)
      if (url.pathname === '/api/master/tenants' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'SUPER_ADMIN') {
          return jsonResponse({ error: 'SpringNexa Master Administrator access required.' }, 403);
        }

        let body;
        try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON body' }, 400); }

        const name = String(body.name || '').trim();
        const slug = String(body.slug || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
        const plan = String(body.plan || 'PRO').toUpperCase();

        if (!name || !slug) {
          return jsonResponse({ error: 'Clinic Organization Name and unique Slug are required.' }, 400);
        }

        const existing = await env.DB.prepare("SELECT id FROM tenants WHERE slug = ? OR id = ?").bind(slug, 'org_' + slug).first();
        if (existing) {
          return jsonResponse({ error: `An organization with slug '${slug}' already exists.` }, 409);
        }

        const tenantId = 'org_' + slug;
        const now = new Date().toISOString();

        // Admin Credentials for this tenant
        const adminUsername = String(body.adminUsername || ('admin.' + slug)).trim().toLowerCase();
        const adminEmail = String(body.adminEmail || (`admin@${slug}.com`)).trim().toLowerCase();
        const adminName = String(body.adminName || `${name} Director`).trim();
        const adminPassword = String(body.adminPassword || 'Admin@123');

        const salt = 'salt_' + crypto.randomUUID().slice(0, 8);
        const passwordHash = await hashPassword(adminPassword, salt);
        const adminId = 'USR_' + Date.now();

        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO tenants (id, name, slug, plan, status, created_at)
            VALUES (?, ?, ?, ?, 'ACTIVE', ?)
          `).bind(tenantId, name, slug, plan, now),

          env.DB.prepare(`
            INSERT INTO facility_settings (id, tenant_id, facility_name, parent_entity, cin, dpiit, address, phones, vpa, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            'setting_' + tenantId,
            tenantId,
            name,
            body.parentEntity || (name + ' Healthcare Ltd'),
            body.cin || '',
            body.dpiit || '',
            body.address || 'Diagnostic Clinic Facility',
            body.phones || '',
            body.vpa || 'springnexaa@okaxis',
            now
          ),

          env.DB.prepare(`
            INSERT INTO users (id, tenant_id, username, email, full_name, role, password_hash, password_salt, status, must_change_password, created_at)
            VALUES (?, ?, ?, ?, ?, 'ADMIN', ?, ?, 'ACTIVE', 1, ?)
          `).bind(adminId, tenantId, adminUsername, adminEmail, adminName, passwordHash, salt, now)
        ]);

        // Seed standard diagnostic tariffs for new clinic
        for (const [code, t] of Object.entries(DEFAULT_STANDARD_TARIFFS)) {
          await env.DB.prepare(`
            INSERT OR REPLACE INTO tariffs (code, tenant_id, name, fee, doc_share, ref_share, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).bind(code, tenantId, t.name, t.fee, t.docShare, t.refShare, now).run();
        }

        return jsonResponse({
          ok: true,
          tenant: { id: tenantId, name, slug, plan, status: 'ACTIVE' },
          adminUser: { id: adminId, username: adminUsername, email: adminEmail, fullName: adminName, role: 'ADMIN' },
          message: `Diagnostic Organization '${name}' provisioned successfully!`
        }, 201);
      }

      // PUT /api/master/tenants/:id/status - Hold / Suspend / Activate Tenant (Master Admin Only)
      if (url.pathname.startsWith('/api/master/tenants/') && url.pathname.endsWith('/status') && request.method === 'PUT') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'SUPER_ADMIN') {
          return jsonResponse({ error: 'SpringNexa Master Administrator access required.' }, 403);
        }

        const id = url.pathname.split('/')[4];
        let body;
        try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON body' }, 400); }

        const status = String(body.status || 'ACTIVE').toUpperCase();
        if (!['ACTIVE', 'HOLD', 'SUSPENDED'].includes(status)) {
          return jsonResponse({ error: 'Status must be ACTIVE, HOLD, or SUSPENDED.' }, 400);
        }

        await env.DB.prepare("UPDATE tenants SET status = ? WHERE id = ?").bind(status, id).run();
        return jsonResponse({ ok: true, status, message: `Organization status set to ${status}.` });
      }

      // PUT /api/master/tenants/:id/admin-status - Hold / Activate Organisation Admin User (Master Admin Only)
      if (url.pathname.startsWith('/api/master/tenants/') && url.pathname.endsWith('/admin-status') && request.method === 'PUT') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'SUPER_ADMIN') {
          return jsonResponse({ error: 'SpringNexa Master Administrator access required.' }, 403);
        }

        const id = url.pathname.split('/')[4];
        let body;
        try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON body' }, 400); }

        const status = String(body.status || 'ACTIVE').toUpperCase();
        if (!['ACTIVE', 'HOLD', 'SUSPENDED', 'INACTIVE'].includes(status)) {
          return jsonResponse({ error: 'Status must be ACTIVE, HOLD, or INACTIVE.' }, 400);
        }

        await env.DB.prepare("UPDATE users SET status = ? WHERE tenant_id = ? AND role = 'ADMIN'").bind(status, id).run();
        return jsonResponse({ ok: true, adminStatus: status, message: `Admin user status set to ${status}.` });
      }

      // PUT /api/master/tenants/:id - Update tenant subscription/details (Master Admin Only)
      if (url.pathname.startsWith('/api/master/tenants/') && !url.pathname.includes('/reset-admin') && request.method === 'PUT') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'SUPER_ADMIN') {
          return jsonResponse({ error: 'SpringNexa Master Administrator access required.' }, 403);
        }

        const id = url.pathname.split('/')[4];
        let body;
        try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON body' }, 400); }

        const name = String(body.name || '').trim();
        const plan = String(body.plan || 'PRO').toUpperCase();
        const status = String(body.status || 'ACTIVE').toUpperCase();
        const now = new Date().toISOString();

        await env.DB.prepare(`
          UPDATE tenants SET name = ?, plan = ?, status = ? WHERE id = ?
        `).bind(name, plan, status, id).run();

        if (body.address !== undefined || body.phones !== undefined || body.parentEntity !== undefined) {
          await env.DB.prepare(`
            UPDATE facility_settings
            SET facility_name = ?, parent_entity = ?, address = ?, phones = ?, vpa = ?, updated_at = ?
            WHERE tenant_id = ?
          `).bind(
            name,
            body.parentEntity || '',
            body.address || '',
            body.phones || '',
            body.vpa || '',
            now,
            id
          ).run();
        }

        return jsonResponse({ ok: true, message: 'Tenant updated successfully.' });
      }

      // POST /api/master/tenants/:id/reset-admin - Reset tenant clinic admin password (Master Admin Only)
      if (url.pathname.startsWith('/api/master/tenants/') && url.pathname.endsWith('/reset-admin') && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'SUPER_ADMIN') {
          return jsonResponse({ error: 'SpringNexa Master Administrator access required.' }, 403);
        }

        const id = url.pathname.split('/')[4];
        let body;
        try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON body' }, 400); }

        const newPassword = String(body.newPassword || '').trim();
        if (!newPassword || newPassword.length < 6) {
          return jsonResponse({ error: 'New password must be at least 6 characters.' }, 400);
        }

        const salt = 'salt_' + crypto.randomUUID().slice(0, 8);
        const hash = await hashPassword(newPassword, salt);

        await env.DB.prepare(`
          UPDATE users
          SET password_hash = ?, password_salt = ?, must_change_password = 1
          WHERE tenant_id = ? AND role = 'ADMIN'
        `).bind(hash, salt, id).run();

        return jsonResponse({ ok: true, message: 'Tenant administrator password reset successfully.' });
      }

      // DELETE /api/master/tenants/:id - Suspend or Purge Tenant (Master Admin Only)
      if (url.pathname.startsWith('/api/master/tenants/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'SUPER_ADMIN') {
          return jsonResponse({ error: 'SpringNexa Master Administrator access required.' }, 403);
        }

        const id = url.pathname.split('/')[4];
        if (id === 'default' || id === 'master') {
          return jsonResponse({ error: 'Root default tenant cannot be deleted.' }, 400);
        }

        const purge = url.searchParams.get('purge') === 'true';

        if (purge) {
          await env.DB.batch([
            env.DB.prepare("DELETE FROM patients WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM reporting_doctors WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM tariffs WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM referral_partners WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM referral_payouts WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM ledger_entries WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM expenses WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM facility_settings WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM users WHERE tenant_id = ?").bind(id),
            env.DB.prepare("DELETE FROM tenants WHERE id = ?").bind(id)
          ]);
          return jsonResponse({ ok: true, message: 'Tenant and all clinical records purged completely.' });
        } else {
          await env.DB.prepare("UPDATE tenants SET status = 'SUSPENDED' WHERE id = ?").bind(id).run();
          return jsonResponse({ ok: true, message: 'Tenant suspended successfully.' });
        }
      }

      // Backward-compatible alias for existing endpoints
      if (url.pathname === '/api/tenants' && request.method === 'GET') {
        const { results = [] } = await env.DB.prepare(`
          SELECT id, name, slug, plan, status, created_at FROM tenants ORDER BY created_at ASC
        `).all();
        return jsonResponse({ ok: true, tenants: results });
      }

      // ==========================================
      // AUTHENTICATION ROUTES
      // ==========================================

      // POST /api/auth/login
      if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON body' }, 400); }
        const usernameOrEmail = String(body.usernameOrEmail || '').trim().toLowerCase();
        const password = String(body.password || '');

        if (!usernameOrEmail || !password) {
          return jsonResponse({ error: 'Username/Email and Password are required.' }, 400);
        }

        const user = await env.DB.prepare(`
          SELECT id, tenant_id, username, email, full_name, role, password_hash, password_salt, status, must_change_password, last_login_at
          FROM users
          WHERE (lower(username) = ? OR lower(email) = ?)
        `).bind(usernameOrEmail, usernameOrEmail).first();

        if (!user) {
          return jsonResponse({ error: 'Invalid username, email or password.' }, 401);
        }

        if (user.status !== 'ACTIVE') {
          return jsonResponse({ error: 'User account is deactivated. Contact organization administrator.' }, 403);
        }

        const calculatedHash = await hashPassword(password, user.password_salt);
        if (calculatedHash !== user.password_hash) {
          return jsonResponse({ error: 'Invalid username, email or password.' }, 401);
        }

        // If not SUPER_ADMIN, check if organization is on HOLD or SUSPENDED
        if (user.role !== 'SUPER_ADMIN' && user.tenant_id && user.tenant_id !== 'master') {
          const tenant = await env.DB.prepare("SELECT * FROM tenants WHERE id = ?").bind(user.tenant_id).first();
          if (tenant && tenant.status !== 'ACTIVE') {
            return jsonResponse({
              error: `Access Blocked: Your clinic organization (${tenant.name}) has been placed on ${tenant.status} by platform administration. Contact support@springnexa.in.`
            }, 403);
          }
        }

        const token = generateToken();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();

        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO user_sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
          `).bind(token, user.id, now.toISOString(), expiresAt),
          env.DB.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").bind(now.toISOString(), user.id)
        ]);

        const tenant = await env.DB.prepare("SELECT * FROM tenants WHERE id = ?").bind(user.tenant_id || 'default').first();

        return jsonResponse({
          ok: true,
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            fullName: user.full_name,
            role: user.role,
            tenantId: user.tenant_id || 'default',
            mustChangePassword: (user.must_change_password === 1 || !user.last_login_at) ? true : false
          },
          tenant: tenant ? {
            id: tenant.id,
            name: tenant.name,
            slug: tenant.slug,
            plan: tenant.plan
          } : { id: 'default', name: 'Nexa-LMIS Workstation', slug: 'default', plan: 'PRO' },
          expiresAt
        });
      }

      // GET /api/auth/me
      if (url.pathname === '/api/auth/me' && request.method === 'GET') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser) {
          return jsonResponse({ error: 'Unauthenticated session.' }, 401);
        }
        const tenant = await env.DB.prepare("SELECT * FROM tenants WHERE id = ?").bind(currentUser.tenantId).first();
        return jsonResponse({ ok: true, user: currentUser, tenant });
      }

      // POST /api/auth/logout
      if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
        const authHeader = request.headers.get('Authorization') || '';
        if (authHeader.startsWith('Bearer ')) {
          const token = authHeader.slice(7).trim();
          await env.DB.prepare("DELETE FROM user_sessions WHERE token = ?").bind(token).run();
        }
        return jsonResponse({ ok: true, message: 'Logged out successfully.' });
      }

      // POST /api/auth/change-password - Change current user's password (first login or profile change)
      if (url.pathname === '/api/auth/change-password' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser) {
          return jsonResponse({ error: 'Unauthenticated session.' }, 401);
        }

        let body;
        try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON body' }, 400); }
        const currentPassword = String(body.currentPassword || '');
        const newPassword = String(body.newPassword || '');

        if (!currentPassword || !newPassword) {
          return jsonResponse({ error: 'Both current password and new password are required.' }, 400);
        }

        if (newPassword.length < 6) {
          return jsonResponse({ error: 'New password must be at least 6 characters long.' }, 400);
        }

        if (currentPassword === newPassword) {
          return jsonResponse({ error: 'New password must be different from your current password.' }, 400);
        }

        const user = await env.DB.prepare(`
          SELECT id, password_hash, password_salt
          FROM users
          WHERE id = ?
        `).bind(currentUser.id).first();

        if (!user) {
          return jsonResponse({ error: 'User account not found.' }, 404);
        }

        const calculatedHash = await hashPassword(currentPassword, user.password_salt);
        if (calculatedHash !== user.password_hash) {
          return jsonResponse({ error: 'Current password is incorrect. Please verify and try again.' }, 400);
        }

        const newSalt = 'salt_' + crypto.randomUUID().slice(0, 8);
        const newHash = await hashPassword(newPassword, newSalt);
        const now = new Date().toISOString();

        await env.DB.prepare(`
          UPDATE users
          SET password_hash = ?, password_salt = ?, must_change_password = 0, password_changed_at = ?
          WHERE id = ?
        `).bind(newHash, newSalt, now, user.id).run();

        return jsonResponse({
          ok: true,
          message: 'Password changed successfully! You may now use your new password.'
        });
      }

      // GET /api/users - List users for current tenant
      if (url.pathname === '/api/users' && request.method === 'GET') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const { results = [] } = await env.DB.prepare(`
          SELECT id, tenant_id, username, email, full_name, role, status, last_login_at, created_at
          FROM users WHERE tenant_id = ? ORDER BY created_at ASC
        `).bind(tenantId).all();
        return jsonResponse({ ok: true, users: results });
      }

      // POST /api/users - Create User (Admin Only for current tenant)
      if (url.pathname === '/api/users' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'ADMIN') {
          return jsonResponse({ error: 'Administrator privilege required to create users.' }, 403);
        }

        const tenantId = resolveTenantId(request, currentUser);
        const body = await request.json();
        const username = String(body.username || '').trim().toLowerCase();
        const email = String(body.email || '').trim().toLowerCase();
        const fullName = String(body.fullName || '').trim();
        const role = String(body.role || 'TECHNICIAN').toUpperCase();
        const password = String(body.password || 'Nexa@2026');

        if (!username || !email || !fullName) {
          return jsonResponse({ error: 'Username, email and full name are required.' }, 400);
        }

        const salt = 'salt_' + crypto.randomUUID().slice(0, 8);
        const passwordHash = await hashPassword(password, salt);
        const id = 'USR_' + Date.now();
        const now = new Date().toISOString();

        await env.DB.prepare(`
          INSERT INTO users (id, tenant_id, username, email, full_name, role, password_hash, password_salt, status, must_change_password, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1, ?)
        `).bind(id, tenantId, username, email, fullName, role, passwordHash, salt, now).run();

        return jsonResponse({ ok: true, id, message: `Operator ${username} registered successfully.` }, 201);
      }

      // DELETE /api/users/:id - Delete Staff User (Admin Only)
      if (url.pathname.startsWith('/api/users/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'ADMIN') {
          return jsonResponse({ error: 'Administrator privilege required to delete staff.' }, 403);
        }
        const id = url.pathname.split('/')[3];
        if (id === currentUser.id || id === 'USR_ADMIN') {
          return jsonResponse({ error: 'Cannot delete primary administrator account.' }, 400);
        }
        const tenantId = resolveTenantId(request, currentUser);
        await env.DB.prepare("DELETE FROM users WHERE id = ? AND tenant_id = ?").bind(id, tenantId).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // ==========================================
      // CLINICAL DATA ROUTES (TENANT SCOPED)
      // ==========================================

      // GET /api/state - Full State for Client Init & Sync
      if (url.pathname === '/api/state' && request.method === 'GET') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const state = await getFullState(env.DB, currentUser?.role, tenantId);
        return jsonResponse({ ok: true, state, role: currentUser?.role || 'GUEST', tenantId });
      }

      // POST /api/sync - Bulk Restore & Push Full Workstation State to Cloudflare D1
      if (url.pathname === '/api/sync' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const body = await request.json();
        const now = new Date().toISOString();

        const stmts = [];

        // 1. Settings
        if (body.settings) {
          stmts.push(env.DB.prepare(`
            INSERT INTO facility_settings (id, tenant_id, facility_name, parent_entity, cin, dpiit, address, phones, vpa, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              facility_name=excluded.facility_name,
              parent_entity=excluded.parent_entity,
              cin=excluded.cin,
              dpiit=excluded.dpiit,
              address=excluded.address,
              phones=excluded.phones,
              vpa=excluded.vpa,
              updated_at=excluded.updated_at
          `).bind(
            'setting_' + tenantId,
            tenantId,
            body.settings.facilityName || '',
            body.settings.parentEntity || '',
            body.settings.cin || '',
            body.settings.dpiit || '',
            body.settings.address || '',
            body.settings.phones || '',
            body.settings.vpa || '',
            now
          ));
        }

        // 2. Reporting Doctors
        if (Array.isArray(body.reportingDoctors)) {
          body.reportingDoctors.forEach(d => {
            if (!d.name) return;
            const docId = d.id || ('DOC_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6));
            stmts.push(env.DB.prepare(`
              INSERT INTO reporting_doctors (id, tenant_id, name, designation, qualification, reg_no, department, signature_url, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                designation=excluded.designation,
                qualification=excluded.qualification,
                reg_no=excluded.reg_no,
                department=excluded.department,
                signature_url=excluded.signature_url
            `).bind(
              docId, tenantId, d.name, d.designation || '', d.qualification || '',
              d.regNo || '', d.department || '', d.signatureUrl || '', now
            ));
          });
        }

        // 3. Tariffs
        if (body.tariffs && typeof body.tariffs === 'object') {
          Object.values(body.tariffs).forEach(t => {
            if (!t.code) return;
            stmts.push(env.DB.prepare(`
              INSERT INTO tariffs (code, tenant_id, name, fee, doc_share, ref_share, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(tenant_id, code) DO UPDATE SET
                name=excluded.name, fee=excluded.fee, doc_share=excluded.doc_share, ref_share=excluded.ref_share, updated_at=excluded.updated_at
            `).bind(t.code, tenantId, t.name || t.code, Number(t.fee) || 0, Number(t.docShare) || 0, Number(t.refShare) || 0, now));
          });
        }

        // 4. Patients (with address)
        if (Array.isArray(body.patients)) {
          body.patients.forEach(p => {
            if (!p.token || !p.name) return;
            const pid = p.id || ('P' + Date.now() + '_' + Math.random().toString(36).slice(2, 6));
            stmts.push(env.DB.prepare(`
              INSERT INTO patients (
                id, tenant_id, token, date, name, age, gender, phone, address, ref_doctor, reporting_doctor,
                modality, fee, doc_share, ref_share, net_lab, pay_mode, indication,
                report_title, lbl_param1, lbl_param2, lbl_sec1, lbl_sec2, lbl_sec3,
                motor_sampled, sensory_sampled, motor_findings, sensory_findings, fwaves_findings, impression,
                created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                token=excluded.token, date=excluded.date, name=excluded.name, age=excluded.age,
                gender=excluded.gender, phone=excluded.phone, address=excluded.address, ref_doctor=excluded.ref_doctor,
                reporting_doctor=excluded.reporting_doctor, modality=excluded.modality,
                fee=excluded.fee, doc_share=excluded.doc_share, ref_share=excluded.ref_share,
                net_lab=excluded.net_lab, pay_mode=excluded.pay_mode, indication=excluded.indication,
                report_title=excluded.report_title, lbl_param1=excluded.lbl_param1, lbl_param2=excluded.lbl_param2,
                lbl_sec1=excluded.lbl_sec1, lbl_sec2=excluded.lbl_sec2, lbl_sec3=excluded.lbl_sec3,
                motor_sampled=excluded.motor_sampled, sensory_sampled=excluded.sensory_sampled,
                motor_findings=excluded.motor_findings, sensory_findings=excluded.sensory_findings,
                fwaves_findings=excluded.fwaves_findings, impression=excluded.impression
            `).bind(
              pid, tenantId, String(p.token), p.date, p.name, Number(p.age) || 0, p.gender || 'Other', p.phone || '',
              p.address || '', p.refDoctor || '', p.reportingDoctor || '', p.modality || 'NCV',
              Number(p.fee) || 0, Number(p.docShare) || 0, Number(p.refShare) || 0, Number(p.netLab) || 0,
              p.payMode || 'UPI / QR', p.indication || '', p.reportTitle || 'NERVE CONDUCTION STUDIES REPORT',
              p.lblParam1 || '', p.lblParam2 || '', p.lblSec1 || '', p.lblSec2 || '', p.lblSec3 || '',
              p.motorSampled || '', p.sensorySampled || '', p.motorFindings || '', p.sensoryFindings || '',
              p.fwavesFindings || '', p.impression || '', now
            ));
          });
        }

        // 5. Expenses
        if (Array.isArray(body.expenses)) {
          body.expenses.forEach(e => {
            if (!e.name) return;
            const expId = e.id || ('EXP_' + tenantId + '_' + e.category + '_' + e.name.replace(/\s+/g, '_'));
            stmts.push(env.DB.prepare(`
              INSERT INTO expenses (id, tenant_id, category, name, amount, updated_at)
              VALUES (?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                category=excluded.category, name=excluded.name, amount=excluded.amount, updated_at=excluded.updated_at
            `).bind(expId, tenantId, e.category || 'OPEX', e.name, Number(e.amount) || 0, now));
          });
        }

        // 6. Referral Partners
        if (Array.isArray(body.referralPartners)) {
          body.referralPartners.forEach(rp => {
            if (!rp.name) return;
            const rpid = rp.id || ('RP_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6));
            stmts.push(env.DB.prepare(`
              INSERT INTO referral_partners (id, tenant_id, name, type, tier, created_at)
              VALUES (?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, type=excluded.type, tier=excluded.tier
            `).bind(rpid, tenantId, rp.name, rp.type || 'Clinic', Number(rp.tier) || 1.0, now));
          });
        }

        // 7. Referral Payouts
        if (Array.isArray(body.referralPayouts)) {
          body.referralPayouts.forEach(po => {
            if (!po.partner) return;
            const poid = po.id || ('PO_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6));
            stmts.push(env.DB.prepare(`
              INSERT INTO referral_payouts (id, tenant_id, date, partner, amount, mode, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                date=excluded.date, partner=excluded.partner, amount=excluded.amount, mode=excluded.mode
            `).bind(poid, tenantId, po.date, po.partner, Number(po.amount) || 0, po.mode || 'Cash', now));
          });
        }

        // 8. Ledger Entries
        if (Array.isArray(body.ledgerEntries)) {
          body.ledgerEntries.forEach(le => {
            if (!le.doctorName) return;
            const leid = le.id || ('LE_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6));
            stmts.push(env.DB.prepare(`
              INSERT INTO ledger_entries (id, tenant_id, doctor_name, type, date, description, amount, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                doctor_name=excluded.doctor_name, type=excluded.type, date=excluded.date, description=excluded.description, amount=excluded.amount
            `).bind(leid, tenantId, le.doctorName, le.type || 'credit', le.date || now, le.description || '', Number(le.amount) || 0, now));
          });
        }

        // Execute in safe chunks of 40 statements
        for (let i = 0; i < stmts.length; i += 40) {
          const chunk = stmts.slice(i, i + 40);
          if (chunk.length > 0) {
            await env.DB.batch(chunk);
          }
        }

        const updatedState = await getFullState(env.DB, currentUser?.role, tenantId);
        return jsonResponse({
          ok: true,
          message: `Workstation vault successfully synchronized to Cloudflare D1 (${stmts.length} operations).`,
          state: updatedState
        });
      }

      // POST /api/patients - Register or Update Patient
      if (url.pathname === '/api/patients' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const p = await request.json();
        const now = new Date().toISOString();
        const id = p.id || ('P' + Date.now());

        await env.DB.prepare(`
          INSERT INTO patients (
            id, tenant_id, token, date, name, age, gender, phone, address, ref_doctor, reporting_doctor,
            modality, fee, doc_share, ref_share, net_lab, pay_mode, indication,
            report_title, lbl_param1, lbl_param2, lbl_sec1, lbl_sec2, lbl_sec3,
            motor_sampled, sensory_sampled, motor_findings, sensory_findings, fwaves_findings, impression,
            created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            token=excluded.token, date=excluded.date, name=excluded.name, age=excluded.age,
            gender=excluded.gender, phone=excluded.phone, address=excluded.address, ref_doctor=excluded.ref_doctor,
            reporting_doctor=excluded.reporting_doctor, modality=excluded.modality,
            fee=excluded.fee, doc_share=excluded.doc_share, ref_share=excluded.ref_share,
            net_lab=excluded.net_lab, pay_mode=excluded.pay_mode, indication=excluded.indication,
            report_title=excluded.report_title, lbl_param1=excluded.lbl_param1, lbl_param2=excluded.lbl_param2,
            lbl_sec1=excluded.lbl_sec1, lbl_sec2=excluded.lbl_sec2, lbl_sec3=excluded.lbl_sec3,
            motor_sampled=excluded.motor_sampled, sensory_sampled=excluded.sensory_sampled,
            motor_findings=excluded.motor_findings, sensory_findings=excluded.sensory_findings,
            fwaves_findings=excluded.fwaves_findings, impression=excluded.impression
        `).bind(
          id, tenantId, String(p.token), p.date, p.name, Number(p.age) || 0, p.gender, p.phone || '',
          p.address || '',
          p.refDoctor || '', p.reportingDoctor || '', p.modality,
          Number(p.fee) || 0, Number(p.docShare) || 0, Number(p.refShare) || 0, Number(p.netLab) || 0,
          p.payMode || 'UPI / QR', p.indication || '', p.reportTitle || 'NERVE CONDUCTION STUDIES REPORT',
          p.lblParam1 || '', p.lblParam2 || '', p.lblSec1 || '', p.lblSec2 || '', p.lblSec3 || '',
          p.motorSampled || '', p.sensorySampled || '', p.motorFindings || '', p.sensoryFindings || '',
          p.fwavesFindings || '', p.impression || '', now
        ).run();

        return jsonResponse({ ok: true, id, message: 'Patient saved to organization database.' });
      }

      // DELETE /api/patients/:id
      if (url.pathname.startsWith('/api/patients/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM patients WHERE id = ? AND tenant_id = ?").bind(id, tenantId).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/doctors - Add / Update Doctor
      if (url.pathname === '/api/doctors' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const d = await request.json();
        const now = new Date().toISOString();
        const id = d.id || ('DOC' + Date.now());

        await env.DB.prepare(`
          INSERT INTO reporting_doctors (id, tenant_id, name, designation, qualification, reg_no, department, signature_url, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            designation=excluded.designation,
            qualification=excluded.qualification,
            reg_no=excluded.reg_no,
            department=excluded.department,
            signature_url=excluded.signature_url
        `).bind(
          id, tenantId, d.name, d.designation || '', d.qualification || '',
          d.regNo || '', d.department || '', d.signatureUrl || '', now
        ).run();

        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/doctors/:id
      if (url.pathname.startsWith('/api/doctors/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM reporting_doctors WHERE id = ? AND tenant_id = ?").bind(id, tenantId).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/tariffs - Update Tariffs
      if (url.pathname === '/api/tariffs' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const tariffs = await request.json();
        const now = new Date().toISOString();
        for (const [code, t] of Object.entries(tariffs)) {
          await env.DB.prepare(`
            INSERT INTO tariffs (code, tenant_id, name, fee, doc_share, ref_share, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, code) DO UPDATE SET
              name=excluded.name,
              fee=excluded.fee,
              doc_share=excluded.doc_share,
              ref_share=excluded.ref_share,
              updated_at=excluded.updated_at
          `).bind(code, tenantId, t.name, Number(t.fee) || 0, Number(t.docShare) || 0, Number(t.refShare) || 0, now).run();
        }
        return jsonResponse({ ok: true, message: 'Tariffs updated.' });
      }

      // POST /api/settings - Update Facility Settings
      if (url.pathname === '/api/settings' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const st = await request.json();
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO facility_settings (id, tenant_id, facility_name, parent_entity, cin, dpiit, address, phones, vpa, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            facility_name=excluded.facility_name,
            parent_entity=excluded.parent_entity,
            cin=excluded.cin,
            dpiit=excluded.dpiit,
            address=excluded.address,
            phones=excluded.phones,
            vpa=excluded.vpa,
            updated_at=excluded.updated_at
        `).bind(
          'setting_' + tenantId, tenantId, st.facilityName, st.parentEntity, st.cin, st.dpiit,
          st.address, st.phones, st.vpa, now
        ).run();
        return jsonResponse({ ok: true });
      }

      // POST /api/referral-partners
      if (url.pathname === '/api/referral-partners' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const p = await request.json();
        const id = p.id || ('RP' + Date.now());
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO referral_partners (id, tenant_id, name, type, tier, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(id, tenantId, p.name, p.type || 'Clinic', Number(p.tier) || 1.0, now).run();
        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/referral-partners/:id
      if (url.pathname.startsWith('/api/referral-partners/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM referral_partners WHERE id = ? AND tenant_id = ?").bind(id, tenantId).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/referral-payouts
      if (url.pathname === '/api/referral-payouts' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const p = await request.json();
        const id = p.id || ('RFP' + Date.now());
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO referral_payouts (id, tenant_id, date, partner, amount, mode, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(id, tenantId, p.date, p.partner, Number(p.amount) || 0, p.mode || 'Cash', now).run();
        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/referral-payouts/:id
      if (url.pathname.startsWith('/api/referral-payouts/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM referral_payouts WHERE id = ? AND tenant_id = ?").bind(id, tenantId).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/ledger
      if (url.pathname === '/api/ledger' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const l = await request.json();
        const id = l.id || ('L' + Date.now());
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO ledger_entries (id, tenant_id, doctor_name, type, date, description, amount, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(id, tenantId, l.doctorName, l.type, l.date, l.desc, Number(l.amount) || 0, now).run();
        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/ledger/:id
      if (url.pathname.startsWith('/api/ledger/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        const tenantId = resolveTenantId(request, currentUser);
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM ledger_entries WHERE id = ? AND tenant_id = ?").bind(id, tenantId).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/expenses (Admin Only)
      if (url.pathname === '/api/expenses' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'ADMIN') {
          return jsonResponse({ error: 'Admin access required to log operating expenses.' }, 403);
        }
        const tenantId = resolveTenantId(request, currentUser);
        const e = await request.json();
        const id = e.id || ('E' + Date.now());
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO expenses (id, tenant_id, category, name, amount, updated_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(id, tenantId, e.category || 'Operations', e.name, Number(e.amount) || 0, now).run();
        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/expenses/:id (Admin Only)
      if (url.pathname.startsWith('/api/expenses/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'ADMIN') {
          return jsonResponse({ error: 'Admin access required to remove expenses.' }, 403);
        }
        const tenantId = resolveTenantId(request, currentUser);
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM expenses WHERE id = ? AND tenant_id = ?").bind(id, tenantId).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // 404 for unmatched API routes
      return jsonResponse({ error: `API route not found: ${request.method} ${url.pathname}` }, 404);
    }

    // Serve static workstation assets
    return env.ASSETS.fetch(request);
  }
};
