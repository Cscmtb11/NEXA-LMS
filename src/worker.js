/**
 * Cloudflare Worker for Nexa-LMIS | Al-Jawahira Electrophysiology Clinical Workstation
 * Compliant with Cloudflare Security Policies & Cloudflare D1 (Serverless SQLite)
 * Includes Secure User Authentication (RBAC: Admin, Doctor, Technician)
 */

const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
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
 * Automatically ensure Cloudflare D1 tables exist and are seeded
 */
let schemaInitialized = false;
async function ensureD1Schema(db) {
  if (schemaInitialized || !db) return;

  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'TECHNICIAN',
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
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
        code TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        fee REAL NOT NULL,
        doc_share REAL NOT NULL,
        ref_share REAL NOT NULL,
        updated_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY,
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
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        tier REAL NOT NULL DEFAULT 1.0,
        created_at TEXT NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS referral_payouts (
        id TEXT PRIMARY KEY,
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
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL
      )
    `)
  ]);

  // Seed default users if empty
  const usersCheck = await db.prepare("SELECT COUNT(*) as count FROM users").first();
  if (!usersCheck || usersCheck.count === 0) {
    const now = new Date().toISOString();
    await db.batch([
      db.prepare(`
        INSERT INTO users (id, username, email, full_name, role, password_hash, password_salt, status, created_at)
        VALUES 
        ('USR_ADMIN', 'admin', 'admin@aljawahira.com', 'Al-Jawahira Administrator', 'ADMIN', '1a82233d9d94ee1bda69664ef3278c26f1b492c2231989cbeac811d5c352ede4', 'salt_admin_2026', 'ACTIVE', ?),
        ('USR_DOC_RAYEES', 'dr.rayees', 'rayees@aljawahira.com', 'Dr. Rayees Ahmad Tarray', 'DOCTOR', '8d3839986ad7e38be81f094b9598b0b0c3f499ea1234bf1e070021ce40bf9064', 'salt_doc_2026', 'ACTIVE', ?),
        ('USR_TECH_KULGAM', 'tech.kulgam', 'tech@aljawahira.com', 'Clinical Technologist Desk', 'TECHNICIAN', '2214da9a419272ca44eda2ba0e777cb8b1ed5fafb021f5058999d22fe04cef14', 'salt_tech_2026', 'ACTIVE', ?)
      `).bind(now, now, now)
    ]);
  }

  // Seed default facility settings if empty
  const settingsCheck = await db.prepare("SELECT COUNT(*) as count FROM facility_settings").first();
  if (!settingsCheck || settingsCheck.count === 0) {
    const now = new Date().toISOString();
    await db.batch([
      db.prepare(`
        INSERT INTO facility_settings (id, facility_name, parent_entity, cin, dpiit, address, phones, vpa, updated_at)
        VALUES ('default', 'AL JAWAHIRA ELECTROPHYSIOLOGY', 'SpringNexa Private Limited', 'U86900JK2026PTC018519', 'DIPP238776', 'Near Gousia Pharmacy District Hospital Road Kulgam', '+91-7006318286 | +91-6006220236', 'springnexaa@okaxis', ?)
      `).bind(now)
    ]);
  }

  schemaInitialized = true;
}

/**
 * Validate Authorization header token
 */
async function authenticateUser(request, db) {
  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  if (!token) return null;

  const session = await db.prepare(`
    SELECT s.token, s.expires_at, u.id, u.username, u.email, u.full_name, u.role, u.status
    FROM user_sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND u.status = 'ACTIVE'
  `).bind(token).first();

  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    await db.prepare("DELETE FROM user_sessions WHERE token = ?").bind(token).run();
    return null;
  }

  return {
    id: session.id,
    username: session.username,
    email: session.email,
    fullName: session.full_name,
    role: session.role
  };
}

/**
 * Load complete application state from Cloudflare D1
 */
async function getFullState(db, userRole = null) {
  const [
    settingsRow,
    doctorsResult,
    tariffsResult,
    patientsResult,
    partnersResult,
    payoutsResult,
    ledgerResult,
    expensesResult
  ] = await Promise.all([
    db.prepare("SELECT * FROM facility_settings WHERE id = 'default'").first(),
    db.prepare("SELECT * FROM reporting_doctors ORDER BY created_at ASC").all(),
    db.prepare("SELECT * FROM tariffs ORDER BY code ASC").all(),
    db.prepare("SELECT * FROM patients ORDER BY date DESC, token DESC").all(),
    db.prepare("SELECT * FROM referral_partners ORDER BY name ASC").all(),
    db.prepare("SELECT * FROM referral_payouts ORDER BY date DESC").all(),
    db.prepare("SELECT * FROM ledger_entries ORDER BY date DESC").all(),
    db.prepare("SELECT * FROM expenses ORDER BY category ASC, name ASC").all()
  ]);

  const tariffsObj = {};
  (tariffsResult.results || []).forEach(t => {
    tariffsObj[t.code] = {
      code: t.code,
      name: t.name,
      fee: t.fee,
      docShare: t.doc_share,
      refShare: t.ref_share
    };
  });

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

  return {
    settings: settingsRow ? {
      facilityName: settingsRow.facility_name,
      parentEntity: settingsRow.parent_entity,
      cin: settingsRow.cin,
      dpiit: settingsRow.dpiit,
      address: settingsRow.address,
      phones: settingsRow.phones,
      vpa: settingsRow.vpa
    } : null,
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
    expenses: (userRole === 'ADMIN') ? (expensesResult.results || []).map(e => ({
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
          error: 'Cloudflare D1 Database binding "DB" is not configured.',
          hint: 'Add [[d1_databases]] binding = "DB" in wrangler.toml'
        }, 503);
      }

      await ensureD1Schema(env.DB);

      // GET /api/health
      if (url.pathname === '/api/health') {
        const test = await env.DB.prepare("SELECT 1 as alive").first();
        return jsonResponse({
          ok: true,
          status: 'healthy',
          database: 'Cloudflare D1 SQLite',
          connected: Boolean(test?.alive),
          timestamp: new Date().toISOString()
        });
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
          SELECT id, username, email, full_name, role, password_hash, password_salt, status
          FROM users
          WHERE (lower(username) = ? OR lower(email) = ?)
        `).bind(usernameOrEmail, usernameOrEmail).first();

        if (!user) {
          return jsonResponse({ error: 'Invalid username, email or password.' }, 401);
        }

        if (user.status !== 'ACTIVE') {
          return jsonResponse({ error: 'User account is deactivated. Contact administrator.' }, 403);
        }

        const calculatedHash = await hashPassword(password, user.password_salt);
        if (calculatedHash !== user.password_hash) {
          return jsonResponse({ error: 'Invalid username, email or password.' }, 401);
        }

        const token = generateToken();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO user_sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
          `).bind(token, user.id, now.toISOString(), expiresAt),
          env.DB.prepare(`
            UPDATE users SET last_login_at = ? WHERE id = ?
          `).bind(now.toISOString(), user.id)
        ]);

        return jsonResponse({
          ok: true,
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            fullName: user.full_name,
            role: user.role
          }
        });
      }

      // GET /api/auth/me
      if (url.pathname === '/api/auth/me' && request.method === 'GET') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser) {
          return jsonResponse({ ok: false, error: 'Unauthorized. Please log in.' }, 401);
        }
        return jsonResponse({ ok: true, user: currentUser });
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

      // GET /api/users - List users
      if (url.pathname === '/api/users' && request.method === 'GET') {
        const { results = [] } = await env.DB.prepare(`
          SELECT id, username, email, full_name, role, status, last_login_at, created_at
          FROM users ORDER BY created_at ASC
        `).all();
        return jsonResponse({ ok: true, users: results });
      }

      // POST /api/users - Create User (Admin Only)
      if (url.pathname === '/api/users' && request.method === 'POST') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'ADMIN') {
          return jsonResponse({ error: 'Administrator privilege required to create users.' }, 403);
        }

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
          INSERT INTO users (id, username, email, full_name, role, password_hash, password_salt, status, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
        `).bind(id, username, email, fullName, role, passwordHash, salt, now).run();

        return jsonResponse({ ok: true, id, message: `User ${username} created successfully.` }, 201);
      }

      // DELETE /api/users/:id - Delete Staff User (Admin Only)
      if (url.pathname.startsWith('/api/users/') && request.method === 'DELETE') {
        const currentUser = await authenticateUser(request, env.DB);
        if (!currentUser || currentUser.role !== 'ADMIN') {
          return jsonResponse({ error: 'Administrator privilege required to delete staff.' }, 403);
        }
        const id = url.pathname.split('/')[3];
        if (id === currentUser.id || id === 'USR_ADMIN') {
          return jsonResponse({ error: 'Cannot delete the master administrator account.' }, 400);
        }
        await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
        return jsonResponse({ ok: true, deleted: id, message: 'User removed from Cloudflare D1.' });
      }


      // ==========================================
      // CLINICAL DATA ROUTES
      // ==========================================

      // GET /api/state - Full State for Client Init & Sync (Role-Filtered)
      if (url.pathname === '/api/state' && request.method === 'GET') {
        const currentUser = await authenticateUser(request, env.DB);
        const state = await getFullState(env.DB, currentUser?.role);
        return jsonResponse({ ok: true, state, role: currentUser?.role || 'GUEST' });
      }

      // POST /api/sync - Bulk Push / Restore State to Cloudflare D1
      if (url.pathname === '/api/sync' && request.method === 'POST') {
        const body = await request.json();
        const now = new Date().toISOString();

        if (body.settings) {
          await env.DB.prepare(`
            INSERT INTO facility_settings (id, facility_name, parent_entity, cin, dpiit, address, phones, vpa, updated_at)
            VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?)
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
            body.settings.facilityName,
            body.settings.parentEntity,
            body.settings.cin,
            body.settings.dpiit,
            body.settings.address,
            body.settings.phones,
            body.settings.vpa,
            now
          ).run();
        }

        if (Array.isArray(body.patients)) {
          for (const p of body.patients) {
            await env.DB.prepare(`
              INSERT INTO patients (
                id, token, date, name, age, gender, phone, ref_doctor, reporting_doctor,
                modality, fee, doc_share, ref_share, net_lab, pay_mode, indication,
                report_title, lbl_param1, lbl_param2, lbl_sec1, lbl_sec2, lbl_sec3,
                motor_sampled, sensory_sampled, motor_findings, sensory_findings, fwaves_findings, impression,
                created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET
                token=excluded.token, date=excluded.date, name=excluded.name, age=excluded.age,
                gender=excluded.gender, phone=excluded.phone, ref_doctor=excluded.ref_doctor,
                reporting_doctor=excluded.reporting_doctor, modality=excluded.modality,
                fee=excluded.fee, doc_share=excluded.doc_share, ref_share=excluded.ref_share,
                net_lab=excluded.net_lab, pay_mode=excluded.pay_mode, indication=excluded.indication,
                report_title=excluded.report_title, lbl_param1=excluded.lbl_param1, lbl_param2=excluded.lbl_param2,
                lbl_sec1=excluded.lbl_sec1, lbl_sec2=excluded.lbl_sec2, lbl_sec3=excluded.lbl_sec3,
                motor_sampled=excluded.motor_sampled, sensory_sampled=excluded.sensory_sampled,
                motor_findings=excluded.motor_findings, sensory_findings=excluded.sensory_findings,
                fwaves_findings=excluded.fwaves_findings, impression=excluded.impression
            `).bind(
              p.id, p.token, p.date, p.name, p.age, p.gender, p.phone || '',
              p.refDoctor || '', p.reportingDoctor || '', p.modality,
              Number(p.fee) || 0, Number(p.docShare) || 0, Number(p.refShare) || 0, Number(p.netLab) || 0,
              p.payMode || 'UPI / QR', p.indication || '', p.reportTitle || '',
              p.lblParam1 || '', p.lblParam2 || '', p.lblSec1 || '', p.lblSec2 || '', p.lblSec3 || '',
              p.motorSampled || '', p.sensorySampled || '', p.motorFindings || '', p.sensoryFindings || '',
              p.fwavesFindings || '', p.impression || '', now
            ).run();
          }
        }

        const updatedState = await getFullState(env.DB);
        return jsonResponse({ ok: true, state: updatedState });
      }

      // POST /api/patients - Create or Update Patient
      if (url.pathname === '/api/patients' && request.method === 'POST') {
        const p = await request.json();
        const now = new Date().toISOString();
        const id = p.id || ('P' + Date.now());

        await env.DB.prepare(`
          INSERT INTO patients (
            id, token, date, name, age, gender, phone, ref_doctor, reporting_doctor,
            modality, fee, doc_share, ref_share, net_lab, pay_mode, indication,
            report_title, lbl_param1, lbl_param2, lbl_sec1, lbl_sec2, lbl_sec3,
            motor_sampled, sensory_sampled, motor_findings, sensory_findings, fwaves_findings, impression,
            created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            token=excluded.token, date=excluded.date, name=excluded.name, age=excluded.age,
            gender=excluded.gender, phone=excluded.phone, ref_doctor=excluded.ref_doctor,
            reporting_doctor=excluded.reporting_doctor, modality=excluded.modality,
            fee=excluded.fee, doc_share=excluded.doc_share, ref_share=excluded.ref_share,
            net_lab=excluded.net_lab, pay_mode=excluded.pay_mode, indication=excluded.indication,
            report_title=excluded.report_title, lbl_param1=excluded.lbl_param1, lbl_param2=excluded.lbl_param2,
            lbl_sec1=excluded.lbl_sec1, lbl_sec2=excluded.lbl_sec2, lbl_sec3=excluded.lbl_sec3,
            motor_sampled=excluded.motor_sampled, sensory_sampled=excluded.sensory_sampled,
            motor_findings=excluded.motor_findings, sensory_findings=excluded.sensory_findings,
            fwaves_findings=excluded.fwaves_findings, impression=excluded.impression
        `).bind(
          id, String(p.token), p.date, p.name, Number(p.age) || 0, p.gender, p.phone || '',
          p.refDoctor || '', p.reportingDoctor || '', p.modality,
          Number(p.fee) || 0, Number(p.docShare) || 0, Number(p.refShare) || 0, Number(p.netLab) || 0,
          p.payMode || 'UPI / QR', p.indication || '', p.reportTitle || 'NERVE CONDUCTION STUDIES REPORT',
          p.lblParam1 || '', p.lblParam2 || '', p.lblSec1 || '', p.lblSec2 || '', p.lblSec3 || '',
          p.motorSampled || '', p.sensorySampled || '', p.motorFindings || '', p.sensoryFindings || '',
          p.fwavesFindings || '', p.impression || '', now
        ).run();

        return jsonResponse({ ok: true, id, message: 'Patient saved to Cloudflare D1.' });
      }

      // DELETE /api/patients/:id
      if (url.pathname.startsWith('/api/patients/') && request.method === 'DELETE') {
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM patients WHERE id = ?").bind(id).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/doctors - Add / Update Doctor
      if (url.pathname === '/api/doctors' && request.method === 'POST') {
        const d = await request.json();
        const now = new Date().toISOString();
        const id = d.id || ('DOC' + Date.now());

        await env.DB.prepare(`
          INSERT INTO reporting_doctors (id, name, designation, qualification, reg_no, department, signature_url, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            designation=excluded.designation,
            qualification=excluded.qualification,
            reg_no=excluded.reg_no,
            department=excluded.department,
            signature_url=excluded.signature_url
        `).bind(
          id, d.name, d.designation || '', d.qualification || '',
          d.regNo || '', d.department || '', d.signatureUrl || '', now
        ).run();

        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/doctors/:id
      if (url.pathname.startsWith('/api/doctors/') && request.method === 'DELETE') {
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM reporting_doctors WHERE id = ?").bind(id).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/tariffs - Update Tariffs
      if (url.pathname === '/api/tariffs' && request.method === 'POST') {
        const tariffs = await request.json();
        const now = new Date().toISOString();
        for (const [code, t] of Object.entries(tariffs)) {
          await env.DB.prepare(`
            INSERT INTO tariffs (code, name, fee, doc_share, ref_share, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(code) DO UPDATE SET
              name=excluded.name,
              fee=excluded.fee,
              doc_share=excluded.doc_share,
              ref_share=excluded.ref_share,
              updated_at=excluded.updated_at
          `).bind(code, t.name, Number(t.fee) || 0, Number(t.docShare) || 0, Number(t.refShare) || 0, now).run();
        }
        return jsonResponse({ ok: true, message: 'Tariffs updated in D1.' });
      }

      // POST /api/settings - Update Facility Settings
      if (url.pathname === '/api/settings' && request.method === 'POST') {
        const st = await request.json();
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO facility_settings (id, facility_name, parent_entity, cin, dpiit, address, phones, vpa, updated_at)
          VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?)
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
          st.facilityName, st.parentEntity, st.cin, st.dpiit,
          st.address, st.phones, st.vpa, now
        ).run();
        return jsonResponse({ ok: true });
      }

      // POST /api/referral-partners
      if (url.pathname === '/api/referral-partners' && request.method === 'POST') {
        const p = await request.json();
        const id = p.id || ('RP' + Date.now());
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO referral_partners (id, name, type, tier, created_at)
          VALUES (?, ?, ?, ?, ?)
        `).bind(id, p.name, p.type || 'Clinic', Number(p.tier) || 1.0, now).run();
        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/referral-partners/:id
      if (url.pathname.startsWith('/api/referral-partners/') && request.method === 'DELETE') {
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM referral_partners WHERE id = ?").bind(id).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/referral-payouts
      if (url.pathname === '/api/referral-payouts' && request.method === 'POST') {
        const p = await request.json();
        const id = p.id || ('RFP' + Date.now());
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO referral_payouts (id, date, partner, amount, mode, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(id, p.date, p.partner, Number(p.amount) || 0, p.mode || 'Cash', now).run();
        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/referral-payouts/:id
      if (url.pathname.startsWith('/api/referral-payouts/') && request.method === 'DELETE') {
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM referral_payouts WHERE id = ?").bind(id).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/ledger
      if (url.pathname === '/api/ledger' && request.method === 'POST') {
        const l = await request.json();
        const id = l.id || ('L' + Date.now());
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO ledger_entries (id, doctor_name, type, date, description, amount, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(id, l.doctorName, l.type, l.date, l.desc, Number(l.amount) || 0, now).run();
        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/ledger/:id
      if (url.pathname.startsWith('/api/ledger/') && request.method === 'DELETE') {
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM ledger_entries WHERE id = ?").bind(id).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      // POST /api/expenses
      if (url.pathname === '/api/expenses' && request.method === 'POST') {
        const e = await request.json();
        const id = e.id || ('E' + Date.now());
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO expenses (id, category, name, amount, created_at)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            category=excluded.category,
            name=excluded.name,
            amount=excluded.amount
        `).bind(id, e.category, e.name, Number(e.amount) || 0, now).run();
        return jsonResponse({ ok: true, id });
      }

      // DELETE /api/expenses/:id
      if (url.pathname.startsWith('/api/expenses/') && request.method === 'DELETE') {
        const id = url.pathname.split('/')[3];
        await env.DB.prepare("DELETE FROM expenses WHERE id = ?").bind(id).run();
        return jsonResponse({ ok: true, deleted: id });
      }

      return jsonResponse({ error: 'Endpoint not found' }, 404);
    }

    // Serve static assets if configured
    if (env?.ASSETS) {
      let assetResponse = await env.ASSETS.fetch(request);
      if (assetResponse.status === 404 && request.method === 'GET' && !url.pathname.includes('.')) {
        const indexUrl = new URL('/index.html', request.url);
        assetResponse = await env.ASSETS.fetch(new Request(indexUrl, request));
      }
      const headers = new Headers(assetResponse.headers);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
        headers.set(k, v);
      }
      return new Response(assetResponse.body, {
        status: assetResponse.status,
        statusText: assetResponse.statusText,
        headers
      });
    }

    return jsonResponse({
      name: 'Nexa-LMIS Al-Jawahira Electrophysiology Clinical Workstation',
      service: 'Cloudflare Worker & D1 SQLite API',
      status: 'active'
    });
  }
};
