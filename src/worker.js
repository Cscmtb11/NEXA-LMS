/**
 * Cloudflare Worker for Nexa-LMIS | Al-Jawahira Electrophysiology Clinical Workstation
 * Compliant with Cloudflare Security Policies & Cloudflare D1 (Serverless SQLite)
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
 * Automatically ensure Cloudflare D1 tables exist and are seeded
 */
let schemaInitialized = false;
async function ensureD1Schema(db) {
  if (schemaInitialized || !db) return;

  await db.batch([
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

  // Seed default facility settings if empty
  const settingsCheck = await db.prepare("SELECT COUNT(*) as count FROM facility_settings").first();
  if (!settingsCheck || settingsCheck.count === 0) {
    const now = new Date().toISOString();
    await db.batch([
      db.prepare(`
        INSERT INTO facility_settings (id, facility_name, parent_entity, cin, dpiit, address, phones, vpa, updated_at)
        VALUES ('default', 'AL JAWAHIRA ELECTROPHYSIOLOGY', 'SpringNexa Private Limited', 'U86900JK2026PTC018519', 'DIPP238776', 'Near Gousia Pharmacy District Hospital Road Kulgam', '+91-7006318286 | +91-6006220236', 'springnexaa@okaxis', ?)
      `).bind(now),

      db.prepare(`
        INSERT INTO reporting_doctors (id, name, designation, qualification, reg_no, department, signature_url, created_at)
        VALUES 
        ('DOC1', 'Dr. Rayees Ahmad Tarray', 'Consultant Neurologist & Reporting Specialist', 'DM / DNB Neurology, MBBS, MD', 'JKMC-REG-2026', 'Department of Clinical Neurophysiology', '', ?),
        ('DOC2', 'Dr. Showkat Ahmad Mir', 'Consultant Neurophysiologist', 'DM Neurology, MBBS', 'JKMC-REG-2021', 'Department of Neurology', '', ?)
      `).bind(now, now),

      db.prepare(`
        INSERT INTO tariffs (code, name, fee, doc_share, ref_share, updated_at)
        VALUES
        ('NCV',  'Nerve Conduction Velocity (Motor & Sensory)', 2500, 1000, 300, ?),
        ('EEG',  'Routine Video Electroencephalography',        2000, 800,  250, ?),
        ('EMG',  'Concentric Needle Electromyography',          3000, 1200, 400, ?),
        ('RNST', 'Repetitive Nerve Stimulation Test',          2200, 900,  250, ?),
        ('VEP',  'Visual Evoked Potential (Pattern Reversal)',  1500, 600,  200, ?),
        ('BERA', 'Brainstem Evoked Response Audiometry',       2500, 1000, 300, ?)
      `).bind(now, now, now, now, now, now),

      db.prepare(`
        INSERT INTO referral_partners (id, name, type, tier, created_at)
        VALUES
        ('RP1', 'District Hospital Kulgam', 'Govt Hospital', 1.0, ?),
        ('RP2', 'Gousia Hospital Kulgam', 'Private Hospital', 1.0, ?),
        ('RP3', 'Gousia Pharmacy Kulgam', 'Local Pharmacy Partner', 1.25, ?),
        ('RP4', 'Dr. Rayees Ahmad Tarray', 'Consultant / Referring', 1.0, ?)
      `).bind(now, now, now, now),

      db.prepare(`
        INSERT INTO expenses (id, category, name, amount, created_at)
        VALUES
        ('E1', 'Debt Servicing', 'Bike EMI', 3000, ?),
        ('E2', 'Debt Servicing', 'Mobile EMI', 1088, ?),
        ('E3', 'Operations', 'Bike Oil / Fuel', 1500, ?),
        ('E4', 'Utilities', 'Bill LL-Power / Electricity', 500, ?),
        ('E5', 'Operations', 'Misc Lab Expenses', 737, ?),
        ('E6', 'Consumables', 'Medical Electrodes / Gel', 500, ?),
        ('E7', 'Facility', 'Home / Lab Misc Overheads', 3000, ?),
        ('E8', 'Telecom', 'Phone & Internet Recharge', 300, ?)
      `).bind(now, now, now, now, now, now, now, now),

      db.prepare(`
        INSERT INTO ledger_entries (id, doctor_name, type, date, description, amount, created_at)
        VALUES
        ('L1', 'Dr. Rayees Ahmad Tarray', 'opening', 'AY 2024-25', 'Legacy Carried Forward Liability', 142800, ?),
        ('L2', 'Dr. Rayees Ahmad Tarray', 'payout', '06-11-2026', 'Bank Settlement Transfer', 48000, ?)
      `).bind(now, now),

      db.prepare(`
        INSERT INTO referral_payouts (id, date, partner, amount, mode, created_at)
        VALUES ('RFP1', '2026-11-05', 'District Hospital Kulgam', 150, 'Cash', ?)
      `).bind(now),

      db.prepare(`
        INSERT INTO patients (
          id, token, date, name, age, gender, phone, ref_doctor, reporting_doctor,
          modality, fee, doc_share, ref_share, net_lab, pay_mode, indication,
          report_title, lbl_param1, lbl_param2, lbl_sec1, lbl_sec2, lbl_sec3,
          motor_sampled, sensory_sampled, motor_findings, sensory_findings, fwaves_findings, impression,
          created_at
        ) VALUES 
        (
          'P001', '1369', '2026-11-05', 'Hanan Qadir', 29, 'Male', '7006318286',
          'District Hospital Kulgam', 'Dr. Rayees Ahmad Tarray', 'NCV', 2500, 1000, 300, 1200,
          'UPI / QR', 'Numbness and paresthesia in left 4th and 5th fingers',
          'NERVE CONDUCTION STUDIES REPORT',
          'Motor Nerves Sampled:', 'Sensory Nerves Sampled:',
          'MOTOR FINDINGS (DML, CMAP, CV):', 'SENSORY FINDINGS (Latency, Amplitude, CV):', 'F-WAVES:',
          'Bilateral Median and Ulnar nerves.', 'Bilateral Median and Ulnar nerves.',
          'Normal DML, CMAP and CV.',
          'Left Ulnar: Decreased Amplitude with Normal Latency and CV\nBilateral Median and Right Ulnar: Normal Latency, Amplitude and CV.',
          'Normal minimum Latencies.',
          'EPS of sampled nerves is Suggestive of Left Ulnar sensory Neuropathy.',
          ?
        ),
        (
          'P002', '1370', '2026-11-06', 'Mohsina Akhter', 34, 'Female', '6006220236',
          'Dr. Rayees Ahmad Tarray', 'Dr. Rayees Ahmad Tarray', 'NCV', 2500, 1000, 300, 1200,
          'Cash', 'Routine upper limb screening',
          'NERVE CONDUCTION STUDIES REPORT',
          'Motor Nerves Sampled:', 'Sensory Nerves Sampled:',
          'MOTOR FINDINGS (DML, CMAP, CV):', 'SENSORY FINDINGS (Latency, Amplitude, CV):', 'F-WAVES:',
          'Bilateral Median and Ulnar nerves.', 'Bilateral Median and Ulnar nerves.',
          'Normal DML, CMAP and CV.',
          'Normal Latency, Amplitude and CV.',
          'Normal minimum Latencies.',
          'EPS of sampled nerves is Within Normal Limits.',
          ?
        )
      `).bind(now, now)
    ]);
  }

  schemaInitialized = true;
}

/**
 * Load complete application state from Cloudflare D1
 */
async function getFullState(db) {
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
    expenses: (expensesResult.results || []).map(e => ({
      id: e.id,
      category: e.category,
      name: e.name,
      amount: e.amount
    }))
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

      // GET /api/state - Full State for Client Init & Sync
      if (url.pathname === '/api/state' && request.method === 'GET') {
        const state = await getFullState(env.DB);
        return jsonResponse({ ok: true, state });
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
