-- ==========================================================
-- Cloudflare D1 (SQLite) Schema for Nexa-LMIS / Al-Jawahira
-- Electrophysiology Clinical Workstation
-- ==========================================================

-- 1. Facility & Corporate Legal Configuration
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
);

-- 2. Reporting Consultant Doctors & Official Digital Signatures
CREATE TABLE IF NOT EXISTS reporting_doctors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  designation TEXT NOT NULL,
  qualification TEXT NOT NULL,
  reg_no TEXT NOT NULL,
  department TEXT NOT NULL,
  signature_url TEXT,
  created_at TEXT NOT NULL
);

-- 3. Master Diagnostic Tariff & Share Splits (Per Modality)
CREATE TABLE IF NOT EXISTS tariffs (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  fee REAL NOT NULL,
  doc_share REAL NOT NULL,
  ref_share REAL NOT NULL,
  updated_at TEXT NOT NULL
);

-- 4. Master Patient & Electrophysiology Studies Registry
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
);

CREATE INDEX IF NOT EXISTS idx_patients_token ON patients(token);
CREATE INDEX IF NOT EXISTS idx_patients_date ON patients(date);
CREATE INDEX IF NOT EXISTS idx_patients_modality ON patients(modality);

-- 5. Referral Partner Directory
CREATE TABLE IF NOT EXISTS referral_partners (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  tier REAL NOT NULL DEFAULT 1.0,
  created_at TEXT NOT NULL
);

-- 6. Referral Commission Payouts
CREATE TABLE IF NOT EXISTS referral_payouts (
  id TEXT PRIMARY KEY,
  date TEXT NOT NULL,
  partner TEXT NOT NULL,
  amount REAL NOT NULL,
  mode TEXT NOT NULL DEFAULT 'Cash',
  created_at TEXT NOT NULL
);

-- 7. Reporting Consultants Unified Settlement Ledger (Weekly Sessions)
CREATE TABLE IF NOT EXISTS ledger_entries (
  id TEXT PRIMARY KEY,
  doctor_name TEXT NOT NULL,
  type TEXT NOT NULL, -- 'opening' or 'payout'
  date TEXT NOT NULL,
  description TEXT NOT NULL,
  amount REAL NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_doctor ON ledger_entries(doctor_name);

-- 8. Monthly Operating Expenses (OPEX)
CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  name TEXT NOT NULL,
  amount REAL NOT NULL,
  created_at TEXT NOT NULL
);

-- ==========================================================
-- Default Seed Data
-- ==========================================================

INSERT OR IGNORE INTO facility_settings (id, facility_name, parent_entity, cin, dpiit, address, phones, vpa, updated_at)
VALUES (
  'default',
  'AL JAWAHIRA ELECTROPHYSIOLOGY',
  'SpringNexa Private Limited',
  'U86900JK2026PTC018519',
  'DIPP238776',
  'Near Gousia Pharmacy District Hospital Road Kulgam',
  '+91-7006318286 | +91-6006220236',
  'springnexaa@okaxis',
  datetime('now')
);

INSERT OR IGNORE INTO reporting_doctors (id, name, designation, qualification, reg_no, department, signature_url, created_at)
VALUES 
  ('DOC1', 'Dr. Rayees Ahmad Tarray', 'Consultant Neurologist & Reporting Specialist', 'DM / DNB Neurology, MBBS, MD', 'JKMC-REG-2026', 'Department of Clinical Neurophysiology', '', datetime('now')),
  ('DOC2', 'Dr. Showkat Ahmad Mir', 'Consultant Neurophysiologist', 'DM Neurology, MBBS', 'JKMC-REG-2021', 'Department of Neurology', '', datetime('now'));

INSERT OR IGNORE INTO tariffs (code, name, fee, doc_share, ref_share, updated_at)
VALUES
  ('NCV',  'Nerve Conduction Velocity (Motor & Sensory)', 2500, 1000, 300, datetime('now')),
  ('EEG',  'Routine Video Electroencephalography',        2000, 800,  250, datetime('now')),
  ('EMG',  'Concentric Needle Electromyography',          3000, 1200, 400, datetime('now')),
  ('RNST', 'Repetitive Nerve Stimulation Test',          2200, 900,  250, datetime('now')),
  ('VEP',  'Visual Evoked Potential (Pattern Reversal)',  1500, 600,  200, datetime('now')),
  ('BERA', 'Brainstem Evoked Response Audiometry',       2500, 1000, 300, datetime('now'));

INSERT OR IGNORE INTO referral_partners (id, name, type, tier, created_at)
VALUES
  ('RP1', 'District Hospital Kulgam', 'Govt Hospital', 1.0, datetime('now')),
  ('RP2', 'Gousia Hospital Kulgam', 'Private Hospital', 1.0, datetime('now')),
  ('RP3', 'Gousia Pharmacy Kulgam', 'Local Pharmacy Partner', 1.25, datetime('now')),
  ('RP4', 'Dr. Rayees Ahmad Tarray', 'Consultant / Referring', 1.0, datetime('now'));

INSERT OR IGNORE INTO expenses (id, category, name, amount, created_at)
VALUES
  ('E1', 'Debt Servicing', 'Bike EMI', 3000, datetime('now')),
  ('E2', 'Debt Servicing', 'Mobile EMI', 1088, datetime('now')),
  ('E3', 'Operations', 'Bike Oil / Fuel', 1500, datetime('now')),
  ('E4', 'Utilities', 'Bill LL-Power / Electricity', 500, datetime('now')),
  ('E5', 'Operations', 'Misc Lab Expenses', 737, datetime('now')),
  ('E6', 'Consumables', 'Medical Electrodes / Gel', 500, datetime('now')),
  ('E7', 'Facility', 'Home / Lab Misc Overheads', 3000, datetime('now')),
  ('E8', 'Telecom', 'Phone & Internet Recharge', 300, datetime('now'));

INSERT OR IGNORE INTO ledger_entries (id, doctor_name, type, date, description, amount, created_at)
VALUES
  ('L1', 'Dr. Rayees Ahmad Tarray', 'opening', 'AY 2024-25', 'Legacy Carried Forward Liability', 142800, datetime('now')),
  ('L2', 'Dr. Rayees Ahmad Tarray', 'payout', '06-11-2026', 'Bank Settlement Transfer', 48000, datetime('now'));

INSERT OR IGNORE INTO referral_payouts (id, date, partner, amount, mode, created_at)
VALUES
  ('RFP1', '2026-11-05', 'District Hospital Kulgam', 150, 'Cash', datetime('now'));

INSERT OR IGNORE INTO patients (
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
  datetime('now')
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
  datetime('now')
);
