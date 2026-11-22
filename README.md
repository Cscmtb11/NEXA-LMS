# Nexa-LMIS | Al-Jawahira Electrophysiology Clinical Workstation

Enterprise Electrophysiology Clinical Workstation upgraded for **Cloudflare Workers** and **Cloudflare D1 (Serverless SQLite)**.

Operated by **SpringNexa Private Limited** for **Al-Jawahira Electrophysiology & Center for NeuroDiagnostics**, Kulgam, J&K.

---

## ⚡ Cloudflare Architecture & Security Policy Compliance

This workstation adheres to Cloudflare Workers runtime standards and edge security policies:

1. **Security Headers & Policy Enforcement**:
   - `Content-Security-Policy`: Strictly allows origin assets and approved medical CDNs (Tailwind CSS, Lucide Icons, SheetJS, QRCode.js, Google Fonts).
   - `Strict-Transport-Security`: `max-age=31536000; includeSubDomains; preload`
   - `X-Content-Type-Options`: `nosniff`
   - `X-Frame-Options`: `SAMEORIGIN` (permits letterhead print previews)
   - `Referrer-Policy`: `strict-origin-when-cross-origin`
   - `Permissions-Policy`: `camera=(), microphone=(), geolocation=(), payment=()`

2. **Cloudflare D1 (Serverless SQLite) Database**:
   - Primary database storage runs on Cloudflare D1 with edge latency (<10ms).
   - Fully parameterized prepared statements (`db.prepare().bind().run()`) prevent SQL injection attacks.
   - Self-bootstrapping schema migration on first run with default seed data.
   - Dual-persistence model: Cloudflare D1 is the primary cloud source of truth, backed up by optimistic local caching and downloadable JSON vault snapshots for local drive mirroring (`E:\Backups\DailyBackup`).

3. **RESTful Worker Endpoints**:
   - `GET /api/health`: Health check and database connectivity probe.
   - `GET /api/state`: Full atomic state retrieval for client synchronization.
   - `POST /api/sync`: Full two-way state reconciliation between local cache and D1.
   - `POST /api/patients` & `DELETE /api/patients/:id`: Complete patient registry CRUD.
   - `POST /api/doctors` & `DELETE /api/doctors/:id`: Reporting consultant management & digital signatures.
   - `POST /api/tariffs`: Master diagnostic study tariff and referral split updates.
   - `POST /api/referral-partners` & `DELETE /api/referral-partners/:id`: Partner directory.
   - `POST /api/referral-payouts` & `DELETE /api/referral-payouts/:id`: Payout accounting.
   - `POST /api/ledger` & `DELETE /api/ledger/:id`: Consultant session ledger.
   - `POST /api/expenses` & `DELETE /api/expenses/:id`: Monthly OPEX tracking.
   - `POST /api/settings`: Legal institutional metadata & UPI merchant VPA config.

---

## 🚀 Deployment Instructions to Cloudflare

### 1. Prerequisites
- Node.js (v18+ or v20+)
- Cloudflare Wrangler CLI (`npm install -g wrangler` or `npx wrangler`)
- Cloudflare Account

### 2. Create Cloudflare D1 Database
In PowerShell or Terminal:
```bash
# Log in to Cloudflare
npx wrangler login

# Create the D1 Database
npx wrangler d1 create al-jawahira-db
```
Wrangler will output the database details:
```toml
[[d1_databases]]
binding = "DB"
database_name = "al-jawahira-db"
database_id = "<YOUR_DATABASE_ID>"
```
Paste `<YOUR_DATABASE_ID>` into `wrangler.toml`.

### 3. Apply SQLite Database Migrations
```bash
# Execute migration against your remote Cloudflare D1 database:
npm run d1:migrate:remote

# Or execute locally for offline development:
npm run d1:migrate:local
```

### 4. Run Locally
```bash
npm run dev
```
Open `http://localhost:8787` to access the live workstation with local D1 simulation.

### 5. Deploy to Cloudflare Edge
```bash
npm run deploy
```
Cloudflare will assign an instant production URL:
`https://al-jawahira-workstation.<your-subdomain>.workers.dev`

---

## 📁 Repository Structure

```
├── migrations/
│   └── 0001_initial_schema.sql    # D1 SQLite schema DDL and seed datasets
├── public/
│   └── index.html                 # Modernized clinical workstation UI & D1 sync engine
├── src/
│   └── worker.js                  # Cloudflare Worker REST API & security policy middleware
├── .gitignore                     # Git exclusions (.wrangler, node_modules)
├── package.json                   # Project scripts and metadata
├── README.md                      # Comprehensive deployment guide
└── wrangler.toml                  # Cloudflare Worker & D1 binding configuration
```

---

## 🛡️ License & Legal Notice
© 2026 SpringNexa Private Limited. All rights reserved.
CIN: `U86900JK2026PTC018519` | DPIIT Reg. No: `DIPP238776`.
Designed for Al-Jawahira Electrophysiology, Near District Hospital Road Kulgam, J&K.
