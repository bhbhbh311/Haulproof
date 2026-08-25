require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { login, requireAuth, createUser } = require('./auth');
const { db } = require('./db');
const { router: msRouter, ssoConfigured, REDIRECT_URI, PORTAL_URL } = require('./msauth');
const loadsRouter = require('./loads');
const podsRouter = require('./pods');
const usersRouter = require('./users');
const orgsRouter = require('./orgs');

const app = express();
// Same-origin portal + credentialed cookies: reflect the request origin and allow credentials.
app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.json({ limit: '2mb' }));

const SESSION_SECURE = (process.env.PORTAL_URL || '').startsWith('https://');

// --- auth: password login (kept as a backup alongside Microsoft SSO) ---
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const result = login(email, password);
  if (!result) return res.status(401).json({ error: 'Wrong email or password' });
  // Also set the session cookie so the portal behaves the same whether you used SSO or a password.
  res.cookie('hp_session', result.token, {
    httpOnly: true, sameSite: 'lax', secure: SESSION_SECURE, maxAge: 12 * 60 * 60 * 1000, path: '/',
  });
  res.json(result);
});

// Tells the portal which sign-in options to show (so the Microsoft button only appears when set up).
app.get('/api/auth/config', (_req, res) => res.json({ microsoft: ssoConfigured() }));

// Microsoft Entra SSO (start + callback).
app.use('/api/auth', msRouter);

// Clear the session cookie.
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('hp_session', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: req.user }));

// --- resources ---
app.use('/api/loads', loadsRouter);
app.use('/api/pods', podsRouter);
app.use('/api/users', usersRouter);
app.use('/api/orgs', orgsRouter);

// The ready-to-share driver link for the SIGNED-IN customer's admin — device key baked in.
// Super-admins provision drivers per customer from the Customers screen instead.
app.get('/api/driver-link', requireAuth, (req, res) => {
  if (req.user.role === 'superadmin') return res.status(400).json({ error: 'Open a customer from the Customers list to get its driver link.' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const org = req.user.orgId ? db.prepare('SELECT * FROM orgs WHERE id = ?').get(req.user.orgId) : null;
  if (!org) return res.status(404).json({ error: 'Your login is not attached to a customer' });
  const origin = (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host'));
  res.json({ key: org.deviceKey, driverUrl: origin + '/driver', link: origin + '/driver?k=' + encodeURIComponent(org.deviceKey) });
});

// --- Boot migration + seeding: make the single-tenant install multi-customer safely ---
function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }
try {
  // 1) A default customer holds any pre-existing (single-tenant) data. Its device key reuses the
  //    legacy INGEST_API_KEY when present, so drivers already configured keep working.
  const defName = (process.env.DEFAULT_ORG_NAME || 'Callahan Transportation').trim();
  let defOrg = db.prepare('SELECT * FROM orgs WHERE name = ?').get(defName);
  if (!defOrg) {
    const id = crypto.randomUUID();
    const key = (process.env.INGEST_API_KEY || '').trim() || newDeviceKey();
    db.prepare(`INSERT INTO orgs (id, name, deviceKey, active, createdAt) VALUES (?,?,?,1,?)`).run(id, defName, key, Date.now());
    defOrg = db.prepare('SELECT * FROM orgs WHERE id = ?').get(id);
    console.log('Created default customer: ' + defName);
  }
  // 2) Backfill any rows that predate multi-customer support into the default customer.
  db.prepare(`UPDATE loads SET orgId = ? WHERE orgId IS NULL`).run(defOrg.id);
  db.prepare(`UPDATE pods  SET orgId = ? WHERE orgId IS NULL`).run(defOrg.id);
  db.prepare(`UPDATE users SET orgId = ? WHERE orgId IS NULL AND role != 'superadmin'`).run(defOrg.id);

  // 3) The default customer's admin (existing password login) — unchanged day-to-day experience.
  const adminEm = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
  if (adminEm && process.env.ADMIN_PASSWORD) {
    const ex = db.prepare('SELECT * FROM users WHERE email = ?').get(adminEm);
    if (!ex) { createUser({ email: adminEm, name: 'Administrator', role: 'admin', password: process.env.ADMIN_PASSWORD, orgId: defOrg.id }); console.log('Seeded customer admin: ' + adminEm); }
    else if (ex.role !== 'superadmin' && !ex.orgId) { db.prepare('UPDATE users SET orgId = ?, role = ? WHERE id = ?').run(defOrg.id, ex.role === 'admin' ? 'admin' : ex.role, ex.id); }
  }

  // 4) The platform master admin (super-admin) — manages all customers. Same password as ADMIN_PASSWORD
  //    unless SUPERADMIN_PASSWORD is set, so no extra secret to configure.
  const superEm = (process.env.SUPERADMIN_EMAIL || 'bharris@callahantrans.com').toLowerCase().trim();
  const superPw = process.env.SUPERADMIN_PASSWORD || process.env.ADMIN_PASSWORD;
  if (superEm && superPw) {
    const ex = db.prepare('SELECT * FROM users WHERE email = ?').get(superEm);
    if (!ex) { createUser({ email: superEm, name: 'Master Admin', role: 'superadmin', password: superPw, orgId: null }); console.log('Seeded super-admin: ' + superEm); }
    else if (ex.role !== 'superadmin') { db.prepare('UPDATE users SET role = ?, orgId = NULL WHERE id = ?').run('superadmin', ex.id); console.log('Promoted to super-admin: ' + superEm); }
  }
} catch (e) { console.error('boot migration failed', e); }

// --- signature setup screen + its pdf.js engine ---
app.get('/prepare', (_req, res) => res.sendFile(path.join(__dirname, 'prepare.html')));

// --- driver app served at /driver so phones just open a URL ---
// Auto-points at this server's origin. Device key is NOT embedded; pass it once via ?k=KEY
// (share that link privately) or drivers set it in the app's Outbox.
let DRIVER_HTML = null;
function driverHtml() {
  if (DRIVER_HTML) return DRIVER_HTML;
  try {
    let html = fs.readFileSync(path.join(__dirname, 'haulproof_driver.html'), 'utf8');
    const boot = '<script>try{var k=new URL(location.href).searchParams.get("k");var cur=JSON.parse(localStorage.getItem("hp_cfg")||"{}");localStorage.setItem("hp_cfg",JSON.stringify({endpoint:location.origin+"/api/pods/ingest",apikey:k||cur.apikey||""}));}catch(e){}</script>';
    DRIVER_HTML = html.replace('<body>', '<body>' + boot);
  } catch { DRIVER_HTML = null; }
  return DRIVER_HTML;
}
app.get('/driver', (_req, res) => { const h = driverHtml(); if (!h) return res.status(404).send('driver app not installed'); res.type('html').send(h); });
function pdfjsFile(name) {
  const roots = [path.join(__dirname, 'node_modules', 'pdfjs-dist', 'build'), path.join(__dirname, 'node_modules', 'pdfjs-dist', 'legacy', 'build')];
  for (const r of roots) { const f = path.join(r, name); if (fs.existsSync(f)) return f; }
  return null;
}
app.get('/vendor/pdf.js', (_req, res) => { const f = pdfjsFile('pdf.min.js') || pdfjsFile('pdf.js'); if (!f) return res.status(404).send('pdfjs missing — run npm install'); res.type('text/javascript'); fs.createReadStream(f).pipe(res); });
app.get('/vendor/pdf.worker.js', (_req, res) => { const f = pdfjsFile('pdf.worker.min.js') || pdfjsFile('pdf.worker.js'); if (!f) return res.status(404).send('pdfjs worker missing'); res.type('text/javascript'); fs.createReadStream(f).pipe(res); });

// --- portal home page (explicit route; we do NOT serve the whole folder so
//     source files, package.json, and the allowlist are never web-exposed) ---
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/api/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`HaulProof backend on http://localhost:${PORT}  (portal: ${PORTAL_URL})`);
  if (ssoConfigured()) {
    console.log(`Microsoft SSO: ON. Register this EXACT redirect URI in your Entra app registration:`);
    console.log(`   ${REDIRECT_URI}`);
  } else {
    console.log(`Microsoft SSO: off (set MS_CLIENT_ID/MS_CLIENT_SECRET to enable). When on, the redirect URI will be:`);
    console.log(`   ${REDIRECT_URI}`);
  }
});
