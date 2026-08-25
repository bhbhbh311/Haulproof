require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { login, requireAuth, createUser } = require('./auth');
const { db } = require('./db');
const { router: msRouter, ssoConfigured, REDIRECT_URI, PORTAL_URL } = require('./msauth');
const loadsRouter = require('./loads');
const podsRouter = require('./pods');

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

// Auto-create the admin from env on first boot (so a managed host needs no manual seed step).
try {
  const em = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
  if (em && process.env.ADMIN_PASSWORD) {
    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(em);
    if (!exists) { createUser({ email: em, name: 'Administrator', role: 'admin', password: process.env.ADMIN_PASSWORD }); console.log('Seeded admin: ' + em); }
  }
} catch (e) { console.error('auto-seed failed', e); }

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
