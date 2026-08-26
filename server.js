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
const driversRouter = require('./drivers');
const { router: carriersRouter } = require('./carriers');
const { router: brokersRouter } = require('./brokers');

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
app.use('/api/drivers', driversRouter);
app.use('/api/carriers', carriersRouter);
app.use('/api/brokers', brokersRouter);

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
    // Installable-app (Add to Home Screen) tags.
    const headTags = '<link rel="manifest" href="/manifest.webmanifest">'
      + '<meta name="theme-color" content="#1655d1">'
      + '<meta name="mobile-web-app-capable" content="yes">'
      + '<meta name="apple-mobile-web-app-capable" content="yes">'
      + '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">'
      + '<meta name="apple-mobile-web-app-title" content="HaulProof">'
      + '<link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">';
    const boot = '<script>try{var k=new URL(location.href).searchParams.get("k");var cur=JSON.parse(localStorage.getItem("hp_cfg")||"{}");localStorage.setItem("hp_cfg",JSON.stringify({endpoint:location.origin+"/api/pods/ingest",apikey:k||cur.apikey||""}));}catch(e){}</script>';
    DRIVER_HTML = html.replace('</head>', headTags + '</head>').replace('<body>', '<body>' + boot);
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

// --- Installable driver app: manifest + icons (Add to Home Screen) ---
const ICON_512 = Buffer.from('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', 'base64');
const ICON_192 = Buffer.from('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', 'base64');
const ICON_APPLE = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAYAAAA9zQYyAAAFXUlEQVR42u3dS2gcdQDH8d/sJpvdNBuSWLIkilmqQdvGoEj1YsnBS/EoJhUVhKK0Nw/iAwVBoViqLZ70oIhIQQ1tEQQj6qGgYKuiprVJLLTNtinbbWOaJk12M/sYD4JPxGayj//85/u9hllmh0/++c9/HnG6h8c9EVlShENAgCYCNBGgiQBNgCYCNBGgiQBNBGgCNBGgiQBNBGgiQBOgiQBNBGgiQBMBmgBNBGgiQBMBmgjQBGgiQBMBmgjQRIAmQBMBmgjQRIAmAjQBmgjQRIAmAjQBmgjQRIAmAjQRoAnQRIAmAjTVvtzoIKDJLsxhRA1oy0fmsKEGdAimGWFCDeiQzJlzo4OhgA3okJ0A2o4a0CHCHAbUgA4ZZklKjRwHNNmRzZgBHbLR2XbMgAYzoAnMgCYwA5rADGgwhzxAW4o5jKMzoMEMaAIzoAnMgAYzmAENZkATmAENJgMCM6D/E3MjUXMVENA1gdQI1GAGdE0h1RM1mAFdF0j1QA1mQNcVUi1RgxnQDYFUC9TcOQfohkKqJkDWmgFdtdaCohqowQxoa1CDGdDWoAYzoK1BDWZAW4MazIC2BjWYAR26E0UwAzoQqLkKCGhrUIMZ0KGefoAZ0EajBjOgQ4kazIC2dqQmQAcaNb8ogLYGNZgBbQ1qMAPaGtRgBrQ1qMEMaGtQgxnQ1qAGM6ADifqfcFMjx8HcwJzu4XGPw0CM0ESAJgI0EaAJ0ESBr8nEneq9oVk/vrVx1duVK556Hz5R1X25u79Vn+6+ddXbZeeKunPXZN2++/VW8SS3WFGh6Gn+WlmX50u6MOvql5kVTZ7L69jUsuYWS4CmgPxJdqR4LKJ4TOpYF1U6FdOW21r/+LnnSZPnCvrk6FUd/vqKpnMuoCm4OY60qS+uTX1xPTOS0uffL2j/oZzGz+SZQ1PwR/NtW9r12av92r/zJiUTUUCTHbAfvb9LX+7t1+a+OKDJjtKpmD5++Rbde/s6QJMdtbdGdeD5tPpvbAE02YP6/WfTiscigCY72tDToue2pwBN9vTEtvXq6Wo2ap9Yh7ak67lK2paIqLOtSQPpuLbekdTIUMealuJizY6efGC9XjmQZYSm+nctX9H5y67GvlvQC+9e0F27pvThkStr+swH7+tQxGHKQQa0mC/rqTfP643Dl3x/Rk9XswY3JABN5rTno4s6Ornke/t7DFqXBjTJ86TXD+Z8b7/x5jigyay+mVjSYr7sa9t0dwzQZFalsqeT0wVf23a1NwGazOvXBX839re2RABN5hXxuf7mGfRmF0DTn1OHpL+LLMsrFWO+g1VXCqMRp6r/DDNMNUUdbe7zt55s0jOIjNAkSdo60Ka2hD8OmUsuoMmcHEd6+iH/d85NZAqAJnN68ZGevz35vdq+nVoy5rtwt12ISyai2r2jV9uHOn1/RnauqBNn84Cm+tfaElFnMqqBdEJDg2u/fVSSDn01r4pBy3aAtqRGrPC4RU/vjM0adRyYQ5Pv3h6bVXauCGgKfmeyK9o7mjNuvwBNq25huazHX8uo4FYATcHH/NieaZ2aKRi5f1adFJr0Ol0by+Rc7diX0c/T5r64kVUO+t88T/rgyJxeei/r+yEAQJMRkL/4YUH7Dub00+lgvE4X0PSv/vrC87MXeeE5GT7quiVPK8XK7/+S4mpJM7OuTs2saCJT0LGpJd9PrgCajD4hDmIs2xGgiQBNBGgiQBOgiQBNBGgiQBMBmgBNBGgiQBMBmgjQBGgiQBMBmqi6Od3D4x6HgRihiQBNBGgiQBOgiQBNBGgiQBMBmgBNBGgiQBMBmgjQBGgiQBMBmgjQRIAmQBMFqd8AcXjdNbjA/LMAAAAASUVORK5CYII=', 'base64');
app.get('/manifest.webmanifest', (_req, res) => {
  res.type('application/manifest+json');
  res.json({
    name: 'HaulProof Driver', short_name: 'HaulProof',
    start_url: '/driver', scope: '/driver', display: 'standalone',
    background_color: '#0e1420', theme_color: '#1655d1',
    icons: [
      { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
      { src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' },
    ],
  });
});
app.get('/icons/icon-512.png', (_req, res) => { res.type('png'); res.send(ICON_512); });
app.get('/icons/icon-192.png', (_req, res) => { res.type('png'); res.send(ICON_192); });
app.get('/icons/apple-touch-icon.png', (_req, res) => { res.type('png'); res.send(ICON_APPLE); });

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
