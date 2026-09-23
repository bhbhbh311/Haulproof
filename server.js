require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { sendMail, helpEmail } = require('./mailer');
const { login, requireAuth, requireSuper, createUser, effectiveCaps } = require('./auth');
const { db } = require('./db');
const { verifyUnsub, optOut, optIn, listOptedOut } = require('./optout');
const { router: msRouter, ssoConfigured, REDIRECT_URI, PORTAL_URL } = require('./msauth');
const loadsRouter = require('./loads');
const podsRouter = require('./pods');
const usersRouter = require('./users');
const orgsRouter = require('./orgs');
const driversRouter = require('./drivers');
const { router: carriersRouter } = require('./carriers');
const { router: brokersRouter } = require('./brokers');
const requestsRouter = require('./requests');
const receiversRouter = require('./receivers');
const customersRouter = require('./customers');

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

app.get('/api/me', requireAuth, (req, res) => {
  // Surface the forced-password-reset flag so a cookie auto-login enforces it too.
  let mustChangePassword = false;
  try { const u = db.prepare('SELECT mustChangePassword FROM users WHERE id = ?').get(req.user.sub); mustChangePassword = !!(u && u.mustChangePassword); } catch (e) {}
  // Effective capabilities (role defaults + admin-granted) so the UI can show the controls this login may use.
  let capabilities = []; try { capabilities = effectiveCaps(req.user); } catch (e) {}
  res.json({ user: Object.assign({}, req.user, { mustChangePassword, capabilities }) });
});

// PUBLIC: the "here's your login" link page reads this to show the user their email + temp password.
// Token comes from an admin generating a login link (POST /api/users/:id/login-link).
app.get('/api/auth/login-info', (req, res) => {
  const token = (req.query.t || '').trim();
  if (!token) return res.status(400).json({ error: 'This link is missing its code.' });
  const row = db.prepare('SELECT * FROM login_links WHERE token = ?').get(token);
  if (!row) return res.status(404).json({ error: 'This link is not valid.' });
  if (row.expiresAt && row.expiresAt < Date.now()) return res.status(410).json({ error: 'This link has expired. Ask your administrator to send a new one.' });
  const user = db.prepare('SELECT email, name, orgId FROM users WHERE id = ?').get(row.userId);
  if (!user) return res.status(404).json({ error: 'This login no longer exists.' });
  const org = user.orgId ? db.prepare('SELECT name FROM orgs WHERE id = ?').get(user.orgId) : null;
  try { db.prepare('UPDATE login_links SET viewedAt = ? WHERE token = ?').run(Date.now(), token); } catch (e) {}
  const origin = (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host'));
  res.json({ email: user.email, name: user.name || '', company: org ? org.name : '', tempPassword: row.tempPassword, signInUrl: origin + '/app' });
});

// PUBLIC: self-service "forgot password". Given an email, if a matching login exists we set a fresh
// temporary password (forcing a reset on next sign-in) and email that person a link to their new
// credentials — reusing the same login-link machinery an admin uses. We ALWAYS return the same
// generic success so this can't be used to probe which emails have accounts.
app.post('/api/auth/forgot-password', (req, res) => {
  const em = ((req.body && req.body.email) || '').toLowerCase().trim();
  const generic = { ok: true, message: 'If that email has an account, a reset link is on its way.' };
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return res.json(generic);
  try {
    const user = db.prepare('SELECT id, email, name FROM users WHERE email = ?').get(em);
    if (!user) return res.json(generic);   // no such login — say nothing revealing
    const temp = crypto.randomBytes(4).toString('hex');            // 8-char temporary password
    db.prepare('UPDATE users SET passHash = ?, mustChangePassword = 1 WHERE id = ?').run(bcrypt.hashSync(temp, 10), user.id);
    const token = crypto.randomBytes(24).toString('hex');
    const now = Date.now(), expiresAt = now + 24 * 60 * 60 * 1000;  // reset link good for 24 hours
    db.prepare('DELETE FROM login_links WHERE userId = ?').run(user.id);
    db.prepare('INSERT INTO login_links (token, userId, tempPassword, expiresAt, createdAt) VALUES (?,?,?,?,?)').run(token, user.id, temp, expiresAt, now);
    const origin = (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host'));
    const link = origin + '/login-info?t=' + token;
    sendMail({
      to: user.email,
      subject: 'Reset your HaulProof password',
      text: `Someone asked to reset the password for your HaulProof login (${user.email}).\n\nOpen this link to see your temporary password and sign in — you'll set a new password right away:\n${link}\n\nThis link expires in 24 hours. If you didn't request this, you can ignore this email; your current password still works until you use the link.`,
    });
    res.json(generic);
  } catch (e) { console.error('forgot-password', e.message); res.json(generic); }
});

// PUBLIC: "still need help" — routes a support request to the configured help inbox. Used by both the
// portal login screen and (via the driver route) the driver app when self-service reset isn't enough.
app.post('/api/auth/help', (req, res) => {
  const b = req.body || {};
  const kind = String(b.kind || 'password').toLowerCase() === 'pin' ? 'PIN' : 'password';
  const em = String(b.email || '').trim();
  const note = String(b.note || '').trim().slice(0, 2000);
  const who = em ? em : '(no email given)';
  const lines = [
    `A HaulProof user needs help with a ${kind} reset.`,
    ``,
    `Their email: ${who}`,
    note ? `\nWhat they said:\n${note}` : `\n(They didn't add a note.)`,
    ``,
    `— Sent automatically from the HaulProof ${kind === 'PIN' ? 'driver app' : 'sign-in page'}.`,
  ];
  sendMail({ to: helpEmail(), subject: `HaulProof help request — ${kind} reset`, text: lines.join('\n') });
  res.json({ ok: true, message: "Thanks — we've sent your request to support. Someone will reach out." });
});

// --- resources ---
app.use('/api/loads', loadsRouter);
app.use('/api/pods', podsRouter);
app.use('/api/users', usersRouter);
app.use('/api/orgs', orgsRouter);
app.use('/api/drivers', driversRouter);
app.use('/api/carriers', carriersRouter);
app.use('/api/brokers', brokersRouter);
app.use('/api/requests', requestsRouter);
app.use('/api/receivers', receiversRouter);
app.use('/api/customers', customersRouter);

// --- Master-Admin dashboard summary: counts across the whole system. Super-admin only. ---
app.get('/api/stats', requireAuth, requireSuper, (_req, res) => {
  const one = (sql, ...args) => { try { const r = db.prepare(sql).get(...args); return r ? Number(Object.values(r)[0]) || 0 : 0; } catch (e) { return 0; } };
  const byKind = (kind) => one('SELECT COUNT(*) c FROM orgs WHERE kind = ?', kind);
  res.json({
    customers: byKind('customer'),
    carriers:  byKind('carrier'),
    brokers:   byKind('broker'),
    receivers: byKind('receiver'),
    orgsTotal: one('SELECT COUNT(*) c FROM orgs'),
    drivers:   one('SELECT COUNT(*) c FROM drivers'),
    users:     one('SELECT COUNT(*) c FROM users'),
    loads:     one('SELECT COUNT(*) c FROM loads'),
    documents: one('SELECT COUNT(*) c FROM pods'),
    signed:    one("SELECT COUNT(*) c FROM pods WHERE status IN ('signed','emailed')"),
    optouts:   one('SELECT COUNT(*) c FROM email_optouts'),
    accessRequests: one("SELECT COUNT(*) c FROM access_requests WHERE status = 'pending'"),
  });
});

// --- Opt-out (unsubscribe) admin views. Super-admin only. ---
app.get('/api/optouts', requireAuth, requireSuper, (_req, res) => {
  res.json({ optouts: listOptedOut() });
});
// Admin re-consent (remove an address from the opt-out list) — e.g. the recipient asked to resume.
app.post('/api/optouts/remove', requireAuth, requireSuper, (req, res) => {
  const email = (req.body && req.body.email) || '';
  if (!email) return res.status(400).json({ error: 'email required' });
  optIn(email);
  res.json({ ok: true });
});

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
app.get('/prepare', (_req, res) => { res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0'); res.sendFile(path.join(__dirname, 'prepare.html')); });
app.get('/request', (_req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(path.join(__dirname, 'request.html')); });
app.get('/login-info', (_req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(path.join(__dirname, 'login-info.html')); });
app.get('/help', (_req, res) => { res.set('Cache-Control', 'no-cache'); res.sendFile(path.join(__dirname, 'help.html')); });

// --- PUBLIC one-click unsubscribe (no login). The token is HMAC-signed for one email address. ---
function unsubPage(title, msg, ok) {
  const color = ok ? '#137a3f' : '#b42318';
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>${title} — HaulProof</title></head>`
    + `<body style="margin:0;background:#f4f6fa;font:16px/1.5 system-ui,Arial,sans-serif;color:#1f2733">`
    + `<div style="max-width:520px;margin:60px auto;background:#fff;border:1px solid #e3e8f0;border-radius:14px;padding:32px 28px;text-align:center">`
    + `<div style="font-size:26px;font-weight:800;color:#1f6feb;margin-bottom:6px">HaulProof</div>`
    + `<h1 style="font-size:20px;color:${color};margin:14px 0 10px">${title}</h1>`
    + `<p style="color:#41505f;margin:0 auto;max-width:400px">${msg}</p>`
    + `<p style="margin-top:26px"><a href="https://haulproofepod.com" style="color:#1f6feb;text-decoration:none;font-weight:600">Go to HaulProof</a></p>`
    + `</div></body></html>`;
}
function doUnsub(req, res) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  const token = (req.query.t || (req.body && req.body.t) || '').toString().trim();
  const email = verifyUnsub(token);
  if (!email) { res.status(400).type('html'); return res.send(unsubPage('Link not valid', 'This unsubscribe link is missing or invalid. If you keep getting documents you don\'t want, reply to the email and let us know.', false)); }
  try { optOut(email, 'unsubscribe-link'); } catch (e) {}
  res.type('html').send(unsubPage('You\'re unsubscribed', `<b>${email}</b> will no longer receive delivery documents from HaulProof. Changed your mind? Ask the sender to add you back.`, true));
}
app.get('/unsubscribe', doUnsub);
app.post('/unsubscribe', express.urlencoded({ extended: false }), doUnsub); // email-client one-click (List-Unsubscribe-Post)

// --- driver app served at /driver so phones just open a URL ---
// Auto-points at this server's origin. Device key is NOT embedded; pass it once via ?k=KEY
// (share that link privately) or drivers set it in the app's Outbox.
let DRIVER_HTML = null, DRIVER_MTIME = 0;
function driverHtml() {
  try {
    const p = path.join(__dirname, 'haulproof_driver.html');
    const mt = fs.statSync(p).mtimeMs;
    // Re-read whenever the file changes on disk, so dropping in a new build takes effect without a restart.
    if (DRIVER_HTML && mt === DRIVER_MTIME) return DRIVER_HTML;
    let html = fs.readFileSync(p, 'utf8');
    // Installable-app (Add to Home Screen) tags.
    const headTags = '<link rel="manifest" href="/manifest.webmanifest">'
      + '<meta name="theme-color" content="#1655d1">'
      + '<meta name="mobile-web-app-capable" content="yes">'
      + '<meta name="apple-mobile-web-app-capable" content="yes">'
      + '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">'
      + '<meta name="apple-mobile-web-app-title" content="HaulProof">'
      + '<link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">'
      // Register the service worker so the home-screen app always loads the freshest
      // build (network-first) and auto-updates itself instead of serving a stale cache.
      // Browsers only check for a new SW on navigation / ~once a day, so an installed
      // home-screen app can keep running a stale build. We poll reg.update() on a timer and
      // whenever the app regains focus, so a new deploy is picked up within a minute — but we
      // never reload while the driver is mid-signature (window.__hpBusy); the update applies
      // the moment they're back on a safe screen, so no in-progress signature is ever lost.
      + '<script>if("serviceWorker" in navigator){try{'
      + 'var _hpHad=!!navigator.serviceWorker.controller,_hpRef=false;'
      + 'function _hpReload(){if(_hpRef)return;if(window.__hpBusy){setTimeout(_hpReload,4000);return;}_hpRef=true;location.reload();}'
      + 'navigator.serviceWorker.addEventListener("controllerchange",function(){if(!_hpHad){_hpHad=true;return;}_hpReload();});'
      + 'navigator.serviceWorker.register("/sw.js",{scope:"/driver"}).then(function(reg){var chk=function(){try{reg.update();}catch(_){}};setInterval(chk,60000);document.addEventListener("visibilitychange",function(){if(!document.hidden)chk();});window.addEventListener("focus",chk);}).catch(function(){});'
      + '}catch(e){}}</script>';
    // Establish the driver's device key on every open. Priority: ?k= from their personal link → whatever the
    // phone already stored → a durable cookie (survives cleared local storage / a home-screen launch with no ?k=).
    // When a fresh ?k= arrives, also write the year-long cookie so the credential sticks to this device.
    const boot = '<script>try{var ck=function(n){var m=document.cookie.match("(?:^|; )"+n+"=([^;]*)");return m?decodeURIComponent(m[1]):"";};var k=new URL(location.href).searchParams.get("k");var cur=JSON.parse(localStorage.getItem("hp_cfg")||"{}");var key=k||cur.apikey||ck("hp_driver_key")||"";if(k){try{var d=new Date(Date.now()+31536000000);document.cookie="hp_driver_key="+encodeURIComponent(k)+";expires="+d.toUTCString()+";path=/;samesite=lax";}catch(_){}}localStorage.setItem("hp_cfg",JSON.stringify({endpoint:location.origin+"/api/pods/ingest",apikey:key}));}catch(e){}</script>';
    DRIVER_HTML = html.replace('</head>', headTags + '</head>').replace('<body>', '<body>' + boot);
    DRIVER_MTIME = mt;
  } catch { DRIVER_HTML = null; }
  return DRIVER_HTML;
}
app.get('/driver', (req, res) => {
  const h = driverHtml(); if (!h) return res.status(404).send('driver app not installed');
  // Durable per-device credential: when the driver opens their personal link (?k=token), remember the token in a
  // year-long cookie so it survives cleared storage, a dropped URL param, and Add-to-Home-Screen relaunches.
  const k = (req.query.k || '').toString().trim();
  if (k) res.cookie('hp_driver_key', k, { sameSite: 'lax', secure: SESSION_SECURE, maxAge: 365 * 24 * 60 * 60 * 1000, path: '/' });
  // Ask the phone to revalidate every open so a new build is picked up instead of a stale cached copy.
  res.set('Cache-Control', 'no-cache, must-revalidate');
  res.type('html').send(h);
});
// --- Service worker: makes the Add-to-Home-Screen app self-updating instead of stale-cached. ---
// Strategy: network-FIRST for the app + its assets (always load the newest build when online),
// cache only as an offline fallback, and never touch API calls (POST uploads / GET loads stay live).
// The cache name is versioned to the current driver build, so every deploy retires the old cache.
const SW_JS = `// HaulProof driver service worker (auto-generated)
var CACHE='__VERSION__';
self.addEventListener('install', function(e){ self.skipWaiting(); });
self.addEventListener('activate', function(e){
  e.waitUntil((async function(){
    var keys = await caches.keys();
    await Promise.all(keys.filter(function(k){ return k!==CACHE; }).map(function(k){ return caches.delete(k); }));
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', function(e){
  var req = e.request;
  if(req.method !== 'GET') return;                       // uploads / posts go straight to the network
  var url;
  try { url = new URL(req.url); } catch(_) { return; }
  if(url.origin !== self.location.origin) return;        // don't touch cross-origin
  if(url.pathname.indexOf('/api/') === 0) return;        // never cache API — always live
  e.respondWith((async function(){
    try {
      var fresh = await fetch(req);                       // network first
      if(fresh && fresh.ok){
        var cacheable = req.mode === 'navigate'
          || url.pathname.indexOf('/icons/') === 0
          || url.pathname.indexOf('/vendor/') === 0
          || url.pathname === '/manifest.webmanifest';
        if(cacheable){ var c = await caches.open(CACHE); c.put(req, fresh.clone()); }
      }
      return fresh;
    } catch(err) {                                        // offline: fall back to cache
      var hit = await caches.match(req);
      if(hit) return hit;
      if(req.mode === 'navigate'){ var d = await caches.match('/driver'); if(d) return d; }
      throw err;
    }
  })());
});`;
app.get('/sw.js', (_req, res) => {
  let ver = 'hp-0';
  try { ver = 'hp-' + Math.floor(fs.statSync(path.join(__dirname, 'haulproof_driver.html')).mtimeMs); } catch (_) {}
  res.type('text/javascript');
  res.set('Cache-Control', 'no-cache, must-revalidate');   // so the phone always re-checks the SW
  res.send(SW_JS.replace('__VERSION__', ver));
});
function pdfjsFile(name) {
  const roots = [path.join(__dirname, 'node_modules', 'pdfjs-dist', 'build'), path.join(__dirname, 'node_modules', 'pdfjs-dist', 'legacy', 'build')];
  for (const r of roots) { const f = path.join(r, name); if (fs.existsSync(f)) return f; }
  return null;
}
app.get('/vendor/pdf.js', (_req, res) => { const f = pdfjsFile('pdf.min.js') || pdfjsFile('pdf.js'); if (!f) return res.status(404).send('pdfjs missing — run npm install'); res.type('text/javascript'); fs.createReadStream(f).pipe(res); });
app.get('/vendor/pdf.worker.js', (_req, res) => { const f = pdfjsFile('pdf.worker.min.js') || pdfjsFile('pdf.worker.js'); if (!f) return res.status(404).send('pdfjs worker missing'); res.type('text/javascript'); fs.createReadStream(f).pipe(res); });

// --- public marketing landing page at the root; the portal app lives at /app ---
//     (explicit routes; we do NOT serve the whole folder so source files,
//     package.json, and the allowlist are never web-exposed) ---
app.get('/', (_req, res) => { res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0'); res.sendFile(path.join(__dirname, 'landing.html')); });
app.get('/app', (_req, res) => { res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0'); res.sendFile(path.join(__dirname, 'index.html')); });

// --- Installable driver app: manifest + icons (Add to Home Screen) ---
const ICON_512 = Buffer.from('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T/b3I+epRp5C0RFYQy6T/D5o4BfZXeF0PwAREdh2EiAw0NMRYExyba/zUCx7xkouqQkwyZ5/YA393SHULvjRwC+yZxQARKSheB5+LDAIIKiX+vnt/pzO9IvsNQUAEWl46tkvMvnUCEhERKQNKQCIiIi0IQUAERGRNqQAICIi0oYUAERERNqQAoCIiEgbUgAQERFpQwoAIiIibUgBQEREpA0pAIiIiLQhBQAREZE2pAAgIiLShhQARERE2pACgIiISBtSABAREWlDCgAiIiJtSAFARESkDSkAiIiItCEFABERkTakACAiItKGFABERETakAKAiIhIG1IAEBERaUMKACIiIm1IAUBERKQNKQCIiIi0IQUAERGRNqQAICIi0oYUAERERNqQAoCIiEgbUgAQERFpQwoAIiIibUgBQEREpA0pAIiIiLQhBQAREZE2pAAgIiLShhQARERE2pACgIiISBtSABAREWlDCgAiIiJtSAFARESkDSkAiIiItCEFABERkTakACAiItKGFABERETakAKAiIhIG1IAEBERaUMKACIiIm1IAUBERKQNKQCIiIi0IQUAERGRNqQAICIi0oYUAERERNqQAoCIiEgbUgAQERFpQwoAIiIibUgBQEREpA0pAIiIiLQhBQAREZE2pAAgIiLShhQARERE2pACgIiISBtSABAREWlDCgAiIiJtSAFARESkDSkAiIiItCEFABERkTakACAiItKGFABERETakLVmuh+CiIiI7E/GgA1Dg/fT/VBERERkf/AeMimDTQVaAhAREWkXHkgFBptJGZz3KAaIiIi0NgPgPanQYDNpm2wBKAGIiIi0NgPOQy4TYHs7AtUAiIiItAnvoStvsd15S+y0BSAiItLqDBB7T3fOYrtygbYARERE2oAx4GKY0ZPC9naGxF7jv4iISOszOA+9HQF2Zk9IHGsJQEREpB3E3tPTEWDnzQhJhQZVAoqIiLQ470kFhnkzUtgFM9Nk04ZY47+IiEhLiz1k04YFM1PY+TPTZGu9ALQJICIi0poMyWJ/Nm2ZPzONnT8zRTaVHAVUAhAREWlRBmLnyaYs82emsL2dAXP6Q6J4uh+ZiIiITKUohjn9Ib2dQXIZ0EFzM1Qjj64GFhERaU3WQCXyHDQ3k1wGBHDI/AyVyGGMEoCIiEgrMsZQjRyPWZAFSALA0rkZMimD11FAERGRluS9J5MyLJ2bAaivAGTpyFpipzpAERGRVmOA2EFHNuCQ+dsFgEPnZ+jrDInUE1hERKT1GIhiT19nyMH1AOCBno6Aow/MUa561QGIiIi0GGMM5arn6AOz9OQDPGDjWgvAY5fmqFSdTgKIiIi0GGugUnUcszQHQBz7ZAsA4KilOXIZi1MhoIiISEuJnSeXsRx7YG7ibdbWpvzHHZynpyNpCKRFABERkdZgSGb8fZ0hTzi0AwBrDfXxn0Wz0xy5JEu56jDaBxAREWkJ1hpKFc8xB+aYNzOV7P+b2imA2HmMgRMP76RcVUdAERGRVmFqHQCffGTHxGoAsK0GAOCkozroyNQuBhIREZGmF8WerlzAU4/uApJAALUAYGu/evwheeb2p6hGHp0GFBERaW71/v+LD0hz3MFJAWB9799Ckgac9/R0BJx8dCfjZTcRCkRERKQ5WWMolh0nHdVBNm1xzk8U+k9sATiXvH7mcV2E1qBNABERkebmgFRoOPnozuTX2w3uEwEgqC0JnHpsF/NnpqhUnbYBREREmpQBqpFjdk/IyUclASDYrsp/IgDUtwFmdIfbtgF0HEBERKQp2QDGS45TH9vFAX0pnN+xvm+HUwD1bYDnPrGHwBq8258PVURERCaLc8ny/+mn9AE8bEzfIQAEQRINnvHYLg6al6GkbQAREZGmYy2UKp7DF2U5pXb8zwY7Dug7BIDkvmBPd0fAi07ooVh2O+wXiIiISOMzxlCqOF7wpB4yaZM0/HvIn7E7/ZvAy07qpTsfEMU6DyAiItJMosjT2xHw0qf0Aju/4+dhASCwBu/h2IPyPOmwDsZKWgUQERFpFoE1jJcdTzysgyOW5PCenRb173QFwLnkPoCznt6H1/XAIiIiTSMZtj3/8sx+DMmYvjM7DQD1QoEXn9jLUUtyjJdj7C43C0RERKQRWAvjlZijluR5wZN6krcFO1/F3+mwXi8GzGctZ//TDEoVj9FxABERkYZmjKFS8Zz19H6yabvT4r+6Xc7r6wP+6af0smh2OukMOBWPVkRERPaZASpVx4LZaU4/pTd52yNM3ncZAKxJmggc0Jfi9FP6GCuqM6CIiEijstZQKDrOOKUv6fznkrF8l3/+0d6hB855/izmzkhRiXa9lCAiIiLTw9Su/Z03I8U5z5+1Wxf6PWIAsDZpHbhwVoqzn97PWDHWKoCIiEiDscZQKMac/fR+Fs5K4R2PWry/W7X93ierAHP6tQogIiLSSJK9f8+CWWn+7YWz2N3T+48aAKxNAsDCWSle8+wZFIrxxJ0BIiIiMr2CwFAoxbzm2TOYNyOF848++4fdXAHAJCHg3JfM5tAF2eSqYGUAERGRaWUNjJcdj1mQ5c0vSGb/u3tqf7cCgDXgvKevM+D//fNsyhWdCBAREZluxhrKFcc7Xz6bvq4A5/1uT9B3u7+fNQbn4cyn9XPiEZ2MjqsgUEREZLpYayiMx5x4RCdnPq0/Wfrfg6Z9ux0ATG0bIJ0yvO+sORjLbhcaiIiIyOTyPrn45wNnzyUdmj1a/oc9CAAAgU0uFXj6Y7t4zbNmMFSIVBAoIiKynwWBYagQ8epn9XPqsZ045wn28M6ePb/ixyQp471nzuGguRlKKggUERHZb6yBUtlx0NwM7z1zTrIavxf39exxAEgKAmF2b4r3nz2XUsXpoiAREZH9xBhDqer5wCvnMru3duxvL4bhvbrk15rktsAzTu3jZSf1MliICbUVICIiMqXCwDBUiHn5yb2ccWofsdv9qv+H2qsAYEySQIyBT7x+AYtmpyhWtBUgIiIyVayBYsWxcFaKj792HrBtLN6r97cvDyR2nvkzU3z6nAVUIw9qEiwiIjJFDNXI8+k3LmD+zPQ+zf5hHwIAJGcQY+d54Qk9vP45M9laiLQVICIiMsnCwLC1EHHO82bxwhN6ksF/H5fdjff7dprf++TK4EIx5kUfWMbf7h+nKx8QOzUJEBER2VeBNYwWYx5/cJ6ffORgOrIWw14V/u9gn1YAqD8AD935gC+9fREzukMqVdUDiIiI7CtroFx1zOgK+dLbF9GVs7CHDX92+b73/V0ktw7FznPYwiyffdMCSrV6AGUAERGRvZPMr5N9/0vespDDFmZrS/+T8/4n6d0kSxSx87zspF4uOO0ABtUlUEREZK8FgWFwNOL8VxzAi05M9v2DSVxen7QAAMklBLHzvO+subziqX0MjKgoUEREZE+FgWFgJOL0U/t47xlzaxX/kzueTmoAMCYJAdbC585dyFOO7GRYTYJERER2W73Zz1OO7OTzb12IDZKxdbKb7k5qAIBttwb25AO+ccESDp6foVCM9/iSAhERkXYT2ORU3SHzM3zjgiV054M9vuVvd03JsLx9k6Cvn7+Y/q6QYmXPbyoSERFpF4GFYsUzozvkm+9awvyZqX1u9vNIpmxIrhcFPvagPN9+zxI6c5ZSdfKqF0VERFpFYKFU8XTlLFe/dylHL81NetHfQ03pcBxYQxx7nnxEJ99611KyaUNFIUBERGSCtVCuerIZyzfftZQnHtZBHE/t4A9THAAgOcYQxZ5TjunkG+cvJRUmIUDbASIi0u4CC5WqJxUavnH+Ek45ppMo9vvlGP1+GYbDWgh4xnFdXPmepeQyhlJl6tONiIhIo6ov++czlivfs5RnHNdFFPv9dnJun+8C2BP1f9gf7yxw1oUrGBmLyWctUax7A0REpH2EAYyVHL2dIVe9ZyknHtGxXwd/2M8BALaFgL/dN85ZFy5n3UCV7nygECAiIm0hDAwj4zHzZqS48t1Lefyh+f0++MM0BABgorLxH6tKvObTK7n9wXH6ukKFABERaWlhrb3v0UtzfP38JRy+KDvl1f67Mi0BACB2yf7HpqGI1392Jb/62wgzukJi75meRyQiIjI1jIHAGAZGI571+G6+8o5FzO5LTYyF0/KYpisAwLYQUKw4zrt0Dd/49QC9nQEGcAoBIiLSAqwBDwyOxrzm2TO46N8WkE3baR38YZoDACQDfX3l45Pf3cjHrlqPtYZcyhIpBYiISBMLraFYdXgH7zlzDhe84gBgx7Fvukx7AIDk7gDvk2YIP7tphPMuXc36rVV6OlQcKCIizSkMDMNjMXP7U1zyloU89/hunEu2A6ait/+eaogAUFcvhLh3TYm3fG41N9xZoK8zBLy2BEREpCkkM3vD1tGIU4/t5AtvXcTB8zPTVuy3Kw0VAGBbXcB42fGhb67niz/ZTBgasilLrBQgIiINLAgMpbKjGnve/IJZfPDVc8k1wH7/zjRcAABwjon7An70pyEu+PJaVm+p0tth8V4FgiIi0lhsbVl/qOBYPCfNha+bx4tP7AV2HNMaSUMGANixLmD5hjIXfHkt19w4TC5jyabVPVBERBpDEBjKFcd42fGiE3v55Bvms3h2uqH2+3emYQNA3fbLJl//5QAfu3oDqzdX6O0IwCTJSkREZH+zFvAwNBazaHaad58+h9c8ewZAw+3370zDBwBIlvwNSYpasbHCR69cz3evHQQDHdkAp+ZBIiKynxgD1hjGSjHew5lP6+d9Z81h0ex0snrN9B/x2x1NEQDqtk9UP7t5mI9+ewO3PDBOLmNrRRYKAiIiMjWMgcAaihVHsew47uA87zt7Ds87vgdojln/9poqAMC2AkBrkmsU/+cXW7jkR5tYsaFCV86SSlmcgoCIiEwSY8BaQ7XqGC05lhyQ5twXz+Z1z5lJNm12WKVuJk0XAOq2T1prt1T5wo83c+XvB9i4NaIzH5AKjYKAiIjstfpSfzX2FIoxB/SleOXT+3nLi2cxtz8FNN+sf3tNGwCA2pHAbR/8B9aVueyaLXznukE2D1XpzAWkQ6OtARER2W31pf5KlAz8s3tSnPG0Ps55/kwOmpsBkoHfGtN0s/7tNXUAqKv3BqifFrh3TYnLrtnC9/8wyMbBiHzt6KD36igoIiI7Zy0YDKXakb7ZfSGveGo/5zxvJocuqA/82878N7uWCAB1rtY7oB4E7l9b5uprt/K964e4f22JdGjIpS020PaAiIhs2993sWe84qhGnkPmZ3n5U3s589R+DpnfegN/XUsFgDrnAb+t89JQIeYHNwzxjd8McOfyIoWSI5+xZFIGY4yOEYqItJH63r73nnLVM152dGYtxxyY45X/NIOXndRLb2cA1HrNmOY41renWjIA1CUrAttqBCLnufmecX78lyF+fvMIy9aWib0nnwlIhSRhQCsDIiItp76v77ynGiWDfmAMB83P8Nzju3nhCT086bCOifEidh5jTEsO/HUtHQDqHlosCFAoOn59ywj/98ch/nBHgS3DEdXYk89YUqEhDLatDLT+R0hEpLXUW/BaY4hiTyXyFMuOMDDM6g156tFdvOTJPTzzuG46c9sa9bdCcd/uaosAUOcB78CzYxhYu6XKH+4s8Me7kpdVmyqMFh3p0JBJJWEgsGYiSFDr9CQiItOvdvvuxMAdO08UQ7nqqESerpxl8QEZnnJEB08+soOTj+5i/ozUxN+PncdgMLb2vtpEWwWA7dUH84cmvfGy4+8PjHP9nWPccGeBu1YUGRqLGSs5UsH2gSApHEnywLZtg/b8aIqITL36c7UxSbW+MeCcJ3YQxcl+fjX2dGQtvR0BRy7JcdKRnZx8dAfHHZwnl9k209/VGNBO2jYAbK/+hWAwD7uycf3WKn9fVuSO5UVuf7DIbQ+Os3k4YryctIK01pAODGFYCwUmeR+29hXleciKgVYPREQexkz8sO3npvYG5z3OJa9jB1HkqcQe5zy5jCWfsczqCTnmwDzHHpjj6CVZHntQnrnbzfIhKejztPegvz0FgIeo7/k/dJugbqzkWL6hzLJ1ZZZvqNReyqzaVGF4LKZcdRTLnlLVYUiKTmxttaB+hMQY05RtI0VEJlv98hxfq7lyPpnVO5cszXsgm7JkM4ZsytLTEbBodpqlczIsnZNm6Zw0B83LcOCcDPmsfdj7n1jeb7EjfJNBAeAR+NoP9WLAwO48NXqgWHZsHopYtanCqk0V1m6psnk4YmshYnA0ZutoxPBYTCXyVKqeSuSoVNWYSETalzWQThnSoa29NvR0BPR1hfR3BvR3hczqCZk/M8XC2WkWzU4zuzckl7E73av3vl69X1uFNe21p7+n/j8IM1fbe6GJWAAAAABJRU5ErkJggg==', 'base64');
const ICON_192 = Buffer.from('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', 'base64');
const ICON_APPLE = Buffer.from('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', 'base64');
app.get('/manifest.webmanifest', (req, res) => {
  res.type('application/manifest+json');
  // Carry the driver's token into the installed app's launch URL (read from the cookie set when they opened
  // their link), so the Add-to-Home-Screen app opens already connected instead of at a bare, keyless /driver.
  const k = ((req.query.k || (req.cookies && req.cookies.hp_driver_key) || '')).toString().trim();
  const startUrl = k ? ('/driver?k=' + encodeURIComponent(k)) : '/driver';
  res.json({
    name: 'HaulProof Driver', short_name: 'HaulProof',
    start_url: startUrl, scope: '/driver', display: 'standalone',
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
