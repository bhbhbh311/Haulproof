// Authentication: password login for dispatch/sales/admins, JWT sessions,
// and per-customer device keys for the driver phones that pull & upload PODs.
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
// Legacy single device key — still honored, and assigned to the default customer on boot.
const LEGACY_INGEST_KEY = process.env.INGEST_API_KEY || '';

function createUser({ email, name, role, password, orgId }) {
  const id = crypto.randomUUID();
  const passHash = bcrypt.hashSync(password, 10);
  db.prepare(
    `INSERT INTO users (id, orgId, email, name, role, passHash, createdAt) VALUES (?,?,?,?,?,?,?)`
  ).run(id, orgId || null, email.toLowerCase().trim(), name || '', role || 'dispatcher', passHash, Date.now());
  return { id, email: email.toLowerCase().trim(), name: name || '', role: role || 'dispatcher', orgId: orgId || null };
}

// What kind of org a user belongs to ('customer' | 'carrier' | null for super-admin).
function orgKindOf(orgId) {
  if (!orgId) return null;
  const o = db.prepare(`SELECT kind FROM orgs WHERE id = ?`).get(orgId);
  return o ? (o.kind || 'customer') : null;
}
// Sign a 12h session token. Carries the user's role, which org they belong to, and that org's kind.
function signToken(u) {
  return jwt.sign({ sub: u.id, email: u.email, role: u.role, name: u.name, orgId: u.orgId || null, orgKind: orgKindOf(u.orgId) }, JWT_SECRET, { expiresIn: '12h' });
}

function login(email, password) {
  const u = db.prepare(`SELECT * FROM users WHERE email = ?`).get((email || '').toLowerCase().trim());
  if (!u || !u.passHash || !bcrypt.compareSync(password || '', u.passHash)) return null;
  const token = signToken(u);
  return { token, user: { id: u.id, email: u.email, name: u.name, role: u.role, orgId: u.orgId || null, orgKind: orgKindOf(u.orgId) } };
}

// Provision (or refresh) a user who signed in through Microsoft SSO. No password is set.
function upsertSsoUser({ email, name, role, orgId }) {
  const em = (email || '').toLowerCase().trim();
  let u = db.prepare(`SELECT * FROM users WHERE email = ?`).get(em);
  if (u) {
    db.prepare(`UPDATE users SET name = ?, role = ? WHERE id = ?`).run(name || u.name || '', role || u.role, u.id);
    u = db.prepare(`SELECT * FROM users WHERE id = ?`).get(u.id);
  } else {
    const id = crypto.randomUUID();
    const randomHash = bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10);
    db.prepare(`INSERT INTO users (id, orgId, email, name, role, passHash, createdAt) VALUES (?,?,?,?,?,?,?)`)
      .run(id, orgId || null, em, name || '', role || 'dispatcher', randomHash, Date.now());
    u = db.prepare(`SELECT * FROM users WHERE id = ?`).get(id);
  }
  return { id: u.id, email: u.email, name: u.name, role: u.role, orgId: u.orgId || null };
}

// Middleware: require a valid session (password login or Microsoft cookie).
function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const bearer = h.startsWith('Bearer ') ? h.slice(7) : null;
  const cookieTok = req.cookies ? req.cookies.hp_session : null;
  const token = bearer || cookieTok;
  if (!token) return res.status(401).json({ error: 'Not signed in' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Session expired — sign in again' }); }
}

// Role helpers.
function isSuper(req) { return req.user && req.user.role === 'superadmin'; }
function requireSuper(req, res, next) { if (!isSuper(req)) return res.status(403).json({ error: 'Master admin only' }); next(); }
function requireAdmin(req, res, next) { // super-admin OR a customer admin
  if (!req.user || (req.user.role !== 'admin' && req.user.role !== 'superadmin')) return res.status(403).json({ error: 'Admins only' });
  next();
}

// --- Device keys: a shared per-customer key OR a personal per-driver token ---
// Resolve the X-Api-Key to its customer (org) and, if it's a driver's personal token, that driver.
function resolveKey(req) {
  const key = (req.headers['x-api-key'] || '').trim();
  if (!key) return null;
  const org = db.prepare(`SELECT * FROM orgs WHERE deviceKey = ? AND active = 1`).get(key);
  if (org) return { org, driver: null };
  const drv = db.prepare(`SELECT * FROM drivers WHERE token = ? AND active = 1`).get(key);
  if (drv) {
    const o = db.prepare(`SELECT * FROM orgs WHERE id = ? AND active = 1`).get(drv.orgId);
    if (o) return { org: o, driver: drv };
  }
  return null;
}
// Backward-compatible: returns just the org for a valid key (shared or driver token).
function orgForApiKey(req) { const r = resolveKey(req); return r ? r.org : null; }
// Middleware: a valid key. Sets req.org (customer) and req.driver (null unless a personal token).
function requireApiKey(req, res, next) {
  const r = resolveKey(req);
  if (!r) return res.status(401).json({ error: 'Invalid device key' });
  req.org = r.org; req.driver = r.driver; next();
}
function hasValidApiKey(req) { return !!resolveKey(req); }

module.exports = {
  createUser, login, signToken, upsertSsoUser,
  requireAuth, requireApiKey, hasValidApiKey, orgForApiKey, resolveKey,
  isSuper, requireSuper, requireAdmin,
  JWT_SECRET, LEGACY_INGEST_KEY,
};
