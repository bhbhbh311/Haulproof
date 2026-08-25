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

// Sign a 12h session token. Carries the user's role AND which customer (org) they belong to.
function signToken(u) {
  return jwt.sign({ sub: u.id, email: u.email, role: u.role, name: u.name, orgId: u.orgId || null }, JWT_SECRET, { expiresIn: '12h' });
}

function login(email, password) {
  const u = db.prepare(`SELECT * FROM users WHERE email = ?`).get((email || '').toLowerCase().trim());
  if (!u || !u.passHash || !bcrypt.compareSync(password || '', u.passHash)) return null;
  const token = signToken(u);
  return { token, user: { id: u.id, email: u.email, name: u.name, role: u.role, orgId: u.orgId || null } };
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

// --- Per-customer device keys (drivers) ---
// Find the customer (org) that owns the X-Api-Key on this request, if any.
function orgForApiKey(req) {
  const key = (req.headers['x-api-key'] || '').trim();
  if (!key) return null;
  return db.prepare(`SELECT * FROM orgs WHERE deviceKey = ? AND active = 1`).get(key) || null;
}
// Middleware: a valid customer device key. Sets req.org to that customer.
function requireApiKey(req, res, next) {
  const org = orgForApiKey(req);
  if (!org) return res.status(401).json({ error: 'Invalid device key' });
  req.org = org; next();
}
function hasValidApiKey(req) { return !!orgForApiKey(req); }

module.exports = {
  createUser, login, signToken, upsertSsoUser,
  requireAuth, requireApiKey, hasValidApiKey, orgForApiKey,
  isSuper, requireSuper, requireAdmin,
  JWT_SECRET, LEGACY_INGEST_KEY,
};
