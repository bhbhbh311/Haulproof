// Authentication: password login for dispatchers/sales, JWT sessions,
// and an API key gate for the driver devices that upload PODs.
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const INGEST_API_KEY = process.env.INGEST_API_KEY || 'dev-ingest-key-change-me';

function createUser({ email, name, role, password }) {
  const id = crypto.randomUUID();
  const passHash = bcrypt.hashSync(password, 10);
  db.prepare(
    `INSERT INTO users (id, email, name, role, passHash, createdAt) VALUES (?,?,?,?,?,?)`
  ).run(id, email.toLowerCase().trim(), name || '', role || 'dispatcher', passHash, Date.now());
  return { id, email, name, role: role || 'dispatcher' };
}

// Sign a 12h session token for a user row (used by password login AND Microsoft SSO).
function signToken(u) {
  return jwt.sign({ sub: u.id, email: u.email, role: u.role, name: u.name }, JWT_SECRET, { expiresIn: '12h' });
}

function login(email, password) {
  const u = db.prepare(`SELECT * FROM users WHERE email = ?`).get((email || '').toLowerCase().trim());
  // SSO-only accounts carry an unusable random passHash, so password login can never match them.
  if (!u || !u.passHash || !bcrypt.compareSync(password || '', u.passHash)) return null;
  const token = signToken(u);
  return { token, user: { id: u.id, email: u.email, name: u.name, role: u.role } };
}

// Provision (or refresh) a user who signed in through Microsoft. No password is ever set —
// we store a random unusable hash so the NOT NULL column is satisfied but password login is impossible.
function upsertSsoUser({ email, name, role }) {
  const em = (email || '').toLowerCase().trim();
  let u = db.prepare(`SELECT * FROM users WHERE email = ?`).get(em);
  if (u) {
    // Keep name/role in sync with the current allowlist on every sign-in.
    db.prepare(`UPDATE users SET name = ?, role = ? WHERE id = ?`).run(name || u.name || '', role || u.role, u.id);
    u = db.prepare(`SELECT * FROM users WHERE id = ?`).get(u.id);
  } else {
    const id = crypto.randomUUID();
    const randomHash = bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10);
    db.prepare(`INSERT INTO users (id, email, name, role, passHash, createdAt) VALUES (?,?,?,?,?,?)`)
      .run(id, em, name || '', role || 'dispatcher', randomHash, Date.now());
    u = db.prepare(`SELECT * FROM users WHERE id = ?`).get(id);
  }
  return { id: u.id, email: u.email, name: u.name, role: u.role };
}

// Middleware: require a valid dispatcher/sales session.
// Accepts EITHER an "Authorization: Bearer <jwt>" header (password login / driver tooling)
// OR the httpOnly "hp_session" cookie set after Microsoft SSO.
function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const bearer = h.startsWith('Bearer ') ? h.slice(7) : null;
  const cookieTok = req.cookies ? req.cookies.hp_session : null;
  const token = bearer || cookieTok;
  if (!token) return res.status(401).json({ error: 'Not signed in' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired — sign in again' });
  }
}

// Middleware: require the shared device API key (driver app uploads)
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key !== INGEST_API_KEY) return res.status(401).json({ error: 'Invalid device key' });
  next();
}
// Non-middleware check, for routes that accept EITHER a session or the device key.
function hasValidApiKey(req) { return !!req.headers['x-api-key'] && req.headers['x-api-key'] === INGEST_API_KEY; }

module.exports = { createUser, login, signToken, upsertSsoUser, requireAuth, requireApiKey, hasValidApiKey, JWT_SECRET };
