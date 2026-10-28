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

// ---- "HaulProof Help" support logins -------------------------------------------------------------------
// One shared password (from the env) for every company's support admin, so the master admin can jump in to
// help. The login email is haulproofhelp+<company-slug>@haulproofepod.com: unique per company (the users table
// requires a unique email), but every one of them still delivers to the HaulProofHelp@haulproofepod.com inbox.
const HELP_PASSWORD = (process.env.HAULPROOF_HELP_PASSWORD || '').trim();
// Ensure the support admin login exists for an org (creating it if needed), and keep its password in sync with
// the current shared password. Idempotent — safe to call on every org-create and on boot. Returns the user row.
function ensureSupportAdmin(orgId) {
  if (!orgId) return null;
  let u = db.prepare(`SELECT * FROM users WHERE orgId = ? AND email LIKE 'haulproofhelp+%@haulproofepod.com'`).get(orgId);
  if (u) {
    // Keep every support login on the current shared password (so it always works even if the password changes).
    if (HELP_PASSWORD && (!u.passHash || !bcrypt.compareSync(HELP_PASSWORD, u.passHash))) {
      try { db.prepare(`UPDATE users SET passHash = ?, role = 'admin' WHERE id = ?`).run(bcrypt.hashSync(HELP_PASSWORD, 10), u.id); } catch (e) {}
    }
    return db.prepare(`SELECT * FROM users WHERE id = ?`).get(u.id);
  }
  const org = db.prepare(`SELECT name FROM orgs WHERE id = ?`).get(orgId);
  let slug = String((org && org.name) || 'company').toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 24) || 'company';
  let email = 'haulproofhelp+' + slug + '@haulproofepod.com';
  if (db.prepare(`SELECT 1 FROM users WHERE email = ?`).get(email)) {
    email = 'haulproofhelp+' + slug + '-' + String(orgId).replace(/[^a-z0-9]/gi, '').slice(0, 6).toLowerCase() + '@haulproofepod.com';
  }
  const pw = HELP_PASSWORD || crypto.randomBytes(18).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  try { createUser({ email, name: 'HaulProof Help', role: 'admin', password: pw, orgId }); }
  catch (e) { return db.prepare(`SELECT * FROM users WHERE orgId = ? AND email LIKE 'haulproofhelp+%@haulproofepod.com'`).get(orgId); }
  return db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
}
// Create the support admin for every existing company (customer/carrier/broker). Idempotent; run on boot.
function backfillSupportAdmins() {
  try {
    const orgs = db.prepare(`SELECT id FROM orgs WHERE kind IN ('customer','carrier','broker')`).all();
    orgs.forEach(o => { try { ensureSupportAdmin(o.id); } catch (e) {} });
  } catch (e) {}
}

// What kind of org a user belongs to ('customer' | 'carrier' | null for super-admin).
function orgKindOf(orgId) {
  if (!orgId) return null;
  const o = db.prepare(`SELECT kind FROM orgs WHERE id = ?`).get(orgId);
  return o ? (o.kind || 'customer') : null;
}
// Full org context for the session: kind (legacy primary role), roles[] (multi-role), parentId, company name.
function orgMetaOf(orgId) {
  if (!orgId) return { kind: null, roles: [], parentId: null, name: null };
  const o = db.prepare(`SELECT name, kind, roles, parentId FROM orgs WHERE id = ?`).get(orgId);
  if (!o) return { kind: null, roles: [], parentId: null, name: null };
  let roles = [];
  try { roles = o.roles ? JSON.parse(o.roles) : []; } catch (e) { roles = []; }
  if (!roles.length) roles = [o.kind || 'customer'];
  return { kind: o.kind || 'customer', roles, parentId: o.parentId || null, name: o.name || null };
}
// Sign a 12h session token. Carries the user's role, which org they belong to, that org's kind + name,
// its full role set (so a customer that is also a receiver gets both views), and its parent (hierarchy).
function signToken(u) {
  const m = orgMetaOf(u.orgId);
  try { if (u.id) db.prepare('UPDATE users SET lastLoginAt = ? WHERE id = ?').run(Date.now(), u.id); } catch (e) {}
  return jwt.sign({ sub: u.id, email: u.email, role: u.role, name: u.name, orgId: u.orgId || null, orgKind: m.kind, orgRoles: m.roles, orgName: m.name, parentId: m.parentId }, JWT_SECRET, { expiresIn: '12h' });
}

function login(email, password) {
  const u = db.prepare(`SELECT * FROM users WHERE email = ?`).get((email || '').toLowerCase().trim());
  if (!u || !u.passHash || !bcrypt.compareSync(password || '', u.passHash)) return null;
  // A deactivated customer/carrier can't sign in (super-admins have no org and are unaffected).
  if (u.orgId) { const o = db.prepare(`SELECT active FROM orgs WHERE id = ?`).get(u.orgId); if (o && !o.active) return null; }
  const token = signToken(u);
  const m = orgMetaOf(u.orgId);
  // Tester flag on the login response too, so the "Show all sections" toggle appears right after sign-in
  // (not only after a refresh, which reloads the user from /api/me). Master admin always has it.
  const betaAccess = (u.role === 'superadmin') || !!u.betaAccess;
  return { token, user: { id: u.id, email: u.email, name: u.name, role: u.role, orgId: u.orgId || null, orgKind: m.kind, orgRoles: m.roles, orgName: m.name, parentId: m.parentId, mustChangePassword: !!u.mustChangePassword, betaAccess } };
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
// ---- Per-user capabilities: admins can grant specific powers to a dispatcher/sales login on top of their
//      role. The four grantable powers, plus what each role gets by default. Admins/super always have all. ----
const ALL_CAPS = ['manage_users', 'manage_drivers', 'manage_customers', 'delete_loadsdocs'];
const ROLE_DEFAULT_CAPS = {
  superadmin: ALL_CAPS.slice(),
  admin: ALL_CAPS.slice(),
  dispatcher: ['manage_drivers', 'manage_customers', 'delete_loadsdocs'], // dispatchers keep their operational powers
  sales: [],                                                              // sales gets only what an admin grants
};
// Extra capabilities an admin explicitly granted this login (stored as a JSON array on the user row).
function grantedCaps(userId) {
  try { const r = db.prepare('SELECT capabilities FROM users WHERE id = ?').get(userId); if (!r || !r.capabilities) return [];
    const a = JSON.parse(r.capabilities); return Array.isArray(a) ? a.filter(c => ALL_CAPS.includes(c)) : []; } catch (e) { return []; }
}
// The full set of capabilities a login effectively has (role defaults + admin-granted extras).
function effectiveCaps(user) {
  if (!user) return [];
  const base = (ROLE_DEFAULT_CAPS[user.role] || []).slice();
  const extra = grantedCaps(user.sub || user.id);
  extra.forEach(c => { if (base.indexOf(c) < 0) base.push(c); });
  return base;
}
function userHasCap(req, cap) {
  if (!req.user) return false;
  if (req.user.role === 'admin' || req.user.role === 'superadmin') return true;
  if ((ROLE_DEFAULT_CAPS[req.user.role] || []).includes(cap)) return true;
  return grantedCaps(req.user.sub || req.user.id).includes(cap);
}
// Middleware factory: allow the request only if the caller has this capability.
function requireCap(cap) {
  return function (req, res, next) {
    if (userHasCap(req, cap)) return next();
    return res.status(403).json({ error: "You don't have permission to do that" });
  };
}
// Managing the driver roster is operational, so dispatchers do it by default; admins may also grant the
// 'manage_drivers' capability to another login (e.g. a sales user). Still scoped to the caller's own org.
function requireDriverManager(req, res, next) {
  if (req.user && (['admin', 'superadmin', 'dispatcher'].includes(req.user.role) || userHasCap(req, 'manage_drivers'))) return next();
  return res.status(403).json({ error: 'Not allowed' });
}

// --- Device keys: a shared per-customer key OR a personal per-driver token ---
// Resolve the X-Api-Key to its customer (org) and, if it's a driver's personal token, that driver.
function resolveKey(req) {
  let key = (req.headers['x-api-key'] || '').trim();
  // Fall back to the durable per-device cookie (set when the driver first opened their personal link), so API
  // calls stay authenticated even if the phone's local storage was cleared or a request omits the header.
  if (!key && req.cookies) key = (req.cookies.hp_driver_key || '').trim();
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

// The per-driver "unlock" value a phone earns by entering the correct PIN. It's an HMAC of the
// driver's token + PIN hash, so only someone who knew the PIN can present it — and changing the
// PIN (or the link) invalidates every device's stored unlock. Empty when the driver has no PIN.
function driverUnlockValue(driver) {
  if (!driver || !driver.pinHash) return '';
  return crypto.createHmac('sha256', JWT_SECRET).update(String(driver.token) + ':' + String(driver.pinHash)).digest('hex');
}

module.exports = {
  createUser, login, signToken, upsertSsoUser,
  ensureSupportAdmin, backfillSupportAdmins,
  requireAuth, requireApiKey, hasValidApiKey, orgForApiKey, resolveKey,
  driverUnlockValue,
  isSuper, requireSuper, requireAdmin, requireDriverManager,
  requireCap, userHasCap, effectiveCaps, ALL_CAPS,
  JWT_SECRET, LEGACY_INGEST_KEY,
};
