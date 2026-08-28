// Team logins WITHIN a customer. A customer admin manages only their own org's people.
const express = require('express');
const bcrypt = require('bcryptjs');
const { createUser, requireAuth, requireAdmin } = require('./auth');
const { db } = require('./db');

const router = express.Router();
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// The org whose users this request manages. Super-admin may target any via ?orgId; admins are pinned to their own.
function scopeOrgId(req) {
  if (req.user.role === 'superadmin') return (req.query.orgId || req.body && req.body.orgId || '').trim() || null;
  return req.user.orgId || null;
}
// Guard: a target user must belong to the caller's scoped org (super-admin bypasses).
function sameOrg(req, targetOrgId) {
  if (req.user.role === 'superadmin') return true;
  return (targetOrgId || null) === (req.user.orgId || null);
}

// List logins in this customer.
router.get('/', requireAuth, requireAdmin, (req, res) => {
  const orgId = scopeOrgId(req);
  const users = db.prepare(
    `SELECT id, email, name, role, createdAt FROM users WHERE orgId IS ? AND role != 'superadmin' ORDER BY createdAt DESC`
  ).all(orgId);
  res.json({ users });
});

// Master notify list: team logins who always get an update email when a load's stops complete.
router.get('/notify', requireAuth, requireAdmin, (req, res) => {
  const orgId = scopeOrgId(req);
  const rows = db.prepare(`SELECT userId FROM org_notify WHERE orgId IS ?`).all(orgId);
  res.json({ userIds: rows.map(r => r.userId) });
});
router.put('/notify', requireAuth, requireAdmin, (req, res) => {
  const orgId = scopeOrgId(req);
  const ids = Array.isArray(req.body && req.body.userIds) ? req.body.userIds : [];
  const valid = ids.filter(uid => db.prepare(`SELECT 1 FROM users WHERE id = ? AND orgId IS ?`).get(uid, orgId));
  db.transaction(() => {
    db.prepare(`DELETE FROM org_notify WHERE orgId IS ?`).run(orgId);
    const ins = db.prepare(`INSERT OR IGNORE INTO org_notify (orgId, userId, createdAt) VALUES (?,?,?)`);
    valid.forEach(uid => ins.run(orgId, uid, Date.now()));
  })();
  res.json({ ok: true, userIds: valid });
});

// Create a login in this customer.
router.post('/', requireAuth, requireAdmin, (req, res) => {
  const orgId = scopeOrgId(req);
  const { email, name, role, password } = req.body || {};
  const em = (email || '').toLowerCase().trim();
  if (!EMAIL_RE.test(em)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const r = role === 'admin' ? 'admin' : (role === 'sales' ? 'sales' : 'dispatcher'); // never create a superadmin here
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(em)) return res.status(409).json({ error: 'That email already has a login' });
  try {
    const u = createUser({ email: em, name: name || '', role: r, password: String(password), orgId });
    res.status(201).json({ user: { id: u.id, email: em, name: name || '', role: r } });
  } catch (e) { res.status(500).json({ error: 'Could not create the login' }); }
});

// --- Super-admin maintenance: a login is unique by email across the WHOLE system, but logins are only
//     listed per-account — so a login attached to a deleted/hidden org becomes invisible while still
//     blocking its email. These two routes let a super-admin locate and clear such a stray login.
//     (Defined BEFORE the '/:id' routes so 'by-email' isn't captured as an :id.)
router.get('/lookup', requireAuth, (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Super-admin only' });
  const em = (req.query.email || '').toLowerCase().trim();
  if (!em) return res.status(400).json({ error: 'email is required' });
  const u = db.prepare('SELECT id, email, name, role, orgId, createdAt FROM users WHERE email = ?').get(em);
  if (!u) return res.json({ user: null });
  const org = u.orgId ? db.prepare('SELECT id, name, kind FROM orgs WHERE id = ?').get(u.orgId) : null;
  res.json({ user: Object.assign({}, u, { org: org || null, orgExists: !!org }) });
});
router.delete('/by-email', requireAuth, (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Super-admin only' });
  const em = (req.query.email || (req.body && req.body.email) || '').toLowerCase().trim();
  if (!em) return res.status(400).json({ error: 'email is required' });
  const u = db.prepare('SELECT id, email, name, role, orgId FROM users WHERE email = ?').get(em);
  if (!u) return res.status(404).json({ error: 'No login exists with that email' });
  if (u.role === 'superadmin') return res.status(400).json({ error: 'Refusing to delete a super-admin login' });
  db.prepare('DELETE FROM users WHERE id = ?').run(u.id);
  res.json({ ok: true, deleted: { id: u.id, email: u.email, name: u.name, role: u.role, orgId: u.orgId } });
});

// Edit a login's email / name / role (fix input mistakes). Same customer only.
router.put('/:id', requireAuth, requireAdmin, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target || target.role === 'superadmin' || !sameOrg(req, target.orgId)) return res.status(404).json({ error: 'That login no longer exists' });
  const b = req.body || {};
  const email = (b.email || '').toLowerCase().trim();
  if (email && !EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (email && email !== target.email) {
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'That email already has a login' });
  }
  const isSelf = target.id === (req.user.sub || req.user.id);
  // Never allow superadmin here; don't let someone demote their own login and lock themselves out.
  let role = target.role;
  if (!isSelf && (b.role === 'admin' || b.role === 'sales' || b.role === 'dispatcher')) role = b.role;
  const name = b.name !== undefined ? String(b.name) : target.name;
  db.prepare('UPDATE users SET email = ?, name = ?, role = ? WHERE id = ?').run(email || target.email, name || '', role, target.id);
  res.json({ user: { id: target.id, email: email || target.email, name: name || '', role } });
});

// Reset a login's password (same customer only).
router.post('/:id/password', requireAuth, requireAdmin, (req, res) => {
  const { password } = req.body || {};
  if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const target = db.prepare('SELECT id, orgId, role FROM users WHERE id = ?').get(req.params.id);
  if (!target || target.role === 'superadmin' || !sameOrg(req, target.orgId)) return res.status(404).json({ error: 'That login no longer exists' });
  db.prepare('UPDATE users SET passHash = ? WHERE id = ?').run(bcrypt.hashSync(String(password), 10), target.id);
  res.json({ ok: true });
});

// Remove a login (same customer only; you cannot remove yourself).
router.delete('/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.params.id === (req.user.sub || req.user.id)) return res.status(400).json({ error: 'You cannot remove your own login' });
  const target = db.prepare('SELECT id, orgId, role FROM users WHERE id = ?').get(req.params.id);
  if (!target || target.role === 'superadmin' || !sameOrg(req, target.orgId)) return res.status(404).json({ error: 'That login no longer exists' });
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  res.json({ ok: true });
});

module.exports = router;
