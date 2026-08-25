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
