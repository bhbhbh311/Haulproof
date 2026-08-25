// Admin-only user management: create / list / reset-password / remove portal logins.
// These are the password logins dispatchers and testers use to sign in.
const express = require('express');
const bcrypt = require('bcryptjs');
const { createUser, requireAuth } = require('./auth');
const { db } = require('./db');

const router = express.Router();

// Only admins may manage logins.
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// List all logins (no password hashes).
router.get('/', requireAuth, requireAdmin, (_req, res) => {
  const users = db.prepare('SELECT id, email, name, role, createdAt FROM users ORDER BY createdAt DESC').all();
  res.json({ users });
});

// Create a login.
router.post('/', requireAuth, requireAdmin, (req, res) => {
  const { email, name, role, password } = req.body || {};
  const em = (email || '').toLowerCase().trim();
  if (!EMAIL_RE.test(em)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const r = role === 'admin' ? 'admin' : 'dispatcher';
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(em);
  if (exists) return res.status(409).json({ error: 'That email already has a login' });
  try {
    const u = createUser({ email: em, name: name || '', role: r, password: String(password) });
    res.status(201).json({ user: { id: u.id, email: em, name: name || '', role: r } });
  } catch (e) {
    res.status(500).json({ error: 'Could not create the login' });
  }
});

// Reset a login's password.
router.post('/:id/password', requireAuth, requireAdmin, (req, res) => {
  const { password } = req.body || {};
  if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = bcrypt.hashSync(String(password), 10);
  const info = db.prepare('UPDATE users SET passHash = ? WHERE id = ?').run(hash, req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'That login no longer exists' });
  res.json({ ok: true });
});

// Remove a login (an admin cannot remove their own account).
router.delete('/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.params.id === (req.user.sub || req.user.id)) return res.status(400).json({ error: 'You cannot remove your own login' });
  const info = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'That login no longer exists' });
  res.json({ ok: true });
});

module.exports = router;
