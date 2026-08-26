// Driver roster for a customer. Admins (and super-admin via ?orgId) add named drivers; each gets a
// personal driver-app link. Drivers do not log into the portal.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth, requireAdmin } = require('./auth');

const router = express.Router();

function newToken() { return 'drv_' + crypto.randomBytes(24).toString('hex'); }
function originOf(req) { return (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host')); }
// The customer this request manages drivers for. Super-admin may target any via ?orgId; admins pinned to their own.
function scopeOrgId(req) {
  if (req.user.role === 'superadmin') return (req.query.orgId || (req.body && req.body.orgId) || '').trim() || null;
  return req.user.orgId || null;
}
function sameOrg(req, orgId) { return req.user.role === 'superadmin' ? true : (orgId || null) === (req.user.orgId || null); }
function driverOut(req, d) {
  return { id: d.id, name: d.name, phone: d.phone, email: d.email || '', active: !!d.active, createdAt: d.createdAt,
    link: originOf(req) + '/driver?k=' + encodeURIComponent(d.token) };
}

// List a customer's drivers.
router.get('/', requireAuth, requireAdmin, (req, res) => {
  const orgId = scopeOrgId(req);
  if (!orgId) return res.status(400).json({ error: 'No customer specified' });
  const rows = db.prepare(`SELECT * FROM drivers WHERE orgId = ? ORDER BY active DESC, createdAt DESC`).all(orgId);
  res.json({ drivers: rows.map(d => driverOut(req, d)) });
});

// Add a driver.
router.post('/', requireAuth, requireAdmin, (req, res) => {
  const orgId = scopeOrgId(req);
  if (!orgId) return res.status(400).json({ error: 'No customer specified' });
  const name = (req.body && req.body.name || '').trim();
  const phone = (req.body && req.body.phone || '').trim();
  const email = (req.body && req.body.email || '').trim();
  if (!name) return res.status(400).json({ error: "Enter the driver's name" });
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO drivers (id, orgId, name, phone, email, token, active, createdAt) VALUES (?,?,?,?,?,?,1,?)`)
    .run(id, orgId, name, phone || null, email || null, newToken(), Date.now());
  res.status(201).json({ driver: driverOut(req, db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(id)) });
});

// Edit a driver's details (fix input mistakes). Same org only.
router.put('/:id', requireAuth, requireAdmin, (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  const b = req.body || {};
  const name = (b.name !== undefined ? String(b.name) : d.name).trim();
  if (!name) return res.status(400).json({ error: "Enter the driver's name" });
  const phone = (b.phone !== undefined ? String(b.phone) : (d.phone || '')).trim();
  const email = (b.email !== undefined ? String(b.email) : (d.email || '')).trim();
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  db.prepare(`UPDATE drivers SET name = ?, phone = ?, email = ? WHERE id = ?`).run(name, phone || null, email || null, d.id);
  res.json({ driver: driverOut(req, db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(d.id)) });
});

// Turn a driver on/off (deactivating instantly revokes their personal link).
router.post('/:id/active', requireAuth, requireAdmin, (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  const active = req.body && req.body.active ? 1 : 0;
  db.prepare(`UPDATE drivers SET active = ? WHERE id = ?`).run(active, d.id);
  res.json({ driver: driverOut(req, db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(d.id)) });
});

// Issue a fresh personal link (invalidates the old one).
router.post('/:id/rotate', requireAuth, requireAdmin, (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  db.prepare(`UPDATE drivers SET token = ? WHERE id = ?`).run(newToken(), d.id);
  res.json({ driver: driverOut(req, db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(d.id)) });
});

// Remove a driver.
router.delete('/:id', requireAuth, requireAdmin, (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  db.prepare(`DELETE FROM drivers WHERE id = ?`).run(d.id);
  res.json({ ok: true });
});

module.exports = router;
