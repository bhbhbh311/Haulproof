// Driver roster for a customer. Admins (and super-admin via ?orgId) add named drivers; each gets a
// personal driver-app link. Drivers do not log into the portal.
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db } = require('./db');
const { requireAuth, requireAdmin, resolveKey, driverUnlockValue } = require('./auth');

const router = express.Router();

function newToken() { return 'drv_' + crypto.randomBytes(24).toString('hex'); }
const PIN_RE = /^\d{4,6}$/;
function originOf(req) { return (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host')); }
// The customer this request manages drivers for. Super-admin may target any via ?orgId; admins pinned to their own.
function scopeOrgId(req) {
  if (req.user.role === 'superadmin') return (req.query.orgId || (req.body && req.body.orgId) || '').trim() || null;
  return req.user.orgId || null;
}
function sameOrg(req, orgId) { return req.user.role === 'superadmin' ? true : (orgId || null) === (req.user.orgId || null); }
function driverOut(req, d) {
  return { id: d.id, name: d.name, phone: d.phone, email: d.email || '', hasPin: !!d.pinHash, active: !!d.active, createdAt: d.createdAt,
    link: originOf(req) + '/driver?k=' + encodeURIComponent(d.token) };
}

// --- Endpoints the DRIVER APP calls with its own token (X-Api-Key), not a portal login ---
// Does this link need a PIN before it can be used? (Lets the app show the lock screen.)
router.get('/link-info', (req, res) => {
  const r = resolveKey(req);
  if (!r) return res.status(401).json({ error: 'This link is not valid' });
  res.json({ requiresPin: !!(r.driver && r.driver.pinHash), name: r.driver ? r.driver.name : '' });
});
// Exchange the correct PIN for an "unlock" value the app stores and replays on every request.
router.post('/verify-pin', (req, res) => {
  const r = resolveKey(req);
  if (!r || !r.driver) return res.status(401).json({ error: 'This link is not valid' });
  const d = r.driver;
  if (!d.pinHash) return res.json({ ok: true, unlock: '' });         // no PIN set — nothing to check
  const pin = String((req.body && req.body.pin) || '');
  if (!bcrypt.compareSync(pin, d.pinHash)) return res.status(401).json({ error: 'That PIN is not correct' });
  res.json({ ok: true, unlock: driverUnlockValue(d) });
});

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
  const pin = String((req.body && req.body.pin) || '').trim();
  if (!name) return res.status(400).json({ error: "Enter the driver's name" });
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (!PIN_RE.test(pin)) return res.status(400).json({ error: 'Set a 4–6 digit PIN for this driver' });   // a PIN is required for every driver
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO drivers (id, orgId, name, phone, email, pinHash, token, active, createdAt) VALUES (?,?,?,?,?,?,?,1,?)`)
    .run(id, orgId, name, phone || null, email || null, pin ? bcrypt.hashSync(pin, 10) : null, newToken(), Date.now());
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
  // PIN is required and can't be removed. undefined = leave as-is; 4–6 digits = set a new one.
  let pinHash = d.pinHash;
  if (b.pin !== undefined) {
    const pin = String(b.pin).trim();
    if (!pin) return res.status(400).json({ error: 'A PIN is required — enter a new one to change it' });
    if (!PIN_RE.test(pin)) return res.status(400).json({ error: 'PIN must be 4 to 6 digits' });
    pinHash = bcrypt.hashSync(pin, 10);
  }
  db.prepare(`UPDATE drivers SET name = ?, phone = ?, email = ?, pinHash = ? WHERE id = ?`).run(name, phone || null, email || null, pinHash, d.id);
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
