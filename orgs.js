// Customers (tenants). Super-admin only: add a customer, create its first admin, see its driver link.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { createUser, requireAuth, requireSuper } = require('./auth');

const router = express.Router();
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }
function originOf(req) {
  return (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host'));
}
function orgOut(req, o) {
  const admins = db.prepare(`SELECT email FROM users WHERE orgId = ? AND role = 'admin' ORDER BY createdAt`).all(o.id).map(r => r.email);
  const userCount = db.prepare(`SELECT COUNT(*) n FROM users WHERE orgId = ?`).get(o.id).n;
  const docCount = db.prepare(`SELECT COUNT(*) n FROM pods WHERE orgId = ?`).get(o.id).n;
  return {
    id: o.id, name: o.name, active: !!o.active, createdAt: o.createdAt,
    contactName: o.contactName, contactEmail: o.contactEmail, contactPhone: o.contactPhone, address: o.address,
    admins, userCount, docCount,
    driverLink: originOf(req) + '/driver?k=' + encodeURIComponent(o.deviceKey),
  };
}

// List customers (carrier orgs are managed under /api/carriers, not here).
// Active only by default; ?includeInactive=1 shows deactivated ones too.
router.get('/', requireAuth, requireSuper, (req, res) => {
  const all = req.query.includeInactive === '1';
  const rows = db.prepare(`SELECT * FROM orgs WHERE (kind='customer' OR kind IS NULL) ${all ? '' : 'AND active = 1'} ORDER BY active DESC, createdAt DESC`).all();
  res.json({ orgs: rows.map(o => orgOut(req, o)) });
});

// Activate / deactivate a customer. Deactivating cuts off its logins and driver links.
router.post('/:id/active', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ? AND (kind='customer' OR kind IS NULL)`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Customer not found' });
  db.prepare(`UPDATE orgs SET active = ? WHERE id = ?`).run(req.body && req.body.active ? 1 : 0, o.id);
  res.json({ org: orgOut(req, db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});

// Create a customer + its first admin login.
router.post('/', requireAuth, requireSuper, (req, res) => {
  const b = req.body || {};
  const name = (b.name || '').trim();
  const adminEmail = (b.adminEmail || '').toLowerCase().trim();
  const adminPassword = b.adminPassword || '';
  if (!name) return res.status(400).json({ error: 'Company name is required' });
  if (!EMAIL_RE.test(adminEmail)) return res.status(400).json({ error: 'A valid admin email is required' });
  if (!adminPassword || String(adminPassword).length < 6) return res.status(400).json({ error: 'Admin password must be at least 6 characters' });
  if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(adminEmail)) return res.status(409).json({ error: 'That admin email already has a login' });

  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, deviceKey, contactName, contactEmail, contactPhone, address, active, createdAt)
              VALUES (?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), (b.contactName || '').trim() || null, (b.contactEmail || '').trim() || null,
         (b.contactPhone || '').trim() || null, (b.address || '').trim() || null, Date.now());
  createUser({ email: adminEmail, name: (b.adminName || '').trim(), role: 'admin', password: String(adminPassword), orgId: id });
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(id);
  res.status(201).json({ org: orgOut(req, o) });
});

// Customer detail + its users.
router.get('/:id', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Customer not found' });
  const users = db.prepare(`SELECT id, email, name, role, createdAt FROM users WHERE orgId = ? ORDER BY createdAt`).all(o.id);
  res.json({ org: orgOut(req, o), users });
});

// Update customer info / active flag.
router.put('/:id', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Customer not found' });
  const b = req.body || {};
  db.prepare(`UPDATE orgs SET name = ?, contactName = ?, contactEmail = ?, contactPhone = ?, address = ?, active = ? WHERE id = ?`)
    .run((b.name || o.name).trim(), (b.contactName ?? o.contactName) || null, (b.contactEmail ?? o.contactEmail) || null,
         (b.contactPhone ?? o.contactPhone) || null, (b.address ?? o.address) || null,
         (b.active === undefined ? o.active : (b.active ? 1 : 0)), o.id);
  res.json({ org: orgOut(req, db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});

// Add another admin to a customer.
router.post('/:id/admins', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Customer not found' });
  const email = (req.body && req.body.email || '').toLowerCase().trim();
  const password = req.body && req.body.password || '';
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'A valid email is required' });
  if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(email)) return res.status(409).json({ error: 'That email already has a login' });
  createUser({ email, name: (req.body.name || '').trim(), role: 'admin', password: String(password), orgId: o.id });
  res.status(201).json({ ok: true });
});

// Rotate a customer's device key (invalidates old driver links).
router.post('/:id/rotate-key', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Customer not found' });
  db.prepare(`UPDATE orgs SET deviceKey = ? WHERE id = ?`).run(newDeviceKey(), o.id);
  res.json({ org: orgOut(req, db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});

// ---- A customer's saved approved carrier/broker roster (master admin) ----
router.get('/:id/partners', requireAuth, requireSuper, (req, res) => {
  const cust = db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(req.params.id);
  if (!cust) return res.status(404).json({ error: 'Customer not found' });
  const rows = db.prepare(`SELECT ap.partnerKind, o.id, o.name, o.mcNumber, o.dotNumber, o.fmcsaVerified, o.allowedToOperate, o.active
     FROM approved_partners ap JOIN orgs o ON o.id = ap.partnerOrgId
     WHERE ap.ownerOrgId = ? ORDER BY o.name COLLATE NOCASE`).all(cust.id);
  const carriers = [], brokers = [];
  rows.forEach(r => {
    const item = { id: r.id, name: r.name, mcNumber: r.mcNumber, dotNumber: r.dotNumber, fmcsaVerified: !!r.fmcsaVerified, allowedToOperate: r.allowedToOperate, active: !!r.active };
    (r.partnerKind === 'broker' ? brokers : carriers).push(item);
  });
  res.json({ carriers, brokers });
});
router.post('/:id/partners', requireAuth, requireSuper, (req, res) => {
  const cust = db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(req.params.id);
  if (!cust) return res.status(404).json({ error: 'Customer not found' });
  const partnerId = (req.body && req.body.partnerId || '').trim();
  const partner = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(partnerId);
  if (!partner || (partner.kind !== 'carrier' && partner.kind !== 'broker')) return res.status(400).json({ error: 'Pick a carrier or broker' });
  db.prepare(`INSERT OR IGNORE INTO approved_partners (ownerOrgId, partnerOrgId, partnerKind, createdAt) VALUES (?,?,?,?)`).run(cust.id, partner.id, partner.kind, Date.now());
  res.status(201).json({ ok: true });
});
router.post('/:id/partners/:partnerId/remove', requireAuth, requireSuper, (req, res) => {
  db.prepare(`DELETE FROM approved_partners WHERE ownerOrgId = ? AND partnerOrgId = ?`).run(req.params.id, req.params.partnerId);
  res.json({ ok: true });
});

module.exports = router;
