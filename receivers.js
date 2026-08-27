// Receivers / consignees. A receiver is an org whose roles include 'receiver'.
// Dispatch tags a signed document with the receiver it was delivered to; the receiver's login can
// then look up everything delivered to them, even loads created by a different customer.
// Listing is available to any signed-in admin (so dispatch can pick a receiver on a load);
// creating / editing is master-admin only, like customers.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { createUser, requireAuth, requireSuper } = require('./auth');

const router = express.Router();
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }

function rolesOf(o) {
  let roles = [];
  try { roles = o.roles ? JSON.parse(o.roles) : []; } catch (e) {}
  if (!roles.length) roles = [o.kind || 'customer'];
  return roles;
}
function isReceiver(o) { return rolesOf(o).includes('receiver'); }

function receiverOut(o) {
  const parent = o.parentId ? db.prepare(`SELECT id, name FROM orgs WHERE id = ?`).get(o.parentId) : null;
  const docCount = db.prepare(`SELECT COUNT(*) n FROM pods WHERE receiverId = ?`).get(o.id).n;
  const admins = db.prepare(`SELECT email FROM users WHERE orgId = ? AND role='admin' ORDER BY createdAt`).all(o.id).map(r => r.email);
  return {
    id: o.id, name: o.name, active: !!o.active, createdAt: o.createdAt,
    roles: rolesOf(o), kind: o.kind || 'customer',
    contactName: o.contactName, contactEmail: o.contactEmail, contactPhone: o.contactPhone, address: o.address,
    parentId: o.parentId || null, parentName: parent ? parent.name : null,
    docCount, admins, hasLogin: admins.length > 0,
  };
}

// List receivers (any org that can receive). Available to any signed-in user so dispatch can pick one.
router.get('/', requireAuth, (req, res) => {
  const all = req.query.includeInactive === '1';
  const rows = db.prepare(`SELECT * FROM orgs WHERE (roles LIKE '%"receiver"%' OR kind='receiver') ${all ? '' : 'AND active = 1'} ORDER BY name COLLATE NOCASE`).all();
  res.json({ receivers: rows.map(receiverOut) });
});

// Create a receiver. An admin login is optional — a receiver can exist purely as a delivery
// destination you tag loads with, and get a login later so they can look their documents up.
router.post('/', requireAuth, requireSuper, (req, res) => {
  const b = req.body || {};
  const name = (b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Receiver name is required' });
  const parentId = (b.parentId || '').trim() || null;
  if (parentId && !db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(parentId)) return res.status(400).json({ error: 'Parent company not found' });
  const adminEmail = (b.adminEmail || '').toLowerCase().trim();
  const adminPassword = b.adminPassword || '';
  if (adminEmail) {
    if (!EMAIL_RE.test(adminEmail)) return res.status(400).json({ error: 'A valid admin email is required' });
    if (String(adminPassword).length < 6) return res.status(400).json({ error: 'Admin password must be at least 6 characters' });
    if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(adminEmail)) return res.status(409).json({ error: 'That email already has a login' });
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, deviceKey, kind, roles, parentId, contactName, contactEmail, contactPhone, address, active, createdAt)
              VALUES (?,?,?,?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), 'receiver', JSON.stringify(['receiver']), parentId,
         (b.contactName || '').trim() || null, (b.contactEmail || adminEmail || '').trim() || null,
         (b.contactPhone || '').trim() || null, (b.address || '').trim() || null, Date.now());
  if (adminEmail) createUser({ email: adminEmail, name: (b.adminName || b.contactName || '').trim(), role: 'admin', password: String(adminPassword), orgId: id });
  res.status(201).json({ receiver: receiverOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(id)) });
});

// Update a receiver's info / parent / active flag.
router.put('/:id', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Receiver not found' });
  const b = req.body || {};
  let parentId = (b.parentId !== undefined) ? ((b.parentId || '').trim() || null) : (o.parentId || null);
  if (parentId === o.id) parentId = null;                              // a location can't be its own parent
  if (parentId && !db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(parentId)) return res.status(400).json({ error: 'Parent company not found' });
  db.prepare(`UPDATE orgs SET name = ?, contactName = ?, contactEmail = ?, contactPhone = ?, address = ?, parentId = ?, active = ? WHERE id = ?`)
    .run((b.name || o.name).trim(), (b.contactName ?? o.contactName) || null, (b.contactEmail ?? o.contactEmail) || null,
         (b.contactPhone ?? o.contactPhone) || null, (b.address ?? o.address) || null, parentId,
         (b.active === undefined ? o.active : (b.active ? 1 : 0)), o.id);
  res.json({ receiver: receiverOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});

// Give a receiver an admin login (so they can look up delivered documents).
router.post('/:id/admins', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Receiver not found' });
  const email = (req.body && req.body.email || '').toLowerCase().trim();
  const password = req.body && req.body.password || '';
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'A valid email is required' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(email)) return res.status(409).json({ error: 'That email already has a login' });
  createUser({ email, name: (req.body.name || '').trim(), role: 'admin', password: String(password), orgId: o.id });
  res.status(201).json({ ok: true });
});

module.exports = router;
