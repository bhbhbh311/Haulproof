// Receivers / consignees. A receiver is a GLOBAL org (roles include 'receiver') so the same
// delivery location isn't entered ten times. Privacy: a customer only sees the receivers THEY
// have linked (customer_receivers) — never the whole registry. When they add one, /match suggests
// existing global records ("is this your customer & delivery location?") so we link instead of duplicating.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { createUser, requireAuth, requireSuper } = require('./auth');

const router = express.Router();
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }
function norm(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }

function rolesOf(o) { let r = []; try { r = o.roles ? JSON.parse(o.roles) : []; } catch (e) {} if (!r.length) r = [o.kind || 'customer']; return r; }
function receiverOut(o) {
  const parent = o.parentId ? db.prepare(`SELECT id, name FROM orgs WHERE id = ?`).get(o.parentId) : null;
  const docCount = db.prepare(`SELECT COUNT(*) n FROM pods WHERE receiverId = ?`).get(o.id).n;
  const admins = db.prepare(`SELECT email FROM users WHERE orgId = ? AND role='admin' ORDER BY createdAt`).all(o.id).map(r => r.email);
  return { id: o.id, name: o.name, active: !!o.active, createdAt: o.createdAt, roles: rolesOf(o), kind: o.kind || 'customer',
    contactName: o.contactName, contactEmail: o.contactEmail, contactPhone: o.contactPhone, address: o.address,
    parentId: o.parentId || null, parentName: parent ? parent.name : null, docCount, admins, hasLogin: admins.length > 0 };
}
function linkReceiver(orgId, receiverId) {
  if (!orgId || !receiverId) return;
  try { db.prepare(`INSERT OR IGNORE INTO customer_receivers (orgId, receiverId, createdAt) VALUES (?,?,?)`).run(orgId, receiverId, Date.now()); } catch (e) {}
}
// Which org "owns" this add/link: a normal admin uses their own org; super may target a customer via body.customerId.
function ownerOrgOf(req, b) { return req.user.role === 'superadmin' ? ((b && b.customerId || '').trim() || null) : (req.user.orgId || null); }

// ---- LIST. Super: the whole registry. Everyone else: only receivers THEY have linked. ----
router.get('/', requireAuth, (req, res) => {
  const all = req.query.includeInactive === '1';
  let rows;
  if (req.user.role === 'superadmin') {
    const linkedTo = (req.query.linkedTo || '').trim();
    if (linkedTo) {
      rows = db.prepare(`SELECT o.* FROM orgs o JOIN customer_receivers cr ON cr.receiverId = o.id
        WHERE cr.orgId = ? ${all ? '' : 'AND o.active = 1'} ORDER BY o.name COLLATE NOCASE`).all(linkedTo);
    } else {
      rows = db.prepare(`SELECT * FROM orgs WHERE (roles LIKE '%"receiver"%' OR kind='receiver') ${all ? '' : 'AND active = 1'} ORDER BY name COLLATE NOCASE`).all();
    }
  } else {
    rows = db.prepare(`SELECT o.* FROM orgs o JOIN customer_receivers cr ON cr.receiverId = o.id
      WHERE cr.orgId = ? ${all ? '' : 'AND o.active = 1'} ORDER BY o.name COLLATE NOCASE`).all(req.user.orgId || '');
  }
  res.json({ receivers: rows.map(receiverOut) });
});

// ---- MATCH the global registry by name (dedupe suggestion). Only surfaced when the user types a
//      specific name — this is a targeted "is this them?" lookup, not a browsable mass list. ----
router.get('/match', requireAuth, (req, res) => {
  const q = norm(req.query.name);
  if (q.length < 2) return res.json({ matches: [] });
  const city = norm(req.query.city);
  const rows = db.prepare(`SELECT * FROM orgs WHERE (roles LIKE '%"receiver"%' OR kind='receiver') AND active = 1`).all();
  const matches = rows.filter(o => {
    const n = norm(o.name);
    if (!(n.includes(q) || q.includes(n))) return false;
    if (city && o.address && !norm(o.address).includes(city)) return false;
    return true;
  }).slice(0, 8).map(o => ({ id: o.id, name: o.name, address: o.address || null, parentName: o.parentId ? (db.prepare(`SELECT name FROM orgs WHERE id=?`).get(o.parentId) || {}).name : null }));
  res.json({ matches });
});

// ---- ADD or LINK. body.receiverId → link an existing global receiver to this customer.
//      Otherwise create a new global receiver and link it. ----
router.post('/', requireAuth, (req, res) => {
  const b = req.body || {};
  const isSuper = req.user.role === 'superadmin';
  const ownerOrg = ownerOrgOf(req, b);
  // Link an existing global receiver.
  if ((b.receiverId || '').trim()) {
    const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(b.receiverId.trim());
    if (!o) return res.status(404).json({ error: 'Receiver not found' });
    linkReceiver(ownerOrg, o.id);
    return res.status(200).json({ receiver: receiverOut(o), linked: true });
  }
  // Create a new global receiver.
  const name = (b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Receiver name is required' });
  const parentId = (b.parentId || '').trim() || null;
  if (parentId && !db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(parentId)) return res.status(400).json({ error: 'Parent company not found' });
  const adminEmail = (b.adminEmail || '').toLowerCase().trim();
  const adminPassword = b.adminPassword || '';
  if (isSuper && adminEmail) {
    if (!EMAIL_RE.test(adminEmail)) return res.status(400).json({ error: 'A valid admin email is required' });
    if (String(adminPassword).length < 6) return res.status(400).json({ error: 'Admin password must be at least 6 characters' });
    if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(adminEmail)) return res.status(409).json({ error: 'That email already has a login' });
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, deviceKey, kind, roles, parentId, contactName, contactEmail, contactPhone, address, active, createdAt)
              VALUES (?,?,?,?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), 'receiver', JSON.stringify(['receiver']), parentId,
         (b.contactName || '').trim() || null, (b.contactEmail || '').trim() || null,
         (b.contactPhone || '').trim() || null, (b.address || b.city || '').trim() || null, Date.now());
  if (isSuper && adminEmail) createUser({ email: adminEmail, name: (b.adminName || b.contactName || '').trim(), role: 'admin', password: String(adminPassword), orgId: id });
  linkReceiver(ownerOrg, id);
  res.status(201).json({ receiver: receiverOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(id)), linked: !!ownerOrg, created: true });
});

// ---- Unlink a receiver from a customer (does NOT delete the global record). ----
router.post('/:id/unlink', requireAuth, (req, res) => {
  const ownerOrg = ownerOrgOf(req, req.body || {});
  if (!ownerOrg) return res.status(400).json({ error: 'No customer to unlink from' });
  db.prepare(`DELETE FROM customer_receivers WHERE orgId = ? AND receiverId = ?`).run(ownerOrg, req.params.id);
  res.json({ ok: true });
});

// ---- Edit the global receiver record (master admin only). ----
router.put('/:id', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Receiver not found' });
  const b = req.body || {};
  let parentId = (b.parentId !== undefined) ? ((b.parentId || '').trim() || null) : (o.parentId || null);
  if (parentId === o.id) parentId = null;
  if (parentId && !db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(parentId)) return res.status(400).json({ error: 'Parent company not found' });
  db.prepare(`UPDATE orgs SET name = ?, contactName = ?, contactEmail = ?, contactPhone = ?, address = ?, parentId = ?, active = ? WHERE id = ?`)
    .run((b.name || o.name).trim(), (b.contactName ?? o.contactName) || null, (b.contactEmail ?? o.contactEmail) || null,
         (b.contactPhone ?? o.contactPhone) || null, (b.address ?? o.address) || null, parentId,
         (b.active === undefined ? o.active : (b.active ? 1 : 0)), o.id);
  res.json({ receiver: receiverOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});

// ---- Give a receiver a login so they can look up delivered documents (master admin only). ----
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
