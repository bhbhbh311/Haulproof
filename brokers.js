// Brokers: a middle layer between a customer (shipper) and a carrier. A customer can hand a load to a
// broker, who then approves carriers and assigns the load to one of them. Brokers are looked up on FMCSA
// (their broker authority) just like carriers.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth, requireAdmin, createUser } = require('./auth');
const { fmcsaLookup, upsertCarrierOrg, carrierOut } = require('./carriers');
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

const router = express.Router();
function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }
function brokerOut(o) {
  return { id: o.id, name: o.name, mcNumber: o.mcNumber, dotNumber: o.dotNumber, fmcsaVerified: !!o.fmcsaVerified,
    allowedToOperate: o.allowedToOperate, address: o.address, contactPhone: o.contactPhone, active: !!o.active };
}
const isAdmin = (req) => req.user.role === 'admin' || req.user.role === 'superadmin';

// Look up a broker on FMCSA (name / MC# / DOT#) — same live source carriers use.
router.get('/lookup', requireAuth, async (req, res) => {
  const mc = (req.query.mc || '').trim(), dot = (req.query.dot || '').trim(), name = (req.query.name || '').trim();
  if (!mc && !dot && !name) return res.status(400).json({ error: 'Search by name, MC#, or DOT#' });
  const fm = await fmcsaLookup({ mc, dot, name });
  res.json({ configured: fm.configured, fmcsa: fm.results, error: fm.error || null });
});

// List saved brokers. Active only unless ?includeInactive=1.
router.get('/', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim();
  const act = req.query.includeInactive === '1' ? '' : 'AND active = 1';
  let rows;
  if (q) rows = db.prepare(`SELECT * FROM orgs WHERE kind='broker' ${act} AND (name LIKE ? OR mcNumber LIKE ? OR dotNumber LIKE ?) ORDER BY active DESC, name`).all('%' + q + '%', '%' + q + '%', '%' + q + '%');
  else rows = db.prepare(`SELECT * FROM orgs WHERE kind='broker' ${act} ORDER BY active DESC, name`).all();
  res.json({ brokers: rows.map(brokerOut) });
});

// Save a broker (from an FMCSA result, or an admin override). Optionally create its first admin login.
router.post('/', requireAuth, (req, res) => {
  const b = req.body || {};
  const name = (b.name || '').trim();
  const mcNumber = (b.mcNumber || '').trim();
  const dotNumber = (b.dotNumber || '').trim();
  const verified = b.fmcsaVerified ? 1 : 0;
  if (!name) return res.status(400).json({ error: 'Broker name is required' });
  if (!verified && !isAdmin(req)) return res.status(403).json({ error: 'Only an admin can add a broker that FMCSA did not verify' });
  let existing = null;
  if (dotNumber) existing = db.prepare(`SELECT * FROM orgs WHERE kind='broker' AND dotNumber = ?`).get(dotNumber);
  if (!existing && mcNumber) existing = db.prepare(`SELECT * FROM orgs WHERE kind='broker' AND mcNumber = ?`).get(mcNumber);
  if (existing) {
    if (verified) db.prepare(`UPDATE orgs SET fmcsaVerified=1, allowedToOperate=?, name=?, address=? WHERE id=?`)
      .run(b.allowedToOperate || existing.allowedToOperate, name, (b.address || existing.address) || null, existing.id);
    return res.json({ broker: brokerOut(db.prepare(`SELECT * FROM orgs WHERE id=?`).get(existing.id)) });
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, kind, deviceKey, mcNumber, dotNumber, fmcsaVerified, allowedToOperate, contactPhone, address, active, createdAt)
              VALUES (?,?, 'broker', ?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), mcNumber || null, dotNumber || null, verified, b.allowedToOperate || null, (b.contactPhone || '').trim() || null, (b.address || '').trim() || null, Date.now());
  const adminEmail = (b.adminEmail || '').toLowerCase().trim();
  if (adminEmail) {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Only an admin can create a broker login' });
    if (!EMAIL_RE.test(adminEmail)) return res.status(400).json({ error: 'A valid broker admin email is required' });
    if (!b.adminPassword || String(b.adminPassword).length < 6) return res.status(400).json({ error: 'Broker admin password must be at least 6 characters' });
    if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(adminEmail)) return res.status(409).json({ error: 'That admin email already has a login' });
    createUser({ email: adminEmail, name: (b.adminName || '').trim(), role: 'admin', password: String(b.adminPassword), orgId: id });
  }
  res.status(201).json({ broker: brokerOut(db.prepare(`SELECT * FROM orgs WHERE id=?`).get(id)) });
});

// Edit a broker's company info.
router.put('/:id', requireAuth, requireAdmin, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ? AND kind='broker'`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Broker not found' });
  const b = req.body || {};
  const name = (b.name !== undefined ? String(b.name) : o.name).trim();
  if (!name) return res.status(400).json({ error: 'Broker name is required' });
  const mcNumber = (b.mcNumber !== undefined ? String(b.mcNumber) : (o.mcNumber || '')).trim();
  const dotNumber = (b.dotNumber !== undefined ? String(b.dotNumber) : (o.dotNumber || '')).trim();
  if (dotNumber) { const dup = db.prepare(`SELECT id FROM orgs WHERE kind='broker' AND dotNumber = ? AND id != ?`).get(dotNumber, o.id); if (dup) return res.status(409).json({ error: 'Another broker already uses that DOT #' }); }
  if (mcNumber) { const dup = db.prepare(`SELECT id FROM orgs WHERE kind='broker' AND mcNumber = ? AND id != ?`).get(mcNumber, o.id); if (dup) return res.status(409).json({ error: 'Another broker already uses that MC #' }); }
  db.prepare(`UPDATE orgs SET name = ?, mcNumber = ?, dotNumber = ?, contactPhone = ?, address = ? WHERE id = ?`)
    .run(name, mcNumber || null, dotNumber || null, (b.contactPhone !== undefined ? String(b.contactPhone).trim() : o.contactPhone) || null, (b.address !== undefined ? String(b.address).trim() : o.address) || null, o.id);
  res.json({ broker: brokerOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});

// Activate / deactivate a broker.
router.post('/:id/active', requireAuth, requireAdmin, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ? AND kind='broker'`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Broker not found' });
  db.prepare(`UPDATE orgs SET active = ? WHERE id = ?`).run(req.body && req.body.active ? 1 : 0, o.id);
  res.json({ broker: brokerOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});

// --- A broker's approved-carrier roster ---
function brokerScope(req) {
  if (req.user.orgKind === 'broker') return req.user.orgId || null;
  if (req.user.role === 'superadmin') return ((req.query.brokerId || (req.body && req.body.brokerId) || '').trim() || null);
  return null;
}
// Carriers this broker has approved.
router.get('/my-carriers', requireAuth, (req, res) => {
  const brokerOrg = brokerScope(req);
  if (!brokerOrg) return res.json({ carriers: [] });
  const rows = db.prepare(`SELECT orgs.* FROM broker_carriers bc JOIN orgs ON orgs.id = bc.carrierId
    WHERE bc.brokerId = ? AND orgs.active = 1 ORDER BY orgs.name`).all(brokerOrg);
  res.json({ carriers: rows.map(carrierOut) });
});
// Approve a carrier into the roster (from FMCSA data, or an admin override).
router.post('/my-carriers', requireAuth, (req, res) => {
  const brokerOrg = brokerScope(req);
  if (!brokerOrg) return res.status(403).json({ error: 'Brokers only' });
  const b = req.body || {};
  const name = (b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Carrier name is required' });
  if (!b.fmcsaVerified && !isAdmin(req)) return res.status(403).json({ error: 'Only an admin can approve a carrier FMCSA did not verify' });
  const carrier = upsertCarrierOrg({ name, mcNumber: b.mcNumber, dotNumber: b.dotNumber, verified: !!b.fmcsaVerified, allowedToOperate: b.allowedToOperate, address: b.address });
  db.prepare(`INSERT OR IGNORE INTO broker_carriers (brokerId, carrierId, createdAt) VALUES (?,?,?)`).run(brokerOrg, carrier.id, Date.now());
  res.status(201).json({ carrier: carrierOut(carrier) });
});
// Remove a carrier from the roster.
router.delete('/my-carriers/:carrierId', requireAuth, (req, res) => {
  const brokerOrg = brokerScope(req);
  if (!brokerOrg) return res.status(403).json({ error: 'Brokers only' });
  db.prepare(`DELETE FROM broker_carriers WHERE brokerId = ? AND carrierId = ?`).run(brokerOrg, req.params.carrierId);
  res.json({ ok: true });
});
// Is a carrier on this broker's approved roster? (used when assigning)
function brokerApproved(brokerId, carrierId) {
  return !!db.prepare(`SELECT 1 FROM broker_carriers WHERE brokerId = ? AND carrierId = ?`).get(brokerId, carrierId);
}

module.exports = { router, brokerApproved };
