// Loads: create, search, assign a carrier, assign a driver/truck/trailer, and read history. Org-scoped.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth } = require('./auth');
const { logEvent } = require('./events');
const { brokerApproved } = require('./brokers');

const router = express.Router();
function myOrg(req) { return req.user.role === 'superadmin' ? ((req.query.orgId || (req.body && req.body.orgId) || '').trim() || null) : (req.user.orgId || null); }
function actorOf(req) { return req.user.email || req.user.name || 'admin'; }
function isCarrier(req) { return req.user.orgKind === 'carrier'; }
function isBroker(req) { return req.user.orgKind === 'broker'; }
// A load the caller's org OWNS (super sees any). A carrier owns loads it created for itself.
function ownedLoad(req, id) {
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id);
  if (!load) return null;
  if (req.user.role === 'superadmin') return load;
  return (load.orgId || null) === (req.user.orgId || null) ? load : null;
}
// A load the caller can VIEW/act on: the owning org, super, OR the assigned carrier.
function accessibleLoad(req, id) {
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id);
  if (!load) return null;
  if (req.user.role === 'superadmin') return load;
  if (isCarrier(req)) return ((load.carrierId || null) === (req.user.orgId || null) || (load.orgId || null) === (req.user.orgId || null)) ? load : null;
  if (isBroker(req)) return ((load.brokerId || null) === (req.user.orgId || null) || (load.orgId || null) === (req.user.orgId || null)) ? load : null;
  return (load.orgId || null) === (req.user.orgId || null) ? load : null;
}
function loadOut(l) { return l; }

// Create/name a load (PO# is the primary identifier, unique per customer).
router.post('/', requireAuth, (req, res) => {
  const orgId = myOrg(req);
  const { loadNumber, poNumber, customer, consignee, origin, destination } = req.body || {};
  if (!poNumber && !loadNumber) return res.status(400).json({ error: 'Provide a PO number or a load number' });
  if (poNumber) {
    const existing = db.prepare(`SELECT * FROM loads WHERE orgId IS ? AND poNumber = ?`).get(orgId, poNumber);
    if (existing) return res.json({ load: loadOut(existing), existed: true });
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, customer, consignee, origin, destination, status, createdBy, createdAt)
     VALUES (?,?,?,?,?,?,?,?, 'open', ?, ?)`)
    .run(id, orgId, loadNumber || null, poNumber || null, customer || null, consignee || null, origin || null, destination || null, req.user.email, Date.now());
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id);
  logEvent({ orgId, loadId: id, poNumber: poNumber || null, type: 'created', detail: 'Load created' + (poNumber ? ' for PO ' + poNumber : ''), actor: actorOf(req) });
  res.json({ load: loadOut(load), existed: false });
});

// Search loads. Customers see their own; a carrier sees loads assigned to it.
router.get('/', requireAuth, (req, res) => {
  const { q, po, load } = req.query;
  const where = [], args = [];
  // Carriers see loads they OWN (self-service) plus loads assigned to them.
  if (isCarrier(req)) { where.push(`(orgId IS ? OR carrierId = ?)`); args.push(req.user.orgId || null, req.user.orgId || ''); }
  // Brokers see loads a customer handed to them.
  else if (isBroker(req)) { where.push(`(orgId IS ? OR brokerId = ?)`); args.push(req.user.orgId || null, req.user.orgId || ''); }
  else { where.push(`orgId IS ?`); args.push(myOrg(req)); }
  if (po) { where.push(`poNumber LIKE ?`); args.push(`%${po}%`); }
  if (load) { where.push(`loadNumber LIKE ?`); args.push(`%${load}%`); }
  if (q) { where.push(`(poNumber LIKE ? OR loadNumber LIKE ? OR customer LIKE ? OR consignee LIKE ? OR carrierName LIKE ?)`); args.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
  const rows = db.prepare(`SELECT * FROM loads WHERE ${where.join(' AND ')} ORDER BY createdAt DESC LIMIT 200`).all(...args);
  // Attach ONLY the latest history event to each load (the list shows the current step;
  // the full timeline lives in the load's detail view).
  const lastEv = db.prepare(`SELECT type, detail, actor, createdAt FROM load_events WHERE loadId = ? ORDER BY createdAt DESC LIMIT 1`);
  // Carrier/broker viewers also see which CUSTOMER each load came from (customers never see this — they
  // only ever see their own loads).
  const viewerIsCB = isCarrier(req) || isBroker(req);
  const orgName = db.prepare(`SELECT name FROM orgs WHERE id = ?`);
  const out = rows.map(l => {
    const o = { ...loadOut(l), lastEvent: lastEv.get(l.id) || null };
    if (viewerIsCB && (l.orgId || null) !== (req.user.orgId || null)) o.customerName = (orgName.get(l.orgId) || {}).name || null;
    return o;
  });
  res.json({ count: out.length, results: out, viewerKind: req.user.orgKind || null });
});

// One load plus its documents.
router.get('/:id', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const pods = db.prepare(`SELECT id, docType, filename, consignee, stopNumber, receiverId, receiverName, salesRepUserId, signedAt, uploadedAt, status FROM pods WHERE loadId = ? ORDER BY (stopNumber IS NULL), stopNumber ASC, uploadedAt ASC`).all(load.id)
    .map(p => ({ ...p, fileUrl: `/api/pods/${p.id}/file` }));
  res.json({ load: loadOut(load), pods });
});

// Who gets update emails for THIS load (chosen from the customer's own team logins).
router.get('/:id/subscribers', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const rows = db.prepare(`SELECT userId FROM load_subscribers WHERE loadId = ?`).all(load.id);
  res.json({ userIds: rows.map(r => r.userId) });
});
router.put('/:id/subscribers', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const ids = Array.isArray(req.body && req.body.userIds) ? req.body.userIds : [];
  const valid = ids.filter(uid => db.prepare(`SELECT 1 FROM users WHERE id = ? AND orgId IS ?`).get(uid, load.orgId || null));
  db.transaction(() => {
    db.prepare(`DELETE FROM load_subscribers WHERE loadId = ?`).run(load.id);
    const ins = db.prepare(`INSERT OR IGNORE INTO load_subscribers (loadId, userId, createdAt) VALUES (?,?,?)`);
    valid.forEach(uid => ins.run(load.id, uid, Date.now()));
  })();
  res.json({ ok: true, userIds: valid });
});

// Edit a load's basic fields (owning customer or super). Changing the PO # cascades to its documents.
router.put('/:id', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const b = req.body || {};
  const loadNumber = (b.loadNumber !== undefined) ? ((b.loadNumber || '').trim() || null) : load.loadNumber;
  const consignee = (b.consignee !== undefined) ? ((b.consignee || '').trim() || null) : load.consignee;
  let poNumber = load.poNumber;
  if (b.poNumber !== undefined) {
    const newPo = (b.poNumber || '').trim();
    if (!newPo) return res.status(400).json({ error: 'PO # cannot be empty' });
    if (newPo !== load.poNumber) {
      const clash = db.prepare(`SELECT id FROM loads WHERE orgId IS ? AND poNumber = ? AND id != ?`).get(load.orgId || null, newPo, load.id);
      if (clash) return res.status(409).json({ error: 'Another load already uses PO ' + newPo });
      poNumber = newPo;
    }
  }
  db.prepare(`UPDATE loads SET loadNumber = ?, consignee = ?, poNumber = ? WHERE id = ?`).run(loadNumber, consignee, poNumber, load.id);
  if (poNumber !== load.poNumber) db.prepare(`UPDATE pods SET poNumber = ? WHERE loadId = ?`).run(poNumber, load.id);
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber, type: 'updated', detail: 'Load details updated', actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id)) });
});

// Hand a load to a broker. Only the owning customer (or super) does this.
router.post('/:id/assign-broker', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const brokerId = (req.body && req.body.brokerId || '').trim();
  const broker = db.prepare(`SELECT * FROM orgs WHERE id = ? AND kind='broker'`).get(brokerId);
  if (!broker) return res.status(400).json({ error: 'Pick a broker from the list' });
  db.prepare(`UPDATE loads SET brokerId = ?, brokerName = ?, status = 'assigned' WHERE id = ?`).run(broker.id, broker.name, load.id);
  const tag = broker.fmcsaVerified ? 'FMCSA-verified' : 'admin override — not FMCSA verified';
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'broker_assigned',
    detail: 'Handed to broker ' + broker.name + (broker.mcNumber ? ' (MC ' + broker.mcNumber + ')' : '') + ' — ' + tag, actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id)) });
});

// Assign a carrier to a load. The owning customer, super, OR the broker the load was handed to.
// A broker may only assign carriers on its approved roster.
router.post('/:id/assign-carrier', requireAuth, (req, res) => {
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const carrierId = (req.body && req.body.carrierId || '').trim();
  const carrier = db.prepare(`SELECT * FROM orgs WHERE id = ? AND kind='carrier'`).get(carrierId);
  if (!carrier) return res.status(400).json({ error: 'Pick a carrier from the list' });
  const isOwner = req.user.role === 'superadmin' || (load.orgId || null) === (req.user.orgId || null);
  const isAssignedBroker = isBroker(req) && (load.brokerId || null) === (req.user.orgId || null);
  if (!isOwner && !isAssignedBroker) return res.status(404).json({ error: 'Load not found' });
  if (isAssignedBroker && !brokerApproved(req.user.orgId, carrier.id)) return res.status(403).json({ error: 'Approve this carrier before assigning it a load' });
  db.prepare(`UPDATE loads SET carrierId = ?, carrierName = ?, status = 'assigned' WHERE id = ?`).run(carrier.id, carrier.name, load.id);
  const tag = carrier.fmcsaVerified ? 'FMCSA-verified' : 'admin override — not FMCSA verified';
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'carrier_assigned',
    detail: (isAssignedBroker ? 'Broker assigned ' : 'Assigned to ') + carrier.name + (carrier.mcNumber ? ' (MC ' + carrier.mcNumber + ')' : '') + ' — ' + tag, actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id)) });
});

// Record the driver + truck + trailer on a load. The assigned carrier, the owning customer, or super.
router.post('/:id/assign-driver', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  let driverName = (req.body && req.body.driverName || '').trim();
  const truck = (req.body && req.body.truck || '').trim();
  const trailer = (req.body && req.body.trailer || '').trim();
  // Optional: pick a registered driver (of the caller's org). We then route the load's prepared docs to
  // that driver's phone (their "Your loads") by stamping assignedDriverId on them.
  const driverId = (req.body && req.body.driverId || '').trim() || null;
  if (driverId) {
    const drv = db.prepare(`SELECT * FROM drivers WHERE id = ? AND orgId = ?`).get(driverId, req.user.orgId || null);
    if (!drv) return res.status(400).json({ error: 'That driver was not found on your account' });
    driverName = drv.name || driverName;
    try { db.prepare(`UPDATE pods SET assignedDriverId = ?, assignedDriverName = ? WHERE loadId = ? AND status IN ('received','prepared')`).run(drv.id, drv.name, load.id); } catch (e) {}
  }
  if (!driverName) return res.status(400).json({ error: "Choose or enter the driver's name" });
  db.prepare(`UPDATE loads SET driverName = ?, truck = ?, trailer = ? WHERE id = ?`).run(driverName, truck || null, trailer || null, load.id);
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'driver_assigned',
    detail: 'Driver ' + driverName + (truck ? ' · Truck ' + truck : '') + (trailer ? ' · Trailer ' + trailer : ''), actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id)) });
});

// The recorded history of a load / PO#.
router.get('/:id/history', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const events = db.prepare(`SELECT type, detail, actor, createdAt FROM load_events WHERE loadId = ? ORDER BY createdAt ASC`).all(load.id);
  res.json({ load: loadOut(load), events });
});

module.exports = router;
