// Loads: create, search, assign a carrier, assign a driver/truck/trailer, and read history. Org-scoped.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const { db, DATA_DIR } = require('./db');
const { requireAuth } = require('./auth');
const { logEvent } = require('./events');
const { brokerApproved } = require('./brokers');
const { customerIdsForRep } = require('./customers');

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
  // A carrier creating its own load IS the carrier — default it to their company (they can change it later).
  let carrierId = null, carrierName = null;
  if (isCarrier(req) && orgId) { carrierId = orgId; const o = db.prepare(`SELECT name FROM orgs WHERE id = ?`).get(orgId); carrierName = o ? o.name : null; }
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, customer, consignee, origin, destination, carrierId, carrierName, status, createdBy, createdAt)
     VALUES (?,?,?,?,?,?,?,?,?,?, 'open', ?, ?)`)
    .run(id, orgId, loadNumber || null, poNumber || null, customer || null, consignee || null, origin || null, destination || null, carrierId, carrierName, req.user.email, Date.now());
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
  // A sales rep's DEFAULT list shows only loads for the customers they're assigned to (so they aren't
  // buried in other reps' work). They can still find anything by searching (q/po/load) — the filter only
  // applies to the plain, unsearched list.
  if (req.user.role === 'sales' && !q && !po && !load) {
    const mine = customerIdsForRep(req.user.sub || req.user.id);
    if (mine.length) { where.push(`customerId IN (${mine.map(() => '?').join(',')})`); args.push(...mine); }
    else { where.push('1 = 0'); }   // no customers assigned yet → empty default list (search still works)
  }
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
  // A load is "complete" when it has at least one document and EVERY document is signed/emailed. Such loads
  // drop off the default Loads list (still findable via search) so only loads needing action remain.
  const podStat = db.prepare(`SELECT COUNT(*) AS total,
     SUM(CASE WHEN status IN ('signed','emailed') THEN 1 ELSE 0 END) AS done,
     SUM(CASE WHEN status = 'awaiting_build' THEN 1 ELSE 0 END) AS awaiting,
     SUM(CASE WHEN status = 'prepared' THEN 1 ELSE 0 END) AS prepared
     FROM pods WHERE loadId = ?`);
  const out = rows.map(l => {
    const o = { ...loadOut(l), lastEvent: lastEv.get(l.id) || null };
    const ps = podStat.get(l.id); o.complete = !!(ps && ps.total > 0 && Number(ps.done) === Number(ps.total));
    // Actionable document state (drives a clear status pill instead of a vague "Updated"):
    o.needsSetup = !!(ps && Number(ps.awaiting) > 0);   // a driver uploaded a doc for dispatch to set up
    o.readyToSign = !!(ps && Number(ps.prepared) > 0);  // dispatch released it — waiting on the driver's signature
    if (viewerIsCB && (l.orgId || null) !== (req.user.orgId || null)) o.customerName = (orgName.get(l.orgId) || {}).name || null;
    return o;
  });
  res.json({ count: out.length, results: out, viewerKind: req.user.orgKind || null });
});

// One load plus its documents.
router.get('/:id', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const pods = db.prepare(`SELECT id, orgId, poNumber, loadNumber, docType, filename, consignee, stopNumber, receiverId, receiverName, salesRepUserId, signedAt, uploadedAt, status, dupWarn FROM pods WHERE loadId = ? ORDER BY (stopNumber IS NULL), stopNumber ASC, uploadedAt ASC`).all(load.id)
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
  // Reassign the load to a different CUSTOMER (Master Admin only). Moves the load and its documents.
  let orgIdNew = load.orgId;
  if (req.user.role === 'superadmin' && b.customerOrgId !== undefined) {
    const newOrg = (b.customerOrgId || '').trim() || null;
    if (newOrg && newOrg !== load.orgId) {
      const org = db.prepare(`SELECT id FROM orgs WHERE id = ? AND kind = 'customer'`).get(newOrg);
      if (!org) return res.status(400).json({ error: 'That customer was not found' });
      const clash2 = db.prepare(`SELECT id FROM loads WHERE orgId IS ? AND poNumber = ? AND id != ?`).get(newOrg, poNumber, load.id);
      if (clash2) return res.status(409).json({ error: 'That customer already has a load with PO ' + poNumber });
      orgIdNew = newOrg;
    }
  }
  // Customer, chosen from the load owner's OWN customer list. A carrier/broker can set/change it on a
  // load THEY created (own); a customer whose load was assigned out can't have its customer changed by
  // the carrier. (Super may set it too.) We snapshot the customer's name onto the load so the existing
  // lists/search keep working, and store customerId so the entry stays linked to the picker list.
  let customerId = load.customerId;
  let customerText = load.customer;
  const canSetCustomer = (req.user.role === 'superadmin' || ((isCarrier(req) || isBroker(req)) && (load.orgId || null) === (req.user.orgId || null)));
  if (b.customerId !== undefined && canSetCustomer) {
    const cid = (b.customerId || '').trim() || null;
    if (!cid) { customerId = null; customerText = null; }
    else {
      const cust = db.prepare(`SELECT * FROM customers WHERE id = ? AND ownerOrgId IS ?`).get(cid, load.orgId || null);
      if (!cust) return res.status(400).json({ error: 'That customer is not in your list' });
      customerId = cust.id; customerText = cust.name;
    }
  } else if (b.customer !== undefined && canSetCustomer) {
    // Back-compat: a plain free-text name still works, and clears any linked list entry.
    customerText = (b.customer || '').trim() || null;
    customerId = null;
  }
  db.prepare(`UPDATE loads SET loadNumber = ?, consignee = ?, poNumber = ?, orgId = ?, customer = ?, customerId = ? WHERE id = ?`).run(loadNumber, consignee, poNumber, orgIdNew, customerText, customerId, load.id);
  if (poNumber !== load.poNumber || orgIdNew !== load.orgId) db.prepare(`UPDATE pods SET poNumber = ?, orgId = ? WHERE loadId = ?`).run(poNumber, orgIdNew, load.id);
  logEvent({ orgId: orgIdNew, loadId: load.id, poNumber, type: 'updated', detail: 'Load details updated' + (orgIdNew !== load.orgId ? ' (customer reassigned)' : ''), actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id)) });
});

// Delete a load and all its documents. Owner (or super) only. Irreversible — the app confirms twice first.
router.delete('/:id', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  try {
    const pods = db.prepare(`SELECT id, filepath FROM pods WHERE loadId = ?`).all(load.id);
    pods.forEach(p => { if (p.filepath) { try { fs.unlinkSync(p.filepath); } catch (e) {} } });
    db.prepare(`DELETE FROM pods WHERE loadId = ?`).run(load.id);
    try { db.prepare(`DELETE FROM load_subscribers WHERE loadId = ?`).run(load.id); } catch (e) {}
    db.prepare(`DELETE FROM loads WHERE id = ?`).run(load.id);
    logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'deleted', detail: 'Load and its ' + pods.length + ' document(s) deleted', actor: actorOf(req) });
    res.json({ ok: true, deletedPods: pods.length });
  } catch (e) { console.error('delete load', e); res.status(500).json({ error: 'Could not delete this load' }); }
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
    // The driver must belong to an org connected to this load — its owner (customer), its assigned carrier,
    // or its broker. A carrier's driver hauls the customer's load, so their orgs legitimately differ.
    // accessibleLoad already confirmed the caller may act on this load.
    const drv = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(driverId);
    const allowedOrgs = new Set([load.orgId, load.carrierId, load.brokerId].filter(Boolean).map(String));
    if (!drv || !allowedOrgs.has(String(drv.orgId || ''))) return res.status(400).json({ error: 'That driver is not on this load’s account or its assigned carrier/broker' });
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
