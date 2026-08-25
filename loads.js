// Loads: create, search, assign a carrier, assign a driver/truck/trailer, and read history. Org-scoped.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth } = require('./auth');
const { logEvent } = require('./events');

const router = express.Router();
function myOrg(req) { return req.user.role === 'superadmin' ? ((req.query.orgId || (req.body && req.body.orgId) || '').trim() || null) : (req.user.orgId || null); }
function actorOf(req) { return req.user.email || req.user.name || 'admin'; }
// A load the caller's customer org owns (super sees any).
function ownedLoad(req, id) {
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id);
  if (!load) return null;
  if (req.user.role === 'superadmin') return load;
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

// Search loads within this customer.
router.get('/', requireAuth, (req, res) => {
  const orgId = myOrg(req);
  const { q, po, load } = req.query;
  const where = [`orgId IS ?`], args = [orgId];
  if (po) { where.push(`poNumber LIKE ?`); args.push(`%${po}%`); }
  if (load) { where.push(`loadNumber LIKE ?`); args.push(`%${load}%`); }
  if (q) { where.push(`(poNumber LIKE ? OR loadNumber LIKE ? OR customer LIKE ? OR consignee LIKE ? OR carrierName LIKE ?)`); args.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
  const rows = db.prepare(`SELECT * FROM loads WHERE ${where.join(' AND ')} ORDER BY createdAt DESC LIMIT 200`).all(...args);
  res.json({ count: rows.length, results: rows.map(loadOut) });
});

// One load plus its documents.
router.get('/:id', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const pods = db.prepare(`SELECT id, docType, filename, consignee, signedAt, uploadedAt, status FROM pods WHERE loadId = ? ORDER BY uploadedAt DESC`).all(load.id)
    .map(p => ({ ...p, fileUrl: `/api/pods/${p.id}/file` }));
  res.json({ load: loadOut(load), pods });
});

// Assign a carrier (from the registry) to a load. The customer that owns the load (or super) does this.
router.post('/:id/assign-carrier', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const carrierId = (req.body && req.body.carrierId || '').trim();
  const carrier = db.prepare(`SELECT * FROM orgs WHERE id = ? AND kind='carrier'`).get(carrierId);
  if (!carrier) return res.status(400).json({ error: 'Pick a carrier from the list' });
  db.prepare(`UPDATE loads SET carrierId = ?, carrierName = ?, status = 'assigned' WHERE id = ?`).run(carrier.id, carrier.name, load.id);
  const tag = carrier.fmcsaVerified ? 'FMCSA-verified' : 'admin override — not FMCSA verified';
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'carrier_assigned',
    detail: 'Assigned to ' + carrier.name + (carrier.mcNumber ? ' (MC ' + carrier.mcNumber + ')' : '') + ' — ' + tag, actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id)) });
});

// Record the driver + truck + trailer on a load. Customer org or super (carrier self-service comes later).
router.post('/:id/assign-driver', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const driverName = (req.body && req.body.driverName || '').trim();
  const truck = (req.body && req.body.truck || '').trim();
  const trailer = (req.body && req.body.trailer || '').trim();
  if (!driverName) return res.status(400).json({ error: "Enter the driver's name" });
  db.prepare(`UPDATE loads SET driverName = ?, truck = ?, trailer = ? WHERE id = ?`).run(driverName, truck || null, trailer || null, load.id);
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'driver_assigned',
    detail: 'Driver ' + driverName + (truck ? ' · Truck ' + truck : '') + (trailer ? ' · Trailer ' + trailer : ''), actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id)) });
});

// The recorded history of a load / PO#.
router.get('/:id/history', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const events = db.prepare(`SELECT type, detail, actor, createdAt FROM load_events WHERE loadId = ? ORDER BY createdAt ASC`).all(load.id);
  res.json({ load: loadOut(load), events });
});

module.exports = router;
