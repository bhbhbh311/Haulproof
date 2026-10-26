// Loads: create, search, assign a carrier, assign a driver/truck/trailer, and read history. Org-scoped.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { db, DATA_DIR } = require('./db');
const { requireAuth, requireCap } = require('./auth');
const { logEvent } = require('./events');
const { brokerApproved } = require('./brokers');
const { customerIdsForRep } = require('./customers');
const { stashDoc, stashLoad } = require('./trash');
const notify = require('./notify');

const router = express.Router();
function myOrg(req) { return req.user.role === 'superadmin' ? ((req.query.orgId || (req.body && req.body.orgId) || '').trim() || null) : (req.user.orgId || null); }
function actorOf(req) { return req.user.email || req.user.name || 'admin'; }
// Stable per-user id for personal preferences (archived loads). JWT carries the user id as `sub`.
function userId(req) { return req.user.sub || req.user.id || req.user.email || ''; }
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
// Should this viewer have the carrier hidden? A CUSTOMER who handed a load to a broker does not see which carrier
// the broker then assigned — that's the broker's business; the customer only ever sees the party they themselves
// assigned (the broker). The broker, the carrier, and master admin all see everything.
function hideCarrierFrom(req, l) {
  if (!l || !l.brokerId) return false;
  if (!req || !req.user || req.user.role === 'superadmin') return false;
  const my = req.user.orgId || null;
  const isBroker = (l.brokerId || null) === my, isCarrier = (l.carrierId || null) === my, isOwner = (l.orgId || null) === my;
  return isOwner && !isBroker && !isCarrier;
}
// Serialize a load for a given viewer (drops the carrier for a customer who handed the load to a broker).
function loadOut(l, req) {
  if (!l) return l;
  if ((l.carrierId || l.carrierName) && hideCarrierFrom(req, l)) {
    return Object.assign({}, l, { carrierId: null, carrierName: null });
  }
  return l;
}

// Create/name a load (PO# is the primary identifier, unique per customer).
router.post('/', requireAuth, (req, res) => {
  const orgId = myOrg(req);
  const { loadNumber, poNumber, customer, consignee, origin, destination } = req.body || {};
  if (!poNumber && !loadNumber) return res.status(400).json({ error: 'Provide a PO number or a load number' });
  if (poNumber) {
    const existing = db.prepare(`SELECT * FROM loads WHERE orgId IS ? AND poNumber = ?`).get(orgId, poNumber);
    if (existing) return res.json({ load: loadOut(existing, req), existed: true });
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
  res.json({ load: loadOut(load, req), existed: false });
});

// Copy a load: create a NEW load that carries the customer, carrier, broker, driver and equipment from an
// existing one ("same carrier, same driver as last time"), with a fresh PO and NO documents. Owner / super only.
router.post('/:id/duplicate', requireAuth, (req, res) => {
  const src = ownedLoad(req, req.params.id);
  if (!src) return res.status(404).json({ error: 'Load not found' });
  const poNumber = (req.body && req.body.poNumber || '').trim();
  const loadNumber = (req.body && req.body.loadNumber || '').trim();
  if (!poNumber) return res.status(400).json({ error: 'A new PO # is required for the copy.' });
  const orgId = src.orgId || null;
  const clash = db.prepare(`SELECT 1 FROM loads WHERE orgId IS ? AND poNumber = ?`).get(orgId, poNumber);
  if (clash) return res.status(409).json({ error: 'A load with PO ' + poNumber + ' already exists — pick a different PO.' });
  const id = crypto.randomUUID();
  const assigned = !!(src.carrierId || src.brokerId);
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, customer, customerId, consignee, origin, destination, carrierId, carrierName, brokerId, brokerName, driverName, truck, trailer, status, createdBy, createdAt)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, orgId, loadNumber || null, poNumber, src.customer || null, src.customerId || null, null, src.origin || null, src.destination || null,
         src.carrierId || null, src.carrierName || null, src.brokerId || null, src.brokerName || null, src.driverName || null, src.truck || null, src.trailer || null,
         assigned ? 'assigned' : 'open', req.user.email, Date.now());
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id);
  logEvent({ orgId, loadId: id, poNumber, type: 'created',
    detail: 'Copied from PO ' + (src.poNumber || src.loadNumber || 'a previous load') + (src.carrierName ? ' · carrier ' + src.carrierName : '') + (src.driverName ? ' · driver ' + src.driverName : ''),
    actor: actorOf(req) });
  res.json({ load: loadOut(load, req) });
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
  // Per-user archiving: each user can hide loads from their own list. The default list drops archived loads;
  // `?archived=1` shows ONLY the archived ones (the "Show archived" cleanup view). A search still looks across
  // everything (archived rows come back flagged so they can be found) so nothing is ever truly lost.
  const uid = userId(req);
  const archIds = uid ? db.prepare(`SELECT loadId FROM load_archives WHERE userId = ?`).all(uid).map(r => r.loadId) : [];
  const archSet = new Set(archIds);
  const archivedOnly = req.query.archived === '1' || req.query.archived === 'true';
  const searching = !!(q || po || load);
  if (archivedOnly) {
    if (archIds.length) { where.push(`id IN (${archIds.map(() => '?').join(',')})`); args.push(...archIds); }
    else { where.push('1 = 0'); }   // nothing archived yet → empty archived view
  } else if (!searching && archIds.length) {
    where.push(`id NOT IN (${archIds.map(() => '?').join(',')})`); args.push(...archIds);
  }
  // Sort by most-recent ACTIVITY (newest first): the later of the load's creation and its latest document
  // upload. So a fresh driver upload floats its load to the top even when the load record itself is older.
  const rows = db.prepare(`SELECT * FROM loads WHERE ${where.join(' AND ')}
     ORDER BY max(loads.createdAt, COALESCE((SELECT MAX(uploadedAt) FROM pods WHERE pods.loadId = loads.id), 0)) DESC
     LIMIT 200`).all(...args);
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
     FROM pods WHERE loadId = ? AND status != 'parked'`);
  const out = rows.map(l => {
    // Scrub the carrier out of the list row's last-event too, so a "Carrier assigned (X)" event doesn't leak
    // the broker's carrier to the customer.
    let le = lastEv.get(l.id) || null;
    if (le && hideCarrierFrom(req, l)) {
      const cn = (l.carrierName || '').toLowerCase();
      if (le.type === 'carrier_assigned' || (cn && (le.detail || '').toLowerCase().includes(cn))) le = null;
    }
    const o = { ...loadOut(l, req), lastEvent: le };
    const ps = podStat.get(l.id); o.complete = !!(ps && ps.total > 0 && Number(ps.done) === Number(ps.total));
    // Actionable document state (drives a clear status pill instead of a vague "Updated"):
    o.needsSetup = !!(ps && Number(ps.awaiting) > 0);   // a driver uploaded a doc for dispatch to set up
    o.readyToSign = !!(ps && Number(ps.prepared) > 0);  // dispatch released it — waiting on the driver's signature
    // Per-stop signing progress so the list can show "1 of 2 signed" and a "✓ Completed" state.
    o.stopsTotal = ps ? Number(ps.total || 0) : 0;      // documents/stops filed on this load
    o.stopsDone = ps ? Number(ps.done || 0) : 0;        // how many are signed/emailed
    if (viewerIsCB && (l.orgId || null) !== (req.user.orgId || null)) o.customerName = (orgName.get(l.orgId) || {}).name || null;
    o.archived = archSet.has(l.id);   // this user has hidden this load from their own list
    return o;
  });
  res.json({ count: out.length, results: out, viewerKind: req.user.orgKind || null, archivedCount: archIds.length });
});

// One load plus its documents.
router.get('/:id', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  // Self-heal a drifted PO: a document's PO must match its load. The dedupe-rename rule could suffix a document's
  // PO (SCR017BOL -> SCR017BOL-4) while it attached to this load by load #, leaving the driver app showing a
  // different PO than dispatch. Bring any out-of-step documents back in line with the load's PO.
  try { if (load.poNumber) db.prepare(`UPDATE pods SET poNumber = ? WHERE loadId = ? AND poNumber IS NOT ?`).run(load.poNumber, load.id, load.poNumber); } catch (e) {}
  const pods = db.prepare(`SELECT id, orgId, poNumber, loadNumber, docType, filename, consignee, stopNumber, receiverId, receiverName, salesRepUserId, signedAt, uploadedAt, status, dupWarn, assignedDriverId, rejectedPage, rejectReason, parkedReason, parkedAt FROM pods WHERE loadId = ? ORDER BY (stopNumber IS NULL), stopNumber ASC, uploadedAt ASC`).all(load.id)
    .map(p => ({ ...p, fileUrl: `/api/pods/${p.id}/file` }));
  const uid = userId(req);
  const archived = uid ? !!db.prepare(`SELECT 1 FROM load_archives WHERE userId = ? AND loadId = ?`).get(uid, load.id) : false;
  res.json({ load: { ...loadOut(load, req), archived }, pods });
});

// Serve one of a load's pickup proof-photos (dispatcher/portal view). Auth'd like the load itself.
router.get('/:loadId/pickup-photo/:photoId', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.loadId);
  if (!load) return res.status(404).end();
  const pid = req.params.photoId;
  if (!/^[a-f0-9-]{36}$/i.test(pid)) return res.status(404).end();
  let photos = []; try { photos = load.pickedUpPhotos ? JSON.parse(load.pickedUpPhotos) : []; } catch (e) {}
  if (!photos.some(p => p && p.id === pid)) return res.status(404).end();
  const fp = path.join(DATA_DIR, 'pickup-photos', pid + '.jpg');
  if (!fs.existsSync(fp)) return res.status(404).end();
  res.setHeader('Content-Type', 'image/jpeg');
  res.setHeader('Cache-Control', 'private, max-age=86400');
  fs.createReadStream(fp).pipe(res);
});

// Serve one of a load's delivery proof-photos (dispatcher/portal view). Auth'd like the load itself.
router.get('/:loadId/delivery-photo/:photoId', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.loadId);
  if (!load) return res.status(404).end();
  const pid = req.params.photoId;
  if (!/^[a-f0-9-]{36}$/i.test(pid)) return res.status(404).end();
  let photos = []; try { photos = load.deliveredPhotos ? JSON.parse(load.deliveredPhotos) : []; } catch (e) {}
  if (!photos.some(p => p && p.id === pid)) return res.status(404).end();
  const fp = path.join(DATA_DIR, 'delivery-photos', pid + '.jpg');
  if (!fs.existsSync(fp)) return res.status(404).end();
  res.setHeader('Content-Type', 'image/jpeg');
  res.setHeader('Cache-Control', 'private, max-age=86400');
  fs.createReadStream(fp).pipe(res);
});

// Dispatch correction: reset a recorded pickup (e.g. a driver tapped "Pickup complete" by mistake). Clears the
// time / GPS / photos (and deletes the photo files) and logs it. Anyone who can manage the load may do it.
router.post('/:id/clear-pickup', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  try {
    const photos = load.pickedUpPhotos ? JSON.parse(load.pickedUpPhotos) : [];
    (photos || []).forEach(p => { if (p && /^[a-f0-9-]{36}$/i.test(p.id)) { try { fs.unlinkSync(path.join(DATA_DIR, 'pickup-photos', p.id + '.jpg')); } catch (e) {} } });
  } catch (e) {}
  // Clear time/GPS/photos. Fall back to just time/GPS if the pickedUpPhotos column isn't present yet (e.g. db.js
  // not deployed in the same push), so a reset never fails for a schema-version mismatch.
  try { db.prepare(`UPDATE loads SET pickedUpAt = NULL, pickedUpGps = NULL, pickedUpPhotos = NULL WHERE id = ?`).run(load.id); }
  catch (e) { try { db.prepare(`UPDATE loads SET pickedUpAt = NULL, pickedUpGps = NULL WHERE id = ?`).run(load.id); } catch (e2) {} }
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'pickup_cleared', detail: 'Pickup reset by dispatch', actor: actorOf(req) });
  const updated = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id);
  res.json({ ok: true, load: loadOut(updated, req) });
});

// Archive / un-archive a load for the CURRENT user only (a personal view filter — never a delete).
// Body { archived: true } hides it from this user's Loads list; { archived: false } brings it back.
router.put('/:id/archive', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);   // must be a load this user can actually see
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const uid = userId(req);
  if (!uid) return res.status(400).json({ error: 'No user' });
  const on = req.body && (req.body.archived === true || req.body.archived === 'true' || req.body.archived === 1);
  if (on) {
    db.prepare(`INSERT OR IGNORE INTO load_archives (userId, loadId, createdAt) VALUES (?,?,?)`).run(uid, load.id, Date.now());
  } else {
    db.prepare(`DELETE FROM load_archives WHERE userId = ? AND loadId = ?`).run(uid, load.id);
  }
  res.json({ ok: true, archived: !!on });
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
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  // A broker/carrier can OPEN a brokered/assigned load, but the customer's fields (PO, load #, customer) are
  // not theirs to edit — return the load unchanged so their auto-save doesn't fail with "Load not found".
  if (!(req.user.role === 'superadmin' || (load.orgId || null) === (req.user.orgId || null))) {
    return res.json({ load: loadOut(load, req) });
  }
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
  // Did anything actually change? Auto-save re-sends the same values on every pause, so only WRITE + LOG when a
  // field really differs — otherwise the history fills with identical "Load details updated" lines.
  const changed = (loadNumber !== load.loadNumber) || (consignee !== load.consignee) || (poNumber !== load.poNumber)
    || (orgIdNew !== load.orgId) || ((customerId || null) !== (load.customerId || null)) || ((customerText || null) !== (load.customer || null));
  if (changed) {
    db.prepare(`UPDATE loads SET loadNumber = ?, consignee = ?, poNumber = ?, orgId = ?, customer = ?, customerId = ? WHERE id = ?`).run(loadNumber, consignee, poNumber, orgIdNew, customerText, customerId, load.id);
    if (poNumber !== load.poNumber || orgIdNew !== load.orgId) db.prepare(`UPDATE pods SET poNumber = ?, orgId = ? WHERE loadId = ?`).run(poNumber, orgIdNew, load.id);
    logEvent({ orgId: orgIdNew, loadId: load.id, poNumber, type: 'updated', detail: 'Load details updated' + (orgIdNew !== load.orgId ? ' (customer reassigned)' : ''), actor: actorOf(req) });
  }
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id), req) });
});

// Delete a load and all its documents. Owner (or super) only. Irreversible — the app confirms twice first.
router.delete('/:id', requireAuth, requireCap('delete_loadsdocs'), (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) {
    // Distinguish "doesn't exist" from "exists but a DIFFERENT company owns it". A carrier/broker can see a
    // load assigned to them (so it shows in their list and opens), but only the OWNING org (or a master admin)
    // may delete it. Returning a plain "Load not found" here made that look like a bug — say who owns it instead.
    const any = db.prepare(`SELECT l.id, l.orgId, o.name AS ownerName FROM loads l LEFT JOIN orgs o ON o.id = l.orgId WHERE l.id = ?`).get(req.params.id);
    if (any) {
      const who = any.ownerName ? ('“' + any.ownerName + '”') : 'another company';
      return res.status(403).json({ error: 'This load belongs to ' + who + ' — your company is only the assigned carrier, so it can’t be deleted from your account. It has to be removed by ' + who + ' (or a master admin).' });
    }
    return res.status(404).json({ error: 'Load not found' });
  }
  try {
    const pods = db.prepare(`SELECT * FROM pods WHERE loadId = ?`).all(load.id);
    // Leave a notice for any driver who was waiting on a doc on this load (uploaded or assigned, not yet done).
    pods.forEach(p => {
      try {
        const drvId = p.signedByDriverId || p.assignedDriverId || null;
        if (drvId && (p.status === 'awaiting_build' || p.status === 'prepared')) {
          db.prepare(`INSERT INTO driver_notices (id, driverId, orgId, kind, poNumber, loadNumber, message, actorName, actorEmail, seen, createdAt)
            VALUES (?,?,?,?,?,?,?,?,?,0,?)`).run(
            crypto.randomUUID(), drvId, p.orgId || null, 'removed', p.poNumber || null, p.loadNumber || null,
            'The load' + (p.poNumber ? ' for PO ' + p.poNumber : '') + ' was deleted by dispatch.',
            (req.user && req.user.name) || null, (req.user && req.user.email) || null, Date.now());
        }
      } catch (e) {}
    });
    // Recoverable delete: snapshot the load and each of its documents into the recovery bin, then remove the
    // live rows but KEEP the PDF files on disk so an admin can restore the whole load exactly. Subscribers are
    // left in place so a restore brings back who was watching the load; they're cleaned up on permanent purge.
    try { stashLoad(load, pods.length, actorOf(req)); pods.forEach(p => { try { stashDoc(p, 'load', actorOf(req)); } catch (e) {} }); }
    catch (e) { console.error('stash on load delete', e.message); }
    db.prepare(`DELETE FROM pods WHERE loadId = ?`).run(load.id);
    db.prepare(`DELETE FROM loads WHERE id = ?`).run(load.id);
    logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'deleted', detail: 'Load and its ' + pods.length + ' document(s) deleted (recoverable)', actor: actorOf(req) });
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
  // A load is handled by a broker OR a direct carrier, not both — handing it to a broker clears any direct carrier.
  db.prepare(`UPDATE loads SET brokerId = ?, brokerName = ?, carrierId = NULL, carrierName = NULL, status = 'assigned' WHERE id = ?`).run(broker.id, broker.name, load.id);
  const tag = broker.fmcsaVerified ? 'FMCSA-verified' : 'admin override — not FMCSA verified';
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'broker_assigned',
    detail: 'Handed to broker ' + broker.name + (broker.mcNumber ? ' (MC ' + broker.mcNumber + ')' : '') + ' — ' + tag, actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id), req) });
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
  // A load has a direct carrier OR a broker, not both. When the OWNER assigns a carrier directly, clear any broker.
  // When the ASSIGNED BROKER assigns a carrier, that carrier sits UNDER the broker, so the broker stays.
  if (isAssignedBroker) db.prepare(`UPDATE loads SET carrierId = ?, carrierName = ?, status = 'assigned' WHERE id = ?`).run(carrier.id, carrier.name, load.id);
  else db.prepare(`UPDATE loads SET carrierId = ?, carrierName = ?, brokerId = NULL, brokerName = NULL, status = 'assigned' WHERE id = ?`).run(carrier.id, carrier.name, load.id);
  const tag = carrier.fmcsaVerified ? 'FMCSA-verified' : 'admin override — not FMCSA verified';
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'carrier_assigned',
    detail: (isAssignedBroker ? 'Broker assigned ' : 'Assigned to ') + carrier.name + (carrier.mcNumber ? ' (MC ' + carrier.mcNumber + ')' : '') + ' — ' + tag, actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id), req) });
});

// Unassign the carrier from a load. Only the owner (the customer who created it) or super — a broker the load
// was handed to can ADD a carrier/driver but not tear down what the customer set up; removing is the owner's call.
router.post('/:id/unassign-carrier', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const newStatus = (!load.brokerId && load.status === 'assigned') ? 'open' : load.status;
  db.prepare(`UPDATE loads SET carrierId = NULL, carrierName = NULL, status = ? WHERE id = ?`).run(newStatus, load.id);
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'carrier_assigned',
    detail: 'Carrier unassigned' + (load.carrierName ? ' (' + load.carrierName + ')' : ''), actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id), req) });
});
// Unassign the broker from a load (owner or super). Also clears any carrier the broker had put on it.
router.post('/:id/unassign-broker', requireAuth, (req, res) => {
  const load = ownedLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const newStatus = load.status === 'assigned' ? 'open' : load.status;
  db.prepare(`UPDATE loads SET brokerId = NULL, brokerName = NULL, carrierId = NULL, carrierName = NULL, status = ? WHERE id = ?`).run(newStatus, load.id);
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'broker_assigned',
    detail: 'Broker unassigned' + (load.brokerName ? ' (' + load.brokerName + ')' : ''), actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id), req) });
});

// Record the driver + truck + trailer on a load. The assigned carrier, the owning customer, or super.
router.post('/:id/assign-driver', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  // If every stop on this load is already signed/emailed, the load is complete — the driver can't be changed.
  // (A partially-complete load can still be reassigned: only its unsigned stops get restamped below.)
  try {
    const st = db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status IN ('signed','emailed') THEN 1 ELSE 0 END) AS done FROM pods WHERE loadId = ? AND status != 'parked'`).get(load.id);
    if (st && Number(st.total) > 0 && Number(st.done) === Number(st.total)) return res.status(409).json({ error: 'Every stop on this load is already signed and completed — the driver can no longer be changed.' });
  } catch (e) {}
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
    // Stamp the driver onto every not-yet-signed doc on the load — including ones still 'awaiting_build'
    // (handed up from a driver, not yet marked ready). Without 'awaiting_build' here, a load assigned before
    // it's marked ready never routes to the driver's phone (their app only shows docs stamped to them).
    try { db.prepare(`UPDATE pods SET assignedDriverId = ?, assignedDriverName = ? WHERE loadId = ? AND status IN ('received','prepared','awaiting_build')`).run(drv.id, drv.name, load.id); } catch (e) {}
    // Any docs already set up ('prepared') just got routed to this driver → email them "ready to sign" (best-effort, once each).
    try { db.prepare(`SELECT id FROM pods WHERE loadId = ? AND status = 'prepared' AND assignedDriverId = ?`).all(load.id, drv.id).forEach(p => notify.notifyDriverReady(p.id)); } catch (e) {}
  }
  if (!driverName) return res.status(400).json({ error: "Choose or enter the driver's name" });
  db.prepare(`UPDATE loads SET driverName = ?, truck = ?, trailer = ? WHERE id = ?`).run(driverName, truck || null, trailer || null, load.id);
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'driver_assigned',
    detail: 'Driver ' + driverName + (truck ? ' · Truck ' + truck : '') + (trailer ? ' · Trailer ' + trailer : ''), actor: actorOf(req) });
  res.json({ load: loadOut(db.prepare(`SELECT * FROM loads WHERE id = ?`).get(load.id), req) });
});

// The recorded history of a load / PO#.
router.get('/:id/history', requireAuth, (req, res) => {
  const load = accessibleLoad(req, req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  let events = db.prepare(`SELECT type, detail, actor, createdAt FROM load_events WHERE loadId = ? ORDER BY createdAt ASC`).all(load.id);
  // Customer who handed off to a broker shouldn't see the carrier the broker picked — drop carrier-assignment
  // events (and anything naming the carrier) from their history view.
  if (hideCarrierFrom(req, load)) {
    const cn = (load.carrierName || '').toLowerCase();
    events = events.filter(e => e.type !== 'carrier_assigned' && !(cn && (e.detail || '').toLowerCase().includes(cn)));
  }
  res.json({ load: loadOut(load, req), events });
});

module.exports = router;
