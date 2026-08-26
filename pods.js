// POD documents: dispatcher upload + signature setup, driver lookup/ingest, portal search.
// Every operation is scoped to ONE customer (org). Drivers are scoped by the customer's device key.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { db, DATA_DIR } = require('./db');
const { requireAuth, requireApiKey, hasValidApiKey, resolveKey, driverUnlockValue } = require('./auth');
const { emailPodCopy } = require('./mailer');
const { logEvent } = require('./events');

const router = express.Router();
const raw = express.raw({ type: ['application/pdf', 'application/octet-stream'], limit: '30mb' });

function uriDec(v) { if (v == null) return v; try { return decodeURIComponent(v); } catch { return v; } }
function decoder(h) { return h['x-enc'] === 'uri' || h['x-pod-enc'] === 'uri' ? uriDec : (v) => v; }
function safeJson(s) { try { return JSON.parse(s); } catch { return null; } }

// Accept either a logged-in session OR a device key (shared org key or a driver's personal token).
function requireAuthOrKey(req, res, next) {
  const r = resolveKey(req);
  if (r) { req.org = r.org; req.driver = r.driver; req.viaKey = true; return next(); }
  return requireAuth(req, res, next);
}
// If this request came in on a PIN-protected driver token, it must carry the matching unlock value.
function enforceDriverPin(req, res, next) {
  if (req.viaKey && req.driver && req.driver.pinHash) {
    const supplied = (req.headers['x-driver-unlock'] || '').trim();
    if (!supplied || supplied !== driverUnlockValue(req.driver)) {
      return res.status(401).json({ error: 'Enter your driver PIN to continue', pin: true });
    }
  }
  next();
}
// The customer this request acts within.
function reqOrgId(req) { return req.viaKey ? req.org.id : (req.user ? req.user.orgId || null : null); }
function isSuperReq(req) { return !req.viaKey && req.user && req.user.role === 'superadmin'; }
// Is this a carrier's device key/driver token? (carrier drivers sign documents that belong to a customer)
function isCarrierKey(req) { return req.viaKey && req.org && req.org.kind === 'carrier'; }
// The carrier org this request belongs to, whether via device key or a logged-in carrier session.
function carrierOrgId(req) {
  if (isCarrierKey(req)) return req.org.id;
  if (!req.viaKey && req.user && req.user.orgKind === 'carrier') return req.user.orgId || null;
  return null;
}
// Can this request touch this document?
function canAccess(req, doc) {
  if (!doc) return false;
  if (isSuperReq(req)) return true;
  const cOrg = carrierOrgId(req);
  if (cOrg) {
    if ((doc.orgId || null) === cOrg) return true;               // the carrier's own document
    if (!doc.loadId) return false;
    const l = db.prepare(`SELECT carrierId FROM loads WHERE id = ?`).get(doc.loadId);
    return !!l && l.carrierId === cOrg;                          // signed on a load assigned to the carrier
  }
  const my = reqOrgId(req);
  if ((doc.orgId || null) === my) return true;                  // the customer's own document
  if (doc.offeredToOrgId === my && doc.claimStatus === 'offered') return true; // offered to this customer (preview before accepting)
  return false;
}

function findOrCreateLoad({ orgId, loadNumber, poNumber, consignee, createdBy }) {
  let row = null;
  if (poNumber) row = db.prepare(`SELECT * FROM loads WHERE orgId IS ? AND poNumber = ?`).get(orgId || null, poNumber);
  if (!row && loadNumber) row = db.prepare(`SELECT * FROM loads WHERE orgId IS ? AND loadNumber = ?`).get(orgId || null, loadNumber);
  if (row) return row;
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, consignee, status, createdBy, createdAt)
     VALUES (?,?,?,?,?, 'open', ?, ?)`).run(id, orgId || null, loadNumber || null, poNumber || null, consignee || null, createdBy || 'dispatch', Date.now());
  return db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id);
}

function rowOut(r) {
  return { ...r, gps: r.gps ? safeJson(r.gps) : null, recipients: r.recipients ? safeJson(r.recipients) : [], fields: r.fields ? (safeJson(r.fields) || []) : [], fileUrl: `/api/pods/${r.id}/file` };
}

// ---- UPLOAD (dispatcher files a document). Session auth; scoped to caller's customer. ----
router.post('/upload', requireAuth, raw, (req, res) => {
  try {
    const dec = decoder(req.headers), h = req.headers;
    // Super-admin files on behalf of a customer/carrier via X-Org; everyone else files under their own org.
    let orgId = req.user.orgId || null;
    if (req.user.role === 'superadmin') orgId = (dec(h['x-org']) || '').trim() || null;
    if (!orgId) return res.status(400).json({ error: 'Choose a customer to file this document under' });
    const poNumber = (dec(h['x-po']) || '').trim();
    const loadNumber = (dec(h['x-load']) || '').trim();
    const consignee = (dec(h['x-consignee']) || '').trim();
    const docType = (dec(h['x-doctype']) || 'POD').trim();
    const filename = (dec(h['x-filename']) || 'document.pdf').trim();
    if (!poNumber) return res.status(422).json({ error: 'Customer PO # is required for every document' });
    if (!req.body || !req.body.length) return res.status(400).json({ error: 'Empty file' });
    if (req.body.slice(0, 5).toString('latin1') !== '%PDF-') return res.status(415).json({ error: 'That file is not a PDF' });
    const id = crypto.randomUUID();
    const filepath = path.join(DATA_DIR, 'pods', id + '.pdf');
    fs.writeFileSync(filepath, req.body);
    const load = findOrCreateLoad({ orgId, loadNumber, poNumber, consignee, createdBy: req.user.email });
    db.prepare(`INSERT INTO pods (id, orgId, loadId, loadNumber, poNumber, consignee, docType, filename, filepath, sizeBytes, fields, recipients, signedAt, status, uploadedAt)
       VALUES (@id,@orgId,@loadId,@loadNumber,@poNumber,@consignee,@docType,@filename,@filepath,@sizeBytes,'[]','[]',@signedAt,'received',@uploadedAt)`)
      .run({ id, orgId, loadId: load.id, loadNumber: loadNumber || null, poNumber, consignee: consignee || null, docType, filename, filepath, sizeBytes: req.body.length, signedAt: Date.now(), uploadedAt: Date.now() });
    logEvent({ orgId, loadId: load.id, poNumber, type: 'document_uploaded', detail: (docType || 'POD') + ' uploaded: ' + (filename || 'document.pdf'), actor: req.user.email });
    res.json({ ok: true, id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Upload failed' }); }
});

// ---- LOOKUP a prepared doc by PO# or Load# (driver pull). Device key OR session; scoped to that customer. ----
router.get('/lookup', requireAuthOrKey, enforceDriverPin, (req, res) => {
  const po = (req.query.po || '').trim(), load = (req.query.load || '').trim();
  if (!po && !load) return res.status(400).json({ error: 'Provide a PO # or Load #' });
  let rows;
  if (isCarrierKey(req)) {
    // A carrier's driver pulls documents on loads the customer assigned to that carrier.
    const where = [`loads.carrierId = ?`], args = [req.org.id];
    const or = [];
    if (po) { or.push(`TRIM(pods.poNumber) = ? COLLATE NOCASE`); args.push(po); }
    if (load) { or.push(`TRIM(pods.loadNumber) = ? COLLATE NOCASE`); args.push(load); }
    where.push('(' + or.join(' OR ') + ')');
    rows = db.prepare(`SELECT pods.* FROM pods JOIN loads ON loads.id = pods.loadId
      WHERE ${where.join(' AND ')} ORDER BY (pods.status='prepared') DESC, pods.uploadedAt DESC LIMIT 1`).all(...args);
  } else {
    const orgId = reqOrgId(req);
    const where = [`orgId IS ?`], args = [orgId];
    const or = [];
    if (po) { or.push(`TRIM(poNumber) = ? COLLATE NOCASE`); args.push(po); }
    if (load) { or.push(`TRIM(loadNumber) = ? COLLATE NOCASE`); args.push(load); }
    where.push('(' + or.join(' OR ') + ')');
    rows = db.prepare(`SELECT * FROM pods WHERE ${where.join(' AND ')} ORDER BY (status='prepared') DESC, uploadedAt DESC LIMIT 1`).all(...args);
  }
  if (!rows.length) return res.status(404).json({ error: 'No document found for that PO # / Load #' });
  const r = rowOut(rows[0]);
  res.json({ id: r.id, poNumber: r.poNumber, loadNumber: r.loadNumber, consignee: r.consignee, filename: r.filename, status: r.status, fields: r.fields, fileUrl: r.fileUrl });
});

// ---- INGEST (signed POD back from the driver app). Device key; stored under that customer. ----
router.post('/ingest', requireApiKey, enforceDriverPin, raw, async (req, res) => {
  try {
    let orgId = req.org.id;
    const h = req.headers, dec = decoder(h);
    const meta = {
      loadNumber: dec(h['x-pod-load']) || null,
      poNumber: dec(h['x-pod-po']) || null,
      consignee: dec(h['x-pod-consignee']) || dec(h['x-pod-name']) || null,
      docType: h['x-pod-type'] || 'POD',
      gps: h['x-pod-gps'] || null,
      signedAt: h['x-pod-signedat'] ? Number(h['x-pod-signedat']) : Date.now(),
      driver: dec(h['x-pod-driver']) || null,
      recipients: (dec(h['x-pod-emails']) || '').split(',').map(s => s.trim()).filter(Boolean),
      filename: dec(h['x-pod-name']) || 'Signed POD',
    };
    // If a named driver's personal token was used, attribute the signature to them automatically.
    if (req.driver && req.driver.name) meta.driver = req.driver.name;
    if (!req.body || !req.body.length) return res.status(400).json({ error: 'Empty document body' });
    if (!meta.poNumber) return res.status(422).json({ error: 'PO number required for every document' });
    // A carrier's driver files the signed POD back to the CUSTOMER that owns the assigned load.
    // If the carrier ISN'T assigned that PO, the driver is filing it on their own — keep it under the
    // carrier so they can view it and later offer it to a customer. (No more silent rejection.)
    let load;
    if (req.org.kind === 'carrier') {
      if (meta.poNumber) load = db.prepare(`SELECT * FROM loads WHERE carrierId = ? AND TRIM(poNumber) = ? COLLATE NOCASE`).get(req.org.id, meta.poNumber);
      if (!load && meta.loadNumber) load = db.prepare(`SELECT * FROM loads WHERE carrierId = ? AND TRIM(loadNumber) = ? COLLATE NOCASE`).get(req.org.id, meta.loadNumber);
      orgId = load ? load.orgId : req.org.id; // assigned → customer; otherwise → the carrier itself
    }
    const id = crypto.randomUUID();
    const filepath = path.join(DATA_DIR, 'pods', id + '.pdf');
    fs.writeFileSync(filepath, req.body);
    if (!load) load = findOrCreateLoad({ orgId, ...meta });
    db.prepare(`INSERT INTO pods (id, orgId, loadId, loadNumber, poNumber, consignee, docType, filename, filepath, sizeBytes, fields, gps, signedAt, recipients, driver, status, uploadedAt)
       VALUES (@id,@orgId,@loadId,@loadNumber,@poNumber,@consignee,@docType,@filename,@filepath,@sizeBytes,'[]',@gps,@signedAt,@recipients,@driver,'signed',@uploadedAt)`)
      .run({ id, orgId, loadId: load.id, loadNumber: meta.loadNumber || load.loadNumber, poNumber: meta.poNumber || load.poNumber,
        consignee: meta.consignee, docType: meta.docType, filename: meta.filename, filepath, sizeBytes: req.body.length,
        gps: meta.gps, signedAt: meta.signedAt, recipients: JSON.stringify(meta.recipients), driver: meta.driver, uploadedAt: Date.now() });
    logEvent({ orgId, loadId: load.id, poNumber: meta.poNumber || load.poNumber, type: 'signed',
      detail: 'Signed POD received' + (meta.driver ? ' — driver ' + meta.driver : ''), actor: meta.driver || 'driver' });
    let mail = { sent: false };
    if (meta.recipients.length) {
      mail = await emailPodCopy({ to: meta.recipients, pod: { ...meta, id, filename: meta.filename }, filePath: filepath });
      if (mail.sent) db.prepare(`UPDATE pods SET status='emailed' WHERE id=?`).run(id);
    }
    res.json({ ok: true, podId: id, loadId: load.id, emailed: !!mail.sent, recipients: meta.recipients });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ingest failed' }); }
});

// ---- SEARCH (portal). Session auth; scoped to caller's customer (super-admin may pass ?orgId). ----
router.get('/', requireAuth, (req, res) => {
  // Carrier view: every document tied to this carrier — filed directly under it OR signed on a load assigned to it.
  // A logged-in carrier always gets this union of their own account; super-admin can request any via ?carrierId.
  let carrierId = (req.query.carrierId || '').trim();
  if (!carrierId && req.user.orgKind === 'carrier') carrierId = req.user.orgId || '';
  if (carrierId) {
    if (req.user.role !== 'superadmin' && (req.user.orgId || null) !== carrierId) return res.status(403).json({ error: 'Not allowed' });
    const where = [`(pods.orgId IS ? OR loads.carrierId = ?)`], args = [carrierId, carrierId];
    if (req.query.po) { where.push(`pods.poNumber LIKE ?`); args.push(`%${req.query.po}%`); }
    if (req.query.q) { where.push(`(pods.poNumber LIKE ? OR pods.loadNumber LIKE ? OR pods.consignee LIKE ? OR pods.filename LIKE ?)`); args.push(`%${req.query.q}%`, `%${req.query.q}%`, `%${req.query.q}%`, `%${req.query.q}%`); }
    const rows = db.prepare(`SELECT pods.id, pods.orgId, pods.loadId, pods.loadNumber, pods.poNumber, pods.consignee, pods.docType, pods.filename, pods.sizeBytes, pods.gps, pods.signedAt, pods.recipients, pods.driver, pods.status, pods.claimStatus, pods.offeredToOrgId, pods.uploadedAt
      FROM pods LEFT JOIN loads ON loads.id = pods.loadId
      WHERE ${where.join(' AND ')} ORDER BY pods.uploadedAt DESC LIMIT 200`).all(...args).map(rowOut);
    return res.json({ count: rows.length, results: rows });
  }
  const orgId = req.user.role === 'superadmin' ? ((req.query.orgId || '').trim() || null) : (req.user.orgId || null);
  const { q, po, load, consignee, from, to } = req.query;
  const where = [`orgId IS ?`], args = [orgId];
  if (po) { where.push(`poNumber LIKE ?`); args.push(`%${po}%`); }
  if (load) { where.push(`loadNumber LIKE ?`); args.push(`%${load}%`); }
  if (consignee) { where.push(`consignee LIKE ?`); args.push(`%${consignee}%`); }
  if (from) { where.push(`uploadedAt >= ?`); args.push(Number(from)); }
  if (to) { where.push(`uploadedAt <= ?`); args.push(Number(to)); }
  if (q) { where.push(`(poNumber LIKE ? OR loadNumber LIKE ? OR consignee LIKE ? OR filename LIKE ?)`); args.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
  const sql = `SELECT id, orgId, loadId, loadNumber, poNumber, consignee, docType, filename, sizeBytes, gps, signedAt, recipients, driver, status, uploadedAt
               FROM pods WHERE ${where.join(' AND ')} ORDER BY uploadedAt DESC LIMIT 200`;
  const rows = db.prepare(sql).all(...args).map(rowOut);
  res.json({ count: rows.length, results: rows });
});

// ---- Carrier → customer hand-off ----
// Documents a carrier has offered to THIS customer, waiting to be accepted.
router.get('/offered', requireAuth, (req, res) => {
  const orgId = req.user.role === 'superadmin' ? ((req.query.orgId || '').trim() || null) : (req.user.orgId || null);
  if (!orgId) return res.json({ count: 0, results: [] });
  const rows = db.prepare(`SELECT pods.id, pods.poNumber, pods.loadNumber, pods.consignee, pods.docType, pods.filename, pods.driver, pods.signedAt, pods.uploadedAt, orgs.name AS fromCarrier
    FROM pods LEFT JOIN orgs ON orgs.id = pods.orgId
    WHERE pods.offeredToOrgId = ? AND pods.claimStatus = 'offered' ORDER BY pods.uploadedAt DESC`).all(orgId)
    .map(r => ({ ...r, fileUrl: `/api/pods/${r.id}/file` }));
  res.json({ count: rows.length, results: rows });
});
// A carrier offers one of its own documents to a customer it has worked with.
router.post('/:id/offer', requireAuth, express.json(), (req, res) => {
  const pod = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!pod) return res.status(404).json({ error: 'Document not found' });
  const isSuper = req.user.role === 'superadmin';
  const carrierOrg = isSuper ? pod.orgId : (req.user.orgId || null);
  // The document must be owned by the carrier making the offer.
  if (!isSuper && pod.orgId !== carrierOrg) return res.status(403).json({ error: 'You can only send your own documents' });
  const toOrgId = (req.body && req.body.toOrgId || '').trim();
  if (!toOrgId) return res.status(400).json({ error: 'Choose a customer to send it to' });
  const cust = db.prepare(`SELECT id, kind FROM orgs WHERE id = ? AND active = 1`).get(toOrgId);
  if (!cust || cust.kind === 'carrier') return res.status(400).json({ error: 'That is not a valid customer' });
  // Privacy: a carrier may only offer to a customer it has an existing load relationship with.
  if (!isSuper) {
    const rel = db.prepare(`SELECT 1 FROM loads WHERE carrierId = ? AND orgId IS ? LIMIT 1`).get(carrierOrg, toOrgId);
    if (!rel) return res.status(403).json({ error: 'You can only send to customers you have hauled a load for' });
  }
  db.prepare(`UPDATE pods SET claimStatus = 'offered', offeredToOrgId = ? WHERE id = ?`).run(toOrgId, pod.id);
  logEvent({ orgId: pod.orgId, loadId: pod.loadId, poNumber: pod.poNumber, type: 'offered', detail: 'Document offered to customer', actor: req.user.email });
  res.json({ ok: true });
});
// A customer accepts an offered document — a copy is filed under the customer, linked to the PO.
router.post('/:id/accept', requireAuth, (req, res) => {
  const pod = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!pod || pod.claimStatus !== 'offered') return res.status(404).json({ error: 'That document is no longer waiting' });
  const custOrg = req.user.role === 'superadmin' ? pod.offeredToOrgId : (req.user.orgId || null);
  if (pod.offeredToOrgId !== custOrg) return res.status(403).json({ error: 'This document was not offered to you' });
  // Copy the PDF into a fresh document owned by the customer, linked to a load by PO.
  const newId = crypto.randomUUID();
  const newPath = path.join(DATA_DIR, 'pods', newId + '.pdf');
  try { fs.copyFileSync(pod.filepath, newPath); } catch (e) { return res.status(500).json({ error: 'Could not file the document' }); }
  const load = findOrCreateLoad({ orgId: custOrg, loadNumber: pod.loadNumber, poNumber: pod.poNumber, consignee: pod.consignee, createdBy: req.user.email });
  db.prepare(`INSERT INTO pods (id, orgId, loadId, loadNumber, poNumber, consignee, docType, filename, filepath, sizeBytes, fields, gps, signedAt, recipients, driver, offeredFromOrgId, status, uploadedAt)
     VALUES (@id,@orgId,@loadId,@loadNumber,@poNumber,@consignee,@docType,@filename,@filepath,@sizeBytes,'[]',@gps,@signedAt,@recipients,@driver,@from,'signed',@uploadedAt)`)
    .run({ id: newId, orgId: custOrg, loadId: load.id, loadNumber: pod.loadNumber, poNumber: pod.poNumber, consignee: pod.consignee,
      docType: pod.docType, filename: pod.filename, filepath: newPath, sizeBytes: pod.sizeBytes, gps: pod.gps, signedAt: pod.signedAt,
      recipients: pod.recipients || '[]', driver: pod.driver, from: pod.orgId, uploadedAt: Date.now() });
  db.prepare(`UPDATE pods SET claimStatus = 'accepted' WHERE id = ?`).run(pod.id);
  logEvent({ orgId: custOrg, loadId: load.id, poNumber: pod.poNumber, type: 'accepted', detail: 'Accepted a document offered by a carrier', actor: req.user.email });
  res.json({ ok: true, podId: newId });
});
// A customer declines an offered document (it stays with the carrier).
router.post('/:id/decline', requireAuth, (req, res) => {
  const pod = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!pod || pod.claimStatus !== 'offered') return res.status(404).json({ error: 'That document is no longer waiting' });
  const custOrg = req.user.role === 'superadmin' ? pod.offeredToOrgId : (req.user.orgId || null);
  if (pod.offeredToOrgId !== custOrg) return res.status(403).json({ error: 'This document was not offered to you' });
  db.prepare(`UPDATE pods SET claimStatus = 'declined' WHERE id = ?`).run(pod.id);
  res.json({ ok: true });
});

// ---- GET one doc + its signature template. Session; same customer only. ----
router.get('/:id', requireAuth, (req, res) => {
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!canAccess(req, row)) return res.status(404).json({ error: 'Not found' });
  res.json(rowOut(row));
});

// ---- SAVE the signature-field template a dispatcher placed. Session; same customer only. ----
router.put('/:id/fields', requireAuth, express.json({ limit: '1mb' }), (req, res) => {
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!canAccess(req, row)) return res.status(404).json({ error: 'Not found' });
  const fields = Array.isArray(req.body && req.body.fields) ? req.body.fields : [];
  const status = fields.length ? 'prepared' : row.status;
  db.prepare(`UPDATE pods SET fields = ?, status = ? WHERE id = ?`).run(JSON.stringify(fields), status, row.id);
  res.json({ ok: true, count: fields.length, status });
});

// ---- DOWNLOAD the PDF. Session OR device key; same customer only. ----
router.get('/:id/file', requireAuthOrKey, enforceDriverPin, (req, res) => {
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!canAccess(req, row) || !row || !fs.existsSync(row.filepath)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${(row.filename || 'POD').replace(/[^\w.\- ]+/g, '_')}.pdf"`);
  fs.createReadStream(row.filepath).pipe(res);
});

module.exports = router;
