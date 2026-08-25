// POD documents: dispatcher upload + signature setup, driver lookup/ingest, portal search.
// Every operation is scoped to ONE customer (org). Drivers are scoped by the customer's device key.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { db, DATA_DIR } = require('./db');
const { requireAuth, requireApiKey, hasValidApiKey, orgForApiKey } = require('./auth');
const { emailPodCopy } = require('./mailer');

const router = express.Router();
const raw = express.raw({ type: ['application/pdf', 'application/octet-stream'], limit: '30mb' });

function uriDec(v) { if (v == null) return v; try { return decodeURIComponent(v); } catch { return v; } }
function decoder(h) { return h['x-enc'] === 'uri' || h['x-pod-enc'] === 'uri' ? uriDec : (v) => v; }
function safeJson(s) { try { return JSON.parse(s); } catch { return null; } }

// Accept either a logged-in session OR a customer device key. Sets req.org when via key.
function requireAuthOrKey(req, res, next) {
  const org = orgForApiKey(req);
  if (org) { req.org = org; req.viaKey = true; return next(); }
  return requireAuth(req, res, next);
}
// The customer this request acts within.
function reqOrgId(req) { return req.viaKey ? req.org.id : (req.user ? req.user.orgId || null : null); }
function isSuperReq(req) { return !req.viaKey && req.user && req.user.role === 'superadmin'; }
// Can this request touch this document?
function canAccess(req, doc) {
  if (!doc) return false;
  if (isSuperReq(req)) return true;
  return (doc.orgId || null) === reqOrgId(req);
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
    const orgId = req.user.orgId || null;
    if (!orgId && req.user.role !== 'superadmin') return res.status(400).json({ error: 'Your login is not attached to a customer' });
    const dec = decoder(req.headers), h = req.headers;
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
    res.json({ ok: true, id });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Upload failed' }); }
});

// ---- LOOKUP a prepared doc by PO# or Load# (driver pull). Device key OR session; scoped to that customer. ----
router.get('/lookup', requireAuthOrKey, (req, res) => {
  const orgId = reqOrgId(req);
  const po = (req.query.po || '').trim(), load = (req.query.load || '').trim();
  if (!po && !load) return res.status(400).json({ error: 'Provide a PO # or Load #' });
  const where = [`orgId IS ?`], args = [orgId];
  const or = [];
  if (po) { or.push(`TRIM(poNumber) = ? COLLATE NOCASE`); args.push(po); }
  if (load) { or.push(`TRIM(loadNumber) = ? COLLATE NOCASE`); args.push(load); }
  where.push('(' + or.join(' OR ') + ')');
  const rows = db.prepare(`SELECT * FROM pods WHERE ${where.join(' AND ')} ORDER BY (status='prepared') DESC, uploadedAt DESC LIMIT 1`).all(...args);
  if (!rows.length) return res.status(404).json({ error: 'No document found for that PO # / Load #' });
  const r = rowOut(rows[0]);
  res.json({ id: r.id, poNumber: r.poNumber, loadNumber: r.loadNumber, consignee: r.consignee, filename: r.filename, status: r.status, fields: r.fields, fileUrl: r.fileUrl });
});

// ---- INGEST (signed POD back from the driver app). Device key; stored under that customer. ----
router.post('/ingest', requireApiKey, raw, async (req, res) => {
  try {
    const orgId = req.org.id;
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
    if (!req.body || !req.body.length) return res.status(400).json({ error: 'Empty document body' });
    if (!meta.poNumber) return res.status(422).json({ error: 'PO number required for every document' });
    const id = crypto.randomUUID();
    const filepath = path.join(DATA_DIR, 'pods', id + '.pdf');
    fs.writeFileSync(filepath, req.body);
    const load = findOrCreateLoad({ orgId, ...meta });
    db.prepare(`INSERT INTO pods (id, orgId, loadId, loadNumber, poNumber, consignee, docType, filename, filepath, sizeBytes, fields, gps, signedAt, recipients, driver, status, uploadedAt)
       VALUES (@id,@orgId,@loadId,@loadNumber,@poNumber,@consignee,@docType,@filename,@filepath,@sizeBytes,'[]',@gps,@signedAt,@recipients,@driver,'signed',@uploadedAt)`)
      .run({ id, orgId, loadId: load.id, loadNumber: meta.loadNumber || load.loadNumber, poNumber: meta.poNumber || load.poNumber,
        consignee: meta.consignee, docType: meta.docType, filename: meta.filename, filepath, sizeBytes: req.body.length,
        gps: meta.gps, signedAt: meta.signedAt, recipients: JSON.stringify(meta.recipients), driver: meta.driver, uploadedAt: Date.now() });
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
router.get('/:id/file', requireAuthOrKey, (req, res) => {
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!canAccess(req, row) || !row || !fs.existsSync(row.filepath)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${(row.filename || 'POD').replace(/[^\w.\- ]+/g, '_')}.pdf"`);
  fs.createReadStream(row.filepath).pipe(res);
});

module.exports = router;
