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
const { descendantOrgIds } = require('./hierarchy');
const { customerDocEmails } = require('./customers');

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
// (req.driver is only ever set when authenticated via a device key, so no viaKey guard is needed —
// and requiring one wrongly skipped enforcement on the ingest route, which sets req.driver but not viaKey.)
function enforceDriverPin(req, res, next) {
  if (req.driver && req.driver.pinHash) {
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
  // A receiver (or its parent company) may view a document that was delivered to it.
  if (doc.receiverId && my && descendantOrgIds(my).includes(doc.receiverId)) return true;
  return false;
}

function findOrCreateLoad({ orgId, loadNumber, poNumber, consignee, createdBy }) {
  let row = null;
  if (poNumber) row = db.prepare(`SELECT * FROM loads WHERE orgId IS ? AND poNumber = ?`).get(orgId || null, poNumber);
  if (!row && loadNumber) row = db.prepare(`SELECT * FROM loads WHERE orgId IS ? AND loadNumber = ?`).get(orgId || null, loadNumber);
  if (row) return row;
  const id = crypto.randomUUID();
  // If the owning org is itself a carrier, it IS the assigned carrier for its own loads (changeable later).
  let carrierId = null, carrierName = null;
  if (orgId) { const o = db.prepare(`SELECT name, kind FROM orgs WHERE id = ?`).get(orgId); if (o && o.kind === 'carrier') { carrierId = orgId; carrierName = o.name; } }
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, consignee, carrierId, carrierName, status, createdBy, createdAt)
     VALUES (?,?,?,?,?,?,?, 'open', ?, ?)`).run(id, orgId || null, loadNumber || null, poNumber || null, consignee || null, carrierId, carrierName, createdBy || 'dispatch', Date.now());
  return db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id);
}

// Keep document PO #s distinct within an org: if a document with this exact PO already exists,
// append -2, -3, … so a newly filed document never collides with a prior one (in the same customer/
// carrier/broker realm). Keys on existing documents, so the first doc for a pre-created load keeps its PO.
function uniquePoForOrg(orgId, po) {
  po = (po || '').trim();
  if (!po) return po;
  const taken = (cand) => !!db.prepare(`SELECT 1 FROM pods WHERE orgId IS ? AND TRIM(poNumber) = ? COLLATE NOCASE LIMIT 1`).get(orgId || null, cand);
  if (!taken(po)) return po;
  let n = 2, cand;
  do { cand = po + '-' + n; n++; } while (taken(cand) && n < 100000);
  return cand;
}

// A signing location is stored as a plain "lat,lng" string. Turn it into a Google Maps link.
function gpsUrl(s) {
  if (!s) return null;
  const m = String(s).match(/-?\d+(?:\.\d+)?\s*,\s*-?\d+(?:\.\d+)?/);
  return m ? 'https://www.google.com/maps?q=' + encodeURIComponent(m[0].replace(/\s+/g, '')) : null;
}
function rowOut(r) {
  const gpsStr = (r.gps && typeof r.gps === 'string' && r.gps.indexOf(',') > -1) ? r.gps : (r.gps ? (safeJson(r.gps) || null) : null);
  const gpsText = (gpsStr && typeof gpsStr === 'object' && gpsStr.lat != null) ? (gpsStr.lat + ',' + gpsStr.lng) : (typeof gpsStr === 'string' ? gpsStr : null);
  return { ...r, gps: gpsText, mapUrl: gpsUrl(gpsText), recipients: r.recipients ? safeJson(r.recipients) : [], fields: r.fields ? (safeJson(r.fields) || []) : [], fileUrl: `/api/pods/${r.id}/file` };
}

// ---- UPLOAD (dispatcher files a document). Session auth; scoped to caller's customer. ----
router.post('/upload', requireAuth, raw, (req, res) => {
  try {
    const dec = decoder(req.headers), h = req.headers;
    // Super-admin files on behalf of a customer/carrier via X-Org; everyone else files under their own org.
    let orgId = req.user.orgId || null;
    if (req.user.role === 'superadmin') orgId = (dec(h['x-org']) || '').trim() || null;
    if (!orgId) return res.status(400).json({ error: 'Choose a customer to file this document under' });
    let poNumber = (dec(h['x-po']) || '').trim();
    const loadNumber = (dec(h['x-load']) || '').trim();
    const consignee = (dec(h['x-consignee']) || '').trim();
    const docType = (dec(h['x-doctype']) || 'POD').trim();
    const filename = (dec(h['x-filename']) || 'document.pdf').trim();
    // Optional: tag this document with the receiver/consignee it's being delivered to, so that
    // receiver can later look it up regardless of which customer owns the load.
    const receiverId = (dec(h['x-receiver']) || '').trim() || null;
    let receiverName = null;
    if (receiverId) { const ro = db.prepare(`SELECT name FROM orgs WHERE id = ?`).get(receiverId); receiverName = ro ? ro.name : null; }
    // Optional stop number for multi-stop loads (1st stop, 2nd stop, …). When present, this document is
    // filed as another stop on the SAME PO/Load — so we do NOT auto-suffix the PO in that case.
    const stopRaw = parseInt((dec(h['x-stop']) || '').trim(), 10);
    const stopProvided = Number.isFinite(stopRaw) && stopRaw > 0;
    // Every document belongs to at least Stop 1 — default to it when no stop was entered.
    const stopNumber = stopProvided ? stopRaw : 1;
    // Team login who reps this stop — emailed when the stop completes. Must belong to the filing org.
    let salesRepUserId = (dec(h['x-salesrep']) || '').trim() || null;
    if (salesRepUserId && !db.prepare(`SELECT 1 FROM users WHERE id = ? AND orgId IS ?`).get(salesRepUserId, orgId)) salesRepUserId = null;
    if (!poNumber) return res.status(422).json({ error: 'Customer PO # is required for every document' });
    if (!req.body || !req.body.length) return res.status(400).json({ error: 'Empty file' });
    if (req.body.slice(0, 5).toString('latin1') !== '%PDF-') return res.status(415).json({ error: 'That file is not a PDF' });
    // Standalone doc: never create an exact duplicate PO # within this org — auto-suffix (-2, -3, …).
    // A stop on a multi-stop load intentionally reuses the same PO, so skip the suffix then.
    if (!stopProvided) poNumber = uniquePoForOrg(orgId, poNumber);
    const id = crypto.randomUUID();
    const filepath = path.join(DATA_DIR, 'pods', id + '.pdf');
    fs.writeFileSync(filepath, req.body);
    const load = findOrCreateLoad({ orgId, loadNumber, poNumber, consignee, createdBy: req.user.email });
    db.prepare(`INSERT INTO pods (id, orgId, loadId, loadNumber, poNumber, consignee, receiverId, receiverName, stopNumber, salesRepUserId, docType, filename, filepath, sizeBytes, fields, recipients, signedAt, status, uploadedAt)
       VALUES (@id,@orgId,@loadId,@loadNumber,@poNumber,@consignee,@receiverId,@receiverName,@stopNumber,@salesRepUserId,@docType,@filename,@filepath,@sizeBytes,'[]','[]',@signedAt,'received',@uploadedAt)`)
      .run({ id, orgId, loadId: load.id, loadNumber: loadNumber || null, poNumber, consignee: consignee || null, receiverId, receiverName, stopNumber, salesRepUserId, docType, filename, filepath, sizeBytes: req.body.length, signedAt: Date.now(), uploadedAt: Date.now() });
    logEvent({ orgId, loadId: load.id, poNumber, type: 'document_uploaded', detail: (docType || 'POD') + ' uploaded: ' + (filename || 'document.pdf') + (stopNumber ? ' (Stop ' + stopNumber + ')' : ''), actor: req.user.email });
    res.json({ ok: true, id, poNumber, stopNumber });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Upload failed' }); }
});

// ---- LOOKUP a prepared doc by PO# or Load# (driver pull). Device key OR session; scoped to that customer. ----
router.get('/lookup', requireAuthOrKey, (req, res) => {
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
      WHERE ${where.join(' AND ')} ORDER BY (pods.status='prepared') DESC, (pods.stopNumber IS NULL), pods.stopNumber ASC, pods.uploadedAt ASC`).all(...args);
  } else {
    const orgId = reqOrgId(req);
    const where = [`orgId IS ?`], args = [orgId];
    const or = [];
    if (po) { or.push(`TRIM(poNumber) = ? COLLATE NOCASE`); args.push(po); }
    if (load) { or.push(`TRIM(loadNumber) = ? COLLATE NOCASE`); args.push(load); }
    where.push('(' + or.join(' OR ') + ')');
    rows = db.prepare(`SELECT * FROM pods WHERE ${where.join(' AND ')} ORDER BY (status='prepared') DESC, (stopNumber IS NULL), stopNumber ASC, uploadedAt ASC`).all(...args);
  }
  if (!rows.length) return res.status(404).json({ error: 'No document found for that PO # / Load #' });
  // A driver signs the prepared docs. Return every prepared stop so they can sign each one; if none are
  // prepared, fall back to whatever matched. Each entry carries its own server id for exact stop matching.
  const prepared = rows.filter(r => r.status === 'prepared');
  const list = (prepared.length ? prepared : rows).slice(0, 50);
  const docs = list.map(row => { const o = rowOut(row); return { id: o.id, poNumber: o.poNumber, loadNumber: o.loadNumber, consignee: o.consignee, stopNumber: o.stopNumber || null, receiverName: o.receiverName || null, docType: o.docType, filename: o.filename, status: o.status, fields: o.fields, fileUrl: o.fileUrl }; });
  res.json(Object.assign({}, docs[0], { docs }));
});

// ---- INGEST (signed POD back from the driver app). Device key; stored under that customer. ----
router.post('/ingest', requireApiKey, raw, async (req, res) => {
  try {
    let orgId = req.org.id;
    const h = req.headers, dec = decoder(h);
    const meta = {
      loadNumber: dec(h['x-pod-load']) || null,
      poNumber: dec(h['x-pod-po']) || null,
      consignee: dec(h['x-pod-consignee']) || null,   // don't fall back to the document name — leave blank if none
      customerId: (dec(h['x-pod-customerid']) || '').trim() || null,   // link to the owner org's customer-list entry
      docType: h['x-pod-type'] || 'POD',
      gps: h['x-pod-gps'] || null,
      signedAt: h['x-pod-signedat'] ? Number(h['x-pod-signedat']) : Date.now(),
      driver: dec(h['x-pod-driver']) || null,
      recipients: (dec(h['x-pod-emails']) || '').split(',').map(s => s.trim()).filter(Boolean),
      filename: dec(h['x-pod-name']) || 'Signed POD',
    };
    // If a named driver's personal token was used, attribute the signature to them automatically.
    if (req.driver && req.driver.name) meta.driver = req.driver.name;
    // "Save, sign later": the driver captured/scanned a document but hasn't signed it. Store it as a
    // PREPARED doc on the load (so it shows up to be signed later by the driver, or organized by dispatch)
    // instead of running the signed-POD + email flow.
    const asPrepared = /^(prepared|unsigned|1|true)$/i.test(String(h['x-pod-status'] || h['x-pod-unsigned'] || '').trim());
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
    // Link the load to a customer from its owner org's list, when the driver picked one (and it belongs there).
    if (meta.customerId) {
      try {
        const cust = db.prepare(`SELECT * FROM customers WHERE id = ? AND ownerOrgId IS ?`).get(meta.customerId, load.orgId || null);
        if (cust) { db.prepare(`UPDATE loads SET customerId = ?, customer = ? WHERE id = ?`).run(cust.id, cust.name, load.id); load.customerId = cust.id; load.customer = cust.name; }
      } catch (e) {}
    }
    db.prepare(`INSERT INTO pods (id, orgId, loadId, loadNumber, poNumber, consignee, docType, filename, filepath, sizeBytes, fields, gps, signedAt, recipients, driver, status, uploadedAt)
       VALUES (@id,@orgId,@loadId,@loadNumber,@poNumber,@consignee,@docType,@filename,@filepath,@sizeBytes,'[]',@gps,@signedAt,@recipients,@driver,@status,@uploadedAt)`)
      .run({ id, orgId, loadId: load.id, loadNumber: meta.loadNumber || load.loadNumber, poNumber: meta.poNumber || load.poNumber,
        consignee: meta.consignee, docType: meta.docType, filename: meta.filename, filepath, sizeBytes: req.body.length,
        gps: meta.gps, signedAt: meta.signedAt, recipients: JSON.stringify(meta.recipients), driver: meta.driver,
        status: asPrepared ? 'prepared' : 'signed', uploadedAt: Date.now() });
    // Remember which driver signed this, so their app can list their own recent documents.
    if (req.driver && req.driver.id) { try { db.prepare(`UPDATE pods SET signedByDriverId = ? WHERE id = ?`).run(req.driver.id, id); } catch (e) {} }
    // A document created by a named driver is automatically assigned to that driver.
    if (req.driver && req.driver.id) { try { db.prepare(`UPDATE pods SET assignedDriverId = ?, assignedDriverName = ? WHERE id = ?`).run(req.driver.id, req.driver.name || null, id); } catch (e) {} }
    // Save-for-later: stop here — it's a prepared (unsigned) doc, so no fingerprint, no prepared-copy
    // cleanup, and no delivery email. It now shows on the load ready to be signed.
    if (asPrepared) {
      try { logEvent({ orgId, loadId: load.id, poNumber: meta.poNumber || load.poNumber, type: 'note',
        detail: 'Document saved to sign later' + (meta.driver ? ' — driver ' + meta.driver : '') + (meta.consignee ? ' · ' + meta.consignee : ''), actor: meta.driver || 'driver' }); } catch (e) {}
      return res.json({ ok: true, podId: id, loadId: load.id, prepared: true });
    }
    // Carry receiver / stop / sales-rep from the prepared doc onto this signed one. When the driver app
    // sends the exact prepared-doc id it signed (X-POD-PrepId), match THAT stop precisely; otherwise fall
    // back to the most recent prepared stop on the load.
    try {
      const prepId = (dec(h['x-pod-prepid']) || '').trim() || null;
      let prep = null;
      if (prepId) prep = db.prepare(`SELECT id, receiverId, receiverName, stopNumber, salesRepUserId FROM pods WHERE id = ? AND loadId = ?`).get(prepId, load.id);
      // Fallbacks for an older driver app that doesn't send the exact stop id (X-POD-PrepId): the most
      // recent prepared stop with details, else any most-recent prepared assigned stop. We resolve to ONE
      // stop and only ever fulfill that one — a multi-stop load must keep its OTHER stops available to sign.
      if (!prep) prep = db.prepare(`SELECT id, receiverId, receiverName, stopNumber, salesRepUserId FROM pods WHERE loadId = ? AND status = 'prepared' AND (receiverId IS NOT NULL OR stopNumber IS NOT NULL OR salesRepUserId IS NOT NULL) ORDER BY uploadedAt DESC LIMIT 1`).get(load.id);
      if (!prep) prep = db.prepare(`SELECT id, receiverId, receiverName, stopNumber, salesRepUserId FROM pods WHERE loadId = ? AND status = 'prepared' AND assignedDriverId IS NOT NULL AND assignedFulfilledAt IS NULL ORDER BY uploadedAt DESC LIMIT 1`).get(load.id);
      if (prep) {
        if (prep.receiverId) db.prepare(`UPDATE pods SET receiverId = ?, receiverName = ? WHERE id = ?`).run(prep.receiverId, prep.receiverName, id);
        if (prep.stopNumber) db.prepare(`UPDATE pods SET stopNumber = ? WHERE id = ?`).run(prep.stopNumber, id);
        if (prep.salesRepUserId) db.prepare(`UPDATE pods SET salesRepUserId = ? WHERE id = ?`).run(prep.salesRepUserId, id);
        // Record a SHA-256 fingerprint of the pre-signature original before we remove it — cheap (a few
        // dozen bytes) integrity proof that the signed doc's underlying pages match what was prepared.
        try {
          const pf = db.prepare(`SELECT filepath FROM pods WHERE id = ?`).get(prep.id);
          if (pf && pf.filepath && fs.existsSync(pf.filepath)) {
            const hash = crypto.createHash('sha256').update(fs.readFileSync(pf.filepath)).digest('hex');
            db.prepare(`UPDATE pods SET originalHash = ? WHERE id = ?`).run(hash, id);
            try { logEvent({ orgId, loadId: load.id, poNumber: meta.poNumber || load.poNumber, type: 'note', detail: 'Original document fingerprint (SHA-256): ' + hash, actor: 'system' }); } catch (_) {}
          }
          // The prepared "ready to sign" copy for THIS stop has now been replaced by the signed copy above —
          // remove it so the stop shows only the signed document (no lingering duplicate to sign). Only ever
          // the ONE exact stop that was just signed; a multi-stop load keeps its other stops to sign.
          db.prepare(`DELETE FROM pods WHERE id = ?`).run(prep.id);
          if (pf && pf.filepath) { try { fs.unlinkSync(pf.filepath); } catch (_) {} }
        } catch (e) {}
      }
    } catch (e) {}
    logEvent({ orgId, loadId: load.id, poNumber: meta.poNumber || load.poNumber, type: 'signed',
      detail: 'Signed POD received' + (meta.driver ? ' — driver ' + meta.driver : ''), actor: meta.driver || 'driver' });
    // Also email the completed doc to the receiver's people who asked for the BOL.
    let bolEmails = [];
    try {
      const p = db.prepare(`SELECT receiverId FROM pods WHERE id = ?`).get(id);
      if (p && p.receiverId) bolEmails = db.prepare(`SELECT email FROM receiver_contacts WHERE receiverId = ? AND receiveBol = 1 AND email IS NOT NULL AND TRIM(email) != ''`).all(p.receiverId).map(r => r.email);
    } catch (e) {}
    // Stop-completed updates → this stop's sales rep + this load's subscribers + the account master list (all team logins).
    let notifyEmails = [];
    try {
      const p = db.prepare(`SELECT salesRepUserId FROM pods WHERE id = ?`).get(id);
      if (p && p.salesRepUserId) { const u = db.prepare(`SELECT email FROM users WHERE id = ?`).get(p.salesRepUserId); if (u && u.email) notifyEmails.push(u.email); }
      db.prepare(`SELECT u.email FROM load_subscribers ls JOIN users u ON u.id = ls.userId WHERE ls.loadId = ? AND u.email IS NOT NULL AND TRIM(u.email) != ''`).all(load.id).forEach(r => notifyEmails.push(r.email));
      db.prepare(`SELECT u.email FROM org_notify onf JOIN users u ON u.id = onf.userId WHERE onf.orgId IS ? AND u.email IS NOT NULL AND TRIM(u.email) != ''`).all(orgId).forEach(r => notifyEmails.push(r.email));
    } catch (e) {}
    // The load's assigned customer's contacts who are flagged to receive signed documents.
    let customerEmails = [];
    try { if (load && load.customerId) customerEmails = customerDocEmails(load.customerId); } catch (e) {}
    const allRecipients = Array.from(new Set([...(meta.recipients || []), ...bolEmails, ...notifyEmails, ...customerEmails]));
    let mail = { sent: false };
    if (allRecipients.length) {
      mail = await emailPodCopy({ to: allRecipients, pod: { ...meta, id, filename: meta.filename }, filePath: filepath });
      if (mail.sent) db.prepare(`UPDATE pods SET status='emailed' WHERE id=?`).run(id);
    }
    // Persist the FULL recipient list on the record (not just the consignee email typed at signing) and
    // record an 'emailed' event on the load history — an audit trail of exactly who was notified.
    try {
      db.prepare(`UPDATE pods SET recipients = ? WHERE id = ?`).run(JSON.stringify(allRecipients), id);
      const stopRow = db.prepare(`SELECT stopNumber FROM pods WHERE id = ?`).get(id);
      const stopTag = (stopRow && stopRow.stopNumber) ? ('Stop ' + stopRow.stopNumber + ' — ') : '';
      const sentTo = mail.sentTo || allRecipients;
      const blocked = mail.blocked || [];
      const optNote = blocked.length ? ' (skipped ' + blocked.length + ' opted-out: ' + blocked.join(', ') + ')' : '';
      let detail;
      if (!allRecipients.length) detail = stopTag + 'No recipients configured — nothing emailed';
      else if (mail.sent) detail = stopTag + 'Emailed to ' + sentTo.length + ' recipient' + (sentTo.length > 1 ? 's' : '') + ': ' + sentTo.join(', ') + optNote;
      else if (mail.simulated) detail = stopTag + 'Email simulated (SMTP not configured) — would have gone to: ' + sentTo.join(', ') + optNote;
      else if (blocked.length && !sentTo.length) detail = stopTag + 'Not emailed — all ' + blocked.length + ' recipient(s) opted out: ' + blocked.join(', ');
      else detail = stopTag + 'Email NOT sent' + (mail.error ? ' (' + mail.error + ')' : '') + ' — intended recipients: ' + allRecipients.join(', ');
      logEvent({ orgId, loadId: load.id, poNumber: meta.poNumber || load.poNumber, type: 'emailed', detail, actor: meta.driver || 'driver' });
    } catch (e) {}
    res.json({ ok: true, podId: id, loadId: load.id, emailed: !!mail.sent, recipients: allRecipients });
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
    const rows = db.prepare(`SELECT pods.id, pods.orgId, pods.loadId, pods.loadNumber, pods.poNumber, pods.consignee, pods.stopNumber, pods.receiverName, pods.docType, pods.filename, pods.sizeBytes, pods.gps, pods.signedAt, pods.recipients, pods.driver, pods.status, pods.claimStatus, pods.offeredToOrgId, pods.assignedDriverId, pods.assignedDriverName, pods.uploadedAt
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
  const sql = `SELECT id, orgId, loadId, loadNumber, poNumber, consignee, stopNumber, receiverName, docType, filename, sizeBytes, gps, signedAt, recipients, driver, status, assignedDriverId, assignedDriverName, uploadedAt
               FROM pods WHERE ${where.join(' AND ')} ORDER BY uploadedAt DESC LIMIT 200`;
  const rows = db.prepare(sql).all(...args).map(rowOut);
  res.json({ count: rows.length, results: rows });
});

// ---- Documents delivered TO this receiver (across every customer that shipped to them). ----
// A parent-company login also sees all of its child locations' received documents.
router.get('/received', requireAuth, (req, res) => {
  let orgId = req.user.orgId || null;
  if (req.user.role === 'superadmin') orgId = (req.query.orgId || '').trim() || orgId;
  if (!orgId) return res.json({ count: 0, results: [] });
  const ids = descendantOrgIds(orgId);
  const ph = ids.map(() => '?').join(',');
  const where = [`pods.receiverId IN (${ph})`, `pods.status IN ('signed','emailed')`];
  const args = [...ids];
  if (req.query.po) { where.push(`pods.poNumber LIKE ?`); args.push(`%${req.query.po}%`); }
  if (req.query.q) { where.push(`(pods.poNumber LIKE ? OR pods.loadNumber LIKE ? OR pods.consignee LIKE ? OR pods.filename LIKE ?)`); args.push(`%${req.query.q}%`, `%${req.query.q}%`, `%${req.query.q}%`, `%${req.query.q}%`); }
  const rows = db.prepare(`SELECT pods.*, orgs.name AS shipperName FROM pods LEFT JOIN orgs ON orgs.id = pods.orgId
     WHERE ${where.join(' AND ')} ORDER BY COALESCE(pods.signedAt, pods.uploadedAt) DESC LIMIT 200`).all(...args).map(rowOut);
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
// Storage gauge (super-admin): total stored document bytes vs the app's persistent-disk budget, so we can
// see how close we are to needing object storage. Registered before '/:id' so it isn't read as an id.
router.get('/storage', requireAuth, (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Super-admin only' });
  const row = db.prepare(`SELECT COUNT(*) AS count, COALESCE(SUM(sizeBytes),0) AS bytes FROM pods`).get();
  const limitBytes = Number(process.env.DISK_LIMIT_BYTES || (1024 * 1024 * 1024)); // Render disk is ~1 GB
  res.json({ count: row.count, bytes: Number(row.bytes) || 0, limitBytes });
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

// ---- EDIT a stop's details (stop #, doc type, receiver, sales rep) without re-uploading the file. ----
router.put('/:id', requireAuth, express.json(), (req, res) => {
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!canAccess(req, row)) return res.status(404).json({ error: 'Not found' });
  const b = req.body || {};
  let stopNumber = row.stopNumber;
  if (b.stopNumber !== undefined) { const n = parseInt(b.stopNumber, 10); stopNumber = (Number.isFinite(n) && n > 0) ? n : null; }
  const docType = (b.docType !== undefined) ? (String(b.docType || '').trim() || 'POD') : row.docType;
  let receiverId = row.receiverId, receiverName = row.receiverName;
  if (b.receiverId !== undefined) {
    receiverId = (b.receiverId || '').trim() || null;
    receiverName = receiverId ? ((db.prepare(`SELECT name FROM orgs WHERE id = ?`).get(receiverId) || {}).name || null) : null;
  }
  let salesRepUserId = row.salesRepUserId;
  if (b.salesRepUserId !== undefined) {
    const rid = (b.salesRepUserId || '').trim() || null;
    salesRepUserId = (rid && db.prepare(`SELECT 1 FROM users WHERE id = ? AND orgId IS ?`).get(rid, row.orgId)) ? rid : null;
  }
  db.prepare(`UPDATE pods SET stopNumber = ?, docType = ?, receiverId = ?, receiverName = ?, salesRepUserId = ? WHERE id = ?`)
    .run(stopNumber, docType, receiverId, receiverName, salesRepUserId, row.id);
  res.json({ ok: true });
});

// ---- DELETE a document (remove a wrong/duplicate upload so a corrected one can be filed). ----
router.delete('/:id', requireAuth, (req, res) => {
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!canAccess(req, row)) return res.status(404).json({ error: 'Not found' });
  try { if (row.filepath && fs.existsSync(row.filepath)) fs.unlinkSync(row.filepath); } catch (e) {}
  db.prepare(`DELETE FROM pods WHERE id = ?`).run(row.id);
  try { logEvent({ orgId: row.orgId, loadId: row.loadId, poNumber: row.poNumber, type: 'document_removed',
    detail: (row.docType || 'Document') + ' removed' + (row.stopNumber ? ' (Stop ' + row.stopNumber + ')' : '') + (row.filename ? ': ' + row.filename : ''), actor: req.user.email }); } catch (e) {}
  res.json({ ok: true });
});

// ---- DOWNLOAD the PDF. Session OR device key; same customer only. ----
router.get('/:id/file', requireAuthOrKey, (req, res) => {
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!canAccess(req, row) || !row || !fs.existsSync(row.filepath)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${(row.filename || 'POD').replace(/[^\w.\- ]+/g, '_')}.pdf"`);
  fs.createReadStream(row.filepath).pipe(res);
});

// ---- ASSIGN a prepared document to a specific driver → it appears as a load in that driver's app. Admin/super. ----
router.post('/:id/assign-driver', requireAuth, express.json(), (req, res) => {
  if (req.user.role !== 'superadmin' && req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const pod = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!canAccess(req, pod)) return res.status(404).json({ error: 'Document not found' });
  const driverId = (req.body && req.body.driverId || '').trim();
  if (!driverId) {   // clear assignment
    db.prepare(`UPDATE pods SET assignedDriverId = NULL, assignedDriverName = NULL WHERE id = ?`).run(pod.id);
    return res.json({ ok: true, assignedDriverId: null, assignedDriverName: null });
  }
  const drv = db.prepare(`SELECT * FROM drivers WHERE id = ? AND active = 1`).get(driverId);
  if (!drv) return res.status(400).json({ error: 'That driver is not on this account' });
  // The driver must belong to an org connected to this document's load — its owner (customer), its assigned
  // carrier, or its broker. A carrier's driver signs the customer's load, so their orgs legitimately differ.
  const asgLoad = pod.loadId ? db.prepare(`SELECT orgId, carrierId, brokerId FROM loads WHERE id = ?`).get(pod.loadId) : null;
  const allowedOrgs = new Set([pod.orgId, asgLoad && asgLoad.orgId, asgLoad && asgLoad.carrierId, asgLoad && asgLoad.brokerId].filter(Boolean).map(String));
  if (!allowedOrgs.has(String(drv.orgId || ''))) return res.status(400).json({ error: 'That driver is not on this load’s account or its assigned carrier/broker' });
  // Re-assigning makes it active again on the new driver's list.
  db.prepare(`UPDATE pods SET assignedDriverId = ?, assignedDriverName = ?, assignedFulfilledAt = NULL WHERE id = ?`).run(drv.id, drv.name, pod.id);
  logEvent({ orgId: pod.orgId, loadId: pod.loadId, poNumber: pod.poNumber, type: 'assigned_driver', detail: 'Assigned to driver ' + drv.name, actor: req.user.email });
  res.json({ ok: true, assignedDriverId: drv.id, assignedDriverName: drv.name });
});

module.exports = router;
