// Driver roster for a customer. Admins (and super-admin via ?orgId) add named drivers; each gets a
// personal driver-app link. Drivers do not log into the portal.
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db } = require('./db');
const { requireAuth, requireDriverManager, resolveKey, driverUnlockValue } = require('./auth');
const { sendMail } = require('./mailer');

const router = express.Router();

function newToken() { return 'drv_' + crypto.randomBytes(24).toString('hex'); }
function escapeHtml(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }

// The driver-link email — plain-text fallback + a formatted HTML version with a real "Open" button and
// add-to-home-screen steps for iPhone and Android. (A mailto: can only send plain text, which is why the
// app sends this itself instead of opening the admin's mail client.)
function driverLinkText(first, orgName, link) {
  return `Hi ${first},\n\n`
    + `You're set up as a driver${orgName ? ' for ' + orgName : ''} on HaulProof. Open this link on your phone to sign deliveries — no app to install and no password:\n\n`
    + `${link}\n\n`
    + `Tip: add it to your home screen so it's one tap away.\n`
    + `• iPhone (Safari): tap the Share button, choose "Add to Home Screen", then tap Add.\n`
    + `• Android (Chrome): tap the menu (⋮, top-right), choose "Add to Home screen", then tap Add.\n\n`
    + `— HaulProof`;
}
function driverLinkHtml(first, orgName, link) {
  const forOrg = orgName ? (' for <b>' + escapeHtml(orgName) + '</b>') : '';
  return `<div style="font-family:-apple-system,system-ui,'Segoe UI',Arial,sans-serif;color:#1f2733;font-size:15px;line-height:1.6;max-width:480px;">`
    + `<p style="margin:0 0 14px;">Hi ${escapeHtml(first)},</p>`
    + `<p style="margin:0 0 22px;">You're set up as a driver${forOrg} on HaulProof. Open it on your phone to sign deliveries — no app to install and no password.</p>`
    + `<p style="margin:0 0 26px;"><a href="${link}" style="display:inline-block;background:#1f6feb;color:#ffffff;font-weight:700;text-decoration:none;font-size:16px;padding:14px 26px;border-radius:10px;">Open HaulProof &rarr;</a></p>`
    + `<div style="background:#f5f8fc;border:1px solid #dde4ec;border-radius:12px;padding:16px 18px;margin:0 0 22px;">`
    + `<p style="margin:0 0 12px;font-weight:700;">Tip: add it to your home screen so it's one tap away.</p>`
    + `<p style="margin:0 0 12px;"><b>iPhone (Safari)</b><br>Tap the Share button <span style="color:#5a6577;">(the square with an arrow pointing up)</span>, choose <b>Add to Home Screen</b>, then tap <b>Add</b>.</p>`
    + `<p style="margin:0;"><b>Android (Chrome)</b><br>Tap the menu <b>&#8942;</b> <span style="color:#5a6577;">(top-right)</span>, choose <b>Add to Home screen</b>, then tap <b>Add</b>.</p>`
    + `</div>`
    + `<p style="margin:0 0 4px;font-size:12.5px;color:#8a94a6;">If the button doesn't work, open this address on your phone:</p>`
    + `<p style="margin:0 0 20px;font-size:12.5px;color:#8a94a6;word-break:break-all;">${escapeHtml(link)}</p>`
    + `<p style="margin:0;color:#8a94a6;font-size:13px;">— HaulProof</p></div>`;
}
const PIN_RE = /^\d{4,6}$/;
function originOf(req) { return (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host')); }
// The customer this request manages drivers for. Super-admin may target any via ?orgId; admins pinned to their own.
function scopeOrgId(req) {
  if (req.user.role === 'superadmin') return (req.query.orgId || (req.body && req.body.orgId) || '').trim() || null;
  return req.user.orgId || null;
}
function sameOrg(req, orgId) { return req.user.role === 'superadmin' ? true : (orgId || null) === (req.user.orgId || null); }
function driverOut(req, d) {
  return { id: d.id, name: d.name, phone: d.phone, email: d.email || '', hasPin: !!d.pinHash, active: !!d.active, createdAt: d.createdAt,
    link: originOf(req) + '/driver?k=' + encodeURIComponent(d.token) };
}

// --- Endpoints the DRIVER APP calls with its own token (X-Api-Key), not a portal login ---
// Does this link need a PIN before it can be used? (Lets the app show the lock screen.)
router.get('/link-info', (req, res) => {
  const r = resolveKey(req);
  if (!r) return res.status(401).json({ error: 'This link is not valid' });
  res.json({ requiresPin: !!(r.driver && r.driver.pinHash), name: r.driver ? r.driver.name : '',
    company: r.org ? r.org.name : '', companyKind: r.org ? (r.org.kind || 'customer') : '' });
});
// Exchange the correct PIN for an "unlock" value the app stores and replays on every request.
router.post('/verify-pin', (req, res) => {
  const r = resolveKey(req);
  if (!r || !r.driver) return res.status(401).json({ error: 'This link is not valid' });
  const d = r.driver;
  if (!d.pinHash) return res.json({ ok: true, unlock: '', name: d.name || '', company: r.org ? r.org.name : '', companyKind: r.org ? (r.org.kind || 'customer') : '' });   // no PIN set — nothing to check
  const pin = String((req.body && req.body.pin) || '');
  if (!bcrypt.compareSync(pin, d.pinHash)) return res.status(401).json({ error: 'That PIN is not correct' });
  res.json({ ok: true, unlock: driverUnlockValue(d), name: d.name || '', company: r.org ? r.org.name : '', companyKind: r.org ? (r.org.kind || 'customer') : '' });
});

// Loads assigned to THIS driver (their personal link) — shown in the driver app as "Your loads".
// Only a personal driver token carries assignments; the shared org key returns nothing.
router.get('/my-loads', (req, res) => {
  const r = resolveKey(req);
  if (!r || !r.driver) return res.json({ loads: [] });
  // Prepared docs the driver should sign: ones dispatch assigned to them, PLUS ones this driver saved
  // themselves ("save to load — sign later"), so a self-saved doc always shows up here to be signed.
  const rows = db.prepare(`SELECT p.*, l.customerId AS loadCustomerId FROM pods p
      LEFT JOIN loads l ON l.id = p.loadId
      WHERE (p.assignedDriverId = ? OR p.signedByDriverId = ?) AND p.status IN ('prepared','awaiting_build') AND p.assignedFulfilledAt IS NULL
      ORDER BY p.uploadedAt DESC`).all(r.driver.id, r.driver.id);
  const parse = (s) => { try { return s ? JSON.parse(s) : []; } catch (e) { return []; } };
  // awaiting_build docs are ones the driver handed to dispatch — shown as "waiting", not yet signable.
  const loads = rows.map(p => ({ id: p.id, loadId: p.loadId, poNumber: p.poNumber, loadNumber: p.loadNumber, consignee: p.consignee,
    customerId: p.loadCustomerId || null, receiverName: p.receiverName, stopNumber: p.stopNumber, docType: p.docType,
    awaiting: p.status === 'awaiting_build',
    filename: p.filename, fields: parse(p.fields), fileUrl: '/api/pods/' + p.id + '/file' }));
  res.json({ loads });
});

// This driver's own recent signed documents (for the "Recent documents" list in their app).
router.get('/my-documents', (req, res) => {
  const r = resolveKey(req);
  if (!r || !r.driver) return res.json({ docs: [] });
  const rows = db.prepare(`SELECT id, loadId, poNumber, loadNumber, consignee, receiverName, stopNumber, filename, docType, status, uploadedAt, signedAt
      FROM pods
      WHERE status IN ('signed','emailed')
        AND (signedByDriverId = ? OR (driver = ? AND orgId IS ?))
      ORDER BY uploadedAt DESC LIMIT 30`).all(r.driver.id, r.driver.name || '', r.driver.orgId || null);
  const docs = rows.map(p => ({ id: p.id, loadId: p.loadId, poNumber: p.poNumber, loadNumber: p.loadNumber, consignee: p.consignee,
    receiverName: p.receiverName, stopNumber: p.stopNumber, docType: p.docType,
    filename: p.filename, when: p.uploadedAt || p.signedAt, fileUrl: '/api/pods/' + p.id + '/file' }));
  res.json({ docs });
});

// --- Driver-app load details: pick/add a customer + edit a load's details (device-key auth) ---
function drvNorm(s) { return String(s || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }
function drvCustOut(c) { return { id: c.id, name: c.name, mcNumber: c.mcNumber, contactName: c.contactName, contactEmail: c.contactEmail }; }

// The driver's org customer list (for the phone picker).
router.get('/customers', (req, res) => {
  const r = resolveKey(req);
  if (!r || !r.org) return res.json({ customers: [] });
  const rows = db.prepare(`SELECT * FROM customers WHERE ownerOrgId = ? ORDER BY name COLLATE NOCASE`).all(r.org.id);
  res.json({ customers: rows.map(drvCustOut) });
});
// Add a customer to the org's list from the phone. Exact-name dedup (unless force), same as the portal.
router.post('/customers', (req, res) => {
  const r = resolveKey(req);
  if (!r || !r.org) return res.status(401).json({ error: 'This link is not valid' });
  const b = req.body || {};
  const name = (b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Customer name is required' });
  const q = drvNorm(name);
  const existing = db.prepare(`SELECT * FROM customers WHERE ownerOrgId = ?`).all(r.org.id).find(x => drvNorm(x.name) === q);
  if (existing && !b.force) return res.json({ customer: drvCustOut(existing), existed: true });
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO customers (id, ownerOrgId, name, contactName, contactEmail, createdAt) VALUES (?,?,?,?,?,?)`)
    .run(id, r.org.id, name, (b.contactName || '').trim() || null, (b.contactEmail || '').trim() || null, Date.now());
  res.status(201).json({ customer: drvCustOut(db.prepare(`SELECT * FROM customers WHERE id = ?`).get(id)), existed: false });
});
// Save a load's details (PO / Load # / Consignee / Customer) for a document the driver has open.
router.post('/pods/:id/details', (req, res) => {
  const r = resolveKey(req);
  if (!r || !r.org) return res.status(401).json({ error: 'This link is not valid' });
  const pod = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!pod) return res.status(404).json({ error: 'Document not found' });
  const load = pod.loadId ? db.prepare(`SELECT * FROM loads WHERE id = ?`).get(pod.loadId) : null;
  const loadOrg = load ? (load.orgId || null) : (pod.orgId || null);
  // Allow if this driver's org owns it, or the doc is assigned to / was signed by this driver.
  const ownOrg = (loadOrg === (r.org.id || null)) || ((pod.orgId || null) === (r.org.id || null));
  const mine = r.driver && (pod.assignedDriverId === r.driver.id || pod.signedByDriverId === r.driver.id);
  if (!ownOrg && !mine) return res.status(403).json({ error: 'Not allowed' });
  const b = req.body || {};
  const po = (b.poNumber !== undefined) ? ((b.poNumber || '').trim() || null) : (load ? load.poNumber : pod.poNumber);
  if (!po) return res.status(400).json({ error: 'PO # is required' });
  const ln = (b.loadNumber !== undefined) ? ((b.loadNumber || '').trim() || null) : (load ? load.loadNumber : pod.loadNumber);
  const cons = (b.consignee !== undefined) ? ((b.consignee || '').trim() || null) : (load ? load.consignee : pod.consignee);
  const curPo = load ? load.poNumber : pod.poNumber;
  if (po !== curPo) {
    const clash = db.prepare(`SELECT id FROM loads WHERE orgId IS ? AND poNumber = ? AND id != ?`).get(loadOrg, po, load ? load.id : '');
    if (clash) return res.status(409).json({ error: 'Another load already uses PO ' + po });
  }
  // Customer can only be changed on a load this driver's org OWNS (mirrors the desktop rule).
  let setCustomer = false, customerId = null, customerName = null;
  if (b.customerId !== undefined && loadOrg === (r.org.id || null)) {
    setCustomer = true;
    const cid = (b.customerId || '').trim() || null;
    if (cid) {
      const c = db.prepare(`SELECT * FROM customers WHERE id = ? AND ownerOrgId IS ?`).get(cid, r.org.id);
      if (!c) return res.status(400).json({ error: 'That customer is not in your list' });
      customerId = c.id; customerName = c.name;
    }
  }
  db.prepare(`UPDATE pods SET poNumber = ?, loadNumber = ?, consignee = ? WHERE id = ?`).run(po, ln, cons, pod.id);
  if (load) {
    if (setCustomer) db.prepare(`UPDATE loads SET poNumber = ?, loadNumber = ?, consignee = ?, customerId = ?, customer = ? WHERE id = ?`).run(po, ln, cons, customerId, customerName, load.id);
    else db.prepare(`UPDATE loads SET poNumber = ?, loadNumber = ?, consignee = ? WHERE id = ?`).run(po, ln, cons, load.id);
    if (po !== curPo) { try { db.prepare(`UPDATE pods SET poNumber = ? WHERE loadId = ?`).run(po, load.id); } catch (e) {} }
  }
  res.json({ ok: true, poNumber: po, loadNumber: ln, consignee: cons, customerId: setCustomer ? customerId : (load ? load.customerId : null) });
});

// List a customer's drivers.
router.get('/', requireAuth, requireDriverManager, (req, res) => {
  const orgId = scopeOrgId(req);
  if (!orgId) return res.status(400).json({ error: 'No customer specified' });
  const rows = db.prepare(`SELECT * FROM drivers WHERE orgId = ? ORDER BY active DESC, createdAt DESC`).all(orgId);
  res.json({ drivers: rows.map(d => driverOut(req, d)) });
});

// Add a driver.
router.post('/', requireAuth, requireDriverManager, (req, res) => {
  const orgId = scopeOrgId(req);
  if (!orgId) return res.status(400).json({ error: 'No customer specified' });
  const name = (req.body && req.body.name || '').trim();
  const phone = (req.body && req.body.phone || '').trim();
  const email = (req.body && req.body.email || '').trim();
  const pin = String((req.body && req.body.pin) || '').trim();
  if (!name) return res.status(400).json({ error: "Enter the driver's name" });
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  if (!PIN_RE.test(pin)) return res.status(400).json({ error: 'Set a 4–6 digit PIN for this driver' });   // a PIN is required for every driver
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO drivers (id, orgId, name, phone, email, pinHash, token, active, createdAt) VALUES (?,?,?,?,?,?,?,1,?)`)
    .run(id, orgId, name, phone || null, email || null, pin ? bcrypt.hashSync(pin, 10) : null, newToken(), Date.now());
  res.status(201).json({ driver: driverOut(req, db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(id)) });
});

// Edit a driver's details (fix input mistakes). Same org only.
router.put('/:id', requireAuth, requireDriverManager, (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  const b = req.body || {};
  const name = (b.name !== undefined ? String(b.name) : d.name).trim();
  if (!name) return res.status(400).json({ error: "Enter the driver's name" });
  const phone = (b.phone !== undefined ? String(b.phone) : (d.phone || '')).trim();
  const email = (b.email !== undefined ? String(b.email) : (d.email || '')).trim();
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address' });
  // PIN is required and can't be removed. undefined = leave as-is; 4–6 digits = set a new one.
  let pinHash = d.pinHash;
  if (b.pin !== undefined) {
    const pin = String(b.pin).trim();
    if (!pin) return res.status(400).json({ error: 'A PIN is required — enter a new one to change it' });
    if (!PIN_RE.test(pin)) return res.status(400).json({ error: 'PIN must be 4 to 6 digits' });
    pinHash = bcrypt.hashSync(pin, 10);
  }
  db.prepare(`UPDATE drivers SET name = ?, phone = ?, email = ?, pinHash = ? WHERE id = ?`).run(name, phone || null, email || null, pinHash, d.id);
  res.json({ driver: driverOut(req, db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(d.id)) });
});

// Turn a driver on/off (deactivating instantly revokes their personal link).
router.post('/:id/active', requireAuth, requireDriverManager, (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  const active = req.body && req.body.active ? 1 : 0;
  db.prepare(`UPDATE drivers SET active = ? WHERE id = ?`).run(active, d.id);
  res.json({ driver: driverOut(req, db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(d.id)) });
});

// Issue a fresh personal link (invalidates the old one).
router.post('/:id/rotate', requireAuth, requireDriverManager, (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  db.prepare(`UPDATE drivers SET token = ? WHERE id = ?`).run(newToken(), d.id);
  res.json({ driver: driverOut(req, db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(d.id)) });
});

// Email a driver their personal link — a formatted message with a real "Open HaulProof" button and
// add-to-home-screen steps. Sent by the app (not a mailto) so it can carry a button, not just a raw URL.
router.post('/:id/email-link', requireAuth, requireDriverManager, async (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  const to = (d.email || '').trim();
  if (!to) return res.status(400).json({ error: 'This driver has no email on file — add one first, or use Text / Copy link.' });
  const org = db.prepare(`SELECT name FROM orgs WHERE id = ?`).get(d.orgId);
  const orgName = org ? org.name : '';
  const link = originOf(req) + '/driver?k=' + encodeURIComponent(d.token);
  const first = (d.name || '').split(/\s+/)[0] || 'there';
  try {
    const r = await sendMail({ to, subject: 'Your HaulProof driver link', text: driverLinkText(first, orgName, link), html: driverLinkHtml(first, orgName, link) });
    if (r && (r.sent || r.simulated)) return res.json({ ok: true, sentTo: to, simulated: !!r.simulated });
    return res.status(502).json({ error: 'Email could not be sent right now' + (r && r.error ? ' (' + r.error + ')' : '') });
  } catch (e) { console.error('email-link', e); return res.status(500).json({ error: 'Email could not be sent right now' }); }
});

// Remove a driver.
router.delete('/:id', requireAuth, requireDriverManager, (req, res) => {
  const d = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(req.params.id);
  if (!d || !sameOrg(req, d.orgId)) return res.status(404).json({ error: 'Driver not found' });
  db.prepare(`DELETE FROM drivers WHERE id = ?`).run(d.id);
  res.json({ ok: true });
});

module.exports = router;
