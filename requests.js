// Public "request access" intake + Master-Admin grant/deny/reply inbox.
// Anyone can submit a request (company account OR driver). Master Admin acts on it.
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { db } = require('./db');
const { requireAuth, requireSuper, createUser } = require('./auth');
const { sendMail } = require('./mailer');

const router = express.Router();
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const ORG_TYPES = ['customer', 'carrier', 'broker', 'receiver'];
function newCode() { return crypto.randomBytes(4).toString('hex').toUpperCase(); }   // 8 chars
function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }
function driverToken() { return 'drv_' + crypto.randomBytes(24).toString('hex'); }
function originOf(req) { return (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host')); }
function parseThread(s) { try { return JSON.parse(s || '[]'); } catch (e) { return []; } }
function adminEmails() { return (process.env.ADMIN_EMAIL || '').split(',').map(s => s.trim()).filter(Boolean); }
function reqOut(r) {
  return { id: r.id, code: r.code, kind: r.kind, orgType: r.orgType, contactName: r.contactName, email: r.email,
    phone: r.phone, company: r.company, mcNumber: r.mcNumber, dotNumber: r.dotNumber, targetCompany: r.targetCompany,
    note: r.note, status: r.status, thread: parseThread(r.thread), createdOrgId: r.createdOrgId, createdDriverId: r.createdDriverId,
    createdAt: r.createdAt, decidedAt: r.decidedAt };
}
function pushThread(r, from, text) {
  const th = parseThread(r.thread); th.push({ from, text, at: Date.now() });
  db.prepare(`UPDATE access_requests SET thread = ? WHERE id = ?`).run(JSON.stringify(th), r.id);
}

// ---- PUBLIC: submit a request ----
router.post('/', express.json(), async (req, res) => {
  const b = req.body || {};
  const kind = b.kind === 'driver' ? 'driver' : 'company';
  const contactName = (b.contactName || '').trim();
  const email = (b.email || '').toLowerCase().trim();
  const phone = (b.phone || '').trim();
  const company = (b.company || '').trim();
  if (!contactName) return res.status(400).json({ error: 'Your name is required' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'A valid email is required' });
  const orgType = kind === 'company' ? (ORG_TYPES.includes(b.orgType) ? b.orgType : 'customer') : null;
  const id = crypto.randomUUID(), code = newCode();
  db.prepare(`INSERT INTO access_requests (id, code, kind, orgType, contactName, email, phone, company, mcNumber, dotNumber, targetCompany, note, status, thread, createdAt)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'pending', '[]', ?)`)
    .run(id, code, kind, orgType, contactName, email, phone || null, company || null,
      (b.mcNumber || '').trim() || null, (b.dotNumber || '').trim() || null, (b.targetCompany || '').trim() || null, (b.note || '').trim() || null, Date.now());
  // Let the Master Admin know a request came in.
  sendMail({ to: adminEmails(), subject: 'New HaulProof access request',
    text: `${contactName} (${email}${phone ? ', ' + phone : ''}) requested ${kind === 'company' ? 'a ' + orgType + ' account' : 'driver access'}${company ? ' — ' + company : ''}${b.targetCompany ? ' (join ' + b.targetCompany + ')' : ''}.\n\nReview it in the Master Admin portal → Access requests.` });
  res.json({ ok: true, code, statusUrl: originOf(req) + '/request?code=' + code });
});

// ---- PUBLIC: check a request by its code ----
router.get('/status', (req, res) => {
  const code = (req.query.code || '').trim().toUpperCase();
  const r = db.prepare(`SELECT * FROM access_requests WHERE code = ?`).get(code);
  if (!r) return res.status(404).json({ error: 'No request found for that code' });
  res.json(reqOut(r));
});
// ---- PUBLIC: requester replies to a question ----
router.post('/status/reply', express.json(), (req, res) => {
  const code = (req.body && req.body.code || '').trim().toUpperCase();
  const text = (req.body && req.body.text || '').trim();
  const r = db.prepare(`SELECT * FROM access_requests WHERE code = ?`).get(code);
  if (!r) return res.status(404).json({ error: 'No request found' });
  if (!text) return res.status(400).json({ error: 'Type a reply' });
  pushThread(r, 'requester', text);
  sendMail({ to: adminEmails(), subject: 'Reply on HaulProof request ' + code, text: `${r.contactName} replied: ${text}` });
  res.json({ ok: true });
});

// ---- ADMIN (Master Admin only) ----
router.get('/', requireAuth, requireSuper, (req, res) => {
  const status = (req.query.status || '').trim();
  const rows = status
    ? db.prepare(`SELECT * FROM access_requests WHERE status = ? ORDER BY createdAt DESC`).all(status)
    : db.prepare(`SELECT * FROM access_requests ORDER BY (status='pending') DESC, createdAt DESC`).all();
  res.json({ requests: rows.map(reqOut), pending: db.prepare(`SELECT COUNT(*) c FROM access_requests WHERE status='pending'`).get().c });
});
router.post('/:id/reply', requireAuth, requireSuper, express.json(), (req, res) => {
  const r = db.prepare(`SELECT * FROM access_requests WHERE id = ?`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  const text = (req.body && req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Type a message' });
  pushThread(r, 'admin', text);
  sendMail({ to: r.email, subject: 'A question about your HaulProof request', text: `${text}\n\nReply here: ${originOf(req)}/request?code=${r.code}` });
  res.json({ ok: true });
});
router.post('/:id/deny', requireAuth, requireSuper, express.json(), (req, res) => {
  const r = db.prepare(`SELECT * FROM access_requests WHERE id = ?`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  const reason = (req.body && req.body.reason || '').trim();
  if (reason) pushThread(r, 'admin', 'Denied: ' + reason);
  db.prepare(`UPDATE access_requests SET status='denied', decidedAt=? WHERE id=?`).run(Date.now(), r.id);
  sendMail({ to: r.email, subject: 'Update on your HaulProof request', text: `Your request was not approved at this time.${reason ? ' ' + reason : ''}\n\nStatus: ${originOf(req)}/request?code=${r.code}` });
  res.json({ ok: true });
});
router.post('/:id/grant', requireAuth, requireSuper, express.json(), (req, res) => {
  const r = db.prepare(`SELECT * FROM access_requests WHERE id = ?`).get(req.params.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  if (r.status === 'granted') return res.status(400).json({ error: 'This request was already granted' });
  const b = req.body || {};
  try {
    if (r.kind === 'company') {
      const orgType = ORG_TYPES.includes(b.orgType) ? b.orgType : (r.orgType || 'customer');
      const name = (b.company || r.company || r.contactName).trim();
      const adminEmail = (b.adminEmail || r.email || '').toLowerCase().trim();
      const parentId = (b.parentId || '').trim() || null;
      if (!EMAIL_RE.test(adminEmail)) return res.status(400).json({ error: 'A valid admin email is required' });
      const existing = db.prepare(`SELECT * FROM users WHERE email = ?`).get(adminEmail);
      if (existing) {
        // One account, two roles: if they already have an account, add this role to it instead of
        // creating a duplicate (e.g. an existing customer who is now also a receiver).
        if (existing.orgId) {
          const org = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(existing.orgId);
          if (org) {
            let roles = []; try { roles = org.roles ? JSON.parse(org.roles) : []; } catch (e) {}
            if (!roles.length) roles = [org.kind || 'customer'];
            if (!roles.includes(orgType)) roles.push(orgType);
            db.prepare(`UPDATE orgs SET roles = ? WHERE id = ?`).run(JSON.stringify(roles), org.id);
            db.prepare(`UPDATE access_requests SET status='granted', decidedAt=?, createdOrgId=? WHERE id=?`).run(Date.now(), org.id, r.id);
            pushThread(r, 'admin', `Approved — added the ${orgType} role to existing account "${org.name}".`);
            sendMail({ to: r.email, subject: 'HaulProof access updated',
              text: `Your account "${org.name}" now has ${orgType} access.\n\nSign in at ${originOf(req)} — your existing login is unchanged.` });
            return res.json({ ok: true, kind: 'company', orgType, orgId: org.id, merged: true });
          }
        }
        return res.status(409).json({ error: 'That email already has a login' });
      }
      const adminPassword = (b.adminPassword || '').trim() || crypto.randomBytes(5).toString('hex');
      const orgId = crypto.randomUUID();
      db.prepare(`INSERT INTO orgs (id, name, deviceKey, kind, roles, parentId, contactName, contactEmail, contactPhone, mcNumber, dotNumber, active, createdAt)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)`)
        .run(orgId, name, newDeviceKey(), orgType, JSON.stringify([orgType]), parentId, r.contactName, adminEmail, r.phone || null, r.mcNumber || null, r.dotNumber || null, Date.now());
      createUser({ email: adminEmail, name: r.contactName, role: 'admin', password: adminPassword, orgId });
      db.prepare(`UPDATE access_requests SET status='granted', decidedAt=?, createdOrgId=? WHERE id=?`).run(Date.now(), orgId, r.id);
      pushThread(r, 'admin', `Approved — ${orgType} account "${name}" created; login emailed.`);
      sendMail({ to: r.email, subject: 'Your HaulProof account is ready',
        text: `Your ${orgType} account "${name}" is set up.\n\nSign in at ${originOf(req)}\nEmail: ${adminEmail}\nTemporary password: ${adminPassword}\n\nPlease change your password after signing in.` });
      return res.json({ ok: true, kind: 'company', orgType, orgId, adminEmail, adminPassword });
    }
    // driver → must be attached to a company
    const targetOrgId = (b.targetOrgId || '').trim();
    if (!targetOrgId) return res.status(400).json({ error: 'Choose which company this driver belongs to' });
    const org = db.prepare(`SELECT * FROM orgs WHERE id = ? AND active = 1`).get(targetOrgId);
    if (!org) return res.status(400).json({ error: 'That company was not found' });
    const pin = (b.pin || '').trim() || String(1000 + Math.floor(Math.random() * 9000));
    const drvId = crypto.randomUUID(), token = driverToken();
    db.prepare(`INSERT INTO drivers (id, orgId, name, phone, email, pinHash, token, active, createdAt) VALUES (?,?,?,?,?,?,?,1,?)`)
      .run(drvId, targetOrgId, r.contactName, r.phone || null, r.email || null, bcrypt.hashSync(pin, 10), token, Date.now());
    const link = originOf(req) + '/driver?k=' + encodeURIComponent(token);
    db.prepare(`UPDATE access_requests SET status='granted', decidedAt=?, createdDriverId=? WHERE id=?`).run(Date.now(), drvId, r.id);
    pushThread(r, 'admin', `Approved — added as a driver for ${org.name}; link + PIN emailed.`);
    sendMail({ to: r.email, subject: 'Your HaulProof driver link',
      text: `You've been added as a driver for ${org.name}.\n\nOpen this link on your phone: ${link}\nYour PIN: ${pin}\n\nOpen it once, enter the PIN, and you're set.` });
    return res.json({ ok: true, kind: 'driver', driverId: drvId, company: org.name, link, pin });
  } catch (e) { console.error('grant', e); return res.status(500).json({ error: 'Could not grant this request' }); }
});

module.exports = router;
