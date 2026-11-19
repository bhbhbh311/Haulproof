// "Who's driving it?" A broker's load with a carrier but no driver: HaulProof emails the carrier a link to a short form
// (/driver-request?t=…) asking for the driver's name and cell #. When the carrier answers, the driver is found or added
// on the carrier's account, put on the load, and texted their HaulProof link (or the carrier gets a Text button to send
// it). A carrier with no HaulProof login yet also gets one (admin), from the email the request went to.
const crypto = require('crypto');
const express = require('express');
const { db } = require('./db');
const { requireAuth } = require('./auth');
const { sendMail } = require('./mailer');
const { logEvent } = require('./events');
const { inviteLogin, originOf } = require('./invite');
const notify = require('./notify');

db.exec(`CREATE TABLE IF NOT EXISTS driver_requests (
  token TEXT PRIMARY KEY, loadId TEXT NOT NULL, carrierId TEXT NOT NULL, email TEXT NOT NULL,
  sentBy TEXT, notifyEmail TEXT, createdAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL,
  answeredAt INTEGER, driverId TEXT)`);

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const DAY = 24 * 60 * 60 * 1000;
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const digits = v => String(v || '').replace(/\D/g, '');
// "CALLAHAN TRANSPORTATION INC" -> "Callahan Transportation"
function tidyCo(n) {
  const s = String(n || '').replace(/[,.]?\s+(INC|LLC|L L C|LLP|CORP|CO|LTD)\.?$/i, '').trim();
  return s === s.toUpperCase() ? s.toLowerCase().replace(/\b[a-z]/g, c => c.toUpperCase()) : s;
}
const orgName = id => { const o = id ? db.prepare(`SELECT name FROM orgs WHERE id = ?`).get(id) : null; return o ? o.name : ''; };
// The company asking: the broker on the load, else the load's owner
const askerOf = load => tidyCo(orgName(load.brokerId) || orgName(load.orgId)) || 'Your broker';
const loadLabel = load => load.loadNumber && load.loadNumber !== load.poNumber ? `load ${load.loadNumber} (PO ${load.poNumber})` : `load ${load.poNumber}`;
const loadDone = load => {
  const st = db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status IN ('signed','emailed') THEN 1 ELSE 0 END) AS done FROM pods
    WHERE loadId = ? AND status NOT IN ('parked','not_used')`).get(load.id);
  return st && Number(st.total) > 0 && Number(st.done) === Number(st.total);
};

// Make the request and email it. Used by the portal/connector route and by FMS. Returns { token, link, sentTo, adminCreated }.
function createRequest(req, load, { email, notifyEmail }) {
  const carrier = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(load.carrierId);
  const token = crypto.randomBytes(24).toString('hex'), now = Date.now();
  const sentBy = req.user.email || req.user.name || 'dispatch';
  db.prepare(`INSERT INTO driver_requests (token, loadId, carrierId, email, sentBy, notifyEmail, createdAt, expiresAt) VALUES (?,?,?,?,?,?,?,?)`)
    .run(token, load.id, carrier.id, email, sentBy, notifyEmail || null, now, now + 14 * DAY);
  const link = originOf(req) + '/driver-request?t=' + token;
  const asker = askerOf(load), what = loadLabel(load);
  const route = [load.origin, load.consignee || load.destination].filter(Boolean).join(' → ');
  const text = `${asker} needs your driver to run ${what}${route ? ' (' + route + ')' : ''} through HaulProof, our driver app for the BOL.\n\n` +
    `Please send us the driver's name and cell # here (takes 30 seconds):\n${link}\n\n` +
    `We'll text the driver their HaulProof link. They tap it, pick a PIN, and the load is there; after delivery they send the signed BOL from it and it comes to your company and ${asker}.\n\nThank you,\n${asker}`;
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:520px;color:#0e1a2d;font-size:15px;line-height:1.5">
    <p><b>${esc(asker)}</b> needs your driver to run <b>${esc(what)}</b>${route ? ' (' + esc(route) + ')' : ''} through HaulProof, our driver app for the BOL.</p>
    <p>Please send us the driver's name and cell #. It takes 30 seconds:</p>
    <p><a href="${esc(link)}" style="display:inline-block;background:#1655d1;color:#fff;text-decoration:none;font-weight:700;padding:12px 22px;border-radius:10px">Enter the driver</a></p>
    <p style="color:#5a6b82;font-size:13.5px">We'll text the driver their HaulProof link. They tap it, pick a PIN, and the load is there; after delivery they send the signed BOL from it and it comes to your company and ${esc(asker)}.</p>
    <p>Thank you,<br>${esc(asker)}</p></div>`;
  sendMail({ to: email, cc: notifyEmail && notifyEmail !== email ? notifyEmail : undefined, subject: `${asker} ${what}: who's driving? (HaulProof)`, text, html })
    .catch(e => console.error('driver request mail', e));
  // A carrier nobody has a login for yet gets one, from this email (it's emailed its own "choose your password" link).
  let adminCreated = false;
  const hasLogin = db.prepare(`SELECT 1 FROM users WHERE orgId = ? AND email NOT LIKE 'haulproofhelp+%' LIMIT 1`).get(carrier.id);
  if (!hasLogin && !db.prepare(`SELECT 1 FROM users WHERE email = ?`).get(email)) {
    try { inviteLogin(req, { email, name: '', role: 'admin', orgId: carrier.id, company: carrier.name }); adminCreated = true; } catch (e) { console.error('carrier admin invite', e); }
  }
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'note',
    detail: `Asked ${carrier.name} (${email}) for the driver's name and cell #` + (adminCreated ? `; set up ${email} as ${carrier.name}'s HaulProof admin` : ''), actor: sentBy });
  return { token, link, sentTo: email, adminCreated };
}

// ---- Signed-in: ask the carrier on a load for its driver ----
const router = express.Router();
router.post('/:id/request-driver', requireAuth, express.json(), (req, res) => {
  if (!['admin', 'dispatcher', 'superadmin'].includes(req.user.role)) return res.status(403).json({ error: 'Not allowed' });
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(req.params.id);
  const mine = load && (req.user.role === 'superadmin' || [load.orgId, load.brokerId].filter(Boolean).includes(req.user.orgId));
  if (!mine) return res.status(404).json({ error: 'Load not found' });
  if (!load.carrierId) return res.status(400).json({ error: 'Put a carrier on the load first' });
  if (loadDone(load)) return res.status(409).json({ error: 'This load is already complete' });
  const email = String((req.body && req.body.email) || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "Enter the carrier's email" });
  const ne = String((req.body && req.body.notifyEmail) || '').trim().toLowerCase();
  const notifyEmail = EMAIL_RE.test(ne) ? ne : (EMAIL_RE.test(req.user.email || '') && !/^haulproofhelp\+/i.test(req.user.email) ? req.user.email : null);
  // Already asked this carrier in the last day and no answer yet: don't email them twice (FMS re-sends a load on
  // each rate con signature). resend: true asks again anyway.
  const open = db.prepare(`SELECT * FROM driver_requests WHERE loadId = ? AND carrierId = ? AND email = ? AND answeredAt IS NULL AND createdAt > ? ORDER BY createdAt DESC`)
    .get(load.id, load.carrierId, email, Date.now() - DAY);
  if (open && !(req.body && req.body.resend)) return res.json({ ok: true, alreadyAsked: true, sentTo: email, link: originOf(req) + '/driver-request?t=' + open.token, adminCreated: false, carrier: load.carrierName });
  if (load.assignedDriverId && !(req.body && req.body.resend)) return res.status(409).json({ error: 'This load already has driver ' + (load.driverName || '') + '. Pass resend to ask the carrier anyway.' });
  const r = createRequest(req, load, { email, notifyEmail });
  res.status(201).json({ ok: true, sentTo: r.sentTo, link: r.link, adminCreated: r.adminCreated, carrier: load.carrierName });
});

// ---- Public: the carrier's form ----
const publicRouter = express.Router();
function openRequest(token) {
  const r = db.prepare(`SELECT * FROM driver_requests WHERE token = ?`).get(String(token || ''));
  if (!r || r.expiresAt < Date.now()) return { error: 'This link has expired. Ask your broker for a new one.' };
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(r.loadId);
  if (!load || load.carrierId !== r.carrierId) return { error: 'This load has been changed or is no longer yours. Call your broker.' };
  return { r, load, carrier: db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(r.carrierId) };
}
publicRouter.get('/:token', (req, res) => {
  const o = openRequest(req.params.token);
  if (o.error) return res.status(404).json({ error: o.error });
  const { load, carrier } = o;
  const drv = load.assignedDriverId ? db.prepare(`SELECT name, phone FROM drivers WHERE id = ?`).get(load.assignedDriverId) : null;
  res.json({ broker: askerOf(load), carrier: carrier ? carrier.name : load.carrierName, poNumber: load.poNumber, loadNumber: load.loadNumber,
    origin: load.origin || null, destination: load.consignee || load.destination || null, done: loadDone(load),
    driver: drv ? { name: drv.name, phone: drv.phone || null } : (load.driverName ? { name: load.driverName, phone: null } : null) });
});
publicRouter.post('/:token', express.json(), async (req, res) => {
  const o = openRequest(req.params.token);
  if (o.error) return res.status(404).json({ error: o.error });
  const { r, load, carrier } = o;
  if (loadDone(load)) return res.status(409).json({ error: 'This load is already complete.' });
  const name = String((req.body && req.body.name) || '').trim().slice(0, 80);
  const phone = digits(req.body && req.body.phone).replace(/^1(?=\d{10}$)/, '');
  if (!name) return res.status(400).json({ error: "Enter the driver's name" });
  if (phone.length !== 10) return res.status(400).json({ error: "Enter the driver's 10-digit cell #" });
  // Same person already on the carrier's account? Match the cell #, then the exact name.
  const list = db.prepare(`SELECT * FROM drivers WHERE orgId = ? AND active = 1`).all(carrier.id);
  let drv = list.find(d => digits(d.phone).slice(-10) === phone) || list.find(d => !digits(d.phone) && d.name.trim().toLowerCase() === name.toLowerCase());
  if (drv) { if (!digits(drv.phone)) db.prepare(`UPDATE drivers SET phone = ? WHERE id = ?`).run(phone, drv.id); }
  else {
    const id = crypto.randomUUID();
    db.prepare(`INSERT INTO drivers (id, orgId, name, phone, pinHash, token, active, mustChangePin, addedByOrgId, addedByName, createdAt) VALUES (?,?,?,?,?,?,1,1,?,?,?)`)
      .run(id, carrier.id, name, phone, null, require('./drivers').newDriverToken(), load.brokerId || load.orgId, askerOf(load), Date.now());
    drv = { id };
  }
  drv = db.prepare(`SELECT * FROM drivers WHERE id = ?`).get(drv.id);
  // Put them on the load: the load's unsigned documents go to their phone (same as Assign driver)
  db.prepare(`UPDATE pods SET assignedDriverId = ?, assignedDriverName = ? WHERE loadId = ? AND status IN ('received','prepared','awaiting_build')`).run(drv.id, drv.name, load.id);
  db.prepare(`UPDATE loads SET driverName = ?, assignedDriverId = ? WHERE id = ?`).run(drv.name, drv.id, load.id);
  try { db.prepare(`SELECT id FROM pods WHERE loadId = ? AND status = 'prepared' AND assignedDriverId = ?`).all(load.id, drv.id).forEach(p => notify.notifyDriverReady(p.id)); } catch (e) {}
  db.prepare(`UPDATE driver_requests SET answeredAt = ?, driverId = ? WHERE token = ?`).run(Date.now(), drv.id, r.token);
  const link = require('./driverlink').driverLink(req, drv);
  // Text the driver their link (when texting is set up); otherwise the carrier gets a Text button on the page.
  let texted = false;
  const T = require('./twilio');
  if (T.configured()) {
    try {
      await T.sendText({ to: phone, orgId: carrier.id, driverId: drv.id, sentBy: r.email,
        loadId: load.id, notifyEmail: r.notifyEmail || null, link, driverName: drv.name, callbackBase: originOf(req),
        body: `${askerOf(load)}: here's your HaulProof driver app for ${loadLabel(load)}, ${drv.name.split(/\s+/)[0]}. Tap the link, pick your own PIN, and the load is there. After delivery, send the signed BOL from it.\n${link}` });
      texted = true;
    } catch (e) { console.error('driver request text', e.message); }
  }
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'driver_assigned',
    detail: `Driver ${drv.name} (${phone.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3')}) given by ${carrier.name}` + (texted ? '; HaulProof link texted to the driver' : ''), actor: r.email });
  const who = [r.notifyEmail].filter(Boolean);
  if (who.length) sendMail({ to: who, subject: `${carrier.name} gave the driver for ${loadLabel(load)}: ${drv.name}`,
    text: `${carrier.name} says ${drv.name} (${phone.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3')}) is driving ${loadLabel(load)}. ` +
      (texted ? 'HaulProof sent the driver a text with their link. If the text doesn’t get through, you’ll get another email saying so.' : 'HaulProof couldn’t text the driver, so the carrier was shown a button to text the link from their phone. You can also send it yourself.') + `\n\nDriver's link: ${link}` }).catch(() => {});
  res.json({ ok: true, driver: drv.name, phone, link, texted, broker: askerOf(load), loadLabel: loadLabel(load) });
});

module.exports = { router, publicRouter, createRequest };
