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

// The email goes out a few minutes after the request, together with any other loads asked of the same carrier email
// in that window (FMS asks once per signed rate con, so a carrier booking 6 loads would otherwise get 6 emails).
for (const c of ['emailedAt INTEGER', 'link TEXT']) { try { db.exec(`ALTER TABLE driver_requests ADD COLUMN ${c}`); } catch (e) {} }
// Requests from before batching were emailed right away (they have no saved link): never send those again
db.prepare(`UPDATE driver_requests SET emailedAt = createdAt WHERE emailedAt IS NULL AND link IS NULL`).run();
const BATCH_MS = () => Math.max(0, Number(process.env.DRIVER_REQUEST_BATCH_MS || 5 * 60 * 1000));
const pending = new Map();   // email -> timer
function scheduleFlush(email) {
  if (pending.has(email)) return;
  pending.set(email, setTimeout(() => { pending.delete(email); flushRequests(email).catch(e => console.error('driver request mail', e)); }, BATCH_MS()));
}
// One email to this carrier address for every request not emailed yet, each load with its own "Enter the driver" button.
async function flushRequests(email) {
  const rows = db.prepare(`SELECT * FROM driver_requests WHERE email = ? AND emailedAt IS NULL AND link IS NOT NULL AND answeredAt IS NULL AND expiresAt > ? ORDER BY createdAt`).all(email, Date.now());
  const latest = new Map(); rows.forEach(r => latest.set(r.loadId, r));   // a load asked twice in the window: its newest link
  const items = [...latest.values()].map(r => ({ r, load: db.prepare(`SELECT * FROM loads WHERE id = ?`).get(r.loadId) })).filter(x => x.load && x.load.carrierId === x.r.carrierId && !loadDone(x.load));
  const stamp = Date.now();
  db.prepare(`UPDATE driver_requests SET emailedAt = ? WHERE email = ? AND emailedAt IS NULL`).run(stamp, email);
  if (!items.length) return 0;
  const asker = askerOf(items[0].load), many = items.length > 1;
  const labels = items.map(x => loadLabel(x.load));
  const what = many ? 'loads ' + items.map(x => x.load.loadNumber || x.load.poNumber).join(', ') : labels[0];
  const routeOf = l => [l.origin, l.consignee || l.destination].filter(Boolean).join(' → ');
  const cc = [...new Set(items.map(x => x.r.notifyEmail).filter(e => e && e !== email))];
  const text = `${asker} needs your driver${many ? 's' : ''} to run ${many ? 'these loads' : what} through HaulProof, our driver app for the BOL.\n\n` +
    `Please send us the driver's name and cell # ${many ? 'for each load ' : ''}here (takes 30 seconds${many ? ' each' : ''}):\n` +
    items.map(x => (many ? `${loadLabel(x.load)}${routeOf(x.load) ? ' (' + routeOf(x.load) + ')' : ''}: ` : '') + x.r.link).join('\n') + '\n\n' +
    `We'll text the driver their HaulProof link. They tap it, pick a PIN, and the load is there; after delivery they send the signed BOL from it and it comes to your company and ${asker}.\n\nThank you,\n${asker}`;
  const btn = link => `<a href="${esc(link)}" style="display:inline-block;background:#1655d1;color:#fff;text-decoration:none;font-weight:700;padding:10px 18px;border-radius:10px">Enter the driver</a>`;
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:560px;color:#0e1a2d;font-size:15px;line-height:1.5">
    <p><b>${esc(asker)}</b> needs your driver${many ? 's' : ''} to run ${many ? 'these loads' : '<b>' + esc(what) + '</b>' + (routeOf(items[0].load) ? ' (' + esc(routeOf(items[0].load)) + ')' : '')} through HaulProof, our driver app for the BOL.</p>
    <p>Please send us the driver's name and cell #${many ? ' for each load' : ''}. It takes 30 seconds${many ? ' each' : ''}:</p>
    ${many ? '<table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%">' + items.map(x => `<tr><td style="padding:8px 10px 8px 0;border-top:1px solid #dfe6f1"><b>${esc(loadLabel(x.load))}</b>${routeOf(x.load) ? '<br><span style="color:#5a6b82;font-size:13.5px">' + esc(routeOf(x.load)) + '</span>' : ''}</td><td style="padding:8px 0;border-top:1px solid #dfe6f1;text-align:right">${btn(x.r.link)}</td></tr>`).join('') + '</table>' : '<p>' + btn(items[0].r.link) + '</p>'}
    <p style="color:#5a6b82;font-size:13.5px">We'll text the driver their HaulProof link. They tap it, pick a PIN, and the load is there; after delivery they send the signed BOL from it and it comes to your company and ${esc(asker)}.</p>
    <p>Thank you,<br>${esc(asker)}</p></div>`;
  await sendMail({ to: email, cc: cc.length ? cc : undefined, subject: `${asker} ${what}: who's driving? (HaulProof)`, text, html });
  return items.length;
}
// After a restart, send anything that was still waiting
setTimeout(() => { try { db.prepare(`SELECT DISTINCT email FROM driver_requests WHERE emailedAt IS NULL AND answeredAt IS NULL AND expiresAt > ?`).all(Date.now()).forEach(r => scheduleFlush(r.email)); } catch (e) {} }, 5000).unref();

// Make the request; its email goes out batched with the carrier's other new requests (see above). Used by the
// portal/connector route and by FMS. Returns { token, link, sentTo, adminCreated }.
function createRequest(req, load, { email, notifyEmail }) {
  const carrier = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(load.carrierId);
  const token = crypto.randomBytes(24).toString('hex'), now = Date.now();
  const sentBy = req.user.email || req.user.name || 'dispatch';
  const link = originOf(req) + '/driver-request?t=' + token;
  db.prepare(`INSERT INTO driver_requests (token, loadId, carrierId, email, sentBy, notifyEmail, createdAt, expiresAt, link) VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(token, load.id, carrier.id, email, sentBy, notifyEmail || null, now, now + 14 * DAY, link);
  scheduleFlush(email);
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
  // Text the driver their link only when the carrier checked "the driver agreed to texts" (or the driver opted in on
  // /sms themselves); otherwise, or when texting isn't set up, the carrier gets a Text button on the page.
  const C = require('./smsconsent');
  const consent = req.body && req.body.consent === true;
  if (consent) C.record({ phone, name: drv.name, source: 'carrier-form:' + r.email, consentText: C.CARRIER_CONSENT_TEXT, ip: req.ip });
  let texted = false;
  const T = require('./twilio');
  if (T.configured() && (consent || C.has(phone))) {
    try {
      await T.sendText({ to: phone, orgId: carrier.id, driverId: drv.id, sentBy: r.email,
        loadId: load.id, notifyEmail: r.notifyEmail || null, link, driverName: drv.name, callbackBase: originOf(req),
        body: `${askerOf(load)}: here's your HaulProof driver app for ${loadLabel(load)}, ${drv.name.split(/\s+/)[0]}. Tap the link, pick your own PIN, and the load is there. After delivery, send the signed BOL from it. Reply STOP to opt out.\n${link}` });
      texted = true;
    } catch (e) { console.error('driver request text', e.message); }
  }
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'driver_assigned',
    detail: `Driver ${drv.name} (${phone.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3')}) given by ${carrier.name}` + (texted ? '; HaulProof link texted to the driver' : ''), actor: r.email });
  const who = [r.notifyEmail].filter(Boolean);
  if (who.length) sendMail({ to: who, subject: `${carrier.name} gave the driver for ${loadLabel(load)}: ${drv.name}`,
    text: `${carrier.name} says ${drv.name} (${phone.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3')}) is driving ${loadLabel(load)}. ` +
      (texted ? 'HaulProof sent the driver a text with their link. If the text doesn’t get through, you’ll get another email saying so.' : 'HaulProof couldn’t text the driver, so the carrier was shown a button to text the link from their phone. You can also send it yourself.') + `\n\nDriver's link: ${link}` }).catch(() => {});
  res.json({ ok: true, driver: drv.name, phone, link, texted, consent: consent || C.has(phone), broker: askerOf(load), loadLabel: loadLabel(load) });
});

module.exports = { router, publicRouter, createRequest, flushRequests };
