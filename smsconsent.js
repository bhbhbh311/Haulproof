// Text-message consent (what Twilio's toll-free verification asks for). A driver's cell # only gets our texts once the
// DRIVER agreed, not just someone on their behalf:
//  - /sms: the public "HaulProof Driver Text Alerts" page, where a driver opts in themselves (confirmed at once)
//  - a reply of YES to our one opt-in text. A carrier's "Who's driving?" form or a dispatcher's "Text link" can only ask:
//    the driver gets a single text asking them to reply YES, and their HaulProof link is held until they do.
// STOP clears it (Twilio also blocks the number on its side). Twilio posts replies to /api/twilio/inbound.
const crypto = require('crypto');
const express = require('express');
const { db } = require('./db');

db.exec(`CREATE TABLE IF NOT EXISTS sms_consent (
  phone TEXT PRIMARY KEY, name TEXT, source TEXT NOT NULL, consentText TEXT NOT NULL, ip TEXT, at INTEGER NOT NULL)`);
// confirmedAt: when the driver themselves agreed (on /sms or by replying YES). askedAt: when we last texted the YES ask.
for (const c of ['confirmedAt INTEGER', 'askedAt INTEGER', 'stoppedAt INTEGER']) {
  try { db.exec(`ALTER TABLE sms_consent ADD COLUMN ${c}`); } catch (e) {}
}
// Texts waiting on the driver's YES (sendText arguments as JSON), sent in order when it comes
db.exec(`CREATE TABLE IF NOT EXISTS sms_pending (id TEXT PRIMARY KEY, phone TEXT NOT NULL, args TEXT NOT NULL, at INTEGER NOT NULL)`);

const PROGRAM = 'HaulProof Driver Text Alerts';
// The words the person agrees to on /sms (kept in step with sms.html)
const CONSENT_TEXT = 'I agree to receive text messages from Callahan Transportation, Inc. at the mobile number above about loads I haul ' +
  'for Callahan: rate confirmation links, my HaulProof driver link, pickup and delivery stops with a link to update dispatch, ' +
  'check-ins while the load is on the road, and reminders to send the signed BOL. ' +
  'Message frequency varies (usually 2–6 per load). Message and data rates may apply. ' +
  'Reply STOP to opt out at any time, HELP for help. Consent is not a condition of any purchase or of hauling a load.';
// The carrier's box on "Who's driving?" (kept in step with driver-request.html): a request to ask the driver, not consent
const CARRIER_CONSENT_TEXT = 'Text the driver their HaulProof link. They will first get one text from Callahan Transportation, Inc. ' +
  'asking them to reply YES to ' + PROGRAM + '; nothing else is sent until they do.';
const YES_CONSENT_TEXT = 'Replied YES to: ';
const STOP_RE = /^(STOP|STOPALL|UNSUBSCRIBE|CANCEL|END|QUIT|OPTOUT|OPT OUT|REVOKE)$/;
const YES_RE = /^(YES|Y|YEP|YEAH|YA|YES PLEASE|OK|OKAY|START|UNSTOP|SUBSCRIBE)$/;

const digits = v => String(v || '').replace(/\D/g, '').replace(/^1(?=\d{10}$)/, '');
const row = phone => db.prepare(`SELECT * FROM sms_consent WHERE phone = ?`).get(digits(phone));

// confirmed: true when it's the driver agreeing themselves. A carrier's request never overwrites a driver's own record.
function record({ phone, name, source, consentText, ip, confirmed = false }) {
  const p = digits(phone);
  if (p.length !== 10) return false;
  const now = Date.now();
  db.prepare(`INSERT INTO sms_consent (phone, name, source, consentText, ip, at, confirmedAt, stoppedAt) VALUES (?,?,?,?,?,?,?,NULL)
    ON CONFLICT(phone) DO UPDATE SET name = COALESCE(excluded.name, sms_consent.name), source = excluded.source, consentText = excluded.consentText,
      ip = excluded.ip, at = excluded.at, confirmedAt = COALESCE(excluded.confirmedAt, sms_consent.confirmedAt),
      stoppedAt = CASE WHEN excluded.confirmedAt IS NOT NULL THEN NULL ELSE sms_consent.stoppedAt END
    WHERE excluded.confirmedAt IS NOT NULL OR sms_consent.confirmedAt IS NULL`)
    .run(p, name || null, source, consentText, ip || null, now, confirmed ? now : null);
  return true;
}
// The driver agreed themselves and hasn't replied STOP since
const confirmed = phone => { const r = row(phone); return !!(r && r.confirmedAt && !r.stoppedAt); };
const has = confirmed;

// The one text a driver gets before they've agreed: who's asking, what they'd get, reply YES.
function askBody(sender, by) {
  return `${sender || 'Callahan Transportation'}: ${by ? by + ' gave us this number' : 'we have this number'} to text you about loads you haul for us ` +
    `(${PROGRAM}: your HaulProof driver link, load updates, BOL reminders). Reply YES to get them. ` +
    `Msg frequency varies, msg & data rates may apply. Reply STOP to opt out, HELP for help.`;
}

// Send a text to a driver, or, if they haven't agreed yet, hold it and ask them to reply YES (at most one ask a day).
// args: twilio.sendText arguments. Returns { sent: true, sid, to, status } or { askedYes: true, to, asked: bool }.
async function sendOrAsk(args, { sender, by } = {}) {
  const T = require('./twilio');
  const p = digits(args.to);
  if (confirmed(p)) return Object.assign({ sent: true }, await T.sendText(args));
  const r = row(p);
  if (r && r.stoppedAt) throw new T.SmsError('This driver replied STOP to our texts. Send them the link from your own phone.');
  // the same text held twice (button pressed again) goes out once
  const held = JSON.stringify(args);
  db.prepare(`DELETE FROM sms_pending WHERE phone = ? AND args = ?`).run(p, held);
  db.prepare(`INSERT INTO sms_pending (id, phone, args, at) VALUES (?,?,?,?)`).run(crypto.randomUUID(), p, held, Date.now());
  const recent = r && r.askedAt && r.askedAt > Date.now() - 24 * 60 * 60 * 1000;
  if (recent) return { askedYes: true, asked: false, to: T.toE164(p) };
  const out = await T.sendText(Object.assign({}, args, { body: askBody(sender, by), kind: 'optin' }));
  if (!r) record({ phone: p, name: args.driverName, source: 'asked', consentText: '(asked to reply YES; no consent yet)' });
  db.prepare(`UPDATE sms_consent SET askedAt = ? WHERE phone = ?`).run(Date.now(), p);
  return { askedYes: true, asked: true, to: out.to, status: out.status };
}

// ---- Public: the driver opts in on /sms ----
const publicRouter = express.Router();
publicRouter.post('/optin', express.json(), async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim().slice(0, 80);
  const phone = digits(b.phone);
  if (!name) return res.status(400).json({ error: 'Enter your name' });
  if (phone.length !== 10) return res.status(400).json({ error: 'Enter your 10-digit mobile number' });
  if (b.consent !== true) return res.status(400).json({ error: 'Check the box to agree to receive texts' });
  record({ phone, name, source: 'sms-page', consentText: CONSENT_TEXT, ip: req.ip, confirmed: true });
  await sendPending(phone);
  res.json({ ok: true, phone });
});

// Send everything held for this number (last 14 days), oldest first
async function sendPending(phone) {
  const p = digits(phone), T = require('./twilio');
  const rows = db.prepare(`SELECT * FROM sms_pending WHERE phone = ? ORDER BY at`).all(p);
  db.prepare(`DELETE FROM sms_pending WHERE phone = ?`).run(p);
  let sent = 0;
  for (const r of rows) {
    if (r.at < Date.now() - 14 * 24 * 60 * 60 * 1000) continue;
    try { await T.sendText(JSON.parse(r.args)); sent++; } catch (e) { console.error('pending text', e.message); }
  }
  return sent;
}

// ---- Twilio: a text came in (POST /api/twilio/inbound, signed by Twilio) ----
const twiml = msg => '<?xml version="1.0" encoding="UTF-8"?><Response>' +
  (msg ? '<Message>' + String(msg).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])) + '</Message>' : '') + '</Response>';
function inboundRoute(originOf) {
  const router = express.Router();
  router.post('/inbound', express.urlencoded({ extended: false }), async (req, res) => {
    const p = req.body || {};
    if (!require('./twilio').signatureOk(originOf(req) + req.originalUrl, p, req.get('X-Twilio-Signature'))) return res.status(403).send('bad signature');
    const from = digits(p.From), word = String(p.Body || '').trim().toUpperCase().replace(/[.!\s]+$/, '').replace(/\s+/g, ' ');
    res.type('text/xml');
    if (from.length !== 10) return res.send(twiml());
    if (STOP_RE.test(word)) {
      // Twilio sends the opt-out confirmation itself
      if (!row(from)) record({ phone: from, source: 'sms-reply', consentText: 'Replied ' + word });
      db.prepare(`UPDATE sms_consent SET stoppedAt = ? WHERE phone = ?`).run(Date.now(), from);
      db.prepare(`DELETE FROM sms_pending WHERE phone = ?`).run(from);
      return res.send(twiml());
    }
    if (YES_RE.test(word)) {
      const r = row(from);
      record({ phone: from, name: r && r.name, source: 'sms-reply', consentText: YES_CONSENT_TEXT + askBody('', ''), confirmed: true });
      const sent = await sendPending(from);
      return res.send(twiml(sent ? '' : `Thanks, you're signed up for ${PROGRAM} from Callahan Transportation. Your HaulProof link will come by text when you have a load. Reply STOP to opt out, HELP for help.`));
    }
    res.send(twiml());   // HELP is answered by Twilio; anything else needs no reply
  });
  return router;
}

module.exports = { publicRouter, inboundRoute, record, has, confirmed, sendOrAsk, sendPending, askBody, CONSENT_TEXT, CARRIER_CONSENT_TEXT, PROGRAM };
