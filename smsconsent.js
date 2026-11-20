// Text-message consent (what Twilio's toll-free verification asks for): a driver's cell # is only texted after
// someone agreed to it on a customer-facing form, with the program's terms shown right there.
// Two places collect it, both recorded here with the exact words agreed to:
//  - /sms: the public "HaulProof Driver Text Alerts" page, where a driver opts in themselves (and reads the terms)
//  - the carrier's "Who's driving?" form (/driver-request), where the carrier confirms the driver agreed
const express = require('express');
const { db } = require('./db');

db.exec(`CREATE TABLE IF NOT EXISTS sms_consent (
  phone TEXT PRIMARY KEY, name TEXT, source TEXT NOT NULL, consentText TEXT NOT NULL, ip TEXT, at INTEGER NOT NULL)`);

const PROGRAM = 'HaulProof Driver Text Alerts';
// The words the person agrees to (shown next to the checkbox on both forms; kept in step with sms.html)
const CONSENT_TEXT = 'I agree to receive text messages from Callahan Transportation, Inc. at the mobile number above about loads I haul ' +
  'for Callahan: rate confirmation links, my HaulProof driver link, pickup and delivery stops with a link to update dispatch, ' +
  'check-ins while the load is on the road, and reminders to send the signed BOL. ' +
  'Message frequency varies (usually 2–6 per load). Message and data rates may apply. ' +
  'Reply STOP to opt out at any time, HELP for help. Consent is not a condition of any purchase or of hauling a load.';
const CARRIER_CONSENT_TEXT = 'The driver agreed to receive text messages from Callahan Transportation, Inc. through HaulProof ' +
  '(' + PROGRAM + ') at this number: their HaulProof driver link, load assignments and delivery/BOL updates. ' +
  'Message frequency varies. Message and data rates may apply. Reply STOP to opt out, HELP for help.';

const digits = v => String(v || '').replace(/\D/g, '').replace(/^1(?=\d{10}$)/, '');

function record({ phone, name, source, consentText, ip }) {
  const p = digits(phone);
  if (p.length !== 10) return false;
  db.prepare(`INSERT INTO sms_consent (phone, name, source, consentText, ip, at) VALUES (?,?,?,?,?,?)
    ON CONFLICT(phone) DO UPDATE SET name = excluded.name, source = excluded.source, consentText = excluded.consentText, ip = excluded.ip, at = excluded.at`)
    .run(p, name || null, source, consentText, ip || null, Date.now());
  return true;
}
const has = phone => !!db.prepare(`SELECT 1 FROM sms_consent WHERE phone = ?`).get(digits(phone));

// ---- Public: the driver opts in on /sms ----
const publicRouter = express.Router();
publicRouter.post('/optin', express.json(), (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim().slice(0, 80);
  const phone = digits(b.phone);
  if (!name) return res.status(400).json({ error: 'Enter your name' });
  if (phone.length !== 10) return res.status(400).json({ error: 'Enter your 10-digit mobile number' });
  if (b.consent !== true) return res.status(400).json({ error: 'Check the box to agree to receive texts' });
  record({ phone, name, source: 'sms-page', consentText: CONSENT_TEXT, ip: req.ip });
  res.json({ ok: true, phone });
});

module.exports = { publicRouter, record, has, CONSENT_TEXT, CARRIER_CONSENT_TEXT, PROGRAM };
