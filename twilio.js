// Text messages through Twilio — sent by the server, so "Text link" works from a PC, not just a phone.
// On only when TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM (or TWILIO_MESSAGING_SERVICE_SID) are set in Render.
// Until then the portal keeps its old behaviour: "Text link" opens Messages on the device with the text filled in.
// Every attempt is logged in sms_log (who sent it, to which number, Twilio's id or the error).
const crypto = require('crypto');
const { db } = require('./db');

db.exec(`CREATE TABLE IF NOT EXISTS sms_log (
  id TEXT PRIMARY KEY, orgId TEXT, driverId TEXT, toNumber TEXT NOT NULL, body TEXT, status TEXT NOT NULL,
  twilioSid TEXT, error TEXT, sentBy TEXT, at INTEGER NOT NULL)`);

// Delivery tracking: each text asks Twilio to report its final status (delivered / undelivered / failed) back to
// /api/twilio/status. loadId and notifyEmail say which load's history gets the result and who hears when it fails.
// kind 'optin': the "reply YES" text a driver gets before their link (see smsconsent.js)
for (const c of ['loadId TEXT', 'notifyEmail TEXT', 'errorCode TEXT', 'link TEXT', 'driverName TEXT', 'updatedAt INTEGER', 'kind TEXT']) {
  try { db.exec(`ALTER TABLE sms_log ADD COLUMN ${c}`); } catch (e) {}
}

const API = () => (process.env.TWILIO_API_BASE || 'https://api.twilio.com').replace(/\/+$/, '');
const configured = () => !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && (process.env.TWILIO_FROM || process.env.TWILIO_MESSAGING_SERVICE_SID));

// US numbers only: 816-555-0100, (816) 555-0100, 1-816… and +1… all become +18165550100
function toE164(phone) {
  let n = String(phone || '').replace(/\D/g, '');
  if (n.length === 10) n = '1' + n;
  return (n.length === 11 && n[0] === '1') ? '+' + n : null;
}

class SmsError extends Error {}

// callbackBase: the site's own address (https://haulproofepod.com); Twilio posts the delivery result there.
async function sendText({ to, body, orgId = null, driverId = null, sentBy = null, loadId = null, notifyEmail = null, link = null, driverName = null, callbackBase = null, kind = null }, { fetchFn = fetch } = {}) {
  if (!configured()) throw new SmsError('Texting isn’t set up yet (Twilio settings in Render)');
  const num = toE164(to);
  if (!num) throw new SmsError('That phone number doesn’t look like a US mobile number');
  const form = new URLSearchParams({ To: num, Body: body });
  if (process.env.TWILIO_MESSAGING_SERVICE_SID) form.set('MessagingServiceSid', process.env.TWILIO_MESSAGING_SERVICE_SID);
  else form.set('From', process.env.TWILIO_FROM);
  if (callbackBase) form.set('StatusCallback', callbackBase.replace(/\/+$/, '') + '/api/twilio/status');
  const log = (status, sid, error) => db.prepare(`INSERT INTO sms_log (id, orgId, driverId, toNumber, body, status, twilioSid, error, sentBy, at, loadId, notifyEmail, link, driverName, kind)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(crypto.randomUUID(), orgId, driverId, num, body, status, sid || null, error || null, sentBy, Date.now(), loadId, notifyEmail, link, driverName, kind);
  let r, j = {};
  try {
    r = await fetchFn(`${API()}/2010-04-01/Accounts/${encodeURIComponent(process.env.TWILIO_ACCOUNT_SID)}/Messages.json`, {
      method: 'POST',
      headers: { Authorization: 'Basic ' + Buffer.from(process.env.TWILIO_ACCOUNT_SID + ':' + process.env.TWILIO_AUTH_TOKEN).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString() });
    j = await r.json().catch(() => ({}));
  } catch (e) { log('failed', null, e.message); throw new SmsError('Couldn’t reach Twilio: ' + e.message); }
  if (!r.ok) {
    const msg = j.message || ('Twilio ' + r.status);
    log('failed', null, msg);
    // 30032/30034 and friends: the number isn't verified/registered for texting yet
    throw new SmsError(/verif|regist|30032|30034|21610|21408/i.test(msg + ' ' + (j.code || '')) ? 'Twilio refused it: ' + msg + ' (the sending number may still be waiting on Twilio’s toll-free verification)' : 'Twilio refused it: ' + msg);
  }
  log(j.status || 'queued', j.sid, null);
  return { sid: j.sid, to: num, status: j.status || 'queued' };
}

// ---- Twilio's delivery report: POST /api/twilio/status (form fields MessageSid, MessageStatus, ErrorCode) ----
// Only Twilio can post it: the X-Twilio-Signature header must be the HMAC-SHA1 (auth token) of the URL plus the sorted
// fields. The final result goes on the text's sms_log row and the load's history; a text that didn't get through also
// emails whoever should hear (the dispatcher) with the driver's link to send from their own phone.
const FINAL = new Set(['delivered', 'undelivered', 'failed']);
const WHY = {
  30032: 'the HaulProof texting number is still waiting on Twilio’s toll-free verification',
  30034: 'the HaulProof texting number isn’t registered for texting yet',
  30003: 'the phone is off or can’t be reached', 30005: 'that number doesn’t exist or isn’t a cell phone',
  30006: 'that number can’t get texts (landline or blocked)', 30007: 'the phone company filtered it as spam',
  30008: 'unknown error from the phone company', 21610: 'the driver had replied STOP to our texts',
};
function signatureOk(url, params, sig) {
  const tok = process.env.TWILIO_AUTH_TOKEN || '';
  if (!tok || !sig) return false;
  const data = url + Object.keys(params).sort().map(k => k + params[k]).join('');
  const want = crypto.createHmac('sha1', tok).update(Buffer.from(data, 'utf8')).digest('base64');
  const a = Buffer.from(want), b = Buffer.from(String(sig));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const fmtPhone = n => String(n || '').replace(/^\+1/, '').replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3');
function statusRoute(originOf) {
  const express = require('express');
  const router = express.Router();
  router.post('/status', express.urlencoded({ extended: false }), (req, res) => {
    const p = req.body || {};
    if (!signatureOk(originOf(req) + req.originalUrl, p, req.get('X-Twilio-Signature'))) return res.status(403).send('bad signature');
    const row = p.MessageSid ? db.prepare(`SELECT * FROM sms_log WHERE twilioSid = ?`).get(String(p.MessageSid)) : null;
    if (!row) return res.status(200).send('ok');   // not one of ours (or already gone): nothing to do
    const status = String(p.MessageStatus || p.SmsStatus || '').toLowerCase();
    const code = p.ErrorCode ? String(p.ErrorCode) : null;
    const wasFinal = FINAL.has(row.status);
    db.prepare(`UPDATE sms_log SET status = ?, errorCode = COALESCE(?, errorCode), updatedAt = ? WHERE id = ?`).run(status || row.status, code, Date.now(), row.id);
    if (!FINAL.has(status) || wasFinal) return res.status(200).send('ok');   // still on its way, or already reported
    const who = row.driverName || 'the driver', ph = fmtPhone(row.toNumber);
    const why = code ? (WHY[code] || 'Twilio error ' + code) : '';
    const load = row.loadId ? db.prepare(`SELECT id, orgId, poNumber, loadNumber FROM loads WHERE id = ?`).get(row.loadId) : null;
    if (load) {
      try {
        require('./events').logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'note', actor: 'Twilio',
          detail: status === 'delivered' ? (row.kind === 'optin' ? `Texted ${who} (${ph}) asking them to reply YES to get HaulProof texts; their link goes out when they do`
              : `Text with the HaulProof link delivered to ${who} (${ph})`)
            : `Text ${row.kind === 'optin' ? 'asking to reply YES for the HaulProof link' : 'with the HaulProof link'} NOT delivered to ${who} (${ph})${why ? ': ' + why : ''}. Send the driver the link from your phone` + (row.link ? ': ' + row.link : '') });
      } catch (e) {}
    }
    if (status !== 'delivered' && row.notifyEmail) {
      const what = load ? `load ${load.loadNumber && load.loadNumber !== load.poNumber ? load.loadNumber + ' (PO ' + load.poNumber + ')' : load.poNumber}` : 'their load';
      require('./mailer').sendMail({ to: row.notifyEmail, subject: `Text didn't reach ${who} for ${what}: send the HaulProof link yourself`,
        text: `HaulProof's text to ${who} (${ph}) with their driver link for ${what} was not delivered${why ? ': ' + why : ''}.\n\n` +
          `Please text or call ${who} and send this link from your own phone:\n${row.link || '(open the driver in HaulProof and use Copy link)'}\n\n` +
          `They tap it, pick a PIN, and the load is there.` }).catch(() => {});
    }
    res.status(200).send('ok');
  });
  return router;
}

module.exports = { configured, toE164, sendText, SmsError, statusRoute, signatureOk };
