// Text messages through Twilio — sent by the server, so "Text link" works from a PC, not just a phone.
// On only when TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM (or TWILIO_MESSAGING_SERVICE_SID) are set in Render.
// Until then the portal keeps its old behaviour: "Text link" opens Messages on the device with the text filled in.
// Every attempt is logged in sms_log (who sent it, to which number, Twilio's id or the error).
const crypto = require('crypto');
const { db } = require('./db');

db.exec(`CREATE TABLE IF NOT EXISTS sms_log (
  id TEXT PRIMARY KEY, orgId TEXT, driverId TEXT, toNumber TEXT NOT NULL, body TEXT, status TEXT NOT NULL,
  twilioSid TEXT, error TEXT, sentBy TEXT, at INTEGER NOT NULL)`);

const API = () => (process.env.TWILIO_API_BASE || 'https://api.twilio.com').replace(/\/+$/, '');
const configured = () => !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && (process.env.TWILIO_FROM || process.env.TWILIO_MESSAGING_SERVICE_SID));

// US numbers only: 816-555-0100, (816) 555-0100, 1-816… and +1… all become +18165550100
function toE164(phone) {
  let n = String(phone || '').replace(/\D/g, '');
  if (n.length === 10) n = '1' + n;
  return (n.length === 11 && n[0] === '1') ? '+' + n : null;
}

class SmsError extends Error {}

async function sendText({ to, body, orgId = null, driverId = null, sentBy = null }, { fetchFn = fetch } = {}) {
  if (!configured()) throw new SmsError('Texting isn’t set up yet (Twilio settings in Render)');
  const num = toE164(to);
  if (!num) throw new SmsError('That phone number doesn’t look like a US mobile number');
  const form = new URLSearchParams({ To: num, Body: body });
  if (process.env.TWILIO_MESSAGING_SERVICE_SID) form.set('MessagingServiceSid', process.env.TWILIO_MESSAGING_SERVICE_SID);
  else form.set('From', process.env.TWILIO_FROM);
  const log = (status, sid, error) => db.prepare(`INSERT INTO sms_log (id, orgId, driverId, toNumber, body, status, twilioSid, error, sentBy, at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(crypto.randomUUID(), orgId, driverId, num, body, status, sid || null, error || null, sentBy, Date.now());
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

module.exports = { configured, toE164, sendText, SmsError };
