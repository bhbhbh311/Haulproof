// Sends email through Microsoft Graph (the mailbox's own Microsoft 365 account) instead of SMTP.
// Switched on by MS_TENANT_ID + MS_CLIENT_ID + MS_CLIENT_SECRET (an Entra app with the Mail.Send
// application permission). Mail goes out from MS_SENDER, or the address in MAIL_FROM.
// It is a drop-in for a nodemailer transport: sendMail(msg) takes the same message object.
// The message is built as MIME so headers like List-Unsubscribe survive. Graph caps a request at
// about 4 MB, so a big message is sent as a draft plus attachment uploads (in chunks), then sent.
const fs = require('fs');
const MailComposer = require('nodemailer/lib/mail-composer');

const LOGIN = () => (process.env.MS_LOGIN_BASE || 'https://login.microsoftonline.com').replace(/\/+$/, '');
const GRAPH = () => (process.env.MS_GRAPH_BASE || 'https://graph.microsoft.com/v1.0').replace(/\/+$/, '');
const DIRECT_MAX = 3 * 1024 * 1024;     // raw MIME bytes we send in one request (base64 grows it by a third)
const SMALL_ATTACH = 3 * 1024 * 1024;   // attachments under this go in one call; bigger ones use an upload session
const CHUNK = 320 * 1024 * 10;          // upload-session chunks must be multiples of 320 KB

function graphConfigured() {
  return !!(process.env.MS_TENANT_ID && process.env.MS_CLIENT_ID && process.env.MS_CLIENT_SECRET);
}
function addressOnly(s) { const m = String(s || '').match(/<([^>]+)>/); return (m ? m[1] : String(s || '')).trim(); }
function sender() { return addressOnly(process.env.MS_SENDER || process.env.MAIL_FROM); }

let tok = null;
async function token() {
  if (tok && tok.exp > Date.now() + 60000) return tok.value;
  const r = await fetch(LOGIN() + '/' + encodeURIComponent(process.env.MS_TENANT_ID) + '/oauth2/v2.0/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: process.env.MS_CLIENT_ID, client_secret: process.env.MS_CLIENT_SECRET,
      scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error('Microsoft sign-in failed: ' + (j.error_description || j.error || r.status));
  tok = { value: j.access_token, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000 };
  return tok.value;
}
async function call(method, path, { body, type = 'application/json', headers = {}, absolute } = {}) {
  const r = await fetch(absolute ? path : GRAPH() + path, { method, body,
    headers: { ...(absolute ? {} : { Authorization: 'Bearer ' + await token() }), ...(body != null ? { 'Content-Type': type } : {}), ...headers } });
  const text = await r.text();
  if (!r.ok) { let m = text; try { const j = JSON.parse(text); m = (j.error && (j.error.message || j.error.code)) || text; } catch (e) {} throw new Error('Microsoft Graph ' + r.status + ': ' + String(m).slice(0, 300)); }
  try { return text ? JSON.parse(text) : {}; } catch (e) { return {}; }
}
function mime(msg) { return new Promise((ok, bad) => new MailComposer(msg).compile().build((e, b) => e ? bad(e) : ok(b))); }
function attachmentBytes(a) { return a.content != null ? Buffer.from(a.content) : fs.readFileSync(a.path); }

async function sendMail(msg) {
  const from = sender();
  if (!from) throw new Error('Set MS_SENDER or MAIL_FROM to the mailbox HaulProof sends from');
  const box = '/users/' + encodeURIComponent(from);
  // The From line must be the mailbox doing the sending (Microsoft refuses "send on behalf of" another mailbox).
  msg = { ...msg, from: process.env.MS_SENDER || process.env.MAIL_FROM };
  const full = await mime(msg);
  if (full.length <= DIRECT_MAX) {
    await call('POST', box + '/sendMail', { body: full.toString('base64'), type: 'text/plain' });
    return { messageId: null, via: 'graph' };
  }
  // Too big for one request: draft without the attachments, add them, then send.
  const attachments = (msg.attachments || []).map(a => ({ name: a.filename || 'attachment', bytes: attachmentBytes(a), type: a.contentType || 'application/octet-stream' }));
  const draft = await call('POST', box + '/messages', { body: (await mime({ ...msg, attachments: [] })).toString('base64'), type: 'text/plain' });
  try {
    for (const a of attachments) {
      if (a.bytes.length < SMALL_ATTACH) {
        await call('POST', box + '/messages/' + draft.id + '/attachments', { body: JSON.stringify({ '@odata.type': '#microsoft.graph.fileAttachment', name: a.name, contentType: a.type, contentBytes: a.bytes.toString('base64') }) });
        continue;
      }
      const s = await call('POST', box + '/messages/' + draft.id + '/attachments/createUploadSession',
        { body: JSON.stringify({ AttachmentItem: { attachmentType: 'file', name: a.name, size: a.bytes.length, contentType: a.type } }) });
      for (let at = 0; at < a.bytes.length; at += CHUNK) {
        const part = a.bytes.subarray(at, Math.min(at + CHUNK, a.bytes.length));
        await call('PUT', s.uploadUrl, { absolute: true, body: part, type: 'application/octet-stream',
          headers: { 'Content-Range': 'bytes ' + at + '-' + (at + part.length - 1) + '/' + a.bytes.length } });
      }
    }
    await call('POST', box + '/messages/' + draft.id + '/send');
  } catch (e) {
    try { await call('DELETE', box + '/messages/' + draft.id); } catch (_) {}
    throw e;
  }
  return { messageId: null, via: 'graph' };
}

module.exports = { graphConfigured, sendMail };
