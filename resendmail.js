// HaulProof email through Resend (resend.com), a sending service for app email such as signed PODs. Switched on by
// RESEND_API_KEY; it then takes priority over Microsoft Graph and SMTP. The sending domain (haulproofepod.com) must
// be verified in Resend. RESEND_FROM sets the From (default "HaulProof <documents@haulproofepod.com>"); replies go to
// HELP_EMAIL (Brian) unless a message sets its own reply-to, since the From address has no mailbox behind it.
// It is a drop-in for a nodemailer transport: sendMail(msg) takes the same message object.
const fs = require('fs');

const API = () => (process.env.RESEND_API_BASE || 'https://api.resend.com').replace(/\/+$/, '');
function resendConfigured() { return !!process.env.RESEND_API_KEY; }
function fromAddr() { return process.env.RESEND_FROM || 'HaulProof <documents@haulproofepod.com>'; }
const list = (v) => (Array.isArray(v) ? v : (v ? String(v).split(',') : [])).map(s => String(s).trim()).filter(Boolean);

async function sendMail(msg) {
  const body = {
    from: fromAddr(),
    to: list(msg.to),
    subject: msg.subject || 'HaulProof',
    reply_to: list(msg.replyTo).length ? list(msg.replyTo) : [(process.env.HELP_EMAIL || 'brian@haulproofepod.com').trim()],
  };
  if (list(msg.cc).length) body.cc = list(msg.cc);
  if (msg.text) body.text = msg.text;
  if (msg.html) body.html = msg.html;
  if (msg.headers) body.headers = msg.headers;
  if (msg.attachments && msg.attachments.length) {
    body.attachments = msg.attachments.map(a => ({
      filename: a.filename || 'attachment',
      content: (a.content != null ? Buffer.from(a.content) : fs.readFileSync(a.path)).toString('base64'),
    }));
  }
  // Resend allows a few requests a second; on "too many requests" wait and try again (a few times).
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(API() + '/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const t = await r.text();
    if (r.ok) { let id = null; try { id = JSON.parse(t).id; } catch (e) {} return { messageId: id, via: 'resend' }; }
    if (r.status === 429 && attempt < 4) { await new Promise(ok => setTimeout(ok, 700 * (attempt + 1))); continue; }
    let m = t; try { const j = JSON.parse(t); m = j.message || j.error || t; } catch (e) {}
    throw new Error('Resend ' + r.status + ': ' + String(m).slice(0, 300));
  }
}

module.exports = { resendConfigured, sendMail, fromAddr };
