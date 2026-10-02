// Sends the consignee their copy of the signed POD.
// If SMTP isn't configured, it logs what it *would* send (safe for dev/demo).
const nodemailer = require('nodemailer');
const { unsubToken, unsubTokenCat, filterOptedOut, filterStatusOptedOut } = require('./optout');

// Base URL for links in emails (unsubscribe, "view/join"). Same source of truth as the portal.
function portalUrl() {
  return (process.env.PORTAL_URL || 'https://haulproofepod.com').replace(/\/+$/, '');
}
// Where "still need help" requests are routed. Configurable so it can move off Brian's inbox later
// without a code change; defaults to his address for now.
function helpEmail() {
  return (process.env.HELP_EMAIL || 'bharris@callahantrans.com').trim();
}
function unsubUrl(email) { return portalUrl() + '/unsubscribe?t=' + unsubToken(email); }
function unsubUrlCat(email, cat) { return portalUrl() + '/unsubscribe?t=' + unsubTokenCat(email, cat); }
// Footer for STATUS (stage) notification emails — a separate unsubscribe from the signed-document copies.
function statusFooterText(email) {
  return `\n\n— — —\nThis is a HaulProof status update (separate from your signed-document emails).\nStop just these status updates: ${unsubUrlCat(email, 'status')}`;
}
function statusFooterHtml(email) {
  return `<hr style="border:none;border-top:1px solid #dde3ec;margin:22px 0 14px">`
    + `<p style="font:12px system-ui,Arial,sans-serif;color:#8a94a6;margin:0">`
    + `This is a HaulProof status update (separate from your signed-document emails). `
    + `<a href="${unsubUrlCat(email, 'status')}" style="color:#8a94a6">Stop just these status updates</a>.</p>`;
}

// Small footer appended to every emailed document: a one-click unsubscribe and a "view/join" invite.
function footerText(email) {
  return `\n\n— — —\nView and manage your delivery documents anytime — join HaulProof (free to view): ${portalUrl()}\n\nDon't want these emails? Unsubscribe: ${unsubUrl(email)}`;
}
function footerHtml(email) {
  const base = portalUrl();
  return `<hr style="border:none;border-top:1px solid #dde3ec;margin:22px 0 14px">`
    + `<p style="font:13px system-ui,Arial,sans-serif;color:#5a6577;margin:0 0 8px">`
    + `View and manage your delivery documents anytime — <a href="${base}" style="color:#1f6feb;font-weight:600;text-decoration:none">join HaulProof</a> (free to view).</p>`
    + `<p style="font:12px system-ui,Arial,sans-serif;color:#8a94a6;margin:0">`
    + `Don't want these emails? <a href="${unsubUrl(email)}" style="color:#8a94a6">Unsubscribe</a>.</p>`;
}

let transport;
function getTransport() {
  if (transport) return transport;
  if (process.env.SMTP_HOST) {
    transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
    });
  } else {
    // No SMTP configured — "stream" transport just logs the message.
    transport = nodemailer.createTransport({ streamTransport: true, newline: 'unix', buffer: true });
  }
  return transport;
}

async function emailPodCopy({ to, pod, filePath }) {
  if (!to || !to.length) return { sent: false, reason: 'no recipients' };
  // Legal/CAN-SPAM: drop anyone who has opted out BEFORE sending. Each remaining recipient gets their
  // own message so their unsubscribe link and List-Unsubscribe header carry a token for their address.
  const { allowed, blocked } = filterOptedOut(to);
  if (!allowed.length) {
    console.log(`[mailer] POD ${pod.id}: all ${blocked.length} recipient(s) opted out — nothing sent`);
    return { sent: false, reason: 'all recipients opted out', blocked };
  }
  const from = process.env.MAIL_FROM || 'documents@haulproofepod.com';
  const subject = `Signed delivery receipt — ${pod.poNumber ? 'PO ' + pod.poNumber : 'Load ' + (pod.loadNumber || pod.id)}`;
  const body = `Attached is the signed proof of delivery for ${pod.consignee || 'your shipment'}.\n\nThank you,\nHaulProof`;

  if (!process.env.SMTP_HOST) {
    console.log(`[mailer:simulated] would email POD ${pod.id} to ${allowed.join(', ')}` + (blocked.length ? ` (skipped opted-out: ${blocked.join(', ')})` : ''));
    return { sent: false, simulated: true, sentTo: allowed, blocked };
  }

  const results = [];
  for (const rcpt of allowed) {
    try {
      const info = await getTransport().sendMail({
        from,
        to: rcpt,
        subject,
        text: body + footerText(rcpt),
        html: `<p style="font:15px system-ui,Arial,sans-serif;color:#1f2733">Attached is the signed proof of delivery for ${pod.consignee || 'your shipment'}.</p><p style="font:15px system-ui,Arial,sans-serif;color:#1f2733">Thank you,<br>HaulProof</p>` + footerHtml(rcpt),
        attachments: [{ filename: (pod.filename || 'POD') + '.pdf', path: filePath }],
        headers: {
          'List-Unsubscribe': `<${unsubUrl(rcpt)}>`,
          'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
        },
      });
      results.push({ to: rcpt, messageId: info.messageId });
    } catch (e) {
      console.error('emailPodCopy to', rcpt, e.message);
    }
  }
  return { sent: results.length > 0, sentTo: results.map(r => r.to), blocked, results };
}

// Generic transactional email (access requests, approvals, questions). Fails soft if SMTP isn't set.
async function sendMail({ to, subject, text, html }) {
  const list = (Array.isArray(to) ? to : [to]).map(s => String(s || '').trim()).filter(Boolean);
  if (!list.length) return { sent: false, reason: 'no recipients' };
  const from = process.env.MAIL_FROM || 'documents@haulproofepod.com';
  try {
    const info = await getTransport().sendMail({ from, to: list.join(', '), subject: subject || 'HaulProof', text, html });
    if (!process.env.SMTP_HOST) { console.log(`[mailer:simulated] would email "${subject}" to ${list.join(', ')}`); return { sent: false, simulated: true }; }
    return { sent: true, messageId: info.messageId };
  } catch (e) { console.error('sendMail', e.message); return { sent: false, error: e.message }; }
}

// Stage/status notification email (driver uploaded, ready to sign, load complete). Honors the SEPARATE
// status opt-out list, so unsubscribing here never affects signed-document copies. Fails soft without SMTP.
async function sendStatusNotice({ to, subject, text, html }) {
  const list = (Array.isArray(to) ? to : [to]).map(s => String(s || '').trim()).filter(Boolean);
  if (!list.length) return { sent: false, reason: 'no recipients' };
  const { allowed, blocked } = filterStatusOptedOut(list);
  if (!allowed.length) return { sent: false, reason: 'all recipients opted out of status updates', blocked };
  const from = process.env.MAIL_FROM || 'documents@haulproofepod.com';
  if (!process.env.SMTP_HOST) {
    console.log(`[mailer:simulated] status "${subject}" to ${allowed.join(', ')}` + (blocked.length ? ` (skipped opted-out: ${blocked.join(', ')})` : ''));
    return { sent: false, simulated: true, sentTo: allowed, blocked };
  }
  const results = [];
  for (const rcpt of allowed) {
    try {
      const info = await getTransport().sendMail({
        from, to: rcpt, subject: subject || 'HaulProof update',
        text: (text || '') + statusFooterText(rcpt),
        html: (html || '') + statusFooterHtml(rcpt),
        headers: {
          'List-Unsubscribe': `<${unsubUrlCat(rcpt, 'status')}>`,
          'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
        },
      });
      results.push({ to: rcpt, messageId: info.messageId });
    } catch (e) { console.error('sendStatusNotice to', rcpt, e.message); }
  }
  return { sent: results.length > 0, sentTo: results.map(r => r.to), blocked, results };
}

module.exports = { emailPodCopy, sendMail, sendStatusNotice, helpEmail, portalUrl };
