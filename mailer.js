// Sends the consignee their copy of the signed POD.
// If SMTP isn't configured, it logs what it *would* send (safe for dev/demo).
const nodemailer = require('nodemailer');

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
  const from = process.env.MAIL_FROM || 'documents@callahantrans.com';
  const info = await getTransport().sendMail({
    from,
    to: to.join(', '),
    subject: `Signed delivery receipt — ${pod.poNumber ? 'PO ' + pod.poNumber : 'Load ' + (pod.loadNumber || pod.id)}`,
    text: `Attached is the signed proof of delivery for ${pod.consignee || 'your shipment'}.\n\nThank you,\nCallahan Transportation`,
    attachments: [{ filename: (pod.filename || 'POD') + '.pdf', path: filePath }],
  });
  if (!process.env.SMTP_HOST) {
    console.log(`[mailer:simulated] would email POD ${pod.id} to ${to.join(', ')}`);
    return { sent: false, simulated: true };
  }
  return { sent: true, messageId: info.messageId };
}

// Generic transactional email (access requests, approvals, questions). Fails soft if SMTP isn't set.
async function sendMail({ to, subject, text, html }) {
  const list = (Array.isArray(to) ? to : [to]).map(s => String(s || '').trim()).filter(Boolean);
  if (!list.length) return { sent: false, reason: 'no recipients' };
  const from = process.env.MAIL_FROM || 'documents@callahantrans.com';
  try {
    const info = await getTransport().sendMail({ from, to: list.join(', '), subject: subject || 'HaulProof', text, html });
    if (!process.env.SMTP_HOST) { console.log(`[mailer:simulated] would email "${subject}" to ${list.join(', ')}`); return { sent: false, simulated: true }; }
    return { sent: true, messageId: info.messageId };
  } catch (e) { console.error('sendMail', e.message); return { sent: false, error: e.message }; }
}

module.exports = { emailPodCopy, sendMail };
