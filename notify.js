// Stage/status notifications: who gets told when a document changes stage, and the messages themselves.
// These go out via mailer.sendStatusNotice, which honors the SEPARATE "status" opt-out list — so turning
// these off never affects a recipient's signed-document copies. All sends are best-effort (fire-and-forget):
// a notification problem must never block the upload/sign/assign action that triggered it.
const { db } = require('./db');
const { sendStatusNotice, portalUrl } = require('./mailer');

const esc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// The account-wide "Always notify" list (Team logins → master list), resolved to emails, for the given orgs.
function masterNotifyEmails(orgIds) {
  const ids = Array.from(new Set((orgIds || []).filter(Boolean).map(String)));
  if (!ids.length) return [];
  try {
    const ph = ids.map(() => '?').join(',');
    return db.prepare(
      `SELECT DISTINCT u.email FROM org_notify onf JOIN users u ON u.id = onf.userId
         WHERE onf.orgId IN (${ph}) AND u.email IS NOT NULL AND TRIM(u.email) != ''`
    ).all(...ids).map(r => r.email);
  } catch (e) { return []; }
}

function wrapHtml(lines) {
  return `<div style="font:15px system-ui,Arial,sans-serif;color:#1f2733">` +
    lines.map(l => `<p style="margin:0 0 10px">${l}</p>`).join('') +
    `<p style="margin:14px 0 0"><a href="${portalUrl()}" style="color:#1f6feb;font-weight:600;text-decoration:none">Open HaulProof →</a></p></div>`;
}

// A driver uploaded a document for dispatch → tell the Always-notify team it's waiting to be set up.
async function notifyDriverUploaded({ load, poNumber, driverName }) {
  try {
    const to = masterNotifyEmails([load && load.orgId, load && load.carrierId, load && load.brokerId]);
    if (!to.length) return;
    const po = poNumber || (load && load.poNumber) || '';
    const who = driverName || 'A driver';
    const subject = `New document to set up — PO ${po}`;
    const text = `${who} uploaded a document for PO ${po}. It's waiting in HaulProof for you to set up the signatures and release it to the driver.\n\nOpen HaulProof: ${portalUrl()}`;
    const html = wrapHtml([
      `<b>${esc(who)}</b> uploaded a document for <b>PO ${esc(po)}</b>.`,
      `It's waiting in HaulProof for you to set up the signatures and release it to the driver.`,
    ]);
    await sendStatusNotice({ to, subject, text, html });
  } catch (e) { /* best-effort */ }
}

// Every stop on a load is signed → tell the Always-notify team the load is complete.
async function notifyLoadComplete({ load, poNumber }) {
  try {
    const to = masterNotifyEmails([load && load.orgId, load && load.carrierId, load && load.brokerId]);
    if (!to.length) return;
    const po = poNumber || (load && load.poNumber) || '';
    const subject = `Load complete — PO ${po}`;
    const text = `All stops on PO ${po} are signed and complete. Signed documents have been emailed out.\n\nOpen HaulProof: ${portalUrl()}`;
    const html = wrapHtml([
      `All stops on <b>PO ${esc(po)}</b> are signed and complete.`,
      `The signed documents have been emailed out.`,
    ]);
    await sendStatusNotice({ to, subject, text, html });
  } catch (e) { /* best-effort */ }
}

// A document is ready for the assigned driver to sign → email that driver (once per driver per doc).
// Only fires when the doc is 'prepared' (released) AND assigned to a driver who has an email on file.
async function notifyDriverReady(podId) {
  try {
    const pod = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(podId);
    if (!pod || pod.status !== 'prepared' || !pod.assignedDriverId) return;
    if (pod.readyNotifiedTo && pod.readyNotifiedTo === pod.assignedDriverId) return;   // already told this driver
    const drv = db.prepare(`SELECT name, email FROM drivers WHERE id = ? AND active = 1`).get(pod.assignedDriverId);
    if (!drv || !drv.email || !/@/.test(drv.email)) return;   // no email → nothing to send (driver sees it in-app)
    const po = pod.poNumber || '';
    const subject = `Ready to sign — PO ${po}`;
    const text = `Hi ${drv.name || ''},\n\nA document for PO ${po} is ready for you to sign in HaulProof. Open your driver link and it'll be under "Your loads."\n`;
    const html = wrapHtml([
      `Hi ${esc(drv.name || '')},`,
      `A document for <b>PO ${esc(po)}</b> is ready for you to sign.`,
      `Open your HaulProof driver link — it's under <b>"Your loads."</b>`,
    ]);
    const r = await sendStatusNotice({ to: [drv.email], subject, text, html });
    // Stamp regardless of send outcome (sent, simulated, or opted-out) so we don't retry the same driver for this doc.
    if (r && (r.sent || r.simulated || r.reason)) {
      db.prepare(`UPDATE pods SET readyNotifiedTo = ? WHERE id = ?`).run(pod.assignedDriverId, pod.id);
    }
  } catch (e) { /* best-effort */ }
}

module.exports = { masterNotifyEmails, notifyDriverUploaded, notifyLoadComplete, notifyDriverReady };
