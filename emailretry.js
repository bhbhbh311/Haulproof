// Signed-copy email delivery tracking. When the email service refuses a signed document's copy (bad login, out of
// credits, mailbox full…), the document is marked 'failed' (or 'partial' if only some recipients failed), the
// failed addresses are kept, and they're retried on a backoff. Dispatch sees a red "Email failed" badge with a
// Resend button (POST /api/pods/:id/resend-email).
const express = require('express');
const { db } = require('./db');
const { requireAuth } = require('./auth');
const { emailPodCopy } = require('./mailer');
const { logEvent } = require('./events');

const RETRY_MINUTES = [30, 60, 120, 240, 480];   // after the 1st failure: 30 min, then 1h, 2h, 4h, 8h — then stop
const MAX_ATTEMPTS = RETRY_MINUTES.length + 1;

function safeJson(s) { try { return JSON.parse(s); } catch (e) { return null; } }

// Record how a signed-copy send went. `intended` = everyone it should have gone to; `mail` = emailPodCopy's result.
// A simulated send (no SMTP set up) or a send with no recipients records nothing.
function recordEmailResult(podId, intended, mail, { manual } = {}) {
  try {
    if (!mail || mail.simulated) return;
    const failed = (mail.failed || []).map(f => f.to);
    const prev = db.prepare(`SELECT emailAttempts FROM pods WHERE id = ?`).get(podId) || {};
    const attempts = manual ? 1 : ((prev.emailAttempts || 0) + 1);
    if (!failed.length) {
      if (mail.sent) db.prepare(`UPDATE pods SET emailStatus='sent', emailError=NULL, emailFailedTo=NULL, emailAttempts=?, emailNextRetryAt=NULL WHERE id=?`).run(attempts, podId);
      return;
    }
    const status = mail.sent ? 'partial' : 'failed';
    const next = attempts < MAX_ATTEMPTS ? Date.now() + RETRY_MINUTES[Math.min(attempts - 1, RETRY_MINUTES.length - 1)] * 60000 : null;
    db.prepare(`UPDATE pods SET emailStatus=?, emailError=?, emailFailedTo=?, emailAttempts=?, emailNextRetryAt=? WHERE id=?`)
      .run(status, String(mail.error || 'Email service refused the message').slice(0, 300), JSON.stringify(failed), attempts, next, podId);
  } catch (e) { console.error('[email-retry] record failed', e.message); }
}

// Send the copy again to the addresses that didn't get it (or, if none are recorded, to everyone it was meant for).
// `only`: dispatch picked which of the intended addresses to try (unticked ones drop out of this copy's retries).
async function resendPod(pod, { manual, actor, only } = {}) {
  const { combinedPodBytes } = require('./pods');   // lazy: pods.js requires this module
  const to = Array.isArray(only) ? only : (safeJson(pod.emailFailedTo) || safeJson(pod.recipients) || []);
  if (!to.length) return { error: 'No recipients on this document' };
  let combined = null; try { combined = await combinedPodBytes(pod); } catch (e) {}
  const mail = await emailPodCopy({ to, pod: { id: pod.id, poNumber: pod.poNumber, loadNumber: pod.loadNumber, consignee: pod.consignee, docType: pod.docType, filename: pod.filename, signedAt: pod.signedAt }, filePath: pod.filepath, contentBytes: combined });
  recordEmailResult(pod.id, to, mail, { manual });
  if (mail.sent && pod.status === 'signed') { try { db.prepare(`UPDATE pods SET status='emailed' WHERE id=?`).run(pod.id); } catch (e) {} }
  try {
    const stopTag = pod.stopNumber ? ('Stop ' + pod.stopNumber + ' — ') : '';
    const failed = (mail.failed || []).map(f => f.to);
    const detail = mail.simulated ? stopTag + 'Email resend simulated (SMTP not configured)'
      : failed.length ? stopTag + (manual ? 'Resend' : 'Automatic retry') + ' — still NOT sent to ' + failed.join(', ') + (mail.error ? ' (' + mail.error + ')' : '') + ((mail.sentTo || []).length ? '; sent to ' + mail.sentTo.join(', ') : '')
      : stopTag + (manual ? 'Resent' : 'Automatic retry sent') + ' to ' + (mail.sentTo || to).join(', ');
    logEvent({ orgId: pod.orgId, loadId: pod.loadId, poNumber: pod.poNumber, type: 'emailed', detail, actor: actor || 'HaulProof' });
  } catch (e) {}
  return mail;
}

// Background retries for failed sends that are due.
let _running = false;
async function retryDue() {
  if (_running) return; _running = true;
  try {
    // (Deleted documents leave the pods table, so they're never retried.)
    const due = db.prepare(`SELECT * FROM pods WHERE emailStatus IN ('failed','partial') AND emailNextRetryAt IS NOT NULL AND emailNextRetryAt <= ? LIMIT 20`).all(Date.now());
    for (const pod of due) {
      const r = await resendPod(pod, { manual: false });
      console.log(`[email-retry] pod=${pod.id} attempt=${(pod.emailAttempts || 0) + 1} sent=${!!(r && r.sent)} failed=${((r && r.failed) || []).length}`);
    }
  } catch (e) { console.error('[email-retry]', e.message); }
  finally { _running = false; }
}
function startRetryLoop() { setInterval(retryDue, 5 * 60000).unref(); setTimeout(retryDue, 60000).unref(); }

const router = express.Router();
router.post('/:id/resend-email', requireAuth, express.json(), async (req, res) => {
  const pods = require('./pods');
  const pod = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!pods.canAccess(req, pod)) return res.status(404).json({ error: 'Document not found' });
  if (!pod.filepath) return res.status(404).json({ error: 'The document file is not available' });
  // Optional subset: only addresses this copy was already meant for (its recipients or the ones that failed).
  let only;
  if (Array.isArray(req.body && req.body.to)) {
    const allowed = new Set([...(safeJson(pod.recipients) || []), ...(safeJson(pod.emailFailedTo) || [])].map(e => String(e).toLowerCase()));
    only = req.body.to.map(e => String(e || '').trim()).filter(e => allowed.has(e.toLowerCase()));
    if (!only.length) return res.status(400).json({ error: 'Tick at least one address' });
  }
  try {
    const mail = await resendPod(pod, { manual: true, actor: req.user.email, only });
    if (mail.error && !mail.failed) return res.status(400).json({ error: mail.error });
    const failed = (mail.failed || []).map(f => f.to);
    res.json({ ok: !failed.length, simulated: !!mail.simulated, sentTo: mail.sentTo || [], failed, error: failed.length ? mail.error : undefined });
  } catch (e) { console.error('resend-email', e); res.status(500).json({ error: 'Could not resend the email' }); }
});

module.exports = { recordEmailResult, resendPod, startRetryLoop, router };
