// Account setup checklist (Dashboard) and the monthly summary email to each company's admins.
const fs = require('fs');
const path = require('path');
const express = require('express');
const { db, DATA_DIR } = require('./db');
const { requireAuth } = require('./auth');
const { resolveUiFlags } = require('./uiflags');

const router = express.Router();
const STATE_FILE = path.join(DATA_DIR, 'monthly-state.json');
const SEND_HOUR_UTC = Number(process.env.MONTHLY_HOUR_UTC || 14);   // ~8–9 am Central on the 1st
const notHelp = (e) => e && !/^haulproofhelp\+/i.test(e);

// ---- "Set up your account": team logins, drivers, carriers & brokers — what's done so far for this company. ----
router.get('/setup-status', requireAuth, (req, res) => {
  const orgId = req.user.orgId;
  if (!orgId) return res.json({ applies: false });
  const org = db.prepare(`SELECT id, name, kind FROM orgs WHERE id = ?`).get(orgId) || {};
  const team = db.prepare(`SELECT email FROM users WHERE orgId = ?`).all(orgId).filter(u => notHelp(u.email)).length;
  const drivers = db.prepare(`SELECT COUNT(*) c FROM drivers WHERE orgId = ? AND active = 1`).get(orgId).c;
  const carriers = db.prepare(`SELECT COUNT(*) c FROM broker_carriers WHERE brokerId = ?`).get(orgId).c;
  const loads = db.prepare(`SELECT COUNT(*) c FROM loads WHERE orgId = ? OR brokerId = ?`).get(orgId, orgId).c;
  const kind = org.kind || 'customer';
  res.json({ applies: true, kind, name: org.name, team, drivers, carriers, loads,
    steps: { team: team > 1, drivers: drivers > 0, carriers: kind === 'carrier' ? null : carriers > 0 } });
});

// ---- Monthly summary: what HaulProof did for a company last month. ----
function monthRange(d) {   // the calendar month before date d (UTC)
  const end = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
  const start = Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1);
  return { start, end, label: new Date(start).toLocaleString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' }), key: new Date(start).toISOString().slice(0, 7) };
}
function buildMonthly(orgId, range) {
  const { start, end } = range;
  const loads = db.prepare(`SELECT l.id, l.customer,
      (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.status NOT IN ('parked','not_used')) AS total,
      (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.status IN ('signed','emailed')) AS done,
      (SELECT MAX(signedAt) FROM pods p WHERE p.loadId = l.id AND p.status IN ('signed','emailed')) AS lastSigned
    FROM loads l WHERE (l.orgId = ? OR l.brokerId = ?) AND l.createdAt < ?`).all(orgId, orgId, end);
  const delivered = loads.filter(l => l.total > 0 && l.done >= l.total && l.lastSigned >= start && l.lastSigned < end);
  const pods = db.prepare(`SELECT p.status, p.emailStatus, p.emailFailedTo, p.signedByDriverId, p.driver FROM pods p
    WHERE (p.orgId = ? OR p.loadId IN (SELECT id FROM loads WHERE brokerId = ?)) AND p.status IN ('signed','emailed') AND p.signedAt >= ? AND p.signedAt < ?`).all(orgId, orgId, start, end);
  const emailed = pods.filter(p => p.emailStatus === 'sent' || p.status === 'emailed').length;
  const emailFailed = pods.filter(p => p.emailFailedTo && p.emailFailedTo !== '[]').length;
  const drivers = new Set(pods.map(p => p.signedByDriverId || (p.driver || '').trim().toLowerCase()).filter(Boolean)).size;
  const rechecked = db.prepare(`SELECT COUNT(*) c FROM broker_carriers bc JOIN orgs o ON o.id = bc.carrierId WHERE bc.brokerId = ? AND o.fmcsaSnapshotAt >= ? AND o.fmcsaSnapshotAt < ?`).get(orgId, start, end).c;
  const byCust = {}; delivered.forEach(l => { const k = (l.customer || '').trim(); if (k) byCust[k] = (byCust[k] || 0) + 1; });
  const topCustomers = Object.entries(byCust).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, n]) => ({ name, loads: n }));
  const alerts = db.prepare(`SELECT DISTINCT carrierName FROM carrier_alerts WHERE ownerOrgId = ? AND type = 'flagged' AND createdAt >= ? AND createdAt < ?`).all(orgId, start, end).map(r => r.carrierName);
  return { delivered: delivered.length, signed: pods.length, emailed, emailFailed, drivers, rechecked, topCustomers, alerts };
}
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function renderMonthly(org, range, m) {
  const { portalUrl } = require('./mailer');
  const link = portalUrl() + '/app';
  const subject = 'Your ' + range.label + ' on HaulProof — ' + m.delivered + ' load' + (m.delivered === 1 ? '' : 's') + ' delivered';
  const tiles = [[m.delivered, 'Loads delivered'], [m.signed, 'Documents signed'], [m.emailed, 'Signed copies emailed'], [m.drivers, 'Drivers active'], [m.rechecked, 'Carriers re-checked with FMCSA']];
  const look = [];
  if (m.alerts.length) look.push(m.alerts.length + ' carrier' + (m.alerts.length === 1 ? '' : 's') + ' changed on FMCSA (' + m.alerts.slice(0, 3).join(', ') + (m.alerts.length > 3 ? '…' : '') + ') — see your Dashboard.');
  if (m.emailFailed) look.push(m.emailFailed + ' signed cop' + (m.emailFailed === 1 ? 'y' : 'ies') + ' couldn’t be emailed — a customer address may be wrong. Retry from the load.');
  const T = [org.name + ' — your ' + range.label + ' on HaulProof', ''];
  tiles.forEach(t => T.push('  ' + t[1] + ': ' + t[0]));
  if (m.topCustomers.length) { T.push('', 'Top customers by loads delivered:'); m.topCustomers.forEach(c => T.push('  • ' + c.name + ' — ' + c.loads)); }
  if (look.length) { T.push('', 'Worth a look:'); look.forEach(l => T.push('  • ' + l)); }
  T.push('', 'Open HaulProof: ' + link, '', 'Sent on the 1st of each month to your company admins. Turn it off under Settings → Monthly summary.');
  const html = '<div style="max-width:620px;margin:0 auto;font:14px system-ui,Arial,sans-serif;color:#1a2440;">'
    + '<div style="font:800 20px system-ui,Arial,sans-serif;color:#12386e;">Your ' + esc(range.label) + ' on HaulProof</div>'
    + '<div style="font-size:13px;color:#5a6787;margin:2px 0 16px;">' + esc(org.name) + '</div>'
    + '<table role="presentation" style="width:100%;border-collapse:separate;border-spacing:8px;"><tr>'
    + tiles.map((t, i) => (i === 3 ? '</tr><tr>' : '') + '<td style="background:#f3f6fb;border:1px solid #dfe5f0;border-radius:10px;padding:12px;vertical-align:top;width:33%;"><div style="font:800 24px system-ui,Arial,sans-serif;">' + t[0] + '</div><div style="font-size:12.5px;color:#4a5778;">' + esc(t[1]) + '</div></td>').join('')
    + '</tr></table>'
    + (m.topCustomers.length ? '<div style="font-weight:700;margin:16px 0 6px;">Top customers by loads delivered</div>' + m.topCustomers.map(c => '<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #eef1f6;font-size:13.5px;"><span>' + esc(c.name) + '</span><span>&nbsp;' + c.loads + '</span></div>').join('') : '')
    + (look.length ? '<div style="margin-top:16px;padding:12px 14px;border-radius:10px;background:#fff7e8;border:1px solid #f0d9a8;"><div style="font-weight:700;margin-bottom:4px;">Worth a look</div>' + look.map(l => '<div style="font-size:13.5px;color:#6b4e12;">• ' + esc(l) + '</div>').join('') + '</div>' : '')
    + '<p style="margin:20px 0 0;"><a href="' + link + '" style="display:inline-block;background:#1f5fd6;color:#fff;font-weight:700;text-decoration:none;padding:11px 18px;border-radius:9px;">Open HaulProof</a></p>'
    + '<p style="font-size:12px;color:#5a6787;margin-top:18px;">Sent on the 1st of each month to your company admins. Turn it off under Settings → Monthly summary.</p></div>';
  return { subject: 'HaulProof: ' + subject, text: T.join('\n'), html };
}
async function sendMonthlyFor(org, range, toOverride) {
  const m = buildMonthly(org.id, range);
  if (!toOverride && !m.delivered && !m.signed) return { skipped: 'no activity' };
  const to = toOverride || db.prepare(`SELECT email FROM users WHERE orgId = ? AND role = 'admin'`).all(org.id).map(u => u.email).filter(notHelp);
  if (!to.length) return { skipped: 'no admins' };
  const msg = renderMonthly(org, range, m);
  const { sendMail } = require('./mailer');
  await sendMail({ to, subject: msg.subject, text: msg.text, html: msg.html });
  return { sent: to.length, stats: m };
}
let running = false;
async function runMonthly(now) {
  now = now || new Date();
  const st = (() => { try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) || {}; } catch (e) { return {}; } })();
  const range = monthRange(now);
  if (running || st.lastMonth === range.key) return { skipped: 'already sent for ' + range.key };
  running = true;
  let sent = 0, skipped = 0;
  try {
    const orgs = db.prepare(`SELECT id, name, kind FROM orgs WHERE active = 1 AND COALESCE(kind,'customer') IN ('customer','broker','carrier')`).all();
    for (const o of orgs) {
      if (!resolveUiFlags(o.id).monthlyReport) { skipped++; continue; }
      try { const r = await sendMonthlyFor(o, range); if (r.sent) sent++; else skipped++; } catch (e) { console.error('[monthly] ' + o.name, e.message); }
    }
    st.lastMonth = range.key; st.at = Date.now();
    try { fs.writeFileSync(STATE_FILE, JSON.stringify(st)); } catch (e) {}
    console.log('[monthly] ' + range.label + ': sent to ' + sent + ' compan' + (sent === 1 ? 'y' : 'ies') + ', ' + skipped + ' skipped');
  } finally { running = false; }
  return { sent, skipped, month: range.key };
}
function startMonthlyReports() {
  const tick = () => { const n = new Date(); if (n.getUTCDate() === 1 && n.getUTCHours() >= SEND_HOUR_UTC) runMonthly(n).catch(e => console.error('[monthly]', e.message)); };
  setTimeout(tick, 6 * 60000).unref();
  setInterval(tick, 30 * 60000).unref();
}
// Master admin: preview a company's report for last month, or email it to yourself.
router.get('/monthly-preview', requireAuth, (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'HaulProof only' });
  const org = db.prepare(`SELECT id, name, kind FROM orgs WHERE id = ?`).get(String(req.query.orgId || ''));
  if (!org) return res.status(404).json({ error: 'Pick a company' });
  const range = monthRange(new Date()), m = buildMonthly(org.id, range);
  res.json(Object.assign({ month: range.label, stats: m }, renderMonthly(org, range, m)));
});
router.post('/monthly-send-test', requireAuth, async (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'HaulProof only' });
  const org = db.prepare(`SELECT id, name, kind FROM orgs WHERE id = ?`).get(String((req.body || {}).orgId || ''));
  if (!org) return res.status(404).json({ error: 'Pick a company' });
  res.json(await sendMonthlyFor(org, monthRange(new Date()), [req.user.email]));
});

module.exports = { router, startMonthlyReports, runMonthly, buildMonthly, monthRange };
