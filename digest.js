// Daily HaulProof digest — once a day, email a summary of what's new (team logins, companies, access requests)
// plus document counts to a configured address. Runs in-process (the web service is always on); the last day it
// sent is kept in a small file on the persistent disk so a restart never re-sends or double-sends.
const fs = require('fs');
const path = require('path');
const { db, DATA_DIR } = require('./db');
const { sendMail, portalUrl } = require('./mailer');

const RECIPIENT    = (process.env.DIGEST_EMAIL || 'brian@haulproofepod.com').trim();
// Optional CC (set DIGEST_CC to an address to copy someone in). Off by default: the digest already goes to Brian@haulproofepod.com.
const CC           = (process.env.DIGEST_CC == null ? '' : process.env.DIGEST_CC).trim();
const SEND_HOUR_UTC = Number(process.env.DIGEST_HOUR_UTC || 12);   // ~7am US Central (CDT). Override via env.
const STATE_FILE   = path.join(DATA_DIR, 'digest-state.json');

function readState() { try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) || {}; } catch (e) { return {}; } }
function writeState(s) { try { fs.writeFileSync(STATE_FILE, JSON.stringify(s)); } catch (e) {} }
function dayKeyUTC(d) { return d.toISOString().slice(0, 10); }
function all(sql, args) { try { return db.prepare(sql).all.apply(db.prepare(sql), args || []); } catch (e) { return []; } }
function count(sql, args) { try { const r = db.prepare(sql).get.apply(db.prepare(sql), args || []); return r ? (r.c || 0) : 0; } catch (e) { return 0; } }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : s; }

// Gather everything new since `sinceTs`, plus current snapshots (pending requests, totals).
function buildDigest(sinceTs) {
  const newUsers = all(`SELECT u.name, u.email, u.role, u.createdAt, o.name AS orgName, o.kind AS orgKind
      FROM users u LEFT JOIN orgs o ON o.id = u.orgId
      WHERE u.createdAt >= ? AND u.role != 'superadmin' ORDER BY u.createdAt ASC`, [sinceTs]);
  const newOrgs = all(`SELECT name, kind, mcNumber, createdAt FROM orgs WHERE createdAt >= ? ORDER BY createdAt ASC`, [sinceTs]);
  // All currently-pending access requests (company + driver), newest first.
  const pendingReqs = all(`SELECT kind, orgType, contactName, company, email, targetCompany, createdAt
      FROM access_requests WHERE status = 'pending' ORDER BY createdAt DESC`);
  const newReqCount = count(`SELECT COUNT(*) c FROM access_requests WHERE createdAt >= ?`, [sinceTs]);
  const docsNew = count(`SELECT COUNT(*) c FROM pods WHERE uploadedAt >= ?`, [sinceTs]);
  const docsTotal = count(`SELECT COUNT(*) c FROM pods`);
  const docsSigned = count(`SELECT COUNT(*) c FROM pods WHERE status IN ('signed','emailed')`);
  const orgTotals = all(`SELECT kind, COUNT(*) c FROM orgs WHERE active = 1 GROUP BY kind`);
  const totalsByKind = {}; orgTotals.forEach(r => { totalsByKind[r.kind || 'customer'] = r.c; });
  // Weekly FMCSA monitoring: carriers/brokers that changed (or cleared) in this period — one line per company, with who uses it.
  const alertRows = all(`SELECT a.carrierId, a.carrierName, a.type, a.problems, a.loads, o.name AS ownerName FROM carrier_alerts a
      LEFT JOIN orgs o ON o.id = a.ownerOrgId WHERE a.createdAt >= ? AND COALESCE(a.ackBy,'') != 'superseded' ORDER BY a.createdAt ASC`, [sinceTs]);
  const carrierChanges = [], seen = {};
  alertRows.forEach(a => {
    const k = a.carrierId + '|' + a.type;
    let c = seen[k];
    if (!c) { c = seen[k] = { name: a.carrierName, type: a.type, problems: a.problems, owners: [], pos: [] }; carrierChanges.push(c); }
    if (a.ownerName && c.owners.indexOf(a.ownerName) < 0) c.owners.push(a.ownerName);
    try { JSON.parse(a.loads || '[]').forEach(l => { const t = 'PO ' + (l.po || '?') + (l.onRoad ? ' (on the road)' : ''); if (c.pos.indexOf(t) < 0) c.pos.push(t); }); } catch (e) {}
  });
  const carriersChecked = count(`SELECT COUNT(*) c FROM orgs WHERE kind IN ('carrier','broker') AND fmcsaSnapshotAt >= ?`, [sinceTs]);
  return { sinceTs, newUsers, newOrgs, pendingReqs, newReqCount, docsNew, docsTotal, docsSigned, totalsByKind, carrierChanges, carriersChecked };
}

function fmtDate(ts) { try { return new Date(ts).toLocaleString('en-US', { timeZone: 'America/Chicago' }); } catch (e) { return new Date(ts).toISOString(); } }

function render(d) {
  const nUsers = d.newUsers.length, nOrgs = d.newOrgs.length, nPend = d.pendingReqs.length;
  const nBad = d.carrierChanges.filter(c => c.type === 'flagged').length;
  const subject = `HaulProof daily — ${nUsers} new login${nUsers === 1 ? '' : 's'}, ${nOrgs} new compan${nOrgs === 1 ? 'y' : 'ies'}, ${nPend} request${nPend === 1 ? '' : 's'} pending` + (nBad ? `, ${nBad} carrier alert${nBad === 1 ? '' : 's'}` : '');
  const carrierLine = (c) => c.name + (c.type === 'flagged' ? ' — ' + (c.problems || 'flagged on FMCSA') : ' — cleared, clean on FMCSA now')
    + (c.owners.length ? ' · used by ' + c.owners.join(', ') : '') + (c.pos.length ? ' · open loads: ' + c.pos.join(', ') : '');
  const nGood = d.carrierChanges.length - nBad;
  const carrierHead = 'FMCSA carrier monitoring — ' + d.carriersChecked + ' checked, ' + nBad + ' changed, ' + nGood + ' cleared';

  // ---- plain text ----
  const T = [];
  T.push('HaulProof daily digest — ' + fmtDate(Date.now()));
  T.push('(covers activity since ' + fmtDate(d.sinceTs) + ')');
  T.push('');
  T.push('NEW TEAM LOGINS / USERS (' + nUsers + ')');
  if (nUsers) d.newUsers.forEach(u => T.push('  • ' + (u.name || u.email) + ' <' + u.email + '> — ' + cap(u.role || 'user') + (u.orgName ? (' @ ' + u.orgName + (u.orgKind ? ' (' + cap(u.orgKind) + ')' : '')) : ' (master admin)')));
  else T.push('  (none)');
  T.push('');
  T.push('NEW COMPANIES (' + nOrgs + ')');
  if (nOrgs) d.newOrgs.forEach(o => T.push('  • ' + o.name + ' — ' + cap(o.kind || 'customer') + (o.mcNumber ? (' · MC ' + o.mcNumber) : '')));
  else T.push('  (none)');
  T.push('');
  T.push('PENDING ACCESS REQUESTS (' + nPend + (d.newReqCount ? (', ' + d.newReqCount + ' new today') : '') + ')');
  if (nPend) d.pendingReqs.forEach(r => {
    const who = r.contactName || r.email || '(no name)';
    const what = r.kind === 'driver' ? ('Driver — wants to join ' + (r.targetCompany || '?')) : ('Company — ' + cap(r.orgType || 'customer') + (r.company ? (': ' + r.company) : ''));
    T.push('  • ' + who + ' — ' + what + (r.email ? (' <' + r.email + '>') : ''));
  });
  else T.push('  (none)');
  T.push('');
  T.push(carrierHead.toUpperCase());
  if (d.carrierChanges.length) d.carrierChanges.forEach(c => T.push('  • ' + (c.type === 'flagged' ? '⚠ ' : '✓ ') + carrierLine(c)));
  else T.push('  (no changes)');
  T.push('');
  T.push('DOCUMENTS');
  T.push('  New in this period: ' + d.docsNew);
  T.push('  Total on file: ' + d.docsTotal + ' (' + d.docsSigned + ' signed/emailed)');
  T.push('');
  const tk = d.totalsByKind;
  T.push('COMPANIES ON PLATFORM: ' + ['customer', 'carrier', 'broker', 'receiver'].map(k => (tk[k] || 0) + ' ' + k + ((tk[k] || 0) === 1 ? '' : 's')).join(' · '));
  T.push('');
  T.push('Open HaulProof: ' + portalUrl() + '/app');

  // ---- HTML ----
  const sec = (title, inner) => '<h2 style="font:700 15px system-ui,Arial,sans-serif;color:#12386e;margin:22px 0 8px;">' + esc(title) + '</h2>' + inner;
  const li = (s) => '<li style="margin:3px 0;">' + s + '</li>';
  const ul = (arr) => arr.length ? ('<ul style="margin:0;padding-left:20px;font:14px system-ui,Arial,sans-serif;color:#1f2733;">' + arr.join('') + '</ul>') : '<div style="font:14px system-ui,Arial,sans-serif;color:#8a94a6;">None.</div>';

  const usersHtml = ul(d.newUsers.map(u => li('<b>' + esc(u.name || u.email) + '</b> &lt;' + esc(u.email) + '&gt; — ' + esc(cap(u.role || 'user')) + (u.orgName ? (' @ ' + esc(u.orgName) + (u.orgKind ? ' <span style="color:#8a94a6;">(' + esc(cap(u.orgKind)) + ')</span>' : '')) : ' <span style="color:#8a94a6;">(master admin)</span>'))));
  const orgsHtml = ul(d.newOrgs.map(o => li('<b>' + esc(o.name) + '</b> — ' + esc(cap(o.kind || 'customer')) + (o.mcNumber ? (' <span style="color:#8a94a6;">· MC ' + esc(o.mcNumber) + '</span>') : ''))));
  const reqsHtml = ul(d.pendingReqs.map(r => {
    const who = esc(r.contactName || r.email || '(no name)');
    const what = r.kind === 'driver' ? ('Driver — wants to join ' + esc(r.targetCompany || '?')) : ('Company — ' + esc(cap(r.orgType || 'customer')) + (r.company ? (': ' + esc(r.company)) : ''));
    return li('<b>' + who + '</b> — ' + what + (r.email ? (' <span style="color:#8a94a6;">&lt;' + esc(r.email) + '&gt;</span>') : ''));
  }));
  const carriersHtml = ul(d.carrierChanges.map(c => li((c.type === 'flagged' ? '<span style="color:#c0392b;font-weight:700;">⚠</span> ' : '<span style="color:#1e8e5a;font-weight:700;">✓</span> ') + '<b>' + esc(c.name) + '</b> — '
    + esc(c.type === 'flagged' ? (c.problems || 'flagged on FMCSA') : 'cleared, clean on FMCSA now')
    + (c.owners.length ? ' <span style="color:#8a94a6;">· used by ' + esc(c.owners.join(', ')) + '</span>' : '') + (c.pos.length ? ' <span style="color:#8a94a6;">· open loads: ' + esc(c.pos.join(', ')) + '</span>' : ''))));
  const docsHtml = '<div style="font:14px system-ui,Arial,sans-serif;color:#1f2733;">New in this period: <b>' + d.docsNew + '</b><br>Total on file: <b>' + d.docsTotal + '</b> (' + d.docsSigned + ' signed/emailed)</div>';
  const totalsHtml = '<div style="font:13px system-ui,Arial,sans-serif;color:#5c6b7a;">' + ['customer', 'carrier', 'broker', 'receiver'].map(k => '<b>' + (tk[k] || 0) + '</b> ' + k + ((tk[k] || 0) === 1 ? '' : 's')).join(' &nbsp;·&nbsp; ') + '</div>';

  const html = '<div style="max-width:620px;margin:0 auto;font:14px system-ui,Arial,sans-serif;color:#1f2733;">'
    + '<div style="font:800 20px system-ui,Arial,sans-serif;color:#12386e;">HaulProof daily digest</div>'
    + '<div style="font:12.5px system-ui,Arial,sans-serif;color:#8a94a6;margin-top:3px;">' + esc(fmtDate(Date.now())) + ' · since ' + esc(fmtDate(d.sinceTs)) + '</div>'
    + sec('New team logins / users (' + nUsers + ')', usersHtml)
    + sec('New companies (' + nOrgs + ')', orgsHtml)
    + sec('Pending access requests (' + nPend + (d.newReqCount ? (' · ' + d.newReqCount + ' new today') : '') + ')', reqsHtml)
    + sec(carrierHead, carriersHtml)
    + sec('Documents', docsHtml)
    + sec('Companies on platform', totalsHtml)
    + '<p style="margin:26px 0 0;"><a href="' + portalUrl() + '/app" style="display:inline-block;background:#1f6feb;color:#fff;font-weight:700;text-decoration:none;padding:11px 20px;border-radius:9px;">Open HaulProof &rarr;</a></p>'
    + '</div>';

  return { subject, text: T.join('\n'), html };
}

// Send the digest now (covering activity since the last send) and record that we sent today.
async function sendNow() {
  const st = readState();
  const sinceTs = st.lastSentTs || (Date.now() - 24 * 3600 * 1000);
  const d = buildDigest(sinceTs);
  const msg = render(d);
  const r = await sendMail({ to: RECIPIENT, cc: CC || undefined, subject: msg.subject, text: msg.text, html: msg.html });
  writeState({ lastSentDay: dayKeyUTC(new Date()), lastSentTs: Date.now() });
  console.log('[digest] sent to ' + RECIPIENT + (CC ? ' (cc ' + CC + ')' : '') + ' — ' + msg.subject + (r && r.sent ? '' : ' (' + (r && r.simulated ? 'simulated' : (r && r.error) || 'not sent') + ')'));
  return r;
}

// Due today? Only once per UTC day, at/after the configured hour.
function maybeSend() {
  const now = new Date(), today = dayKeyUTC(now), st = readState();
  if (st.lastSentDay === today) return Promise.resolve();
  if (now.getUTCHours() < SEND_HOUR_UTC) return Promise.resolve();
  return sendNow();
}

function startDailyDigest() {
  // A nudge shortly after boot (catches the case where the service restarts after the send hour), then hourly.
  setTimeout(() => { maybeSend().catch(e => console.error('digest', e && e.message)); }, 90 * 1000);
  setInterval(() => { maybeSend().catch(e => console.error('digest', e && e.message)); }, 30 * 60 * 1000);
  console.log('[digest] daily digest armed — to ' + RECIPIENT + ' at/after ' + SEND_HOUR_UTC + ':00 UTC');
}

module.exports = { startDailyDigest, sendNow, buildDigest, render, RECIPIENT };
