// "Check on these": loads with a pickup appointment coming up (or past) where the driver hasn't tapped "On my way"
// (or hasn't picked up once the time has passed), or no driver is on the load yet. The list shows on the portal
// Dashboard, comes from the connector (check_on_drivers), and is emailed to the company's check-on contacts as loads
// become due (each load once per reason, so nobody gets the same reminder every 10 minutes).
// Pickup times are Central time (the office's). A pickup with only a date is checked from 8:00 AM that day.
const express = require('express');
const { db } = require('./db');
const { requireAuth } = require('./auth');
const { logEvent } = require('./events');

for (const [t, c] of [['loads', 'pickupAt INTEGER'], ['loads', 'pickupNote TEXT'], ['loads', 'checkOnStage TEXT'], ['orgs', 'checkOnEmails TEXT']]) {
  try { db.exec(`ALTER TABLE ${t} ADD COLUMN ${c}`); } catch (e) {}
}

const TZ = 'America/Chicago';
const MIN = 60000;
const LEAD_EN_ROUTE = 120 * MIN;   // not "On my way" within 2 hours of pickup
const LEAD_NO_DRIVER = 240 * MIN;  // no driver within 4 hours of pickup
const LATE_PICKUP = 60 * MIN;      // not picked up an hour after the pickup time
const REASON = {
  no_driver: 'No driver on the load yet',
  not_en_route: 'Driver hasn’t tapped “On my way” yet',
  late_pickup: 'Past the pickup time and not picked up',
};

// Central wall time -> epoch ms
function ctToEpoch(y, mo, d, h, mi) {
  const guess = Date.UTC(y, mo - 1, d, h, mi);
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: TZ, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    .formatToParts(new Date(guess)).map(x => [x.type, x.value]));
  const asIf = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute);
  return guess - (asIf - guess);
}
function fmtCT(ms, withDay = true) {
  if (!ms) return '';
  return new Date(ms).toLocaleString('en-US', Object.assign({ timeZone: TZ, hour: 'numeric', minute: '2-digit' }, withDay ? { weekday: 'short', month: 'numeric', day: 'numeric' } : {}));
}

// "11/20 8:00 AM", "11/20/2026 0800", "11/20 7-3", "2026-11-20T08:00", "2026-11-20", an ISO time with a zone, or epoch ms.
// Returns { at, note } (note keeps a window or "FCFS"), or null when it can't be read. now: for the year.
function parsePickup(v, now = Date.now()) {
  if (v == null || v === '') return null;
  if (typeof v === 'number' && isFinite(v)) return { at: v, note: null };
  const s = String(v).trim();
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/.test(s)) { const t = Date.parse(s); return isNaN(t) ? null : { at: t, note: null }; }
  let y, mo, d, rest;
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})[T\s]*(.*)$/);
  if (m) { y = +m[1]; mo = +m[2]; d = +m[3]; rest = m[4]; }
  else if ((m = s.match(/^(\d{1,2})\/(\d{1,2})(?:\/(\d{2,4}))?\s*(.*)$/))) {
    mo = +m[1]; d = +m[2]; rest = m[4];
    if (m[3]) y = m[3].length === 2 ? 2000 + +m[3] : +m[3];
    else {   // no year: this year, or next year if that date is more than two months back
      const cy = +new Intl.DateTimeFormat('en-US', { timeZone: TZ, year: 'numeric' }).format(new Date(now));
      y = cy; if (ctToEpoch(cy, mo, d, 0, 0) < now - 60 * 24 * 60 * MIN) y = cy + 1;
    }
  } else return null;
  if (!(mo >= 1 && mo <= 12 && d >= 1 && d <= 31)) return null;
  rest = String(rest || '').trim();
  let h = 8, mi = 0, note = null;
  const tm = rest.match(/^(\d{1,2})(?::?(\d{2}))?\s*(a\.?m?\.?|p\.?m?\.?)?(?:\s*(?:-|–|to)\s*(\d{1,2})(?::?(\d{2}))?\s*(a\.?m?\.?|p\.?m?\.?)?)?\s*(.*)$/i);
  if (tm && rest) {
    h = +tm[1]; mi = tm[2] ? +tm[2] : 0;
    const ap = (tm[3] || '').toLowerCase();
    if (ap.startsWith('p') && h < 12) h += 12;
    if (ap.startsWith('a') && h === 12) h = 0;
    if (h > 23 || mi > 59) return null;
    note = tm[4] ? rest : ((tm[7] || '').trim() || null);   // a window like "7-3" is checked from its start and kept as the note
  } else note = rest || 'date only';   // "FCFS", "anytime", or nothing: date only, checked from 8:00 AM
  return { at: ctToEpoch(y, mo, d, h, mi), note: note ? note.slice(0, 80) : null };
}

// Set the pickup appointment from a request body (pickup: text/ISO/ms; pickupNote) — used by create and edit.
// Returns a history line, or null when nothing changed. Throws a 400-able Error when it can't read it.
function applyPickup(load, b, actor) {
  if (!b || (b.pickup === undefined && b.pickupAt === undefined && b.pickupNote === undefined)) return null;
  const raw = b.pickup !== undefined ? b.pickup : b.pickupAt;
  let at = load.pickupAt || null, note = load.pickupNote || null;
  if (raw !== undefined) {
    if (raw === null || raw === '') { at = null; note = null; }
    else { const p = parsePickup(raw); if (!p) { const e = new Error('Couldn’t read the pickup time. Use e.g. 11/20 8:00 AM, 11/20 7-3, or 2026-11-20T08:00'); e.status = 400; throw e; } at = p.at; note = p.note; }
  }
  if (b.pickupNote !== undefined) note = String(b.pickupNote || '').trim().slice(0, 80) || null;
  if (at === (load.pickupAt || null) && note === (load.pickupNote || null)) return null;
  db.prepare(`UPDATE loads SET pickupAt = ?, pickupNote = ?, checkOnStage = NULL WHERE id = ?`).run(at, note, load.id);
  const line = at ? 'Pickup appointment set: ' + fmtCT(at) + (note && note !== 'date only' ? ' (' + note + ')' : note === 'date only' ? ' (date only)' : '') : 'Pickup appointment removed';
  try { logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'updated', detail: line, actor }); } catch (e) {}
  return line;
}

const fmtPhone = p => { const n = String(p || '').replace(/\D/g, '').replace(/^1(?=\d{10}$)/, ''); return n.length === 10 ? n.replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3') : (p || null); };

// The loads to check on for one company (as owner or broker), most urgent first.
function dueList(orgId, now = Date.now()) {
  const rows = db.prepare(`SELECT l.*, d.phone AS driverPhone, c.name AS carrierOrgName, c.contactPhone AS carrierPhone,
      (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.status NOT IN ('parked','not_used')) AS docs,
      (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.status IN ('signed','emailed')) AS signed
    FROM loads l LEFT JOIN drivers d ON d.id = l.assignedDriverId LEFT JOIN orgs c ON c.id = l.carrierId
    WHERE (l.orgId = ? OR l.brokerId = ?) AND l.pickupAt IS NOT NULL AND l.pickedUpAt IS NULL
      AND l.pickupAt <= ? AND l.pickupAt >= ?`).all(orgId, orgId, now + LEAD_NO_DRIVER, now - 3 * 24 * 60 * MIN);
  const out = [];
  for (const l of rows) {
    if (l.completeNotifiedAt || (l.docs > 0 && l.signed >= l.docs)) continue;   // done
    const until = l.pickupAt - now;
    let stage = null;
    if (!l.driverName && !l.assignedDriverId) stage = 'no_driver';
    else if (until <= -LATE_PICKUP) stage = 'late_pickup';
    else if (!l.enRouteAt && until <= LEAD_EN_ROUTE) stage = 'not_en_route';
    if (!stage) continue;
    out.push({ id: l.id, poNumber: l.poNumber, loadNumber: l.loadNumber, customer: l.customer, origin: l.origin,
      pickupAt: l.pickupAt, pickupNote: l.pickupNote, pickupText: fmtCT(l.pickupAt) + (l.pickupNote && l.pickupNote !== 'date only' ? ' (' + l.pickupNote + ')' : l.pickupNote === 'date only' ? ' (date only)' : ''),
      minutesUntilPickup: Math.round(until / MIN), stage, reason: REASON[stage],
      carrier: l.carrierName || null, carrierPhone: fmtPhone(l.carrierPhone), driver: l.driverName || null, driverPhone: fmtPhone(l.driverPhone),
      enRouteAt: l.enRouteAt || null, alerted: l.checkOnStage === stage });
  }
  const rank = { late_pickup: 0, not_en_route: 1, no_driver: 2 };
  return out.sort((a, b) => rank[a.stage] - rank[b.stage] || a.pickupAt - b.pickupAt);
}

const portalBase = () => (process.env.PORTAL_URL || 'https://haulproofepod.com').replace(/\/+$/, '');
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
function emailFor(items, fresh) {
  const row = i => `<tr><td style="padding:6px 8px;border-top:1px solid #e3e9f2"><a href="${portalBase()}/app?load=${encodeURIComponent(i.id)}">${esc(i.loadNumber || i.poNumber)}</a><br><span style="color:#5a6b82">${esc(i.customer || '')}</span></td>
    <td style="padding:6px 8px;border-top:1px solid #e3e9f2">${esc(i.pickupText)}${i.origin ? '<br><span style="color:#5a6b82">' + esc(i.origin) + '</span>' : ''}</td>
    <td style="padding:6px 8px;border-top:1px solid #e3e9f2"><b>${esc(i.reason)}</b></td>
    <td style="padding:6px 8px;border-top:1px solid #e3e9f2">${esc(i.carrier || '')}${i.carrierPhone ? '<br><a href="tel:' + esc(i.carrierPhone) + '">' + esc(i.carrierPhone) + '</a>' : ''}</td>
    <td style="padding:6px 8px;border-top:1px solid #e3e9f2">${esc(i.driver || '—')}${i.driverPhone ? '<br><a href="tel:' + esc(i.driverPhone) + '">' + esc(i.driverPhone) + '</a>' : ''}</td></tr>`;
  const table = list => `<table style="border-collapse:collapse;font-size:14px;width:100%"><tr style="text-align:left;color:#5a6b82;font-size:12px"><th style="padding:6px 8px">Load</th><th style="padding:6px 8px">Pickup</th><th style="padding:6px 8px">Why</th><th style="padding:6px 8px">Carrier</th><th style="padding:6px 8px">Driver</th></tr>${list.map(row).join('')}</table>`;
  const others = items.filter(i => !fresh.includes(i));
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#0e1a2d;max-width:760px">
    <p>${fresh.length === 1 ? 'This load needs' : 'These loads need'} a check-in call: the pickup time is close or past and the driver hasn't shown "On my way" (or picked up) in HaulProof.</p>
    ${table(fresh)}
    ${others.length ? '<p style="margin-top:18px;color:#5a6b82">Still on the list from earlier:</p>' + table(others) : ''}
    <p style="margin-top:18px"><a href="${portalBase()}/app" style="display:inline-block;background:#1655d1;color:#fff;font-weight:700;text-decoration:none;padding:10px 18px;border-radius:9px">Open the check-on list</a></p>
    <p style="color:#5a6b82;font-size:12.5px">A load comes off the list once the driver taps "On my way" (and then "Pickup complete" after the pickup time). Pickup times are Central.</p></div>`;
  const text = 'Check on these loads (pickup close or past, driver not "On my way" in HaulProof):\n\n' +
    items.map(i => `${i.loadNumber || i.poNumber} · ${i.pickupText} · ${i.reason} · ${i.carrier || ''} ${i.carrierPhone || ''} · driver ${i.driver || '—'} ${i.driverPhone || ''}`).join('\n') +
    `\n\n${portalBase()}/app`;
  const subject = fresh.length === 1 ? `Check on load ${fresh[0].loadNumber || fresh[0].poNumber}: ${fresh[0].reason}` : `Check on ${fresh.length} loads: pickup close and driver not on the way`;
  return { subject, html, text };
}

// One pass: for each company with check-on contacts, email the loads that just became due (or changed reason).
async function tick(now = Date.now(), { anyHour = false } = {}) {
  const hourCT = +new Intl.DateTimeFormat('en-US', { timeZone: TZ, hour: 'numeric', hourCycle: 'h23' }).format(new Date(now));
  const orgs = db.prepare(`SELECT id, name, checkOnEmails FROM orgs WHERE checkOnEmails IS NOT NULL AND checkOnEmails != '' AND active = 1`).all();
  const sent = [];
  for (const o of orgs) {
    const items = dueList(o.id, now);
    const fresh = items.filter(i => !i.alerted);
    // loads no longer due drop their mark, so a later reason emails again
    const dueIds = new Set(items.map(i => i.id));
    for (const l of db.prepare(`SELECT id FROM loads WHERE (orgId = ? OR brokerId = ?) AND checkOnStage IS NOT NULL`).all(o.id, o.id)) if (!dueIds.has(l.id)) db.prepare(`UPDATE loads SET checkOnStage = NULL WHERE id = ?`).run(l.id);
    if (!fresh.length || (!anyHour && (hourCT < 5 || hourCT >= 21))) continue;   // quiet overnight; due loads wait for the morning
    const to = o.checkOnEmails.split(/[;,\s]+/).filter(Boolean);
    const msg = emailFor(items, fresh);
    try { await require('./mailer').sendMail({ to, subject: msg.subject, text: msg.text, html: msg.html }); } catch (e) { console.error('[check-on] mail', e.message); continue; }
    for (const i of fresh) {
      db.prepare(`UPDATE loads SET checkOnStage = ? WHERE id = ?`).run(i.stage, i.id);
      try { logEvent({ orgId: o.id, loadId: i.id, poNumber: i.poNumber, type: 'note', detail: `Check-on reminder sent to ${to.join(', ')}: ${i.reason} (pickup ${i.pickupText})`, actor: 'HaulProof' }); } catch (e) {}
    }
    sent.push({ org: o.name, to, loads: fresh.map(i => i.loadNumber || i.poNumber) });
  }
  return sent;
}
function start() {
  setTimeout(() => tick().catch(e => console.error('[check-on]', e.message)), 2 * MIN).unref();
  setInterval(() => tick().catch(e => console.error('[check-on]', e.message)), 10 * MIN).unref();
}

// ---- Routes (mounted at /api/loads, before the /:id routes) ----
const router = express.Router();
function orgOf(req) { return req.user.role === 'superadmin' ? (String(req.query.orgId || (req.body && req.body.orgId) || '').trim() || req.user.orgId || null) : (req.user.orgId || null); }
router.get('/check-on', requireAuth, (req, res) => {
  if (!['admin', 'dispatcher', 'superadmin', 'sales'].includes(req.user.role)) return res.status(403).json({ error: 'Not allowed' });
  const org = orgOf(req); if (!org) return res.json({ items: [], emails: [] });
  const o = db.prepare(`SELECT checkOnEmails FROM orgs WHERE id = ?`).get(org);
  res.json({ items: dueList(org), emails: String((o && o.checkOnEmails) || '').split(/[;,\s]+/).filter(Boolean),
    rules: { notEnRouteMinutesBefore: LEAD_EN_ROUTE / MIN, noDriverMinutesBefore: LEAD_NO_DRIVER / MIN, latePickupMinutesAfter: LATE_PICKUP / MIN } });
});
router.put('/check-on/settings', requireAuth, express.json(), (req, res) => {
  if (!['admin', 'dispatcher', 'superadmin'].includes(req.user.role)) return res.status(403).json({ error: 'Not allowed' });
  const org = orgOf(req); if (!org) return res.status(400).json({ error: 'No company' });
  const list = (Array.isArray(req.body && req.body.emails) ? req.body.emails : String((req.body && req.body.emails) || '').split(/[;,\s]+/))
    .map(s => String(s).trim().toLowerCase()).filter(Boolean);
  if (list.some(e => !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e))) return res.status(400).json({ error: 'Enter valid email addresses' });
  db.prepare(`UPDATE orgs SET checkOnEmails = ? WHERE id = ?`).run(list.join(', ') || null, org);
  res.json({ ok: true, emails: list });
});

module.exports = { router, start, tick, dueList, applyPickup, parsePickup, ctToEpoch, fmtCT };
