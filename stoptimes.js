// Driver in/out times at each stop — the pickup (stop 0) and each delivery stop — for time-on-site / detention.
// Turned on per account with the "stopTimes" flag (uiflags.js). The driver taps Check in on arrival; the check-out
// is either tapped, or recorded automatically when the driver marks "Pickup complete" (pickup) or sends the
// signed documents (that delivery stop). Dispatch can correct any time; every change lands in the load history.
//
// Kept in its own table keyed by load + stop rather than on the pod row, because signing replaces the prepared
// pod with a new signed one (pods.js ingest) — anything stored on the prepared row would be lost.
const crypto = require('crypto');
const { db } = require('./db');
const { logEvent } = require('./events');
const { resolveUiFlags } = require('./uiflags');

db.exec(`
CREATE TABLE IF NOT EXISTS stop_times (
  id          TEXT PRIMARY KEY,
  loadId      TEXT NOT NULL,
  kind        TEXT NOT NULL,              -- 'pickup' | 'delivery'
  stopNumber  INTEGER NOT NULL DEFAULT 0, -- 0 for the pickup; the delivery stop # otherwise
  inAt        INTEGER, inGps  TEXT, inBy  TEXT,
  outAt       INTEGER, outGps TEXT, outBy TEXT,
  outSource   TEXT,                       -- 'driver' | 'pickup' | 'delivery' | 'dispatch'
  updatedAt   INTEGER NOT NULL,
  UNIQUE (loadId, kind, stopNumber)
);
`);

const KINDS = ['pickup', 'delivery'];
// Is in/out time tracking on for this load? The load's owning account decides (falling back to the driver's).
function enabledFor(load, fallbackOrgId) {
  try { return !!resolveUiFlags((load && load.orgId) || fallbackOrgId || null).stopTimes; } catch (e) { return false; }
}
function stopKey(kind, stopNumber) {
  if (KINDS.indexOf(kind) < 0) return null;
  if (kind === 'pickup') return { kind, stop: 0 };
  const n = parseInt(stopNumber, 10);
  return { kind, stop: Number.isFinite(n) && n > 0 ? n : 1 };
}
// GPS arrives as {lat,lng,acc} from the driver app or "lat,lng" from a signed upload; store as JSON {lat,lng,acc}.
function gpsJson(g) {
  if (!g) return null;
  if (typeof g === 'string') { const m = /^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/.exec(g); return m ? JSON.stringify({ lat: +m[1], lng: +m[2], acc: null }) : null; }
  if (typeof g.lat === 'number' && typeof g.lng === 'number') return JSON.stringify({ lat: g.lat, lng: g.lng, acc: typeof g.acc === 'number' ? Math.round(g.acc) : null });
  return null;
}
const parseGps = (s) => { try { return s ? JSON.parse(s) : null; } catch (e) { return null; } };
const stopLabel = (k) => k.kind === 'pickup' ? 'pickup' : 'Stop ' + k.stop;
const near = (gj) => { const g = parseGps(gj); return g ? ' near ' + g.lat.toFixed(5) + ', ' + g.lng.toFixed(5) : ''; };

function row(loadId, k) { return db.prepare(`SELECT * FROM stop_times WHERE loadId = ? AND kind = ? AND stopNumber = ?`).get(loadId, k.kind, k.stop); }
function ensureRow(loadId, k) {
  db.prepare(`INSERT OR IGNORE INTO stop_times (id, loadId, kind, stopNumber, updatedAt) VALUES (?,?,?,?,?)`).run(crypto.randomUUID(), loadId, k.kind, k.stop, Date.now());
  return row(loadId, k);
}
function out(r) {
  return { kind: r.kind, stopNumber: r.stopNumber, inAt: r.inAt || null, inGps: parseGps(r.inGps), inBy: r.inBy || null,
    outAt: r.outAt || null, outGps: parseGps(r.outGps), outBy: r.outBy || null, outSource: r.outSource || null };
}
// Every in/out time on a load, pickup first then stops in order.
function listFor(loadId) {
  return db.prepare(`SELECT * FROM stop_times WHERE loadId = ? ORDER BY (kind = 'delivery'), stopNumber`).all(loadId)
    .filter(r => r.inAt || r.outAt).map(out);
}
// The same, for many loads at once: { loadId: [times…] }.
function mapFor(loadIds) {
  const m = {};
  if (!loadIds || !loadIds.length) return m;
  db.prepare(`SELECT * FROM stop_times WHERE loadId IN (${loadIds.map(() => '?').join(',')}) ORDER BY (kind = 'delivery'), stopNumber`).all(...loadIds)
    .forEach(r => { if (r.inAt || r.outAt) (m[r.loadId] = m[r.loadId] || []).push(out(r)); });
  return m;
}

// Driver taps Check in / Check out. Re-tapping refreshes that time.
function driverMark({ load, kind, stopNumber, action, gps, driverName }) {
  const k = stopKey(kind, stopNumber);
  if (!k || (action !== 'in' && action !== 'out')) throw new Error('Unknown stop or action');
  ensureRow(load.id, k);
  const at = Date.now(), gj = gpsJson(gps), by = driverName || 'Driver';
  if (action === 'in') db.prepare(`UPDATE stop_times SET inAt = ?, inGps = ?, inBy = ?, updatedAt = ? WHERE loadId = ? AND kind = ? AND stopNumber = ?`).run(at, gj, by, at, load.id, k.kind, k.stop);
  else db.prepare(`UPDATE stop_times SET outAt = ?, outGps = ?, outBy = ?, outSource = 'driver', updatedAt = ? WHERE loadId = ? AND kind = ? AND stopNumber = ?`).run(at, gj, by, at, load.id, k.kind, k.stop);
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: action === 'in' ? 'checked_in' : 'checked_out',
    detail: (action === 'in' ? 'Checked in at ' : 'Checked out of ') + stopLabel(k) + ' by ' + by + near(gj), actor: by });
  return out(row(load.id, k));
}
// Driver undoes their own last tap (e.g. checked in at the wrong stop).
function driverUndo({ load, kind, stopNumber, action, driverName }) {
  const k = stopKey(kind, stopNumber);
  if (!k || (action !== 'in' && action !== 'out')) throw new Error('Unknown stop or action');
  if (!row(load.id, k)) return null;
  const col = action === 'in' ? 'inAt = NULL, inGps = NULL, inBy = NULL' : 'outAt = NULL, outGps = NULL, outBy = NULL, outSource = NULL';
  db.prepare(`UPDATE stop_times SET ${col}, updatedAt = ? WHERE loadId = ? AND kind = ? AND stopNumber = ?`).run(Date.now(), load.id, k.kind, k.stop);
  logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'stop_time_cleared',
    detail: (action === 'in' ? 'Check-in at ' : 'Check-out of ') + stopLabel(k) + ' undone by ' + (driverName || 'driver'), actor: driverName || 'Driver' });
  return out(row(load.id, k));
}
// Automatic check-out when the driver completes the pickup or sends a stop's signed documents. Never overwrites a
// check-out already recorded (a driver tap or a dispatch correction wins), and only when the account has it on.
function autoOut({ load, kind, stopNumber, at, gps, by, source, fallbackOrgId }) {
  try {
    if (!load || !enabledFor(load, fallbackOrgId)) return;
    const k = stopKey(kind, stopNumber); if (!k) return;
    const r = ensureRow(load.id, k);
    if (r.outAt) return;
    const when = at || Date.now();
    db.prepare(`UPDATE stop_times SET outAt = ?, outGps = ?, outBy = ?, outSource = ?, updatedAt = ? WHERE id = ?`).run(when, gpsJson(gps), by || null, source, Date.now(), r.id);
    logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'checked_out',
      detail: 'Checked out of ' + stopLabel(k) + ' automatically (' + (source === 'pickup' ? 'pickup complete' : 'documents signed') + ')' + (by ? ' — ' + by : ''), actor: by || 'system' });
  } catch (e) { /* best-effort: never block a pickup or a signed upload */ }
}
// Undo an automatic check-out when the action that caused it is undone (e.g. the pickup is reset).
function clearAutoOut(load, kind, stopNumber, source) {
  try {
    const k = stopKey(kind, stopNumber); if (!k) return;
    db.prepare(`UPDATE stop_times SET outAt = NULL, outGps = NULL, outBy = NULL, outSource = NULL, updatedAt = ? WHERE loadId = ? AND kind = ? AND stopNumber = ? AND outSource = ?`)
      .run(Date.now(), load.id, k.kind, k.stop, source);
  } catch (e) {}
}
// Dispatch sets or clears a time (inAt/outAt: epoch ms, or null to clear; undefined = leave as is).
function dispatchSet({ load, kind, stopNumber, inAt, outAt, actor }) {
  const k = stopKey(kind, stopNumber);
  if (!k) throw new Error('Unknown stop');
  const valid = (v) => v === null || (typeof v === 'number' && Number.isFinite(v) && v > 946684800000 && v < Date.now() + 2 * 86400000);
  if ((inAt !== undefined && !valid(inAt)) || (outAt !== undefined && !valid(outAt))) throw new Error('That time doesn’t look right');
  const cur = ensureRow(load.id, k);
  // The portal's editor works to the minute, so a time equal to the stored one at minute precision is unchanged —
  // otherwise re-saving an untouched driver time would relabel it "set by dispatch" (and drop its GPS/source).
  const sameMinute = (a, b) => a != null && b != null && Math.floor(a / 60000) === Math.floor(b / 60000);
  if (sameMinute(inAt, cur.inAt)) inAt = undefined;
  if (sameMinute(outAt, cur.outAt)) outAt = undefined;
  const nIn = inAt === undefined ? cur.inAt : inAt, nOut = outAt === undefined ? cur.outAt : outAt;
  if (nIn && nOut && nOut < nIn) throw new Error('The out time is before the in time');
  const now = Date.now(), changed = [];
  if (inAt !== undefined && inAt !== cur.inAt) { db.prepare(`UPDATE stop_times SET inAt = ?, inBy = ?, inGps = CASE WHEN ? IS NULL THEN NULL ELSE inGps END, updatedAt = ? WHERE id = ?`).run(inAt, actor, inAt, now, cur.id); changed.push(inAt === null ? 'cleared time in' : 'set time in'); }
  if (outAt !== undefined && outAt !== cur.outAt) { db.prepare(`UPDATE stop_times SET outAt = ?, outBy = ?, outSource = ?, outGps = CASE WHEN ? IS NULL THEN NULL ELSE outGps END, updatedAt = ? WHERE id = ?`).run(outAt, actor, outAt === null ? null : 'dispatch', outAt, now, cur.id); changed.push(outAt === null ? 'cleared time out' : 'set time out'); }
  if (changed.length) logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'stop_time_edited',
    detail: 'Dispatch ' + changed.join(' and ') + ' at ' + stopLabel(k), actor });
  return out(row(load.id, k));
}

module.exports = { enabledFor, listFor, mapFor, driverMark, driverUndo, autoOut, clearAutoOut, dispatchSet };
