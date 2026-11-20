// A driver's link, short enough to text: https://haulproofepod.com/go/K7M2QX9PRA. /go/<code> sends the phone on to the
// driver app with their full key (/driver?k=…). Codes skip look-alike characters (0/O, 1/I/L) so one read aloud or
// retyped still works. 10 characters from 31 = about 50 bits, and the driver's own PIN locks the app once they set it.
const crypto = require('crypto');
const { db } = require('./db');

const ABC = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const newCode = () => Array.from(crypto.randomBytes(10), b => ABC[b % ABC.length]).join('');
const originOf = req => (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host'));

// The driver's short code, made the first time it's asked for
function shortCodeFor(d) {
  if (d.shortCode) return d.shortCode;
  for (let i = 0; i < 5; i++) {
    const c = newCode();
    try { if (db.prepare(`UPDATE drivers SET shortCode = ? WHERE id = ? AND shortCode IS NULL`).run(c, d.id).changes) { d.shortCode = c; return c; } }
    catch (e) { continue; }   // that code is taken (unique index): try another
    const now = db.prepare(`SELECT shortCode FROM drivers WHERE id = ?`).get(d.id);   // someone else just made one
    if (now && now.shortCode) { d.shortCode = now.shortCode; return now.shortCode; }
  }
  return null;
}
// The link to give a driver: the short one, or the full one if a code couldn't be made
function driverLink(req, d) {
  const c = shortCodeFor(d);
  return c ? originOf(req) + '/go/' + c : originOf(req) + '/driver?k=' + encodeURIComponent(d.token);
}
const driverByCode = code => db.prepare(`SELECT * FROM drivers WHERE shortCode = ? COLLATE NOCASE`).get(String(code || '').trim());

// When a driver taps their link (before any PIN), so dispatch can see it went through: the first and latest time on
// the driver, and a line in the history of each load they're on (at most once every 3 hours per load).
for (const c of ['linkOpenedAt INTEGER', 'linkLastOpenedAt INTEGER']) { try { db.exec(`ALTER TABLE drivers ADD COLUMN ${c}`); } catch (e) {} }
const THREE_H = 3 * 60 * 60 * 1000;
function noteLinkOpened(d, now = Date.now()) {
  if (!d || !d.id) return;
  try {
    db.prepare(`UPDATE drivers SET linkOpenedAt = COALESCE(linkOpenedAt, ?), linkLastOpenedAt = ? WHERE id = ?`).run(now, now, d.id);
    const loads = db.prepare(`SELECT l.id, l.orgId, l.poNumber FROM loads l WHERE l.assignedDriverId = ?
        AND (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.status IN ('signed','emailed'))
          < (CASE WHEN l.podMode = 'paper' THEN COALESCE(l.paperStops, 1) ELSE 1 END)
      ORDER BY l.createdAt DESC LIMIT 20`).all(d.id);
    const recent = db.prepare(`SELECT 1 FROM load_events WHERE loadId = ? AND type = 'driver_opened' AND createdAt > ? LIMIT 1`);
    const { logEvent } = require('./events');
    loads.forEach(l => { if (!recent.get(l.id, now - THREE_H)) logEvent({ orgId: l.orgId, loadId: l.id, poNumber: l.poNumber, type: 'driver_opened',
      detail: `${d.name} opened their HaulProof link` + (d.pinHash ? '' : ' (no PIN yet)'), actor: d.name }); });
  } catch (e) { console.error('link opened', e.message); }
}

module.exports = { driverLink, shortCodeFor, driverByCode, noteLinkOpened };
