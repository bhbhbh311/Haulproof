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

module.exports = { driverLink, shortCodeFor, driverByCode };
