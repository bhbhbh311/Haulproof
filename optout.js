// Email opt-out (unsubscribe) helpers. Legal/CAN-SPAM compliance: any recipient of an emailed
// document can opt out with one click, and once opted out we never email them a document again.
//
// The unsubscribe link carries an HMAC-signed token (email + signature) so a recipient can opt
// themselves out from the email with no login, but the link cannot be forged to opt out an
// arbitrary address by guessing a URL. We reuse JWT_SECRET as the signing key.
const crypto = require('crypto');
const { db } = require('./db');
const { JWT_SECRET } = require('./auth');

const norm = (e) => String(e || '').trim().toLowerCase();

// Compact base64url of an HMAC over the (normalized) email.
function sign(email) {
  return crypto.createHmac('sha256', JWT_SECRET).update('optout:' + norm(email)).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Token embedded in the unsubscribe URL: base64url(email).sig
function unsubToken(email) {
  const e = norm(email);
  const b = Buffer.from(e, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return b + '.' + sign(e);
}

// Verify a token from the URL; returns the email if valid, else null.
function verifyUnsub(token) {
  try {
    const [b, sig] = String(token || '').split('.');
    if (!b || !sig) return null;
    const email = Buffer.from(b.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const expect = sign(email);
    // constant-time compare
    const a = Buffer.from(sig), c = Buffer.from(expect);
    if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return null;
    return norm(email);
  } catch (e) { return null; }
}

function isOptedOut(email) {
  const e = norm(email);
  if (!e) return false;
  return !!db.prepare('SELECT 1 FROM email_optouts WHERE email = ?').get(e);
}

function optOut(email, source, note) {
  const e = norm(email);
  if (!e) return false;
  db.prepare('INSERT OR IGNORE INTO email_optouts (email, createdAt, source, note) VALUES (?,?,?,?)')
    .run(e, Date.now(), source || 'unknown', note || null);
  return true;
}

// Remove an address from the opt-out list (admin action / re-consent).
function optIn(email) {
  const e = norm(email);
  if (!e) return false;
  db.prepare('DELETE FROM email_optouts WHERE email = ?').run(e);
  return true;
}

// Given a list of recipient emails, return { allowed, blocked } split by opt-out status.
function filterOptedOut(list) {
  const seen = new Set();
  const allowed = [], blocked = [];
  (list || []).forEach(raw => {
    const e = norm(raw);
    if (!e || seen.has(e)) return;
    seen.add(e);
    if (isOptedOut(e)) blocked.push(raw); else allowed.push(raw);
  });
  return { allowed, blocked };
}

function listOptedOut() {
  return db.prepare('SELECT email, createdAt, source, note FROM email_optouts ORDER BY createdAt DESC').all();
}

module.exports = { unsubToken, verifyUnsub, isOptedOut, optOut, optIn, filterOptedOut, listOptedOut, norm };
