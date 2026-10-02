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

// Category-scoped signature, so a status-update unsubscribe link can't opt someone out of documents (or vice versa).
function signCat(email, cat) {
  return crypto.createHmac('sha256', JWT_SECRET).update('optout:' + String(cat) + ':' + norm(email)).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const b64url = (s) => Buffer.from(s, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

// v1 token embedded in the unsubscribe URL: base64url(email).sig  — ALWAYS the 'documents' category.
function unsubToken(email) {
  const e = norm(email);
  return b64url(e) + '.' + sign(e);
}
// v2 token carrying a category: base64url(email).category.sig  — used for status-update emails.
function unsubTokenCat(email, cat) {
  const e = norm(email);
  return b64url(e) + '.' + encodeURIComponent(String(cat)) + '.' + signCat(e, String(cat));
}

// Verify a token from the URL; returns { email, category } if valid, else null.
// Backward-compatible: a 2-part token is a v1 'documents' unsubscribe link.
function verifyUnsub(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length === 2) {
      const [b, sig] = parts; if (!b || !sig) return null;
      const email = unb64url(b); const expect = sign(email);
      const a = Buffer.from(sig), c = Buffer.from(expect);
      if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return null;
      return { email: norm(email), category: 'documents' };
    }
    if (parts.length === 3) {
      const [b, catRaw, sig] = parts; if (!b || !catRaw || !sig) return null;
      const cat = decodeURIComponent(catRaw); const email = unb64url(b); const expect = signCat(email, cat);
      const a = Buffer.from(sig), c = Buffer.from(expect);
      if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return null;
      return { email: norm(email), category: cat };
    }
    return null;
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

// ---- STATUS (stage-notification) opt-outs — a separate list from document opt-outs above. ----
function isStatusOptedOut(email) {
  const e = norm(email);
  if (!e) return false;
  return !!db.prepare('SELECT 1 FROM status_optouts WHERE email = ?').get(e);
}
function statusOptOut(email, source, note) {
  const e = norm(email);
  if (!e) return false;
  db.prepare('INSERT OR IGNORE INTO status_optouts (email, createdAt, source, note) VALUES (?,?,?,?)')
    .run(e, Date.now(), source || 'unknown', note || null);
  return true;
}
function statusOptIn(email) {
  const e = norm(email);
  if (!e) return false;
  db.prepare('DELETE FROM status_optouts WHERE email = ?').run(e);
  return true;
}
function filterStatusOptedOut(list) {
  const seen = new Set();
  const allowed = [], blocked = [];
  (list || []).forEach(raw => {
    const e = norm(raw);
    if (!e || seen.has(e)) return;
    seen.add(e);
    if (isStatusOptedOut(e)) blocked.push(raw); else allowed.push(raw);
  });
  return { allowed, blocked };
}
function listStatusOptedOut() {
  return db.prepare('SELECT email, createdAt, source, note FROM status_optouts ORDER BY createdAt DESC').all();
}

module.exports = {
  unsubToken, unsubTokenCat, verifyUnsub, norm,
  isOptedOut, optOut, optIn, filterOptedOut, listOptedOut,
  isStatusOptedOut, statusOptOut, statusOptIn, filterStatusOptedOut, listStatusOptedOut,
};
