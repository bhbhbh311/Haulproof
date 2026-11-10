// A new login gets an email with a "Choose your password" link (login-info.html → POST /api/auth/set-password).
// Nobody types a password for someone else. Used wherever a login is created for a new company.
const crypto = require('crypto');
const { db } = require('./db');
const { createUser } = require('./auth');
const { sendMail } = require('./mailer');

const originOf = req => (process.env.PORTAL_URL || '').replace(/\/+$/, '') || (req.protocol + '://' + req.get('host'));

// Make a 7-day, one-use link for an existing login. Their current password (if any) keeps working until they use it.
function passwordLink(req, userId) {
  const token = crypto.randomBytes(24).toString('hex'), now = Date.now();
  db.prepare('DELETE FROM login_links WHERE userId = ?').run(userId);
  // tempPassword is never shown; the column just can't be empty
  db.prepare('INSERT INTO login_links (token, userId, tempPassword, expiresAt, createdAt) VALUES (?,?,?,?,?)')
    .run(token, userId, crypto.randomBytes(8).toString('hex'), now + 7 * 24 * 60 * 60 * 1000, now);
  return originOf(req) + '/login-info?t=' + token;
}

// Create a login and email it the link. `company` names the account in the email. Returns { user, link }.
function inviteLogin(req, { email, name, role, orgId, company }) {
  const user = createUser({ email, name: name || '', role: role || 'admin', password: crypto.randomBytes(16).toString('hex'), orgId });
  const link = passwordLink(req, user.id);
  sendMail({ to: email, subject: 'Your HaulProof login is ready',
    text: `You've been set up on HaulProof${name ? ', ' + name : ''}${company ? ' for ' + company : ''}.\n\nOpen this link to choose your password and sign in:\n${link}\n\nThis link expires in 7 days.` });
  return { user, link };
}

module.exports = { inviteLogin, passwordLink, originOf };
