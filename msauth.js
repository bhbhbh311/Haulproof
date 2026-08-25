// Microsoft Entra ID (Azure AD) single sign-on for the dispatch portal.
//
// Flow (OpenID Connect authorization-code + PKCE, confidential client):
//   1. GET /api/auth/microsoft            -> redirect the browser to Microsoft's login page
//   2. Microsoft authenticates the user and redirects back to
//      GET /api/auth/microsoft/callback   -> we exchange the code for tokens over a direct
//                                            server->Microsoft TLS call, read the ID token,
//                                            check the allowlist, then set our own session cookie.
//
// The ID token is obtained directly from Microsoft's token endpoint over TLS (not through the
// browser), so for a confidential client it can be trusted after validating aud / iss / nonce / exp.
// (Want belt-and-suspenders JWKS signature verification too? See the note in the README.)

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const { upsertSsoUser, signToken } = require('./auth');

const router = express.Router();

const TENANT = process.env.MS_TENANT_ID || 'common';
const CLIENT_ID = process.env.MS_CLIENT_ID || '';
const CLIENT_SECRET = process.env.MS_CLIENT_SECRET || '';
// PORTAL_URL is the single source of truth for the portal's address (no trailing slash).
const PORTAL_URL = (process.env.PORTAL_URL || 'http://localhost:4000').replace(/\/+$/, '');
// The redirect URI is derived from PORTAL_URL so there's only one setting to change when you
// know your domain. Set MS_REDIRECT_URI only if you need it to differ from the portal host.
const CALLBACK_PATH = '/api/auth/microsoft/callback';
const REDIRECT_URI = process.env.MS_REDIRECT_URI || (PORTAL_URL + CALLBACK_PATH);
const AUTHORITY = `https://login.microsoftonline.com/${TENANT}`;
const SCOPE = 'openid profile email';

// SSO is "configured" only when the Entra app-registration values are present.
function ssoConfigured() { return !!(CLIENT_ID && CLIENT_SECRET); }

const ALLOWLIST_PATH = path.join(__dirname, '..', 'sso-allowlist.json');

// Load the allowlist fresh every sign-in so edits apply without a restart.
function loadAllowlist() {
  try {
    const j = JSON.parse(fs.readFileSync(ALLOWLIST_PATH, 'utf8'));
    const norm = (a) => (Array.isArray(a) ? a.map((e) => String(e).toLowerCase().trim()).filter(Boolean) : []);
    return { admins: norm(j.admins), users: norm(j.users) };
  } catch {
    return { admins: [], users: [] };
  }
}

// Decide whether an email is allowed and with what role. null => denied.
function roleForEmail(email) {
  const em = (email || '').toLowerCase().trim();
  if (!em) return null;
  const { admins, users } = loadAllowlist();
  if (admins.includes(em)) return 'admin';
  if (users.includes(em)) return 'dispatcher';
  return null;
}

function b64url(buf) { return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

// Decode a JWT payload WITHOUT signature verification (safe here: the token came straight from
// Microsoft's token endpoint over TLS). We still validate the claims below.
function decodeJwtPayload(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('malformed id_token');
  const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  return JSON.parse(json);
}

function emailFromClaims(c) {
  return (c.email || c.preferred_username || c.upn || '').toLowerCase().trim();
}

// Short-lived signed-ish transaction cookie carrying state + PKCE verifier + nonce between the
// two legs of the flow. httpOnly so the browser JS can't read it.
const TXN_COOKIE = 'hp_oauth';
function setTxnCookie(res, data) {
  res.cookie(TXN_COOKIE, JSON.stringify(data), {
    httpOnly: true, sameSite: 'lax', secure: isSecure(), maxAge: 10 * 60 * 1000, path: '/',
  });
}
function isSecure() { return PORTAL_URL.startsWith('https://'); }

// ---- Leg 1: start sign-in ----
router.get('/microsoft', (req, res) => {
  if (!ssoConfigured()) return res.redirect(`${PORTAL_URL}/?sso=unconfigured`);
  const state = b64url(crypto.randomBytes(16));
  const nonce = b64url(crypto.randomBytes(16));
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  setTxnCookie(res, { state, nonce, verifier });

  const p = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    response_mode: 'query',
    scope: SCOPE,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  res.redirect(`${AUTHORITY}/oauth2/v2.0/authorize?${p.toString()}`);
});

// ---- Leg 2: Microsoft redirects back here ----
router.get('/microsoft/callback', async (req, res) => {
  const fail = (reason) => res.redirect(`${PORTAL_URL}/?sso=${encodeURIComponent(reason)}`);
  try {
    if (req.query.error) return fail(req.query.error_description || req.query.error);
    const code = req.query.code;
    const returnedState = req.query.state;
    let txn = {};
    try { txn = JSON.parse(req.cookies[TXN_COOKIE] || '{}'); } catch { txn = {}; }
    res.clearCookie(TXN_COOKIE, { path: '/' });
    if (!code || !returnedState || returnedState !== txn.state) return fail('bad_state');

    // Exchange the auth code for tokens (server-to-server, includes the client secret + PKCE verifier).
    const body = new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      code_verifier: txn.verifier || '',
    });
    const tokRes = await fetch(`${AUTHORITY}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!tokRes.ok) {
      const t = await tokRes.text().catch(() => '');
      console.error('token exchange failed', tokRes.status, t);
      return fail('token_exchange_failed');
    }
    const tok = await tokRes.json();
    if (!tok.id_token) return fail('no_id_token');

    const claims = decodeJwtPayload(tok.id_token);
    // Validate the ID token claims.
    if (claims.aud !== CLIENT_ID) return fail('bad_audience');
    if (txn.nonce && claims.nonce && claims.nonce !== txn.nonce) return fail('bad_nonce');
    if (claims.exp && Date.now() / 1000 > claims.exp + 60) return fail('token_expired');
    // Issuer must belong to Microsoft; if a specific tenant is configured, it must match.
    const iss = String(claims.iss || '');
    if (!/^https:\/\/login\.microsoftonline\.com\//.test(iss) && !/sts\.windows\.net/.test(iss)) return fail('bad_issuer');
    if (TENANT !== 'common' && TENANT !== 'organizations' && claims.tid && claims.tid !== TENANT) return fail('wrong_tenant');

    const email = emailFromClaims(claims);
    const role = roleForEmail(email);
    if (!role) return fail('not_authorized');

    const name = claims.name || email;
    const user = upsertSsoUser({ email, name, role });
    const session = signToken(user);

    // Set our own httpOnly session cookie and bounce back to the portal (no token in the URL).
    res.cookie('hp_session', session, {
      httpOnly: true, sameSite: 'lax', secure: isSecure(), maxAge: 12 * 60 * 60 * 1000, path: '/',
    });
    return res.redirect(`${PORTAL_URL}/?sso=ok`);
  } catch (e) {
    console.error('SSO callback error', e);
    return fail('sso_error');
  }
});

module.exports = { router, ssoConfigured, roleForEmail, loadAllowlist, REDIRECT_URI, PORTAL_URL };
