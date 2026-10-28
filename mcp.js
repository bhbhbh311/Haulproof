// AI connector: lets AI apps (Claude's "Add custom connector", and other MCP clients) work with HaulProof.
//
//  • Sign-in is standard OAuth 2.1 (dynamic client registration + PKCE). The person connecting signs in with their
//    own HaulProof login and approves the connection; the AI then acts as THAT login — same permissions, same
//    company walls. Tokens are opaque random strings; only their SHA-256 hashes are stored.
//  • /mcp speaks the Model Context Protocol (Streamable HTTP, stateless JSON responses).
//  • Every tool calls HaulProof's own REST API in-process (with a short session token for the connected login), so
//    the AI goes through exactly the same rules, history entries, and driver notifications as the portal.
//  • /api/ai-connections lets a login see and disconnect the AI apps it has connected.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { db } = require('./db');
const { requireAuth, signToken, JWT_SECRET } = require('./auth');

const router = express.Router();
const PORT = process.env.PORT || 4000;
const SCOPE = 'haulproof';
const ACCESS_TTL = 60 * 60 * 1000;               // 1 hour
const REFRESH_TTL = 60 * 24 * 60 * 60 * 1000;    // 60 days (rotated on every use)
const CODE_TTL = 10 * 60 * 1000;                 // 10 minutes
const aidocs = require('./aidocs');
const aiplace = require('./aiplace');
const MAX_DOC_BYTES = 20 * 1024 * 1024;   // base64 of 20 MB still fits the 28 MB /mcp body limit
const UPLOAD_LINK_MS = 30 * 60 * 1000;   // get_upload_link links last 30 minutes and work once

db.exec(`
-- One-time upload links from the get_upload_link tool: POST a PDF to /u/<token> to attach it to a load's stop.
CREATE TABLE IF NOT EXISTS upload_links (
  tokenHash    TEXT PRIMARY KEY,
  userId       TEXT NOT NULL,
  loadId       TEXT NOT NULL,
  stopNumber   INTEGER NOT NULL DEFAULT 1,
  docType      TEXT,
  filename     TEXT,
  expiresAt    INTEGER NOT NULL,
  usedAt       INTEGER
);
CREATE TABLE IF NOT EXISTS oauth_clients (
  id           TEXT PRIMARY KEY,
  secretHash   TEXT,                 -- NULL for public (PKCE-only) clients
  name         TEXT,
  redirectUris TEXT NOT NULL,        -- JSON array
  createdAt    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  codeHash     TEXT PRIMARY KEY,
  clientId     TEXT NOT NULL,
  userId       TEXT NOT NULL,
  redirectUri  TEXT NOT NULL,
  challenge    TEXT NOT NULL,
  expiresAt    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
  tokenHash    TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,        -- 'access' | 'refresh'
  clientId     TEXT NOT NULL,
  userId       TEXT NOT NULL,
  expiresAt    INTEGER NOT NULL,
  createdAt    INTEGER NOT NULL,
  lastUsedAt   INTEGER
);
`);

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const randomToken = (prefix) => prefix + b64url(crypto.randomBytes(32));
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
// Public base URL as the caller reached us (Render terminates TLS, so trust its forwarded proto).
function baseUrl(req) {
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
  return proto + '://' + req.get('host');
}
function clientRow(id) { return id ? db.prepare(`SELECT * FROM oauth_clients WHERE id = ?`).get(id) : null; }
function redirectAllowed(client, uri) {
  try { return JSON.parse(client.redirectUris || '[]').indexOf(uri) >= 0; } catch (e) { return false; }
}
// A login that may connect: exists, and (if it belongs to a company) that company is active.
function userRow(id) {
  const u = id ? db.prepare(`SELECT * FROM users WHERE id = ?`).get(id) : null;
  if (!u) return null;
  if (u.orgId) { const o = db.prepare(`SELECT active FROM orgs WHERE id = ?`).get(u.orgId); if (o && !o.active) return null; }
  return u;
}
function sessionUser(req) {
  const tok = req.cookies && req.cookies.hp_session;
  if (!tok) return null;
  try { return userRow(jwt.verify(tok, JWT_SECRET).sub); } catch (e) { return null; }
}
function orgName(orgId) { const o = orgId ? db.prepare(`SELECT name FROM orgs WHERE id = ?`).get(orgId) : null; return o ? o.name : null; }

// ======================================= OAuth discovery + endpoints =======================================
const formParser = express.urlencoded({ extended: false });

function protectedResourceMeta(req, res) {
  const base = baseUrl(req);
  res.json({ resource: base + '/mcp', authorization_servers: [base], scopes_supported: [SCOPE], bearer_methods_supported: ['header'], resource_name: 'HaulProof' });
}
router.get('/.well-known/oauth-protected-resource', protectedResourceMeta);
router.get('/.well-known/oauth-protected-resource/mcp', protectedResourceMeta);
router.get('/.well-known/oauth-authorization-server', (req, res) => {
  const base = baseUrl(req);
  res.json({
    issuer: base,
    authorization_endpoint: base + '/oauth/authorize',
    token_endpoint: base + '/oauth/token',
    registration_endpoint: base + '/oauth/register',
    revocation_endpoint: base + '/oauth/revoke',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    scopes_supported: [SCOPE],
  });
});

// Dynamic client registration (RFC 7591). Redirect URIs must be https, or http on localhost for desktop tools.
router.post('/oauth/register', (req, res) => {
  const b = req.body || {};
  const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris.map(String) : [];
  const okUri = (u) => { try { const x = new URL(u); return x.protocol === 'https:' || (x.protocol === 'http:' && /^(localhost|127\.0\.0\.1|\[::1\])$/.test(x.hostname)); } catch (e) { return false; } };
  if (!uris.length || !uris.every(okUri)) return res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris must be https (or http://localhost)' });
  const method = b.token_endpoint_auth_method || 'none';
  if (['none', 'client_secret_post', 'client_secret_basic'].indexOf(method) < 0) return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'unsupported token_endpoint_auth_method' });
  const id = 'hpc_' + b64url(crypto.randomBytes(12));
  const secret = method === 'none' ? null : randomToken('hps_');
  const name = String(b.client_name || 'AI app').slice(0, 80);
  db.prepare(`INSERT INTO oauth_clients (id, secretHash, name, redirectUris, createdAt) VALUES (?,?,?,?,?)`)
    .run(id, secret ? sha(secret) : null, name, JSON.stringify(uris), Date.now());
  const out = { client_id: id, client_name: name, redirect_uris: uris, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: method, client_id_issued_at: Math.floor(Date.now() / 1000) };
  if (secret) { out.client_secret = secret; out.client_secret_expires_at = 0; }
  res.status(201).json(out);
});

// Signed form token for the consent page, so an approval can only come from the page we rendered for this login.
function consentSig(userId, q) {
  return crypto.createHmac('sha256', JWT_SECRET)
    .update([userId, q.client_id, q.redirect_uri, q.code_challenge, q.state || ''].join('|')).digest('hex');
}
function authorizeError(res, msg) {
  res.status(400).type('html').send(page('Can’t connect', '<p>' + esc(msg) + '</p><p class="sub">Close this window and try connecting again from your AI app.</p>'));
}
function redirectWith(res, redirectUri, params) {
  const u = new URL(redirectUri);
  Object.keys(params).forEach(k => { if (params[k] != null) u.searchParams.set(k, params[k]); });
  res.redirect(u.toString());
}

router.get('/oauth/authorize', (req, res) => {
  const q = req.query;
  const client = clientRow(q.client_id);
  if (!client) return authorizeError(res, 'This AI app isn’t registered with HaulProof.');
  if (!q.redirect_uri || !redirectAllowed(client, q.redirect_uri)) return authorizeError(res, 'The return address for this AI app doesn’t match its registration.');
  if (q.response_type !== 'code') return redirectWith(res, q.redirect_uri, { error: 'unsupported_response_type', state: q.state });
  if (!q.code_challenge || (q.code_challenge_method || 'plain') !== 'S256') return redirectWith(res, q.redirect_uri, { error: 'invalid_request', error_description: 'PKCE S256 is required', state: q.state });

  const user = sessionUser(req);
  const appName = esc(client.name || 'An AI app');
  if (!user) {
    // Not signed in: a compact sign-in form that sets the normal portal session, then reloads this page.
    return res.type('html').send(page('Connect ' + appName + ' to HaulProof',
      '<p><b>' + appName + '</b> wants to connect to your HaulProof account. Sign in to continue.</p>' +
      '<form id="f"><label>Email<input id="em" type="email" autocomplete="username" required></label>' +
      '<label>Password<input id="pw" type="password" autocomplete="current-password" required></label>' +
      '<div id="msg" class="err"></div><button class="btn" type="submit">Sign in</button></form>' +
      '<script>document.getElementById("f").addEventListener("submit",function(e){e.preventDefault();var m=document.getElementById("msg");m.textContent="";' +
      'fetch("/api/auth/login",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:document.getElementById("em").value,password:document.getElementById("pw").value})})' +
      '.then(function(r){return r.json().then(function(j){if(!r.ok)throw new Error(j.error||"Sign-in failed");location.reload();});}).catch(function(err){m.textContent=err.message;});});</script>'));
  }
  if (!user.orgId) {
    return res.type('html').send(page('Use a company login',
      '<p>You’re signed in as <b>' + esc(user.email) + '</b>, a Master Admin login that isn’t tied to a company, so an AI couldn’t create loads with it.</p>' +
      '<p class="sub">Sign in with a company login, or use <b>HaulProof Help</b> to switch into the company first, then connect again.</p>'));
  }
  const company = esc(orgName(user.orgId) || 'your company');
  const hidden = ['client_id', 'redirect_uri', 'code_challenge', 'state', 'scope', 'resource']
    .map(k => '<input type="hidden" name="' + k + '" value="' + esc(q[k] || '') + '">').join('');
  res.type('html').send(page('Connect ' + appName + ' to HaulProof',
    '<p><b>' + appName + '</b> wants to work in HaulProof as <b>' + esc(user.name || user.email) + '</b> at <b>' + company + '</b>.</p>' +
    '<p class="sub">It gets the same permissions as your login and only sees ' + company + '’s data. It will be able to:</p>' +
    '<ul><li>Look up loads, customers and drivers</li><li>Create loads and change their PO #, load # and customer</li>' +
    '<li>Assign drivers (which sends the load to their phone)</li><li>Add customers</li><li>Attach BOL/POD PDFs to a load’s stops</li></ul>' +
    '<p class="sub">You can disconnect it any time from <b>Settings → AI connections</b> in HaulProof.</p>' +
    '<form method="post" action="/oauth/authorize">' + hidden +
    '<input type="hidden" name="sig" value="' + consentSig(user.id, q) + '">' +
    '<div class="row"><button class="btn ghost" name="decision" value="deny" type="submit">Cancel</button>' +
    '<button class="btn" name="decision" value="allow" type="submit">Allow</button></div></form>' +
    '<p class="sub small">Not ' + esc(user.email) + '? Sign out of HaulProof in this browser, then connect again.</p>'));
});

router.post('/oauth/authorize', formParser, (req, res) => {
  const q = req.body || {};
  const client = clientRow(q.client_id);
  if (!client || !q.redirect_uri || !redirectAllowed(client, q.redirect_uri)) return authorizeError(res, 'This connection request is no longer valid.');
  const user = sessionUser(req);
  if (!user || !user.orgId) return authorizeError(res, 'Your HaulProof sign-in expired. Start connecting again.');
  const expected = consentSig(user.id, q);
  if (!q.sig || q.sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(q.sig), Buffer.from(expected))) return authorizeError(res, 'This connection request is no longer valid.');
  if (q.decision !== 'allow') return redirectWith(res, q.redirect_uri, { error: 'access_denied', state: q.state });
  const code = randomToken('hpa_');
  db.prepare(`INSERT INTO oauth_codes (codeHash, clientId, userId, redirectUri, challenge, expiresAt) VALUES (?,?,?,?,?,?)`)
    .run(sha(code), client.id, user.id, q.redirect_uri, q.code_challenge, Date.now() + CODE_TTL);
  redirectWith(res, q.redirect_uri, { code, state: q.state });
});

function tokenError(res, status, error, desc) { res.status(status).set('Cache-Control', 'no-store').json({ error, error_description: desc }); }
// Authenticate the client at the token endpoint: public clients send only client_id; confidential ones prove the secret.
function tokenClient(req) {
  const b = req.body || {};
  let id = b.client_id, secret = b.client_secret;
  const h = req.headers.authorization || '';
  if (h.startsWith('Basic ')) {
    const dec = Buffer.from(h.slice(6), 'base64').toString('utf8'); const i = dec.indexOf(':');
    id = decodeURIComponent(dec.slice(0, i)); secret = decodeURIComponent(dec.slice(i + 1));
  }
  const c = clientRow(id);
  if (!c) return null;
  if (c.secretHash && (!secret || sha(secret) !== c.secretHash)) return null;
  return c;
}
function issueTokens(clientId, userId) {
  const access = randomToken('hpat_'), refresh = randomToken('hprt_'), now = Date.now();
  const ins = db.prepare(`INSERT INTO oauth_tokens (tokenHash, kind, clientId, userId, expiresAt, createdAt) VALUES (?,?,?,?,?,?)`);
  ins.run(sha(access), 'access', clientId, userId, now + ACCESS_TTL, now);
  ins.run(sha(refresh), 'refresh', clientId, userId, now + REFRESH_TTL, now);
  return { access_token: access, token_type: 'Bearer', expires_in: Math.floor(ACCESS_TTL / 1000), refresh_token: refresh, scope: SCOPE };
}
router.post('/oauth/token', formParser, (req, res) => {
  const b = req.body || {};
  const client = tokenClient(req);
  if (!client) return tokenError(res, 401, 'invalid_client', 'Unknown client or bad client secret');
  db.prepare(`DELETE FROM oauth_tokens WHERE expiresAt < ?`).run(Date.now());
  if (b.grant_type === 'authorization_code') {
    const row = b.code ? db.prepare(`SELECT * FROM oauth_codes WHERE codeHash = ?`).get(sha(b.code)) : null;
    if (row) db.prepare(`DELETE FROM oauth_codes WHERE codeHash = ?`).run(row.codeHash);   // single use
    if (!row || row.clientId !== client.id || row.expiresAt < Date.now()) return tokenError(res, 400, 'invalid_grant', 'Code is invalid or expired');
    if (b.redirect_uri && b.redirect_uri !== row.redirectUri) return tokenError(res, 400, 'invalid_grant', 'redirect_uri mismatch');
    if (!b.code_verifier || b64url(crypto.createHash('sha256').update(String(b.code_verifier)).digest()) !== row.challenge) return tokenError(res, 400, 'invalid_grant', 'PKCE verification failed');
    if (!userRow(row.userId)) return tokenError(res, 400, 'invalid_grant', 'Login no longer active');
    return res.set('Cache-Control', 'no-store').json(issueTokens(client.id, row.userId));
  }
  if (b.grant_type === 'refresh_token') {
    const row = b.refresh_token ? db.prepare(`SELECT * FROM oauth_tokens WHERE tokenHash = ? AND kind = 'refresh'`).get(sha(b.refresh_token)) : null;
    if (!row || row.clientId !== client.id || row.expiresAt < Date.now()) return tokenError(res, 400, 'invalid_grant', 'Refresh token is invalid or expired');
    db.prepare(`DELETE FROM oauth_tokens WHERE tokenHash = ?`).run(row.tokenHash);       // rotate
    if (!userRow(row.userId)) return tokenError(res, 400, 'invalid_grant', 'Login no longer active');
    return res.set('Cache-Control', 'no-store').json(issueTokens(client.id, row.userId));
  }
  return tokenError(res, 400, 'unsupported_grant_type', 'Use authorization_code or refresh_token');
});
router.post('/oauth/revoke', formParser, (req, res) => {
  const t = (req.body && req.body.token) || '';
  if (t) db.prepare(`DELETE FROM oauth_tokens WHERE tokenHash = ?`).run(sha(t));
  res.status(200).json({});
});

// ======================================= "AI connections" (portal) =======================================
router.get('/api/ai-connections', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT t.clientId, c.name, MIN(t.createdAt) AS connectedAt, MAX(COALESCE(t.lastUsedAt, t.createdAt)) AS lastUsedAt
    FROM oauth_tokens t LEFT JOIN oauth_clients c ON c.id = t.clientId
    WHERE t.userId = ? AND t.kind = 'refresh' AND t.expiresAt > ? GROUP BY t.clientId ORDER BY lastUsedAt DESC`).all(req.user.sub, Date.now());
  res.json({ connections: rows.map(r => ({ clientId: r.clientId, name: r.name || 'AI app', connectedAt: r.connectedAt, lastUsedAt: r.lastUsedAt })) });
});
router.delete('/api/ai-connections/:clientId', requireAuth, (req, res) => {
  const n = db.prepare(`DELETE FROM oauth_tokens WHERE userId = ? AND clientId = ?`).run(req.user.sub, req.params.clientId).changes;
  res.json({ ok: true, removed: n });
});

// ============================================== MCP endpoint ==============================================
class ToolError extends Error {}
// Resolve the bearer token to the connected login. Records last use so the portal can show it.
function mcpUser(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  const row = db.prepare(`SELECT * FROM oauth_tokens WHERE tokenHash = ? AND kind = 'access'`).get(sha(h.slice(7).trim()));
  if (!row || row.expiresAt < Date.now()) return null;
  const u = userRow(row.userId);
  if (!u) return null;
  const now = Date.now();
  db.prepare(`UPDATE oauth_tokens SET lastUsedAt = ? WHERE userId = ? AND clientId = ? AND kind = 'refresh'`).run(now, row.userId, row.clientId);
  return u;
}
// Call HaulProof's own REST API as the connected login.
async function api(user, method, path, opts) {
  opts = opts || {};
  const headers = Object.assign({ Authorization: 'Bearer ' + signToken(user) }, opts.headers || {});
  let body = opts.body;
  if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.json); }
  const r = await fetch('http://127.0.0.1:' + PORT + path, { method, headers, body });
  let data = {}; try { data = await r.json(); } catch (e) {}
  if (!r.ok) throw new ToolError(data.error || ('HaulProof returned an error (' + r.status + ')'));
  return data;
}
const norm = (s) => String(s || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s || '').trim());
// Pick one item by id or by name: exact, then normalized, then a single partial match. Ambiguity is an error.
function pickOne(list, ref, label, nameOf) {
  const r = String(ref || '').trim();
  if (!r) throw new ToolError('No ' + label + ' given.');
  const byId = list.find(x => x.id === r); if (byId) return byId;
  const n = norm(r);
  const exact = list.filter(x => norm(nameOf(x)) === n);
  if (exact.length === 1) return exact[0];
  const partial = exact.length ? exact : list.filter(x => norm(nameOf(x)).indexOf(n) >= 0);
  if (partial.length === 1) return partial[0];
  if (!partial.length) throw new ToolError('No ' + label + ' matches "' + r + '".' + (list.length ? ' Known: ' + list.slice(0, 30).map(nameOf).join(', ') + '.' : ''));
  throw new ToolError('"' + r + '" matches more than one ' + label + ': ' + partial.slice(0, 10).map(nameOf).join(', ') + '. Be more specific or use the id.');
}
async function customers(user) { return (await api(user, 'GET', '/api/customers')).customers || []; }
async function drivers(user) { return ((await api(user, 'GET', '/api/drivers')).drivers || []).filter(d => d.active !== false && d.active !== 0); }
const driverLabel = (d) => d.name + (d.phone ? ' (' + d.phone + ')' : (d.email ? ' (' + d.email + ')' : ''));
async function resolveCustomer(user, ref) { return pickOne(await customers(user), ref, 'customer', c => c.name); }
async function resolveDriver(user, ref) {
  const list = await drivers(user);
  const r = String(ref || '').trim(), digits = r.replace(/\D/g, '');
  if (digits.length >= 7) { const byPhone = list.filter(d => String(d.phone || '').replace(/\D/g, '').endsWith(digits.slice(-10))); if (byPhone.length === 1) return byPhone[0]; }
  return pickOne(list, ref, 'driver', d => d.name);
}
// A load by id, PO #, or load # (case-insensitive exact match).
async function resolveLoad(user, ref) {
  const r = String(ref || '').trim();
  if (!r) throw new ToolError('No load given — pass its PO # or id.');
  if (isUuid(r)) return api(user, 'GET', '/api/loads/' + r);
  const rows = (await api(user, 'GET', '/api/loads?q=' + encodeURIComponent(r))).results || [];
  let hit = rows.filter(l => norm(l.poNumber) === norm(r));
  if (!hit.length) hit = rows.filter(l => norm(l.loadNumber) === norm(r));
  if (!hit.length) throw new ToolError('No load with PO # or load # "' + r + '".' + (rows.length ? ' Close matches: ' + rows.slice(0, 8).map(l => l.poNumber || l.loadNumber).join(', ') + '.' : ''));
  if (hit.length > 1) throw new ToolError('More than one load matches "' + r + '". Use the load id.');
  return api(user, 'GET', '/api/loads/' + hit[0].id);
}
function loadSummary(l) {
  return { id: l.id, po_number: l.poNumber || null, load_number: l.loadNumber || null, customer: l.customer || null,
    driver: l.driverName || null, truck: l.truck || null, trailer: l.trailer || null, carrier: l.carrierName || null,
    status: l.status || null, created_at: l.createdAt ? new Date(l.createdAt).toISOString() : null };
}
const DOC_STATUS = { awaiting_build: 'needs signature setup', received: 'received', prepared: 'ready to sign', signed: 'signed', emailed: 'signed and emailed', needs_reupload: 'needs re-upload', parked: 'set aside' };
function loadDetail(d, base) {
  return Object.assign(loadSummary(d.load), {
    portal_link: base + '/app?load=' + encodeURIComponent(d.load.id),
    documents: (d.pods || []).filter(p => p.status !== 'parked').map(p => ({ id: p.id, stop: p.stopNumber, type: p.docType, filename: p.filename, status: DOC_STATUS[p.status] || p.status, receiver: p.receiverName || null, signature_setup_link: base + '/prepare?id=' + p.id })),
    // Driver check-in / check-out per stop (when the account records in/out times).
    in_out_times: (d.stopTimes || []).map(t => {
      const iso = (ms) => ms ? new Date(ms).toISOString() : null;
      return { stop: t.kind === 'pickup' ? 'pickup' : 'stop ' + t.stopNumber, time_in: iso(t.inAt), time_out: iso(t.outAt),
        minutes_on_site: (t.inAt && t.outAt) ? Math.round((t.outAt - t.inAt) / 60000) : null, out_recorded_by: t.outSource };
    }),
  });
}
// Same buckets as the dispatch Dashboard: needs setup → done → on the road → ready for the driver → open.
function loadCat(l) {
  if (l.needsSetup) return 'setup';
  if (l.stopsTotal > 0 && l.stopsDone >= l.stopsTotal) return 'done';
  if (l.pickedUpAt || l.stopsDone > 0) return 'road';
  if (l.readyToSign) return 'ready';
  return 'open';
}
// A 7-day download link for one signed document, openable without signing in (for billing / sending to someone).
function downloadLink(base, pod) { return base + '/d/' + jwt.sign({ k: 'dl', p: pod.id }, JWT_SECRET, { expiresIn: '7d' }); }
const isSigned = (p) => p.status === 'signed' || p.status === 'emailed';
function needCompany(user) { if (!user.orgId) throw new ToolError('This login isn’t tied to a company, so it can’t change loads. Reconnect with a company login.'); }
// Only the owning company files documents (uploads land under the uploader's company).
function needOwner(user, load) { if ((load.orgId || null) !== (user.orgId || null)) throw new ToolError('Load ' + (load.poNumber || load.id) + ' belongs to another company, so documents can’t be attached from this login.'); }

// Fetch a PDF from a public https URL. Blocks private/internal addresses so the server can't be pointed at itself.
async function fetchPdfFromUrl(url) {
  let u; try { u = new URL(url); } catch (e) { throw new ToolError('file_url is not a valid URL.'); }
  if (u.protocol !== 'https:') throw new ToolError('file_url must start with https://');
  const addrs = await require('dns').promises.lookup(u.hostname, { all: true }).catch(() => []);
  if (!addrs.length) throw new ToolError('Couldn’t find the server in file_url.');
  const priv = (a) => /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(a) || /^(::1$|::$|f[cd]|fe80|::ffff:(10|127|169\.254|192\.168)\.)/i.test(a);
  if (addrs.some(a => priv(a.address))) throw new ToolError('file_url points to a private network address.');
  const r = await fetch(u.toString(), { redirect: 'error' }).catch(() => null);
  if (!r || !r.ok) throw new ToolError('Couldn’t download file_url' + (r ? ' (HTTP ' + r.status + ')' : '') + '.');
  const len = Number(r.headers.get('content-length') || 0);
  if (len > MAX_DOC_BYTES) throw new ToolError('That file is too large (max 20 MB).');
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > MAX_DOC_BYTES) throw new ToolError('That file is too large (max 20 MB).');
  return buf;
}

const str = (description) => ({ type: 'string', description });
const TOOLS = [
  { name: 'whoami', title: 'Who am I connected as',
    description: 'Shows which HaulProof login and company this connection acts as, and what it can do.',
    inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: true },
    run: async (user) => ({ name: user.name || null, email: user.email, role: user.role, company: orgName(user.orgId) }) },

  { name: 'list_customers', title: 'List customers',
    description: 'Lists the companies on this account’s customer list (the customer a load is for). Optionally filter by name.',
    inputSchema: { type: 'object', properties: { search: str('Part of a customer name to filter by') } }, annotations: { readOnlyHint: true },
    run: async (user, a) => { const n = norm(a.search); return { customers: (await customers(user)).filter(c => !n || norm(c.name).indexOf(n) >= 0).map(c => ({ id: c.id, name: c.name })) }; } },

  { name: 'add_customer', title: 'Add a customer',
    description: 'Adds a company to this account’s customer list. If one with the same name already exists, returns it instead of adding a duplicate. Check list_customers first.',
    inputSchema: { type: 'object', properties: { name: str('Company name, e.g. "Dannar Outdoor Solutions LLC"') }, required: ['name'] },
    run: async (user, a) => { needCompany(user); const r = await api(user, 'POST', '/api/customers', { json: { name: String(a.name || '').trim() } }); return { customer: { id: r.customer.id, name: r.customer.name }, already_existed: !!r.existed }; } },

  { name: 'list_drivers', title: 'List drivers',
    description: 'Lists this account’s active drivers. Optionally filter by name or phone.',
    inputSchema: { type: 'object', properties: { search: str('Part of a driver name or phone number') } }, annotations: { readOnlyHint: true },
    run: async (user, a) => { const n = norm(a.search), dg = String(a.search || '').replace(/\D/g, ''); return { drivers: (await drivers(user)).filter(d => !n || norm(d.name).indexOf(n) >= 0 || (dg.length >= 3 && String(d.phone || '').replace(/\D/g, '').indexOf(dg) >= 0)).map(d => ({ id: d.id, name: d.name, phone: d.phone || null, email: d.email || null })) }; } },

  { name: 'add_drivers', title: 'Add drivers',
    description: 'Adds one or more drivers to this account (same as the portal\'s Drivers → Import). A driver whose name is already on the roster is skipped. Each new driver gets a personal link to open on their phone; they set their own PIN on first use. Confirm the list with the user before adding.',
    inputSchema: { type: 'object', properties: { drivers: { type: 'array', minItems: 1, maxItems: 200, description: 'Drivers to add',
      items: { type: 'object', properties: { name: str('Driver full name'), phone: str('Phone (optional)'), email: str('Email (optional) — lets dispatch email them their link') }, required: ['name'] } } }, required: ['drivers'] },
    run: async (user, a) => { needCompany(user);
      const records = (a.drivers || []).map(d => ({ name: String(d.name || '').trim(), phone: d.phone ? String(d.phone).trim() : '', email: d.email ? String(d.email).trim() : '' })).filter(d => d.name);
      const r = await api(user, 'POST', '/api/drivers/import', { json: { records } });
      return { added: r.created || 0, skipped: r.skipped || 0, errors: r.errors || [],
        drivers: (r.drivers || []).map(d => ({ name: d.name, email: d.email || null, link: d.link || null })),
        note: 'Send each driver their own link privately (or use Email next to their name in HaulProof → Drivers).' }; } },

  { name: 'add_team_logins', title: 'Add team logins',
    description: 'Creates portal logins for people on this account (same as Team logins → Import). Role is dispatcher (default), sales, or admin — admins get a copy of every signed document and can manage the account, so only use admin when the user asks for it. Existing emails are skipped. Each new person gets a set-up link to choose their own password. Confirm the list and roles with the user before creating.',
    inputSchema: { type: 'object', properties: { logins: { type: 'array', minItems: 1, maxItems: 200, description: 'Logins to create',
      items: { type: 'object', properties: { email: str('Work email'), name: str('Full name'), role: { type: 'string', enum: ['dispatcher', 'sales', 'admin'], description: 'Default dispatcher' } }, required: ['email'] } } }, required: ['logins'] },
    run: async (user, a) => { needCompany(user);
      const records = (a.logins || []).map(l => ({ email: String(l.email || '').trim(), name: l.name ? String(l.name).trim() : '', role: l.role || 'dispatcher' })).filter(l => l.email);
      const r = await api(user, 'POST', '/api/users/import', { json: { records } });
      return { created: r.created || 0, skipped: r.skipped || 0, errors: r.errors || [],
        logins: (r.links || []).map(l => ({ email: l.email, name: l.name || null, role: l.role, setup_link: l.link })),
        note: 'Send each person their own set-up link privately; it lets them choose their password. Existing emails were skipped.' }; } },

  { name: 'needs_attention', title: 'What needs attention',
    description: 'The dispatch Dashboard as data: counts of loads by status and the list of what is waiting on dispatch right now — documents needing signature setup, signed copies whose email failed, loads with no driver — plus who is on the road. Use it for "what needs my attention?" or "what is happening today?".',
    inputSchema: { type: 'object', properties: {} }, annotations: { readOnlyHint: true },
    run: async (user, a, base) => {
      const loads = (await api(user, 'GET', '/api/loads')).results || [];
      const day0 = new Date(); day0.setHours(0, 0, 0, 0);
      const item = (l, extra) => Object.assign({ po_number: l.poNumber || l.loadNumber || null, customer: l.customer || l.customerName || null, driver: l.driverName || null,
        stops: l.stopsTotal ? (l.stopsDone + ' of ' + l.stopsTotal + ' signed') : null, portal_link: base + '/app?load=' + encodeURIComponent(l.id) }, extra || {});
      const by = (k) => loads.filter(l => loadCat(l) === k);
      const noDriver = loads.filter(l => !l.driverName && ['ready', 'open'].indexOf(loadCat(l)) >= 0);
      const failed = loads.filter(l => l.emailFailed > 0);
      return {
        counts: { needs_signature_setup: by('setup').length, ready_for_driver: by('ready').length, on_the_road: by('road').length, waiting_on_paperwork: by('open').length,
          completed: by('done').length, email_failed: failed.length, no_driver: noDriver.length, signed_today: loads.filter(l => l.lastSignedAt && l.lastSignedAt >= day0.getTime()).length },
        needs_attention: [
          ...failed.map(l => item(l, { issue: 'Signed copy email failed — use send_signed_copy to resend' })),
          ...by('setup').map(l => item(l, { issue: 'Signature boxes not placed — the driver can’t sign yet (place_signatures)' })),
          ...noDriver.map(l => item(l, { issue: 'No driver assigned (assign_driver)' })),
        ].slice(0, 40),
        on_the_road: by('road').slice(0, 25).map(l => item(l, { picked_up_at: l.pickedUpAt ? new Date(l.pickedUpAt).toISOString() : null })),
        note: loads.length >= 200 ? 'Only the 200 most recent loads were checked.' : undefined,
      };
    } },

  { name: 'send_signed_copy', title: 'Send or resend a signed copy',
    description: 'Emails signed documents. With "to": sends the signed copy of a load (all signed stops, or one stop) to those addresses — e.g. a customer asking for the POD. Without "to": resends signed copies whose email failed — for one load, or for every load with a failed email when no load is given. Confirm the addresses with the user before sending.',
    inputSchema: { type: 'object', properties: { load: str('PO #, load #, or load id (optional when resending all failed emails)'), stop: { type: 'integer', minimum: 1, description: 'Only this stop (optional)' },
      to: { type: 'array', items: { type: 'string' }, maxItems: 20, description: 'Email addresses to send to (leave out to resend failed emails)' } } },
    run: async (user, a) => {
      const to = (a.to || []).map(e => String(e).trim()).filter(Boolean);
      let loadsToDo = [];
      if (a.load) loadsToDo = [await resolveLoad(user, a.load)];
      else if (to.length) throw new ToolError('Say which load to send (PO #).');
      else { const rows = ((await api(user, 'GET', '/api/loads')).results || []).filter(l => l.emailFailed > 0); for (const l of rows) loadsToDo.push(await api(user, 'GET', '/api/loads/' + l.id)); }
      const results = [];
      for (const d of loadsToDo) {
        let pods = (d.pods || []).filter(isSigned);
        if (a.stop) pods = pods.filter(p => Number(p.stopNumber || 1) === Number(a.stop));
        if (!to.length) pods = pods.filter(p => p.emailStatus === 'failed' || p.emailStatus === 'partial');
        for (const p of pods) {
          const label = { po_number: d.load.poNumber, stop: p.stopNumber || 1 };
          try {
            const r = to.length ? await api(user, 'POST', '/api/pods/' + p.id + '/send', { json: { emails: to } })
                                : await api(user, 'POST', '/api/pods/' + p.id + '/resend-email', { json: {} });
            const failed = r.failed || [], sentTo = r.sentTo || [];
            const ok = !failed.length && (r.ok === true || r.sent === true) && (sentTo.length > 0 || r.sent === true);
            results.push(Object.assign(label, r.simulated ? { result: 'not sent — email isn’t set up on the server' }
              : ok ? { result: 'sent', sent_to: sentTo.length ? sentTo : to, skipped_unsubscribed: (r.blocked && r.blocked.length) ? r.blocked : undefined }
              : { result: 'failed', not_sent_to: failed.length ? failed : to, error: r.error || 'The email service refused it — check the email setup.' }));
          } catch (e) { results.push(Object.assign(label, { result: 'failed', error: e.message })); }
        }
      }
      if (!results.length) return { sent: 0, note: to.length ? 'That load has no signed documents' + (a.stop ? ' for stop ' + a.stop : '') + ' yet.' : 'No failed emails to resend.' };
      return { sent: results.filter(r => r.result === 'sent').length, failed: results.filter(r => r.result !== 'sent').length, results };
    } },

  { name: 'get_signed_documents', title: 'Get signed documents',
    description: 'Lists signed documents (BOLs/PODs) with a download link for each PDF — for billing, invoicing or sending to someone. Filter by customer, PO #, and/or signed date range. Download links work for 7 days without signing in, so only share them with people who should see the document.',
    inputSchema: { type: 'object', properties: { customer: str('Customer name (optional)'), po_number: str('PO # or part of it (optional)'),
      signed_from: str('Earliest signed date, YYYY-MM-DD (optional)'), signed_to: str('Latest signed date, YYYY-MM-DD (optional)'), limit: { type: 'integer', minimum: 1, maximum: 200, description: 'Max documents (default 50)' } } },
    annotations: { readOnlyHint: true },
    run: async (user, a, base) => {
      const from = a.signed_from ? Date.parse(a.signed_from + 'T00:00:00') : null, to = a.signed_to ? Date.parse(a.signed_to + 'T23:59:59') : null;
      if ((a.signed_from && isNaN(from)) || (a.signed_to && isNaN(to))) throw new ToolError('Dates must look like 2026-10-28.');
      const loads = (await api(user, 'GET', '/api/loads' + (a.po_number ? '?q=' + encodeURIComponent(a.po_number) : ''))).results || [];
      const custOf = {}; loads.forEach(l => { custOf[l.id] = l.customer || l.customerName || null; });
      const pods = ((await api(user, 'GET', '/api/pods' + (a.po_number ? '?po=' + encodeURIComponent(a.po_number) : ''))).results || []).filter(isSigned);
      const cn = norm(a.customer);
      const rows = pods.filter(p => (!from || (p.signedAt && p.signedAt >= from)) && (!to || (p.signedAt && p.signedAt <= to)) && (!cn || norm(custOf[p.loadId]).indexOf(cn) >= 0))
        .sort((x, y) => (y.signedAt || 0) - (x.signedAt || 0)).slice(0, Math.min(Number(a.limit) || 50, 200));
      return { total: rows.length, documents: rows.map(p => ({ po_number: p.poNumber || null, load_number: p.loadNumber || null, customer: custOf[p.loadId] || null, stop: p.stopNumber || 1,
        type: p.docType || null, consignee: p.consignee || p.receiverName || null, driver: p.driver || null, signed_at: p.signedAt ? new Date(p.signedAt).toISOString() : null,
        download_link: downloadLink(base, p) })),
        note: (cn && !loads.length) ? 'No loads found to match that customer.' : 'Download links expire in 7 days.' };
    } },

  { name: 'find_loads', title: 'Find loads',
    description: 'Searches loads by PO #, load #, customer, consignee or carrier. With no search, returns the most recent loads.',
    inputSchema: { type: 'object', properties: { search: str('PO #, load #, customer name, etc.'), limit: { type: 'integer', minimum: 1, maximum: 100, description: 'Max results (default 25)' } } }, annotations: { readOnlyHint: true },
    run: async (user, a) => { const r = await api(user, 'GET', '/api/loads' + (a.search ? '?q=' + encodeURIComponent(a.search) : '')); const rows = r.results || []; return { total: rows.length, loads: rows.slice(0, Math.min(Number(a.limit) || 25, 100)).map(loadSummary) }; } },

  { name: 'get_load', title: 'Get a load',
    description: 'Gets one load with its documents (each stop’s BOL/POD and whether it still needs signature setup, is ready to sign, or is signed).',
    inputSchema: { type: 'object', properties: { load: str('PO #, load #, or load id') }, required: ['load'] }, annotations: { readOnlyHint: true },
    run: async (user, a, base) => loadDetail(await resolveLoad(user, a.load), base) },

  { name: 'create_load', title: 'Create a load',
    description: 'Creates a load identified by its customer PO #. Optionally sets the load #, the customer (must already be on the customer list — use add_customer first if needed) and the driver (sends the load to their phone). If a load with that PO # already exists, it is returned unchanged.',
    inputSchema: { type: 'object', properties: {
      po_number: str('Customer PO # (required, unique per account)'), load_number: str('Your load #'),
      customer: str('Customer name or id from list_customers'), driver: str('Driver name, phone, or id from list_drivers'),
      truck: str('Truck #'), trailer: str('Trailer #') }, required: ['po_number'] },
    run: async (user, a, base) => {
      needCompany(user);
      const po = String(a.po_number || '').trim(); if (!po) throw new ToolError('po_number is required.');
      // Resolve names first so a typo fails before anything is created.
      const cust = a.customer ? await resolveCustomer(user, a.customer) : null;
      const drv = a.driver ? await resolveDriver(user, a.driver) : null;
      const c = await api(user, 'POST', '/api/loads', { json: { poNumber: po, loadNumber: String(a.load_number || '').trim() || undefined } });
      if (c.existed) return Object.assign({ already_existed: true, note: 'A load with this PO # already exists; nothing was changed. Use update_load or assign_driver to change it.' }, loadDetail(await api(user, 'GET', '/api/loads/' + c.load.id), base));
      if (cust) await api(user, 'PUT', '/api/loads/' + c.load.id, { json: { customerId: cust.id } });
      if (drv) await api(user, 'POST', '/api/loads/' + c.load.id + '/assign-driver', { json: { driverId: drv.id, truck: a.truck || '', trailer: a.trailer || '' } });
      return Object.assign({ created: true }, loadDetail(await api(user, 'GET', '/api/loads/' + c.load.id), base));
    } },

  { name: 'update_load', title: 'Update a load',
    description: 'Changes a load’s PO #, load # or customer. Pass customer "none" to clear it. Only the company that owns the load can change these.',
    inputSchema: { type: 'object', properties: { load: str('Current PO #, load #, or load id'), po_number: str('New PO #'), load_number: str('New load #'), customer: str('Customer name or id, or "none"') }, required: ['load'] },
    run: async (user, a, base) => {
      needCompany(user);
      const d = await resolveLoad(user, a.load);
      const body = {};
      if (a.po_number != null) body.poNumber = String(a.po_number).trim();
      if (a.load_number != null) body.loadNumber = String(a.load_number).trim();
      if (a.customer != null) body.customerId = /^(none|null|)$/i.test(String(a.customer).trim()) ? '' : (await resolveCustomer(user, a.customer)).id;
      if (!Object.keys(body).length) throw new ToolError('Nothing to change — pass po_number, load_number or customer.');
      const r = await api(user, 'PUT', '/api/loads/' + d.load.id, { json: body });
      if (body.customerId !== undefined && (r.load.customerId || '') !== (body.customerId || '')) throw new ToolError('This login can’t change the customer on that load.');
      return Object.assign({ updated: true }, loadDetail(await api(user, 'GET', '/api/loads/' + d.load.id), base));
    } },

  { name: 'assign_driver', title: 'Assign a driver',
    description: 'Puts a driver (and optionally truck/trailer) on a load. Its ready-to-sign documents go to that driver’s phone.',
    inputSchema: { type: 'object', properties: { load: str('PO #, load #, or load id'), driver: str('Driver name, phone, or id from list_drivers'), truck: str('Truck #'), trailer: str('Trailer #') }, required: ['load', 'driver'] },
    run: async (user, a, base) => {
      needCompany(user);
      const d = await resolveLoad(user, a.load), drv = await resolveDriver(user, a.driver);
      // The assign endpoint overwrites truck/trailer, so keep the load's current ones unless new ones were given.
      const truck = a.truck != null ? a.truck : (d.load.truck || ''), trailer = a.trailer != null ? a.trailer : (d.load.trailer || '');
      await api(user, 'POST', '/api/loads/' + d.load.id + '/assign-driver', { json: { driverId: drv.id, truck, trailer } });
      return Object.assign({ assigned: driverLabel(drv) }, loadDetail(await api(user, 'GET', '/api/loads/' + d.load.id), base));
    } },

  { name: 'attach_document', title: 'Attach a document',
    description: 'Attaches a BOL/POD PDF to a stop on a load, given as base64 (file_base64) or a public https link (file_url). The document lands as "needs signature setup": someone places the signature boxes in HaulProof (signature_setup_link) before the driver can sign it.',
    inputSchema: { type: 'object', properties: {
      load: str('PO #, load #, or load id'), file_base64: str('The PDF, base64-encoded'), file_url: str('Public https link to the PDF'),
      filename: str('File name, e.g. "BOL-4821.pdf"'), stop_number: { type: 'integer', minimum: 1, description: 'Stop number (default 1)' },
      doc_type: { type: 'string', enum: ['BOL', 'POD', 'LUMPER', 'OTHER'], description: 'Document type (default BOL)' } }, required: ['load'] },
    run: async (user, a, base) => {
      needCompany(user);
      const d = await resolveLoad(user, a.load); needOwner(user, d.load);
      let buf;
      if (a.file_base64) { buf = Buffer.from(String(a.file_base64).replace(/^data:[^,]*,/, ''), 'base64'); if (buf.length > MAX_DOC_BYTES) throw new ToolError('That file is too large (max 20 MB).'); }
      else if (a.file_url) buf = await fetchPdfFromUrl(a.file_url);
      else throw new ToolError('Pass the PDF as file_base64 or file_url — or use get_upload_link to upload the file directly.');
      return attachPdf(user, d.load, buf, { stop: a.stop_number, docType: a.doc_type, filename: a.filename }, base);
    } },
  { name: 'get_upload_link', title: 'Get a document upload link',
    description: 'Makes a one-time link (good for 30 minutes) for attaching a BOL/POD PDF to a stop on a load — use it when the PDF is a file you have but can\'t pass as file_url. Send the PDF bytes to upload_url with an HTTP POST (Content-Type: application/pdf), or give the link to the user to open and pick the file. The document lands as "needs signature setup".',
    inputSchema: { type: 'object', properties: {
      load: str('PO #, load #, or load id'), filename: str('File name, e.g. "BOL-4821.pdf"'),
      stop_number: { type: 'integer', minimum: 1, description: 'Stop number (default 1)' },
      doc_type: { type: 'string', enum: ['BOL', 'POD', 'LUMPER', 'OTHER'], description: 'Document type (default BOL)' } }, required: ['load'] },
    run: async (user, a, base) => {
      needCompany(user);
      const d = await resolveLoad(user, a.load); needOwner(user, d.load);
      const token = crypto.randomBytes(24).toString('base64url'), exp = Date.now() + UPLOAD_LINK_MS;
      db.prepare(`INSERT INTO upload_links (tokenHash, userId, loadId, stopNumber, docType, filename, expiresAt) VALUES (?,?,?,?,?,?,?)`)
        .run(sha(token), user.id, d.load.id, Math.max(1, parseInt(a.stop_number, 10) || 1), a.doc_type || 'BOL', String(a.filename || 'document.pdf').slice(0, 120), exp);
      return { upload_url: base + '/u/' + token, expires_at: new Date(exp).toISOString(), po_number: d.load.poNumber,
        how_to_use: 'POST the PDF to upload_url with Content-Type: application/pdf (one file, max 20 MB, one use). Or open upload_url in a browser to choose the file.' };
    } },
  { name: 'review_pages', title: 'Review a document’s pages',
    description: 'Reads every page of a document on a load and labels it (bill of lading, terms, mill/material certificate, invoice…), and suggests which pages to keep for the driver to sign. Changes nothing — show the user the plan, then call trim_document with the pages they approve. Uses AI (about 1–3¢ per document).',
    annotations: { readOnlyHint: true },
    inputSchema: { type: 'object', properties: {
      document: str('Document id (from get_load / attach_document)'), load: str('Or: PO #, load #, or load id …'),
      stop_number: { type: 'integer', minimum: 1, description: '… with the stop number (default 1)' } } },
    run: async (user, a, base) => {
      const { pod, buf } = await docForEdit(user, a);
      const info = await aidocs.pageInfo(buf);
      const acc = aiplace.aiAccess(pod.orgId);
      if (!acc.ok) return { document_id: pod.id, pages: info.numPages, ai: 'unavailable', note: acc.message + ' Look at the document (signature_setup_link) and call trim_document with the pages to keep.', signature_setup_link: base + '/prepare?id=' + pod.id };
      const r = await aidocs.reviewPages({ user }, pod.id, buf, info);
      if (r.error) throw new ToolError('The AI couldn’t read this document (' + r.error + '). Look at it in HaulProof and call trim_document with the pages to keep.');
      return { document_id: pod.id, po_number: pod.poNumber, stop: pod.stopNumber, total_pages: info.numPages, pages: r.pages, suggested_keep_pages: r.keep_pages, note: r.note,
        next_step: 'Confirm with the user, then call trim_document with keep_pages (or stops to split it).', ai_cost_usd: r.costUsd != null ? Math.round(r.costUsd * 10000) / 10000 : null };
    } },
  { name: 'trim_document', title: 'Trim or split a document',
    description: 'Keeps only the chosen pages of a document that hasn’t been signed yet — and can split it into several stops at once. Give keep_pages (1-based, in order) for one document, or stops: [{stop_number, pages}] to split. The original is kept in HaulProof’s recovery bin. Confirm the pages with the user first (review_pages suggests them). Signature boxes must be placed again afterwards (place_signatures).',
    inputSchema: { type: 'object', properties: {
      document: str('Document id'), load: str('Or: PO #, load #, or load id …'),
      stop_number: { type: 'integer', minimum: 1, description: '… with the stop number (default 1)' },
      keep_pages: { type: 'array', items: { type: 'integer', minimum: 1 }, description: 'Pages to keep, 1-based, in the order wanted' },
      stops: { type: 'array', items: { type: 'object', properties: { stop_number: { type: 'integer', minimum: 1 }, pages: { type: 'array', items: { type: 'integer', minimum: 1 } } }, required: ['stop_number', 'pages'] }, description: 'Split into stops instead: each stop gets these pages' } } },
    run: async (user, a, base) => {
      const { pod, buf } = await docForEdit(user, a);
      const n = (await aidocs.pageInfo(buf)).numPages;
      let groups;
      if (Array.isArray(a.stops) && a.stops.length) groups = a.stops.map(g => ({ stop: parseInt(g.stop_number, 10), pages: (g.pages || []).map(Number) }));
      else if (Array.isArray(a.keep_pages) && a.keep_pages.length) groups = [{ stop: pod.stopNumber || 1, pages: a.keep_pages.map(Number) }];
      else throw new ToolError('Say which pages to keep (keep_pages) or how to split it (stops). review_pages can suggest them.');
      groups.forEach(g => {
        if (!(g.stop >= 1)) throw new ToolError('Every stop needs a stop_number of 1 or more.');
        if (!g.pages.length) throw new ToolError('Stop ' + g.stop + ' has no pages.');
        g.pages.forEach(p => { if (!(Number.isInteger(p) && p >= 1 && p <= n)) throw new ToolError('Page ' + p + ' doesn’t exist — the document has ' + n + ' page' + (n === 1 ? '' : 's') + '.'); });
      });
      if (new Set(groups.map(g => g.stop)).size !== groups.length) throw new ToolError('Each stop_number can appear only once.');
      const enc = (v) => encodeURIComponent(String(v));
      const baseName = String(pod.filename || 'document.pdf').replace(/\.pdf$/i, '');
      const made = [];
      for (const g of groups) {
        const bytes = await aidocs.subsetPdf(buf, g.pages);
        const name = groups.length > 1 ? baseName + ' - Stop ' + g.stop + '.pdf' : baseName + '.pdf';
        const r = await api(user, 'POST', '/api/pods/upload', { body: bytes, headers: {
          'Content-Type': 'application/pdf', 'X-POD-Enc': 'uri', 'X-PO': enc(pod.poNumber || ''), 'X-Load': enc(pod.loadNumber || ''),
          'X-Stop': String(g.stop), 'X-DocType': enc(pod.docType || 'BOL'), 'X-Filename': enc(name), 'X-Build': 'dispatch',
          'X-SalesRep': enc(pod.salesRepUserId || '') } });
        if (pod.assignedDriverId) { try { await api(user, 'POST', '/api/pods/' + r.id + '/assign-driver', { json: { driverId: pod.assignedDriverId } }); } catch (e) {} }
        made.push({ document_id: r.id, stop: g.stop, pages_kept: g.pages, page_count: g.pages.length, status: 'needs signature setup', signature_setup_link: base + '/prepare?id=' + r.id });
      }
      await api(user, 'DELETE', '/api/pods/' + pod.id + '?superseded=1');
      return { trimmed_from: { document_id: pod.id, pages: n, kept_in_recovery_bin: true }, documents: made,
        next_step: 'Call place_signatures for each new document so it goes to the driver.' };
    } },
  { name: 'place_signatures', title: 'Place signature boxes',
    description: 'Puts the signature, date and time boxes on a document that hasn’t been signed, then marks it ready to sign so it goes to the driver’s phone. Uses this customer’s saved layout when there is one (free); otherwise the AI places them (about 5¢ per page) — best on PDFs with real text; for phone photos, suggest the user checks the boxes in HaulProof (signature_setup_link). Set save_as_layout to remember an AI layout for this customer.',
    inputSchema: { type: 'object', properties: {
      document: str('Document id'), load: str('Or: PO #, load #, or load id …'),
      stop_number: { type: 'integer', minimum: 1, description: '… with the stop number (default 1)' },
      method: { type: 'string', enum: ['auto', 'saved_layout', 'ai'], description: 'auto (default): saved layout if one exists, else AI' },
      save_as_layout: { type: 'boolean', description: 'After an AI placement, save it as this customer’s layout for this document type' } } },
    run: async (user, a, base) => {
      const { pod, buf } = await docForEdit(user, a);
      const info = await aidocs.pageInfo(buf);
      const method = a.method || 'auto';
      let fields = [], source, note = '', cost = null;
      let tpl = null; try { tpl = await api(user, 'GET', '/api/pods/' + pod.id + '/template'); } catch (e) {}
      if (method !== 'ai' && tpl && tpl.exists && (tpl.fields || []).length) {
        fields = aidocs.layoutToFields(tpl.fields, info.numPages); source = 'saved layout' + (tpl.customerName ? ' for ' + tpl.customerName : '') + ' · ' + (tpl.docType || 'BOL');
      } else if (method === 'saved_layout') {
        throw new ToolError('There’s no saved layout for this customer and document type yet. Use method "ai", or set it up once in HaulProof (signature_setup_link: ' + base + '/prepare?id=' + pod.id + ').');
      } else {
        const acc = aiplace.aiAccess(pod.orgId);
        if (!acc.ok) throw new ToolError('No saved layout for this customer, and ' + acc.message.charAt(0).toLowerCase() + acc.message.slice(1) + ' Place the boxes in HaulProof: ' + base + '/prepare?id=' + pod.id);
        const r = await aidocs.aiFields({ user }, pod.id, buf, info);
        if (r.error || !(r.fields || []).length) throw new ToolError('The AI couldn’t place boxes on this document' + (r.error ? ' (' + r.error + ')' : '') + '. Place them in HaulProof: ' + base + '/prepare?id=' + pod.id);
        fields = r.fields; source = 'AI (' + (r.model || 'Claude') + ')'; note = r.note || ''; cost = r.costUsd;
      }
      const saved = await api(user, 'PUT', '/api/pods/' + pod.id + '/fields', { json: { fields } });
      let layoutSaved = false;
      if (a.save_as_layout && source.indexOf('AI') === 0) { try { await api(user, 'POST', '/api/pods/' + pod.id + '/save-template', { json: { fields } }); layoutSaved = true; } catch (e) {} }
      const summary = {}; fields.forEach(f => { const k = (f.role || '') + ' · ' + f.kind; summary[k] = (summary[k] || 0) + 1; });
      return { document_id: pod.id, stop: pod.stopNumber, status: saved.status === 'prepared' ? 'ready to sign — sent to the driver' : (saved.status || 'saved'),
        boxes_placed: fields.length, boxes: summary, placed_by: source, note, layout_saved: layoutSaved,
        review_link: base + '/prepare?id=' + pod.id, ai_cost_usd: cost != null ? Math.round(cost * 10000) / 10000 : null };
    } },
];

// A document the connected login may edit (not signed yet), by id or by load + stop, with its PDF bytes.
async function docForEdit(user, a) {
  needCompany(user);
  let id = String(a.document || '').trim();
  if (!id) {
    if (!a.load) throw new ToolError('Say which document: its id (document) or the load and stop_number.');
    const d = await resolveLoad(user, a.load); needOwner(user, d.load);
    const stop = Math.max(1, parseInt(a.stop_number, 10) || 1);
    const hits = (d.pods || []).filter(p => (p.stopNumber || 1) === stop && p.status !== 'parked');
    const open = hits.filter(p => p.status !== 'signed' && p.status !== 'emailed');
    if (!open.length) throw new ToolError(hits.length ? 'Stop ' + stop + ' is already signed.' : 'No document on stop ' + stop + ' of that load.');
    if (open.length > 1) throw new ToolError('Stop ' + stop + ' has more than one document — pass the document id: ' + open.map(p => p.id + ' (' + (p.filename || p.docType) + ')').join(', '));
    id = open[0].id;
  }
  const pod = await api(user, 'GET', '/api/pods/' + encodeURIComponent(id));
  if ((pod.orgId || null) !== (user.orgId || null)) throw new ToolError('That document belongs to another company.');
  if (pod.status === 'signed' || pod.status === 'emailed') throw new ToolError('That document is already signed, so it can’t be changed.');
  const row = db.prepare(`SELECT filepath FROM pods WHERE id = ?`).get(pod.id);
  let buf; try { buf = require('fs').readFileSync(row.filepath); } catch (e) { throw new ToolError('The document’s file isn’t available.'); }
  return { pod, buf };
}

// Attach a PDF to a load's stop as the connected login (shared by attach_document and upload links).
async function attachPdf(user, load, buf, o, base) {
  if (!buf || buf.slice(0, 5).toString('latin1') !== '%PDF-') throw new ToolError('That file isn’t a PDF.');
  if (buf.length > MAX_DOC_BYTES) throw new ToolError('That file is too large (max 20 MB).');
  const enc = (v) => encodeURIComponent(String(v));
  const stop = Math.max(1, parseInt(o.stop, 10) || 1);
  const r = await api(user, 'POST', '/api/pods/upload', { body: buf, headers: {
    'Content-Type': 'application/pdf', 'X-POD-Enc': 'uri', 'X-PO': enc(load.poNumber || ''), 'X-Load': enc(load.loadNumber || ''),
    'X-Stop': String(stop), 'X-DocType': enc(o.docType || 'BOL'), 'X-Filename': enc(o.filename || 'document.pdf'), 'X-Build': 'dispatch' } });
  return { attached: true, document_id: r.id, stop: r.stopNumber, po_number: r.poNumber, status: 'needs signature setup', signature_setup_link: base + '/prepare?id=' + r.id, load: loadDetail(await api(user, 'GET', '/api/loads/' + load.id), base) };
}
const TOOL_BY_NAME = {}; TOOLS.forEach(t => { TOOL_BY_NAME[t.name] = t; });

const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const INSTRUCTIONS = 'HaulProof is an electronic proof-of-delivery system for trucking. Loads are identified by the customer PO #. ' +
  'Before creating a load, check list_customers and list_drivers so names match; add_customer only when the company truly is not on the list. ' +
  'To get a document ready for the driver: attach it, call review_pages and confirm the pages with the user, trim_document, then place_signatures. To attach a PDF you hold as a file, use get_upload_link and POST the file to the link (or give the link to the user). Documents attached with attach_document or an upload link still need their signature boxes placed in HaulProof (signature_setup_link) before a driver can sign. ' +
  'Assigning a driver sends the load to their phone, so confirm the driver with the user when unsure. ' +
  'For "what needs my attention" use needs_attention. To send a customer their signed POD or resend failed emails use send_signed_copy (confirm addresses first). For billing, get_signed_documents lists signed PDFs with 7-day download links. ' +
  'To set up an account in bulk, add_drivers and add_team_logins take a list (e.g. from a spreadsheet the user shares); confirm names, emails and roles first.';

async function handleRpc(msg, user, base) {
  const id = msg.id;
  const ok = (result) => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
  switch (msg.method) {
    case 'initialize': {
      const asked = msg.params && msg.params.protocolVersion;
      return ok({ protocolVersion: PROTOCOLS.indexOf(asked) >= 0 ? asked : PROTOCOLS[0], capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'haulproof', title: 'HaulProof', version: '1.0.0' }, instructions: INSTRUCTIONS });
    }
    case 'ping': return ok({});
    case 'tools/list': return ok({ tools: TOOLS.map(t => ({ name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations })) });
    case 'tools/call': {
      const p = msg.params || {}, tool = TOOL_BY_NAME[p.name];
      if (!tool) return fail(-32602, 'Unknown tool: ' + p.name);
      try {
        const out = await tool.run(user, p.arguments || {}, base);
        return ok({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
      } catch (e) {
        if (!(e instanceof ToolError)) console.error('MCP tool error', p.name, e);
        return ok({ content: [{ type: 'text', text: e instanceof ToolError ? e.message : 'Something went wrong in HaulProof. Try again, or do this in the portal.' }], isError: true });
      }
    }
    default: return fail(-32601, 'Method not found: ' + msg.method);
  }
}

router.post('/mcp', async (req, res) => {
  const user = mcpUser(req);
  if (!user) {
    return res.status(401).set('WWW-Authenticate', 'Bearer resource_metadata="' + baseUrl(req) + '/.well-known/oauth-protected-resource"')
      .set('Access-Control-Expose-Headers', 'WWW-Authenticate')
      .json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Sign in to HaulProof to use this connector.' } });
  }
  const msg = req.body;
  if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0') return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request' } });
  if (msg.id === undefined || msg.id === null) return res.status(202).end();   // a notification — nothing to answer
  res.json(await handleRpc(msg, user, baseUrl(req)));
});
// Stateless server: no server-initiated stream and no sessions to end.
router.get('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').end());
router.delete('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').end());

// ---- Upload links (get_upload_link): the link itself is the credential — one use, 30 minutes. ----
function uploadLink(token) {
  const row = db.prepare(`SELECT * FROM upload_links WHERE tokenHash = ?`).get(sha(String(token || '')));
  if (!row || row.usedAt || row.expiresAt < Date.now()) return null;
  return row;
}
// A signed document's download link from get_signed_documents (7 days, no sign-in needed).
router.get('/d/:token', async (req, res) => {
  let t; try { t = jwt.verify(req.params.token, JWT_SECRET); } catch (e) { return res.status(410).type('text').send('This download link has expired or is not valid. Ask for a new one.'); }
  if (!t || t.k !== 'dl') return res.status(404).type('text').send('Not found');
  const pod = db.prepare('SELECT * FROM pods WHERE id = ?').get(t.p);
  if (!pod || !pod.filepath || !require('fs').existsSync(pod.filepath) || (pod.status !== 'signed' && pod.status !== 'emailed')) return res.status(404).type('text').send('That document is no longer available.');
  const name = ((pod.poNumber ? 'PO ' + pod.poNumber : 'BOL') + (pod.stopNumber ? ' stop ' + pod.stopNumber : '')).replace(/[^\w.\- ]+/g, '_');
  res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', 'inline; filename="' + name + '.pdf"'); res.setHeader('Cache-Control', 'private, no-store');
  try { const b = await require('./pods').combinedPodBytes(pod); if (b && b.length) return res.end(Buffer.from(b)); } catch (e) {}
  require('fs').createReadStream(pod.filepath).pipe(res);
});
router.get('/u/:token', (req, res) => {
  const row = uploadLink(req.params.token);
  if (!row) return res.status(404).send(page('Link expired', '<p class="sub">This upload link has expired or was already used. Ask for a new one.</p>'));
  const load = db.prepare(`SELECT poNumber FROM loads WHERE id = ?`).get(row.loadId) || {};
  res.send(page('Upload a document', '<p class="sub">Attach a PDF to <b>PO ' + esc(load.poNumber || '') + '</b> · Stop ' + row.stopNumber + ' (' + esc(row.docType || 'BOL') + ').</p>' +
    '<input type="file" id="f" accept="application/pdf" style="margin-top:10px"><div class="err" id="m"></div><div class="row"><button class="btn" id="go">Upload</button></div>' +
    '<script>document.getElementById("go").onclick=async function(){var f=document.getElementById("f").files[0],m=document.getElementById("m");if(!f){m.textContent="Choose a PDF first.";return;}this.disabled=true;m.style.color="#5c6b7a";m.textContent="Uploading…";' +
    'try{var r=await fetch(location.pathname,{method:"POST",headers:{"Content-Type":"application/pdf"},body:f});var j=await r.json().catch(function(){return{};});if(!r.ok)throw new Error(j.error||"Upload failed");m.style.color="#12784a";m.textContent="✓ Uploaded. Dispatch can place the signature boxes now. You can close this page.";}catch(e){m.style.color="#c0392b";m.textContent=e.message;this.disabled=false;}};</script>'));
});
router.post('/u/:token', express.raw({ type: () => true, limit: '21mb' }), async (req, res) => {
  const row = uploadLink(req.params.token);
  if (!row) return res.status(404).json({ error: 'This upload link has expired or was already used.' });
  const user = userRow(row.userId), load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(row.loadId);
  if (!user || !load) return res.status(404).json({ error: 'That load is no longer available.' });
  const buf = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  // Claim the link before uploading so it can't be used twice.
  const claim = db.prepare(`UPDATE upload_links SET usedAt = ? WHERE tokenHash = ? AND usedAt IS NULL`).run(Date.now(), row.tokenHash);
  if (!claim.changes) return res.status(404).json({ error: 'This upload link was already used.' });
  try {
    const out = await attachPdf(user, load, buf, { stop: row.stopNumber, docType: row.docType, filename: row.filename }, baseUrl(req));
    res.json({ ok: true, document_id: out.document_id, stop: out.stop, po_number: out.po_number, status: out.status, signature_setup_link: out.signature_setup_link });
  } catch (e) {
    db.prepare(`UPDATE upload_links SET usedAt = NULL WHERE tokenHash = ?`).run(row.tokenHash);   // a bad file doesn't burn the link
    res.status(e instanceof ToolError ? 400 : 500).json({ error: e instanceof ToolError ? e.message : 'Upload failed' });
  }
});

// A plain, self-contained page for the sign-in / approve screens.
function page(title, body) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + title + ' — HaulProof</title><style>' +
    ':root{--ink:#16202b;--muted:#5c6b7a;--line:#dde4ec;--primary:#1655d1;}' +
    '*{box-sizing:border-box}body{margin:0;background:#f2f4f8;color:var(--ink);font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5}' +
    '.card{max-width:460px;margin:48px auto;background:#fff;border:1px solid var(--line);border-radius:14px;padding:26px;box-shadow:0 10px 40px rgba(10,20,50,.08)}' +
    '.brand{font-weight:800;margin-bottom:14px}.brand b{color:var(--primary)}h1{font-size:20px;margin:0 0 10px}' +
    '.sub{color:var(--muted);font-size:14px}.small{font-size:12.5px;margin-top:16px}ul{padding-left:20px;margin:8px 0 12px}li{margin:3px 0}' +
    'label{display:block;font-size:13px;font-weight:600;color:var(--muted);margin:10px 0 0}input[type=email],input[type=password]{display:block;width:100%;margin-top:4px;font:inherit;padding:10px 12px;border:1px solid #cdd7e3;border-radius:8px}' +
    '.btn{font:inherit;font-weight:700;border:none;border-radius:9px;padding:10px 18px;background:var(--primary);color:#fff;cursor:pointer;margin-top:14px}.btn.ghost{background:#fff;color:var(--ink);border:1px solid #c6d0db}' +
    '.row{display:flex;gap:10px;justify-content:flex-end}.err{color:#c0392b;font-size:13px;min-height:18px;margin-top:8px}' +
    '@media(max-width:520px){.card{margin:16px;padding:20px}}</style></head><body><div class="card"><div class="brand">Haul<b>Proof</b></div><h1>' + title + '</h1>' + body + '</div></body></html>';
}

module.exports = router;
