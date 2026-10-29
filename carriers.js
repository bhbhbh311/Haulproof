// Carriers: FMCSA validation + the registry of carrier orgs a customer can assign loads to.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth, requireAdmin, createUser } = require('./auth');
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

const router = express.Router();
const FMCSA_BASE = process.env.FMCSA_BASE || 'https://mobile.fmcsa.dot.gov/qc/services/';   // overridable for tests
const WEBKEY = (process.env.FMCSA_WEBKEY || '').trim();

function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }

// Create or refresh a carrier org from FMCSA data (shared by the carriers routes and broker approvals).
// De-dupes on DOT# (preferred) then MC#. Returns the carrier org row.
function upsertCarrierOrg({ name, mcNumber, dotNumber, verified, allowedToOperate, address, contactPhone }) {
  name = String(name || '').trim(); mcNumber = String(mcNumber || '').trim(); dotNumber = String(dotNumber || '').trim();
  let existing = null;
  if (dotNumber) existing = db.prepare(`SELECT * FROM orgs WHERE kind='carrier' AND dotNumber = ?`).get(dotNumber);
  if (!existing && mcNumber) existing = db.prepare(`SELECT * FROM orgs WHERE kind='carrier' AND mcNumber = ?`).get(mcNumber);
  if (existing) {
    // A lookup only refreshes the authority flags (and fills a missing address); the name of a shared
    // carrier is changed only by the carrier itself or HaulProof (PUT /:id).
    if (verified) db.prepare(`UPDATE orgs SET fmcsaVerified=1, allowedToOperate=?, address=? WHERE id=?`)
      .run(allowedToOperate || existing.allowedToOperate, (existing.address || address) || null, existing.id);
    return db.prepare(`SELECT * FROM orgs WHERE id=?`).get(existing.id);
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, kind, deviceKey, mcNumber, dotNumber, fmcsaVerified, allowedToOperate, contactPhone, address, active, createdAt)
              VALUES (?,?, 'carrier', ?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), mcNumber || null, dotNumber || null, verified ? 1 : 0, allowedToOperate || null, String(contactPhone || '').trim() || null, String(address || '').trim() || null, Date.now());
  return db.prepare(`SELECT * FROM orgs WHERE id=?`).get(id);
}

// The same for a broker company (a customer saving a broker it works with). De-dupes on DOT# then MC#.
function upsertBrokerOrg({ name, mcNumber, dotNumber, verified, allowedToOperate, address }) {
  name = String(name || '').trim(); mcNumber = String(mcNumber || '').trim(); dotNumber = String(dotNumber || '').trim();
  let existing = null;
  if (dotNumber) existing = db.prepare(`SELECT * FROM orgs WHERE kind='broker' AND dotNumber = ?`).get(dotNumber);
  if (!existing && mcNumber) existing = db.prepare(`SELECT * FROM orgs WHERE kind='broker' AND mcNumber = ?`).get(mcNumber);
  if (existing) {
    if (verified) db.prepare(`UPDATE orgs SET fmcsaVerified=1, allowedToOperate=?, address=? WHERE id=?`).run(allowedToOperate || existing.allowedToOperate, (existing.address || address) || null, existing.id);
    return db.prepare(`SELECT * FROM orgs WHERE id=?`).get(existing.id);
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, kind, deviceKey, mcNumber, dotNumber, fmcsaVerified, allowedToOperate, address, active, createdAt)
              VALUES (?,?, 'broker', ?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), mcNumber || null, dotNumber || null, verified ? 1 : 0, allowedToOperate || null, String(address || '').trim() || null, Date.now());
  return db.prepare(`SELECT * FROM orgs WHERE id=?`).get(id);
}

// ---- Authority gate for saving a company as a carrier or broker. Active authority of that type → saved plainly.
// Anything else (pending, inactive, none on file, or FMCSA couldn't be checked) needs an admin override, and the
// company then carries a warning until a later check finds the authority active (see recheckAuthority). ----
const AUTH_WORDS = { pending: 'is pending', inactive: 'is inactive or revoked', none: 'isn’t on file', unknown: 'couldn’t be checked' };
function authWarningText(kind, state) { return 'FMCSA ' + (kind === 'broker' ? 'broker' : 'carrier') + ' authority ' + (AUTH_WORDS[state] || AUTH_WORDS.unknown); }
async function authorityState(kind, dotNumber) {
  const d = String(dotNumber || '').replace(/\D/g, '');
  if (!d) return 'unknown';
  let a = null; try { a = await fetchAuthority(d); } catch (e) { a = null; }
  if (!a) return 'unknown';
  return (a.state && a.state[kind]) || (a[kind] ? 'active' : 'none');
}
// Returns { ok, warning } or { ok:false, status, body } for the route to send.
async function authorityGate(req, kind, dotNumber, name, override) {
  const state = await authorityState(kind, dotNumber);
  if (state === 'active') return { ok: true, warning: null };
  const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
  const warning = authWarningText(kind, state);
  if (isAdmin && override) return { ok: true, warning };
  return { ok: false, status: 409, body: { code: 'authority', state, canOverride: isAdmin,
    error: (name || 'This company') + ': ' + warning + '.' + (isAdmin ? ' You can add it anyway — it will show a warning until FMCSA shows the authority as active.' : ' Ask an admin if it should be added anyway.') } };
}
function setAuthWarning(orgId, warning) {
  try { db.prepare(`UPDATE orgs SET authWarning = ?, authCheckedAt = ? WHERE id = ?`).run(warning || null, Date.now(), orgId); } catch (e) {}
}
// Re-check flagged companies against FMCSA once a week each (a daily timer picks up the ones last checked over 7
// days ago, so restarts don't add checks): clear the warning once the authority is active.
const WEEK = 7 * 24 * 3600000;
async function recheckAuthority() {
  if (!WEBKEY) return;
  const rows = db.prepare(`SELECT id, kind, dotNumber, authWarning FROM orgs WHERE authWarning IS NOT NULL AND dotNumber IS NOT NULL AND kind IN ('carrier','broker')
    AND COALESCE(authCheckedAt,0) < ? ORDER BY COALESCE(authCheckedAt,0) LIMIT 100`).all(Date.now() - WEEK);
  for (const o of rows) {
    const state = await authorityState(o.kind, o.dotNumber);
    if (state === 'unknown') continue;   // FMCSA didn't answer — keep the old warning, try again next time
    setAuthWarning(o.id, state === 'active' ? null : authWarningText(o.kind, state));
    if (state === 'active') console.log('[authority] ' + o.id + ' now active — warning cleared');
  }
}
function startAuthorityRecheck() { setTimeout(() => recheckAuthority().catch(() => {}), 120000).unref(); setInterval(() => recheckAuthority().catch(() => {}), 24 * 3600000).unref(); }

// "Check FMCSA now" on a flagged carrier/broker — anyone who works with it, at most once an hour per company.
router.post('/:id/recheck-authority', requireAuth, async (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ? AND kind IN ('carrier','broker')`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Company not found' });
  const linked = req.user.role === 'superadmin' || req.user.orgId === o.id
    || db.prepare(`SELECT 1 FROM broker_carriers WHERE brokerId = ? AND carrierId = ?`).get(req.user.orgId || '', o.id)
    || db.prepare(`SELECT 1 FROM loads WHERE (orgId = ? OR brokerId = ?) AND (carrierId = ? OR brokerId = ?) LIMIT 1`).get(req.user.orgId || '', req.user.orgId || '', o.id, o.id);
  if (!linked) return res.status(404).json({ error: 'Company not found' });
  if (!o.authWarning) return res.json({ ok: true, authWarning: null, state: 'active' });
  if (o.authCheckedAt && Date.now() - o.authCheckedAt < 3600000) {
    const mins = Math.ceil((3600000 - (Date.now() - o.authCheckedAt)) / 60000);
    return res.status(429).json({ error: 'Checked with FMCSA less than an hour ago — try again in ' + mins + ' minute' + (mins === 1 ? '' : 's') + '.' });
  }
  const state = await authorityState(o.kind, o.dotNumber);
  if (state === 'unknown') return res.status(502).json({ error: 'FMCSA didn’t answer — try again later.' });
  const warning = state === 'active' ? null : authWarningText(o.kind, state);
  setAuthWarning(o.id, warning);
  res.json({ ok: true, state, authWarning: warning });
});

// Pull a carrier object out of QCMobile's response (content is an object for id lookups, array for name).
function pickCarriers(json) {
  if (!json || !json.content) return [];
  const arr = Array.isArray(json.content) ? json.content : [json.content];
  return arr.map(x => x && x.carrier).filter(Boolean);
}
function normalize(c, mcHint) {
  return {
    name: c.legalName || c.dbaName || '',
    dba: c.dbaName || '',
    dotNumber: c.dotNumber != null ? String(c.dotNumber) : '',
    mcNumber: mcHint ? String(mcHint) : '',
    allowedToOperate: c.allowedToOperate || '',
    statusCode: c.statusCode || '',
    address: [c.phyStreet, c.phyCity, c.phyState, c.phyZipcode].filter(Boolean).join(', '),
    verified: true,
    _recordAuth: authorityFromRecords([c]),   // the company record's own authority fields, when FMCSA includes them
  };
}
// A carrier's MC (docket) number lives on a SEPARATE FMCSA sub-record, not on the
// snapshot returned by name/DOT lookups — so fetch it by DOT# and pull the MC docket.
async function fetchMcByDot(dot) {
  const d = String(dot || '').replace(/\D/g, '');
  if (!WEBKEY || !d) return '';
  const url = FMCSA_BASE + 'carriers/' + encodeURIComponent(d) + '/docket-numbers?webKey=' + encodeURIComponent(WEBKEY);
  try {
    const r = await fetch(url, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(6000) });
    if (!r.ok) return '';
    const json = await r.json();
    const arr = Array.isArray(json.content) ? json.content : (json.content ? [json.content] : []);
    // Prefer an actual "MC" prefix; otherwise take the first docket on file.
    const pick = arr.find(x => x && String(x.prefix || '').toUpperCase() === 'MC') || arr[0];
    if (!pick) return '';
    return pick.docketNumber != null ? String(pick.docketNumber).replace(/\D/g, '') : '';
  } catch (e) { return ''; }
}
// FMCSA operating authority lives on a SEPARATE sub-record. Returns { broker, carrier } booleans
// (carrier = active common OR contract authority), or null when FMCSA didn't answer / had no data —
// callers treat null as "unknown" and must NOT block on it.
async function fetchAuthority(dot) {
  const d = String(dot || '').replace(/\D/g, '');
  if (!WEBKEY || !d) return null;
  const url = FMCSA_BASE + 'carriers/' + encodeURIComponent(d) + '/authority?webKey=' + encodeURIComponent(WEBKEY);
  try {
    const r = await fetch(url, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(10000) });
    // FMCSA answers "no authority" with a 404 or an empty list — that's "none on file", not a failed check.
    if (r.status === 404) { console.log('[fmcsa] authority dot=' + d + ' 404 → none on file'); return { broker: false, carrier: false, state: { carrier: 'none', broker: 'none' } }; }
    if (!r.ok) { console.log('[fmcsa] authority dot=' + d + ' HTTP ' + r.status); return null; }
    const json = await r.json();
    const arr = Array.isArray(json.content) ? json.content : (json.content ? [json.content] : []);
    if (!arr.length) { console.log('[fmcsa] authority dot=' + d + ' empty → none on file'); return { broker: false, carrier: false, state: { carrier: 'none', broker: 'none' } }; }
    const read = authorityFromRecords(arr);
    if (!read) { console.log('[fmcsa] authority dot=' + d + ' no status fields in ' + JSON.stringify(arr).slice(0, 300)); return { broker: false, carrier: false, state: { carrier: 'none', broker: 'none' } }; }
    return read;
  } catch (e) { console.log('[fmcsa] authority dot=' + d + ' failed: ' + e.message); return null; }
}
// Read authority status fields from FMCSA records (the authority sub-record, or a company record that carries the
// same fields). Returns { broker, carrier, state } or null when no status fields are present.
function authorityFromRecords(arr) {
    let broker = false, common = false, contract = false, sawAny = false;
    // Inactive ("I") and pending flags too, so a lookup can say Active / Pending / Inactive / none for each type.
    const inactive = { carrier: false, broker: false }, pending = { carrier: false, broker: false };
    // The status fields can sit at the top of each record or nested — scan recursively. "A" = active, "I" = inactive.
    const scan = (o) => {
      if (!o || typeof o !== 'object') return;
      for (const k in o) {
        const v = o[k];
        if (v && typeof v === 'object') { scan(v); continue; }
        const key = k.toLowerCase(), val = String(v == null ? '' : v).toUpperCase(), act = val === 'A';
        const type = key.indexOf('broker') === 0 ? 'broker' : (key.indexOf('common') === 0 || key.indexOf('contract') === 0) ? 'carrier' : null;
        if (key === 'brokerauthoritystatus') { sawAny = true; if (act) broker = true; else if (val === 'I') inactive.broker = true; }
        else if (key === 'commonauthoritystatus') { sawAny = true; if (act) common = true; else if (val === 'I') inactive.carrier = true; }
        else if (key === 'contractauthoritystatus') { sawAny = true; if (act) contract = true; else if (val === 'I') inactive.carrier = true; }
        else if (type && key.indexOf('pending') >= 0 && (val === 'Y' || val === 'A')) { sawAny = true; pending[type] = true; }
        else if (type && key.indexOf('revocation') >= 0 && (val === 'Y' || val === 'A')) { sawAny = true; inactive[type] = true; }
      }
    };
    (arr || []).forEach(scan);
    if (!sawAny) return null;
    const carrier = common || contract;
    const stateOf = (activeNow, t) => activeNow ? 'active' : pending[t] ? 'pending' : inactive[t] ? 'inactive' : 'none';
    return { broker, carrier, state: { carrier: stateOf(carrier, 'carrier'), broker: stateOf(broker, 'broker') } };
}

// Call FMCSA QCMobile. Returns { configured, results, error }.
async function fmcsaLookup({ mc, dot, name }) {
  if (!WEBKEY) return { configured: false, results: [] };
  let url;
  if (dot) url = FMCSA_BASE + 'carriers/' + encodeURIComponent(String(dot).replace(/\D/g, ''));
  else if (mc) url = FMCSA_BASE + 'carriers/docket-number/' + encodeURIComponent(String(mc).replace(/\D/g, ''));
  else if (name) url = FMCSA_BASE + 'carriers/name/' + encodeURIComponent(name);
  else return { configured: true, results: [] };
  url += (url.includes('?') ? '&' : '?') + 'webKey=' + encodeURIComponent(WEBKEY);
  try {
    const r = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!r.ok) return { configured: true, results: [], error: 'FMCSA returned ' + r.status };
    const json = await r.json();
    // Keep the list short so the follow-up MC# lookups stay quick.
    const raw = pickCarriers(json).slice(0, 15);
    // Diagnostic: which authority/status fields FMCSA's company record carries (field names and values only).
    try { raw.slice(0, 4).forEach(x => console.log('[fmcsa] record dot=' + x.dotNumber + ' ' + JSON.stringify(Object.fromEntries(Object.entries(x).filter(([k]) => /authority|broker|common|contract|status/i.test(k)))))); } catch (e) {}
    const carriers = raw.map(c => normalize(c, mc));
    // Fill in the MC# from the docket sub-record wherever we don't already have one.
    // A few companies at a time (not all ~30 requests at once) so FMCSA doesn't throttle the lookup.
    const one = async (c) => {
      if (!c.mcNumber && c.dotNumber) { c.mcNumber = await fetchMcByDot(c.dotNumber); }
      if (c.dotNumber) {
        const a = await fetchAuthority(c.dotNumber);
        // null = FMCSA didn't answer; leave the flags undefined so the UI/rules treat it as "unknown".
        // The authority sub-record can come back empty while the company record itself shows the status — use whichever
        // says more (anything beyond "none on file").
        const rec = c._recordAuth, more = (x) => x && x.state && (x.state.carrier !== 'none' || x.state.broker !== 'none');
        const use = more(a) ? a : (more(rec) ? rec : (a || rec));
        if (rec && !more(a) && more(rec)) console.log('[fmcsa] dot=' + c.dotNumber + ' authority from the company record: ' + JSON.stringify(rec.state));
        if (use) { c.authBroker = use.broker; c.authCarrier = use.carrier; c.authState = use.state; }
      }
      delete c._recordAuth;
    };
    for (let i = 0; i < carriers.length; i += 4) await Promise.all(carriers.slice(i, i + 4).map(one));
    return { configured: true, results: carriers };
  } catch (e) {
    return { configured: true, results: [], error: 'Could not reach FMCSA' };
  }
}

// Look up carriers to assign — searches FMCSA (live) plus already-saved carriers in your registry.
router.get('/lookup', requireAuth, async (req, res) => {
  const mc = (req.query.mc || '').trim(), dot = (req.query.dot || '').trim(), name = (req.query.name || '').trim();
  if (!mc && !dot && !name) return res.status(400).json({ error: 'Search by name, MC#, or DOT#' });
  const fm = await fmcsaLookup({ mc, dot, name });
  res.json({ configured: fm.configured, fmcsa: fm.results, error: fm.error || null });
});

// Customers this carrier has hauled for (used for the "offer a document to a customer" picker).
router.get('/my-customers', requireAuth, (req, res) => {
  const carrierOrg = req.user.role === 'superadmin' ? (req.query.carrierId || '').trim() : (req.user.orgId || null);
  if (!carrierOrg) return res.json({ customers: [] });
  const rows = db.prepare(`SELECT DISTINCT orgs.id, orgs.name FROM loads JOIN orgs ON orgs.id = loads.orgId
    WHERE loads.carrierId = ? AND (orgs.kind IS NULL OR orgs.kind != 'carrier') ORDER BY orgs.name`).all(carrierOrg);
  res.json({ customers: rows });
});

// List saved carrier orgs (optionally filtered by q). Active only unless ?includeInactive=1.
router.get('/', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim();
  const act = req.query.includeInactive === '1' ? '' : 'AND active = 1';
  let rows;
  if (q) rows = db.prepare(`SELECT * FROM orgs WHERE kind='carrier' ${act} AND (name LIKE ? OR mcNumber LIKE ? OR dotNumber LIKE ?) ORDER BY active DESC, name`).all('%' + q + '%', '%' + q + '%', '%' + q + '%');
  else rows = db.prepare(`SELECT * FROM orgs WHERE kind='carrier' ${act} ORDER BY active DESC, name`).all();
  res.json({ carriers: rows.map(carrierOut) });
});

// Edit a carrier's company info (fix mistakes). Admin/super.
router.put('/:id', requireAuth, requireAdmin, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ? AND kind='carrier'`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Carrier not found' });
  // Carriers are shared across HaulProof: only the master admin, or the carrier's own admins, may edit one.
  if (req.user.role !== 'superadmin' && req.user.orgId !== o.id) return res.status(403).json({ error: 'Only this carrier or HaulProof can change its company info' });
  const b = req.body || {};
  const name = (b.name !== undefined ? String(b.name) : o.name).trim();
  if (!name) return res.status(400).json({ error: 'Carrier name is required' });
  const mcNumber = (b.mcNumber !== undefined ? String(b.mcNumber) : (o.mcNumber || '')).trim();
  const dotNumber = (b.dotNumber !== undefined ? String(b.dotNumber) : (o.dotNumber || '')).trim();
  // Don't let two carriers collide on the same DOT# / MC#.
  if (dotNumber) { const dup = db.prepare(`SELECT id FROM orgs WHERE kind='carrier' AND dotNumber = ? AND id != ?`).get(dotNumber, o.id); if (dup) return res.status(409).json({ error: 'Another carrier already uses that DOT #' }); }
  if (mcNumber) { const dup = db.prepare(`SELECT id FROM orgs WHERE kind='carrier' AND mcNumber = ? AND id != ?`).get(mcNumber, o.id); if (dup) return res.status(409).json({ error: 'Another carrier already uses that MC #' }); }
  db.prepare(`UPDATE orgs SET name = ?, mcNumber = ?, dotNumber = ?, contactPhone = ?, address = ? WHERE id = ?`)
    .run(name, mcNumber || null, dotNumber || null, (b.contactPhone !== undefined ? String(b.contactPhone).trim() : o.contactPhone) || null, (b.address !== undefined ? String(b.address).trim() : o.address) || null, o.id);
  res.json({ carrier: carrierOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});

// Activate / deactivate a carrier (admin/super).
router.post('/:id/active', requireAuth, requireAdmin, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ? AND kind='carrier'`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Carrier not found' });
  // Turning a carrier off locks out its logins and drivers, so only the master admin may do it.
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Only HaulProof can turn a carrier on or off' });
  db.prepare(`UPDATE orgs SET active = ? WHERE id = ?`).run(req.body && req.body.active ? 1 : 0, o.id);
  res.json({ carrier: carrierOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});
function carrierOut(o) {
  return { id: o.id, name: o.name, mcNumber: o.mcNumber, dotNumber: o.dotNumber, fmcsaVerified: !!o.fmcsaVerified,
    allowedToOperate: o.allowedToOperate, address: o.address, contactPhone: o.contactPhone, active: !!o.active, authWarning: o.authWarning || null };
}

// Save a carrier into the registry (from an FMCSA result, or an admin override for one FMCSA didn't return).
// A NON-verified (override) carrier requires an admin/super — a plain dispatcher cannot invent carriers.
router.post('/', requireAuth, async (req, res) => {
  const b = req.body || {};
  const name = (b.name || '').trim();
  const mcNumber = (b.mcNumber || '').trim();
  const dotNumber = (b.dotNumber || '').trim();
  const verified = b.fmcsaVerified ? 1 : 0;
  if (!name) return res.status(400).json({ error: 'Carrier name is required' });
  if (!verified && !(req.user.role === 'admin' || req.user.role === 'superadmin')) {
    return res.status(403).json({ error: 'Only an admin can add a carrier that FMCSA did not verify' });
  }
  // De-dupe on DOT# (preferred) or MC#.
  let existing = null;
  if (dotNumber) existing = db.prepare(`SELECT * FROM orgs WHERE kind='carrier' AND dotNumber = ?`).get(dotNumber);
  if (!existing && mcNumber) existing = db.prepare(`SELECT * FROM orgs WHERE kind='carrier' AND mcNumber = ?`).get(mcNumber);
  if (existing) {
    // Refresh verification snapshot if this call carries a verified result.
    if (verified && (req.user.role === 'superadmin' || req.user.orgId === existing.id)) db.prepare(`UPDATE orgs SET fmcsaVerified=1, allowedToOperate=?, name=?, address=? WHERE id=?`)
      .run(b.allowedToOperate || existing.allowedToOperate, name, (b.address || existing.address) || null, existing.id);
    return res.json({ carrier: carrierOut(db.prepare(`SELECT * FROM orgs WHERE id=?`).get(existing.id)) });
  }
  // Authority rule: a company with FMCSA BROKER authority but NO carrier (common/contract) authority may not be
  // added as a carrier — it can only broker loads. Use the flags the lookup already carried when present;
  // otherwise re-check FMCSA by DOT. Unknown authority never blocks the add (fail-open on an FMCSA hiccup).
  let auth = null;
  if (b.authBroker !== undefined || b.authCarrier !== undefined) auth = { broker: !!b.authBroker, carrier: !!b.authCarrier };
  else if (dotNumber) { try { auth = await fetchAuthority(dotNumber); } catch (e) { auth = null; } }
  if (auth && auth.broker && !auth.carrier) {
    // Broker-only companies normally can't be carriers — but an admin can override and add it anyway
    // (confirmed in the UI), so a company you work through can still be assigned as a carrier when needed.
    const isAdmin = req.user.role === 'admin' || req.user.role === 'superadmin';
    if (!(isAdmin && b.override)) {
      return res.status(409).json({ code: 'broker_only', canOverride: isAdmin,
        error: name + ' holds FMCSA Broker authority only — it should be added as a Broker, not a Carrier.' });
    }
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, kind, deviceKey, mcNumber, dotNumber, fmcsaVerified, allowedToOperate, contactPhone, address, active, createdAt)
              VALUES (?,?, 'carrier', ?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), mcNumber || null, dotNumber || null, verified, b.allowedToOperate || null, (b.contactPhone || '').trim() || null, (b.address || '').trim() || null, Date.now());
  // Optionally create the carrier's first admin login (master/customer admin only).
  const adminEmail = (b.adminEmail || '').toLowerCase().trim();
  if (adminEmail) {
    if (!(req.user.role === 'admin' || req.user.role === 'superadmin')) return res.status(403).json({ error: 'Only an admin can create a carrier login' });
    if (!EMAIL_RE.test(adminEmail)) return res.status(400).json({ error: 'A valid carrier admin email is required' });
    if (!b.adminPassword || String(b.adminPassword).length < 6) return res.status(400).json({ error: 'Carrier admin password must be at least 6 characters' });
    if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(adminEmail)) return res.status(409).json({ error: 'That admin email already has a login' });
    createUser({ email: adminEmail, name: (b.adminName || '').trim(), role: 'admin', password: String(b.adminPassword), orgId: id });
  }
  res.status(201).json({ carrier: carrierOut(db.prepare(`SELECT * FROM orgs WHERE id=?`).get(id)) });
});

// ---- Per-org CARRIER ROSTER: "the carriers you work with." Lets a customer (or any org) save carriers found on
// FMCSA and reuse them on loads instead of re-looking them up each time. Stored in broker_carriers keyed by the
// caller's own org id (that table is just a generic org→carrier link; a customer's roster never mixes with a
// broker's because org ids are unique). ----
function rosterOrg(req) {
  if (req.user.role === 'superadmin') return ((req.query.orgId || (req.body && req.body.orgId) || '').trim() || null);
  return req.user.orgId || null;
}
router.get('/roster', requireAuth, (req, res) => {
  const org = rosterOrg(req);
  if (!org) return res.json({ carriers: [] });
  const rows = db.prepare(`SELECT orgs.* FROM broker_carriers bc JOIN orgs ON orgs.id = bc.carrierId
    WHERE bc.brokerId = ? AND orgs.active = 1 ORDER BY orgs.name`).all(org);
  res.json({ carriers: rows.map(o => Object.assign(carrierOut(o), { kind: o.kind === 'broker' ? 'broker' : 'carrier' })) });
});
router.post('/roster', requireAuth, async (req, res) => {
  const org = rosterOrg(req);
  if (!org) return res.status(403).json({ error: 'No organization on this login' });
  const b = req.body || {};
  const name = (b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Carrier name is required' });
  if (!b.fmcsaVerified && !(req.user.role === 'admin' || req.user.role === 'superadmin')) {
    return res.status(403).json({ error: 'Only an admin can add a carrier FMCSA did not verify' });
  }
  // A customer can also save the brokers it hands loads to (kind: 'broker'); a broker's own roster is carriers only.
  const asBroker = b.kind === 'broker';
  if (asBroker && req.user.orgKind === 'broker') return res.status(400).json({ error: 'Your approved list is for carriers' });
  const gate = await authorityGate(req, asBroker ? 'broker' : 'carrier', b.dotNumber, name, !!b.override);
  if (!gate.ok) return res.status(gate.status).json(gate.body);
  const carrier = asBroker
    ? upsertBrokerOrg({ name, mcNumber: b.mcNumber, dotNumber: b.dotNumber, verified: !!b.fmcsaVerified, allowedToOperate: b.allowedToOperate, address: b.address })
    : upsertCarrierOrg({ name, mcNumber: b.mcNumber, dotNumber: b.dotNumber, verified: !!b.fmcsaVerified, allowedToOperate: b.allowedToOperate, address: b.address });
  db.prepare(`INSERT OR IGNORE INTO broker_carriers (brokerId, carrierId, createdAt) VALUES (?,?,?)`).run(org, carrier.id, Date.now());
  setAuthWarning(carrier.id, gate.warning);
  const saved = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(carrier.id);
  res.status(201).json({ carrier: Object.assign(carrierOut(saved), { kind: asBroker ? 'broker' : 'carrier' }) });
});
router.delete('/roster/:carrierId', requireAuth, (req, res) => {
  const org = rosterOrg(req);
  if (!org) return res.status(403).json({ error: 'No organization on this login' });
  db.prepare(`DELETE FROM broker_carriers WHERE brokerId = ? AND carrierId = ?`).run(org, req.params.carrierId);
  res.json({ ok: true });
});

module.exports = { router, fmcsaLookup, upsertCarrierOrg, carrierOut, authorityGate, setAuthWarning, startAuthorityRecheck, recheckAuthority };
