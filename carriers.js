// Carriers: FMCSA validation + the registry of carrier orgs a customer can assign loads to.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth, requireAdmin, createUser } = require('./auth');
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

const router = express.Router();
const FMCSA_BASE = 'https://mobile.fmcsa.dot.gov/qc/services/';
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
    if (verified) db.prepare(`UPDATE orgs SET fmcsaVerified=1, allowedToOperate=?, name=?, address=? WHERE id=?`)
      .run(allowedToOperate || existing.allowedToOperate, name || existing.name, (address || existing.address) || null, existing.id);
    return db.prepare(`SELECT * FROM orgs WHERE id=?`).get(existing.id);
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, kind, deviceKey, mcNumber, dotNumber, fmcsaVerified, allowedToOperate, contactPhone, address, active, createdAt)
              VALUES (?,?, 'carrier', ?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), mcNumber || null, dotNumber || null, verified ? 1 : 0, allowedToOperate || null, String(contactPhone || '').trim() || null, String(address || '').trim() || null, Date.now());
  return db.prepare(`SELECT * FROM orgs WHERE id=?`).get(id);
}

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
    const r = await fetch(url, { headers: { 'Accept': 'application/json' }, signal: AbortSignal.timeout(6000) });
    if (!r.ok) return null;
    const json = await r.json();
    const arr = Array.isArray(json.content) ? json.content : (json.content ? [json.content] : []);
    let broker = false, common = false, contract = false, sawAny = false;
    // The three status fields can sit at the top of each record or nested — scan recursively. "A" = active.
    const scan = (o) => {
      if (!o || typeof o !== 'object') return;
      for (const k in o) {
        const v = o[k];
        if (v && typeof v === 'object') { scan(v); continue; }
        const key = k.toLowerCase(), act = String(v == null ? '' : v).toUpperCase() === 'A';
        if (key === 'brokerauthoritystatus') { sawAny = true; if (act) broker = true; }
        else if (key === 'commonauthoritystatus') { sawAny = true; if (act) common = true; }
        else if (key === 'contractauthoritystatus') { sawAny = true; if (act) contract = true; }
      }
    };
    arr.forEach(scan);
    if (!sawAny) return null;
    return { broker, carrier: (common || contract) };
  } catch (e) { return null; }
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
    const carriers = pickCarriers(json).slice(0, 15).map(c => normalize(c, mc));
    // Fill in the MC# from the docket sub-record wherever we don't already have one.
    await Promise.all(carriers.map(async (c) => {
      if (!c.mcNumber && c.dotNumber) { c.mcNumber = await fetchMcByDot(c.dotNumber); }
      if (c.dotNumber) {
        const a = await fetchAuthority(c.dotNumber);
        // null = FMCSA didn't tell us; leave the flags undefined so the UI/rules treat it as "unknown".
        if (a) { c.authBroker = a.broker; c.authCarrier = a.carrier; }
      }
    }));
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
  db.prepare(`UPDATE orgs SET active = ? WHERE id = ?`).run(req.body && req.body.active ? 1 : 0, o.id);
  res.json({ carrier: carrierOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id)) });
});
function carrierOut(o) {
  return { id: o.id, name: o.name, mcNumber: o.mcNumber, dotNumber: o.dotNumber, fmcsaVerified: !!o.fmcsaVerified,
    allowedToOperate: o.allowedToOperate, address: o.address, contactPhone: o.contactPhone, active: !!o.active };
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
    if (verified) db.prepare(`UPDATE orgs SET fmcsaVerified=1, allowedToOperate=?, name=?, address=? WHERE id=?`)
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
    return res.status(409).json({ code: 'broker_only', error: name + ' holds FMCSA Broker authority only — add it as a Broker, not a Carrier.' });
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
  res.json({ carriers: rows.map(carrierOut) });
});
router.post('/roster', requireAuth, (req, res) => {
  const org = rosterOrg(req);
  if (!org) return res.status(403).json({ error: 'No organization on this login' });
  const b = req.body || {};
  const name = (b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Carrier name is required' });
  if (!b.fmcsaVerified && !(req.user.role === 'admin' || req.user.role === 'superadmin')) {
    return res.status(403).json({ error: 'Only an admin can add a carrier FMCSA did not verify' });
  }
  const carrier = upsertCarrierOrg({ name, mcNumber: b.mcNumber, dotNumber: b.dotNumber, verified: !!b.fmcsaVerified, allowedToOperate: b.allowedToOperate, address: b.address });
  db.prepare(`INSERT OR IGNORE INTO broker_carriers (brokerId, carrierId, createdAt) VALUES (?,?,?)`).run(org, carrier.id, Date.now());
  res.status(201).json({ carrier: carrierOut(carrier) });
});
router.delete('/roster/:carrierId', requireAuth, (req, res) => {
  const org = rosterOrg(req);
  if (!org) return res.status(403).json({ error: 'No organization on this login' });
  db.prepare(`DELETE FROM broker_carriers WHERE brokerId = ? AND carrierId = ?`).run(org, req.params.carrierId);
  res.json({ ok: true });
});

module.exports = { router, fmcsaLookup, upsertCarrierOrg, carrierOut };
