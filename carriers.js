// Carriers: FMCSA validation + the registry of carrier orgs a customer can assign loads to.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth, requireAdmin } = require('./auth');

const router = express.Router();
const FMCSA_BASE = 'https://mobile.fmcsa.dot.gov/qc/services/';
const WEBKEY = (process.env.FMCSA_WEBKEY || '').trim();

function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }

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
    const carriers = pickCarriers(json).slice(0, 25).map(c => normalize(c, mc));
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

// List saved carrier orgs (optionally filtered by q on name/MC/DOT).
router.get('/', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim();
  let rows;
  if (q) rows = db.prepare(`SELECT * FROM orgs WHERE kind='carrier' AND (name LIKE ? OR mcNumber LIKE ? OR dotNumber LIKE ?) ORDER BY name`).all('%' + q + '%', '%' + q + '%', '%' + q + '%');
  else rows = db.prepare(`SELECT * FROM orgs WHERE kind='carrier' ORDER BY name`).all();
  res.json({ carriers: rows.map(carrierOut) });
});
function carrierOut(o) {
  return { id: o.id, name: o.name, mcNumber: o.mcNumber, dotNumber: o.dotNumber, fmcsaVerified: !!o.fmcsaVerified,
    allowedToOperate: o.allowedToOperate, address: o.address, contactPhone: o.contactPhone, active: !!o.active };
}

// Save a carrier into the registry (from an FMCSA result, or an admin override for one FMCSA didn't return).
// A NON-verified (override) carrier requires an admin/super — a plain dispatcher cannot invent carriers.
router.post('/', requireAuth, (req, res) => {
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
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, kind, deviceKey, mcNumber, dotNumber, fmcsaVerified, allowedToOperate, contactPhone, address, active, createdAt)
              VALUES (?,?, 'carrier', ?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), mcNumber || null, dotNumber || null, verified, b.allowedToOperate || null, (b.contactPhone || '').trim() || null, (b.address || '').trim() || null, Date.now());
  res.status(201).json({ carrier: carrierOut(db.prepare(`SELECT * FROM orgs WHERE id=?`).get(id)) });
});

module.exports = { router, fmcsaLookup };
