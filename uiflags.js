// Per-org "Simple mode" field flags. Each flag = is this optional input SHOWN. Hiding one removes it from the
// dispatcher edit form, the setup guide, the docs table, AND the driver app — data is never deleted, just hidden,
// so turning a flag back on reveals any values already there. PO # and the document/signatures are always required.
const { db } = require('./db');

// Defaults for a brand-new account: the simplest possible start. Customer stays ON because it links the saved
// signature layouts; Load #, Delivered-to (receiver) and Sales rep start OFF and an admin turns them on as needed.
const DEFAULTS = { loadNumber: false, receiver: false, salesRep: false, customer: true };
const KEYS = Object.keys(DEFAULTS);

// The effective flags for an org: stored values merged over the defaults (missing keys fall back to the default).
function resolveUiFlags(orgId) {
  let stored = {};
  try {
    if (orgId) {
      const r = db.prepare('SELECT uiFlags FROM orgs WHERE id = ?').get(orgId);
      if (r && r.uiFlags) { stored = JSON.parse(r.uiFlags) || {}; }
    }
  } catch (e) { stored = {}; }
  const out = {};
  KEYS.forEach(k => { out[k] = (k in stored) ? !!stored[k] : DEFAULTS[k]; });
  return out;
}

// Persist a patch (only the keys provided change; the rest keep their current effective value).
function setUiFlags(orgId, patch) {
  const cur = resolveUiFlags(orgId);
  const next = {};
  KEYS.forEach(k => { next[k] = (patch && k in patch) ? !!patch[k] : cur[k]; });
  if (orgId) db.prepare('UPDATE orgs SET uiFlags = ? WHERE id = ?').run(JSON.stringify(next), orgId);
  return next;
}

module.exports = { DEFAULTS, KEYS, resolveUiFlags, setUiFlags };
