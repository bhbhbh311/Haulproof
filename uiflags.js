// Per-org "Simple mode" field flags. Each flag = is this optional input SHOWN. Hiding one removes it from the
// dispatcher edit form, the setup guide, the docs table, AND the driver app — data is never deleted, just hidden,
// so turning a flag back on reveals any values already there. PO # and the document/signatures are always required.
const { db } = require('./db');

// Defaults for a brand-new account: the simplest possible start. Customer stays ON because it links the saved
// signature layouts; Load #, Delivered-to (receiver) and Sales rep start OFF and an admin turns them on as needed.
// auditTrail is a document setting rather than a hidden field: ON (default) appends the signature
// audit-trail page (signer/role/time/GPS) to the signed PDF; OFF skips that page. The GPS/time data is
// still captured, stored on the load, and stamped under each signature either way — only the summary page drops.
// allowBrokerDrivers (carriers): may a broker who's been assigned one of this carrier's loads add drivers
// into this carrier's account on their behalf? ON by default so small owner-operators are set up for them;
// a carrier that manages its own roster can turn it off.
// Photo-proof settings — two levels each for pickup and delivery:
//   allowPickupPhoto    : when ON, the driver is OFFERED the pickup photo sheet but can skip it (optional proof).
//   requirePickupPhoto  : when ON, the driver MUST take at least one photo (up to 6) to record "Pickup complete".
//   allowDeliveryPhoto  : when ON, the driver is OFFERED a delivery-photo capture on the send screen (optional).
//   requireDeliveryPhoto: when ON, the driver MUST attach at least one delivery photo before "Send & complete".
// "Require" implies "allow". All OFF by default (pickup stays a one-tap GPS+time stamp; delivery takes no photos).
const DEFAULTS = { loadNumber: false, receiver: false, salesRep: false, customer: true, auditTrail: true, allowBrokerDrivers: true, allowPickupPhoto: false, requirePickupPhoto: false, allowDeliveryPhoto: false, requireDeliveryPhoto: false };
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
