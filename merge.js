// Merge a duplicate company into the real one (master admin). Made for the case where the same carrier/broker
// ended up with two accounts — e.g. a broker added it by MC #, then its dispatcher's access request created a
// second one. The duplicate's people (team logins and drivers) move into the real account; the duplicate is
// turned off and marked mergedInto so it stays in history but can't be used or picked again.
// Deliberately narrow: a duplicate that already holds loads or documents is refused, so nothing with paperwork
// is moved blindly. HaulProof Help support logins stay behind (the real account has its own).
const { db } = require('./db');

class MergeError extends Error {}

function mergeCompanyInto(fromId, intoId) {
  if (!fromId || !intoId) throw new MergeError('Pick both companies');
  if (fromId === intoId) throw new MergeError('That is the same company');
  const from = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(fromId);
  const into = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(intoId);
  if (!from || !into) throw new MergeError('Company not found');
  if (from.mergedInto) throw new MergeError(from.name + ' was already merged');
  if (!into.active) throw new MergeError(into.name + ' is turned off; merge into an active account');
  if ((from.kind || 'customer') !== (into.kind || 'customer')) throw new MergeError(`${from.name} is a ${from.kind || 'customer'} and ${into.name} is a ${into.kind || 'customer'}; only the same type can be merged`);
  const loads = db.prepare(`SELECT COUNT(*) n FROM loads WHERE orgId = ? OR carrierId = ? OR brokerId = ?`).get(fromId, fromId, fromId).n;
  const docs = db.prepare(`SELECT COUNT(*) n FROM pods WHERE orgId = ?`).get(fromId).n;
  if (loads || docs) throw new MergeError(`${from.name} (the duplicate) already has ${loads} load(s) and ${docs} document(s); merge it by hand so nothing is lost`);

  const support = `LOWER(email) LIKE 'haulproofhelp+%'`;
  const movedUsers = db.prepare(`SELECT email FROM users WHERE orgId = ? AND NOT (${support})`).all(fromId).map(u => u.email);
  const movedDrivers = db.prepare(`SELECT name FROM drivers WHERE orgId = ?`).all(fromId).map(d => d.name);
  db.transaction(() => {
    db.prepare(`UPDATE users SET orgId = ? WHERE orgId = ? AND NOT (${support})`).run(intoId, fromId);
    db.prepare(`UPDATE drivers SET orgId = ? WHERE orgId = ?`).run(intoId, fromId);
    db.prepare(`UPDATE orgs SET active = 0, mergedInto = ? WHERE id = ?`).run(intoId, fromId);
    // Access requests that pointed at the duplicate now point at the real account.
    try { db.prepare(`UPDATE access_requests SET createdOrgId = ? WHERE createdOrgId = ?`).run(intoId, fromId); } catch (e) {}
  })();
  return { from: from.name, into: into.name, type: into.kind || 'customer', movedLogins: movedUsers, movedDrivers };
}

module.exports = { mergeCompanyInto, MergeError };
