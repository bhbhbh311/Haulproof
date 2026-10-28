// Receivers / consignees. A receiver is a GLOBAL org (roles include 'receiver') so the same
// delivery location isn't entered ten times. Privacy: a customer only sees the receivers THEY
// have linked (customer_receivers) — never the whole registry. When they add one, /match suggests
// existing global records ("is this your customer & delivery location?") so we link instead of duplicating.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { createUser, requireAuth, requireSuper, requireCap, userHasCap } = require('./auth');

const router = express.Router();
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
function newDeviceKey() { return 'dk_' + crypto.randomBytes(24).toString('hex'); }
function norm(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }
// Name without punctuation, "the" or company suffixes — "DOHERTY STEEL INC." and "Doherty Steel" match.
const SUFFIX = new Set(['inc', 'llc', 'llp', 'lp', 'co', 'corp', 'corporation', 'company', 'ltd', 'the', 'incorporated', 'dba']);
function core(s) { return norm(s).split(' ').filter(w => w && !SUFFIX.has(w)).join(' '); }

function rolesOf(o) { let r = []; try { r = o.roles ? JSON.parse(o.roles) : []; } catch (e) {} if (!r.length) r = [o.kind || 'customer']; return r; }
// Contacts belong to whoever added them: each customer keeps its own people at a receiver (only it sees, edits and
// emails them); ownerOrgId NULL = the receiver's own people, managed by the master admin and emailed on every load.
function contactsOf(id, ownerOrgId) {
  return db.prepare(`SELECT id, name, email, phone, receiveBol FROM receiver_contacts WHERE receiverId = ? AND ownerOrgId IS ? ORDER BY createdAt`).all(id, ownerOrgId || null)
    .map(c => ({ id: c.id, name: c.name || '', email: c.email || '', phone: c.phone || '', receiveBol: !!c.receiveBol }));
}
function setContacts(receiverId, contacts, ownerOrgId) {
  db.prepare(`DELETE FROM receiver_contacts WHERE receiverId = ? AND ownerOrgId IS ?`).run(receiverId, ownerOrgId || null);
  const ins = db.prepare(`INSERT INTO receiver_contacts (id, receiverId, name, email, phone, receiveBol, ownerOrgId, createdAt) VALUES (?,?,?,?,?,?,?,?)`);
  (Array.isArray(contacts) ? contacts : []).forEach(c => {
    const name = String(c && c.name || '').trim(), email = String(c && c.email || '').trim().toLowerCase(), phone = String(c && c.phone || '').trim();
    if (!name && !email) return;                                   // skip empty rows
    ins.run(crypto.randomUUID(), receiverId, name || null, email || null, phone || null, (c && c.receiveBol) ? 1 : 0, ownerOrgId || null, Date.now());
  });
}
// One-time: contacts added before per-customer ownership were shared by every customer using the receiver. Give each
// linked customer its own copy (so nobody loses anyone) and drop the shared row; unlinked receivers keep theirs as
// the receiver's own people.
try {
  db.exec(`CREATE TABLE IF NOT EXISTS app_migrations (name TEXT PRIMARY KEY, at INTEGER NOT NULL)`);
  if (!db.prepare(`SELECT 1 FROM app_migrations WHERE name = 'receiver_contacts_owner'`).get()) {
    db.transaction(() => {
      const rows = db.prepare(`SELECT * FROM receiver_contacts WHERE ownerOrgId IS NULL`).all();
      const links = db.prepare(`SELECT orgId FROM customer_receivers WHERE receiverId = ?`);
      const ins = db.prepare(`INSERT INTO receiver_contacts (id, receiverId, name, email, phone, receiveBol, ownerOrgId, createdAt) VALUES (?,?,?,?,?,?,?,?)`);
      rows.forEach(c => { const owners = links.all(c.receiverId).map(r => r.orgId); if (!owners.length) return;
        owners.forEach(o => ins.run(crypto.randomUUID(), c.receiverId, c.name, c.email, c.phone, c.receiveBol, o, c.createdAt));
        db.prepare(`DELETE FROM receiver_contacts WHERE id = ?`).run(c.id); });
      db.prepare(`INSERT INTO app_migrations (name, at) VALUES ('receiver_contacts_owner', ?)`).run(Date.now());
    })();
  }
} catch (e) { console.error('receiver contacts migration', e.message); }
function addressLine(o) { return [o.address, o.city, o.state, o.zip].map(s => (s || '').trim()).filter(Boolean).join(', '); }
function receiverOut(o, ownerOrgId) {
  const parent = o.parentId ? db.prepare(`SELECT id, name FROM orgs WHERE id = ?`).get(o.parentId) : null;
  const docCount = db.prepare(`SELECT COUNT(*) n FROM pods WHERE receiverId = ?`).get(o.id).n;
  const admins = db.prepare(`SELECT email FROM users WHERE orgId = ? AND role='admin' ORDER BY createdAt`).all(o.id).map(r => r.email);
  return { id: o.id, name: o.name, active: !!o.active, createdAt: o.createdAt, roles: rolesOf(o), kind: o.kind || 'customer',
    contactName: o.contactName, contactEmail: o.contactEmail, contactPhone: o.contactPhone,
    address: o.address, city: o.city, state: o.state, zip: o.zip, addressLine: addressLine(o), externalId: o.externalId || null,
    parentId: o.parentId || null, parentName: parent ? parent.name : null, docCount, admins, hasLogin: admins.length > 0,
    contacts: contactsOf(o.id, ownerOrgId), mergedInto: o.mergedInto || null };
}
function linkReceiver(orgId, receiverId) {
  if (!orgId || !receiverId) return;
  try { db.prepare(`INSERT OR IGNORE INTO customer_receivers (orgId, receiverId, createdAt) VALUES (?,?,?)`).run(orgId, receiverId, Date.now()); } catch (e) {}
}
// Which org "owns" this add/link: a normal admin uses their own org; super may target a customer via body.customerId.
function ownerOrgOf(req, b) { return req.user.role === 'superadmin' ? ((b && b.customerId || '').trim() || null) : (req.user.orgId || null); }
// Whose contacts a list shows: the master admin sees a customer's when managing that customer, else the receiver's own.
function viewerOwner(req) { return req.user.role === 'superadmin' ? ((req.query.linkedTo || req.query.customerId || '').trim() || null) : (req.user.orgId || null); }

// ---- LIST. Super: the whole registry. Everyone else: only receivers THEY have linked. ----
router.get('/', requireAuth, (req, res) => {
  const all = req.query.includeInactive === '1';
  let rows;
  if (req.user.role === 'superadmin') {
    const linkedTo = (req.query.linkedTo || '').trim();
    if (linkedTo) {
      rows = db.prepare(`SELECT o.* FROM orgs o JOIN customer_receivers cr ON cr.receiverId = o.id
        WHERE cr.orgId = ? ${all ? '' : 'AND o.active = 1'} ORDER BY o.name COLLATE NOCASE`).all(linkedTo);
    } else {
      rows = db.prepare(`SELECT * FROM orgs WHERE (roles LIKE '%"receiver"%' OR kind='receiver') AND mergedInto IS NULL ${all ? '' : 'AND active = 1'} ORDER BY name COLLATE NOCASE`).all();
    }
  } else {
    rows = db.prepare(`SELECT o.* FROM orgs o JOIN customer_receivers cr ON cr.receiverId = o.id
      WHERE cr.orgId = ? ${all ? '' : 'AND o.active = 1'} ORDER BY o.name COLLATE NOCASE`).all(req.user.orgId || '');
  }
  const owner = viewerOwner(req);
  res.json({ receivers: rows.map(o => receiverOut(o, owner)) });
});

// ---- MATCH the global registry by name (dedupe suggestion). Only surfaced when the user types a
//      specific name — this is a targeted "is this them?" lookup, not a browsable mass list. ----
router.get('/match', requireAuth, (req, res) => {
  const q = core(req.query.name);
  if (q.length < 2) return res.json({ matches: [] });
  const city = norm(req.query.city);
  const rows = db.prepare(`SELECT * FROM orgs WHERE (roles LIKE '%"receiver"%' OR kind='receiver') AND active = 1 AND mergedInto IS NULL`).all();
  const matches = rows.filter(o => {
    const n = core(o.name);
    if (!n || !(n.includes(q) || q.includes(n))) return false;
    if (city && !norm(addressLine(o)).includes(city)) return false;
    return true;
  }).sort((x, y) => (core(x.name) === q ? 0 : 1) - (core(y.name) === q ? 0 : 1)).slice(0, 8)
    .map(o => ({ id: o.id, name: o.name, address: addressLine(o) || null, parentName: o.parentId ? (db.prepare(`SELECT name FROM orgs WHERE id=?`).get(o.parentId) || {}).name : null }));
  res.json({ matches });
});

// ---- ADD or LINK. body.receiverId → link an existing global receiver to this customer.
//      Otherwise create a new global receiver and link it. ----
router.post('/', requireAuth, requireCap('manage_customers'), (req, res) => {
  const b = req.body || {};
  const isSuper = req.user.role === 'superadmin';
  const ownerOrg = ownerOrgOf(req, b);
  // Link an existing global receiver.
  if ((b.receiverId || '').trim()) {
    const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(b.receiverId.trim());
    if (!o) return res.status(404).json({ error: 'Receiver not found' });
    linkReceiver(ownerOrg, o.id);
    return res.status(200).json({ receiver: receiverOut(o, ownerOrg), linked: true });
  }
  // Create a new global receiver.
  const name = (b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Receiver name is required' });
  const parentId = (b.parentId || '').trim() || null;
  if (parentId && !db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(parentId)) return res.status(400).json({ error: 'Parent company not found' });
  const adminEmail = (b.adminEmail || '').toLowerCase().trim();
  const adminPassword = b.adminPassword || '';
  if (isSuper && adminEmail) {
    if (!EMAIL_RE.test(adminEmail)) return res.status(400).json({ error: 'A valid admin email is required' });
    if (String(adminPassword).length < 6) return res.status(400).json({ error: 'Admin password must be at least 6 characters' });
    if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(adminEmail)) return res.status(409).json({ error: 'That email already has a login' });
  }
  const id = crypto.randomUUID();
  db.prepare(`INSERT INTO orgs (id, name, deviceKey, kind, roles, parentId, contactName, contactEmail, contactPhone, address, city, state, zip, externalId, active, createdAt)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)`)
    .run(id, name, newDeviceKey(), 'receiver', JSON.stringify(['receiver']), parentId,
         (b.contactName || '').trim() || null, (b.contactEmail || '').trim() || null,
         (b.phone || b.contactPhone || '').trim() || null,
         (b.address || '').trim() || null, (b.city || '').trim() || null, (b.state || '').trim() || null, (b.zip || '').trim() || null,
         (b.externalId || '').trim() || null, Date.now());
  if (isSuper && adminEmail) createUser({ email: adminEmail, name: (b.adminName || b.contactName || '').trim(), role: 'admin', password: String(adminPassword), orgId: id });
  setContacts(id, b.contacts, ownerOrg);
  linkReceiver(ownerOrg, id);
  res.status(201).json({ receiver: receiverOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(id), ownerOrg), linked: !!ownerOrg, created: true });
});

// ---- BULK IMPORT (master admin). Create/refresh many global receivers at once, deduping on
//      externalId (e.g. "hubspot:12345") so re-running never duplicates. customerId optional:
//      omit/blank => receivers land UNLINKED in the global registry (each customer claims their own);
//      set => also link every imported receiver to that customer. ----
router.post('/import', requireAuth, requireCap('manage_customers'), (req, res) => {
  const b = req.body || {};
  const records = Array.isArray(b.records) ? b.records : [];
  if (!records.length) return res.status(400).json({ error: 'No records to import' });
  const customerId = (b.customerId || '').trim() || null;
  if (customerId && !db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(customerId)) {
    return res.status(400).json({ error: 'customerId not found' });
  }
  const byExt = db.prepare(`SELECT * FROM orgs WHERE externalId = ?`);
  const insert = db.prepare(`INSERT INTO orgs (id, name, deviceKey, kind, roles, contactName, contactPhone, address, city, state, zip, externalId, active, createdAt)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?)`);
  const update = db.prepare(`UPDATE orgs SET name = ?, address = ?, city = ?, state = ?, zip = ?, contactName = ?, contactPhone = ? WHERE id = ?`);
  let created = 0, updated = 0, linked = 0, skipped = 0; const errors = [];
  const run = db.transaction((rows) => {
    for (const r of rows) {
      try {
        const name = String(r && r.name || '').trim();
        if (!name) { skipped++; continue; }
        const ext = String(r && r.externalId || '').trim() || null;
        const address = String(r && r.address || '').trim() || null;
        const city = String(r && r.city || '').trim() || null;
        const state = String(r && r.state || '').trim() || null;
        const zip = String(r && r.zip || '').trim() || null;
        const phone = String(r && (r.phone || r.contactPhone) || '').trim() || null;
        const cName = String(r && (r.contactName || r.contact) || '').trim() || null;
        let existing = ext ? byExt.get(ext) : null;
        let id;
        if (existing) { id = existing.id; update.run(name, address, city, state, zip, (cName || existing.contactName || null), phone, id); updated++; }
        else { id = crypto.randomUUID(); insert.run(id, name, newDeviceKey(), 'receiver', JSON.stringify(['receiver']), cName, phone, address, city, state, zip, ext, Date.now()); created++; }
        if (customerId) { linkReceiver(customerId, id); linked++; }
      } catch (e) { if (errors.length < 8) errors.push(String(e && e.message || e)); }
    }
  });
  run(records);
  res.json({ ok: true, total: records.length, created, updated, linked, skipped, unlinked: !customerId, errors });
});

// ---- Unlink a receiver from a customer (does NOT delete the global record). ----
router.post('/:id/unlink', requireAuth, requireCap('manage_customers'), (req, res) => {
  const ownerOrg = ownerOrgOf(req, req.body || {});
  if (!ownerOrg) return res.status(400).json({ error: 'No customer to unlink from' });
  db.prepare(`DELETE FROM customer_receivers WHERE orgId = ? AND receiverId = ?`).run(ownerOrg, req.params.id);
  res.json({ ok: true });
});

// ---- Edit the receiver record. Master admin can edit any; a customer admin can edit a
//      receiver they've linked (customer_receivers). ----
router.put('/:id', requireAuth, requireCap('manage_customers'), (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Receiver not found' });
  if (req.user.role !== 'superadmin') {
    if (req.user.role !== 'admin' && !userHasCap(req, 'manage_customers')) return res.status(403).json({ error: 'Admins only' });
    const linked = db.prepare(`SELECT 1 FROM customer_receivers WHERE orgId = ? AND receiverId = ?`).get(req.user.orgId || '', o.id);
    if (!linked) return res.status(403).json({ error: 'You can only edit receivers you have added' });
  }
  const b = req.body || {};
  let parentId = (b.parentId !== undefined) ? ((b.parentId || '').trim() || null) : (o.parentId || null);
  if (parentId === o.id) parentId = null;
  if (parentId && !db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(parentId)) return res.status(400).json({ error: 'Parent company not found' });
  db.prepare(`UPDATE orgs SET name = ?, contactName = ?, contactEmail = ?, contactPhone = ?, address = ?, city = ?, state = ?, zip = ?, externalId = ?, parentId = ?, active = ? WHERE id = ?`)
    .run((b.name || o.name).trim(), (b.contactName ?? o.contactName) || null, (b.contactEmail ?? o.contactEmail) || null,
         ((b.phone ?? b.contactPhone) ?? o.contactPhone) || null, (b.address ?? o.address) || null,
         (b.city ?? o.city) || null, (b.state ?? o.state) || null, (b.zip ?? o.zip) || null, (b.externalId ?? o.externalId) || null,
         parentId, (b.active === undefined ? o.active : (b.active ? 1 : 0)), o.id);
  const owner = ownerOrgOf(req, b);
  if (b.contacts !== undefined) setContacts(o.id, b.contacts, owner);
  res.json({ receiver: receiverOut(db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(o.id), owner) });
});

// ---- Master admin: duplicate receivers. Groups active receivers whose names match once punctuation and company
//      suffixes are ignored, with what each one has (address, documents, customers, contacts) to decide. ----
router.get('/duplicates', requireAuth, requireSuper, (req, res) => {
  const rows = db.prepare(`SELECT * FROM orgs WHERE (roles LIKE '%"receiver"%' OR kind='receiver') AND active = 1 AND mergedInto IS NULL`).all();
  const groups = {};
  rows.forEach(o => { const k = core(o.name); if (k) (groups[k] = groups[k] || []).push(o); });
  const isParent = new Set(rows.filter(o => o.parentId).map(o => o.parentId));
  // Same street + zip (case, punctuation and "St"/"Street" style differences ignored) = probably the same place.
  const addrKey = o => { const a = String(o.address || '').toLowerCase().replace(/\b(street|st|avenue|ave|road|rd|drive|dr|north|n|south|s|east|e|west|w)\b/g, m => m[0]).replace(/[^a-z0-9]/g, '');
    return a ? a + '|' + String(o.zip || '').replace(/\D/g, '').slice(0, 5) : ''; };
  const docs = db.prepare(`SELECT COUNT(*) n FROM pods WHERE receiverId = ?`), custs = db.prepare(`SELECT o.name FROM customer_receivers cr JOIN orgs o ON o.id = cr.orgId WHERE cr.receiverId = ?`);
  const ccount = db.prepare(`SELECT COUNT(*) n FROM receiver_contacts WHERE receiverId = ?`), pname = db.prepare(`SELECT name FROM orgs WHERE id = ?`);
  // A parent with its locations is already sorted out; a group only needs review while it has a loose record
  // (not a location and not a parent). Parents and locations stay in the group so the loose one can join them.
  // A group needs review while it has a loose record, two records at the same address, or a location filed under another location.
  const byId = {}; rows.forEach(o => byId[o.id] = o);
  const needsReview = g => g.some(o => !o.parentId && !isParent.has(o.id)) || g.some(o => o.parentId && byId[o.parentId] && byId[o.parentId].parentId)
    || g.some((o, i) => { const k = addrKey(o); return k && g.some((x, j) => j !== i && addrKey(x) === k); });
  const out = Object.values(groups).filter(g => g.length > 1 && needsReview(g)).map(g => g.map(o => ({ id: o.id, name: o.name, addressLine: addressLine(o) || null,
      parentId: o.parentId || null, parentName: o.parentId ? ((pname.get(o.parentId) || {}).name || null) : null, isParent: isParent.has(o.id), addrKey: addrKey(o),
      docCount: docs.get(o.id).n, usedBy: custs.all(o.id).map(r => r.name), contacts: ccount.get(o.id).n, createdAt: o.createdAt })))
    .map(g => g.sort((a, b) => (b.isParent - a.isParent) || (!!b.parentId - !!a.parentId) || a.name.localeCompare(b.name)))
    .sort((a, b) => a[0].name.localeCompare(b[0].name));
  res.json({ groups: out });
});
// Merge duplicates into one: documents, customer links, contacts (each customer keeps its own), locations and logins
// move to the kept receiver; the others are switched off and marked merged so nothing points at them.
router.post('/merge', requireAuth, requireSuper, (req, res) => {
  const b = req.body || {}, keepId = String(b.keepId || '').trim();
  const ids = (Array.isArray(b.mergeIds) ? b.mergeIds : []).map(String).filter(x => x && x !== keepId);
  const keep = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(keepId);
  if (!keep || !ids.length) return res.status(400).json({ error: 'Pick the receiver to keep and at least one to merge into it' });
  let moved = { documents: 0, links: 0, contacts: 0 };
  db.transaction(() => {
    ids.forEach(id => {
      const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(id); if (!o) return;
      moved.documents += db.prepare(`UPDATE pods SET receiverId = ?, receiverName = ? WHERE receiverId = ?`).run(keep.id, keep.name, id).changes;
      db.prepare(`SELECT orgId FROM customer_receivers WHERE receiverId = ?`).all(id).forEach(r => { moved.links += db.prepare(`INSERT OR IGNORE INTO customer_receivers (orgId, receiverId, createdAt) VALUES (?,?,?)`).run(r.orgId, keep.id, Date.now()).changes; });
      db.prepare(`DELETE FROM customer_receivers WHERE receiverId = ?`).run(id);
      moved.contacts += db.prepare(`UPDATE receiver_contacts SET receiverId = ? WHERE receiverId = ?`).run(keep.id, id).changes;
      db.prepare(`UPDATE orgs SET parentId = ? WHERE parentId = ? AND id != ?`).run(keep.id, id, keep.id);
      db.prepare(`UPDATE users SET orgId = ? WHERE orgId = ?`).run(keep.id, id);
      if (!addressLine(keep) && addressLine(o)) { db.prepare(`UPDATE orgs SET address = ?, city = ?, state = ?, zip = ? WHERE id = ?`).run(o.address, o.city, o.state, o.zip, keep.id); Object.assign(keep, { address: o.address, city: o.city, state: o.state, zip: o.zip }); }
      db.prepare(`UPDATE orgs SET active = 0, mergedInto = ? WHERE id = ?`).run(keep.id, id);
    });
    // The same person added twice by the same customer collapses to one (keeps "gets BOL" if either had it).
    db.prepare(`SELECT ownerOrgId, LOWER(email) em, MIN(createdAt) first, MAX(receiveBol) bol, COUNT(*) n FROM receiver_contacts WHERE receiverId = ? AND email IS NOT NULL GROUP BY ownerOrgId, LOWER(email) HAVING n > 1`).all(keep.id).forEach(d => {
      const ids2 = db.prepare(`SELECT id FROM receiver_contacts WHERE receiverId = ? AND ownerOrgId IS ? AND LOWER(email) = ? ORDER BY createdAt`).all(keep.id, d.ownerOrgId, d.em).map(r => r.id);
      db.prepare(`UPDATE receiver_contacts SET receiveBol = ? WHERE id = ?`).run(d.bol, ids2[0]);
      ids2.slice(1).forEach(x => db.prepare(`DELETE FROM receiver_contacts WHERE id = ?`).run(x));
    });
  })();
  console.log('[receivers] merged ' + ids.length + ' into ' + keep.name + ' by ' + req.user.email);
  res.json({ ok: true, kept: keep.name, merged: ids.length, moved });
});
// Different addresses, same company: keep them separate and roll them up as locations of one parent.
// newParentName instead of parentId: create a plain parent company (no address) and put every location under it.
router.post('/group', requireAuth, requireSuper, (req, res) => {
  const b = req.body || {}, newName = String(b.newParentName || '').trim();
  let parentId = String(b.parentId || '').trim(), created = null;
  if (newName) {
    // Reuse a plain parent company (no address of its own) with exactly that name; a real location is never reused.
    const existing = db.prepare(`SELECT id, name FROM orgs WHERE (roles LIKE '%"receiver"%' OR kind='receiver') AND mergedInto IS NULL AND parentId IS NULL AND LOWER(TRIM(name)) = LOWER(?)
      AND COALESCE(TRIM(address),'') = '' AND COALESCE(TRIM(city),'') = '' AND COALESCE(TRIM(zip),'') = ''`).get(newName);
    if (existing) parentId = existing.id;
    else { parentId = crypto.randomUUID(); created = newName;
      db.prepare(`INSERT INTO orgs (id, name, deviceKey, kind, roles, active, createdAt) VALUES (?,?,?,?,?,1,?)`).run(parentId, newName, newDeviceKey(), 'receiver', JSON.stringify(['receiver']), Date.now()); }
  }
  // Locations always sit directly under the top company: picking a location as the parent files them under its parent instead.
  for (let i = 0, p; i < 5 && (p = db.prepare(`SELECT parentId FROM orgs WHERE id = ?`).get(parentId)) && p.parentId; i++) parentId = p.parentId;
  const kids = (Array.isArray(b.childIds) ? b.childIds : []).map(String).filter(x => x && x !== parentId);
  if (!db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(parentId) || !kids.length) return res.status(400).json({ error: 'Pick the parent company and at least one location' });
  const n = kids.reduce((t, id) => t + db.prepare(`UPDATE orgs SET parentId = ? WHERE id = ?`).run(parentId, id).changes, 0);
  res.json({ ok: true, grouped: n, parentId, createdParent: created });
});

// ---- Give a receiver a login so they can look up delivered documents (master admin only). ----
router.post('/:id/admins', requireAuth, requireSuper, (req, res) => {
  const o = db.prepare(`SELECT * FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Receiver not found' });
  const email = (req.body && req.body.email || '').toLowerCase().trim();
  const password = req.body && req.body.password || '';
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'A valid email is required' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(email)) return res.status(409).json({ error: 'That email already has a login' });
  createUser({ email, name: (req.body.name || '').trim(), role: 'admin', password: String(password), orgId: o.id });
  res.status(201).json({ ok: true });
});

module.exports = router;
