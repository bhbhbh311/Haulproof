// Each org's PRIVATE customer list — the companies a carrier/broker/customer hauls for. Modeled on the
// receivers list: you pick from your own list or add to it. De-duplicated so the same company isn't
// entered twice. Each customer can carry a list of email contacts who receive its signed documents.
// (Linking an entry to a real customer tenant account is a later, approval-gated step.)
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth } = require('./auth');

const router = express.Router();
// The org whose list we're reading/writing. Super-admin may target one via ?orgId=; everyone else is
// pinned to their own org.
function ownerOrg(req) {
  return req.user.role === 'superadmin' ? ((req.query.orgId || (req.body && req.body.orgId) || '').trim() || null) : (req.user.orgId || null);
}
function norm(s) { return String(s || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }
// Clean an incoming contacts array into [{name,email,receiveDocs}] — only rows that have an email.
function cleanContacts(arr) {
  if (!Array.isArray(arr)) return [];
  const seen = new Set();
  const out = [];
  arr.forEach(c => {
    if (!c) return;
    const email = String(c.email || '').trim();
    if (!email) return;
    const key = email.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name: String(c.name || '').trim(), email, receiveDocs: c.receiveDocs === false ? false : true });
  });
  return out;
}
function parseContacts(s) { try { const a = JSON.parse(s || '[]'); return Array.isArray(a) ? a : []; } catch (e) { return []; } }
function cOut(c) {
  return {
    id: c.id, name: c.name, mcNumber: c.mcNumber, dotNumber: c.dotNumber,
    contactName: c.contactName, contactEmail: c.contactEmail, contactPhone: c.contactPhone,
    address: c.address, note: c.note, linkedOrgId: c.linkedOrgId,
    contacts: parseContacts(c.contacts),
  };
}
// Pull the fields we accept off a request body (used by both create and edit).
function fieldsFrom(b) {
  return {
    mcNumber: (b.mcNumber || '').trim() || null,
    dotNumber: (b.dotNumber || '').trim() || null,
    contactName: (b.contactName || '').trim() || null,
    contactEmail: (b.contactEmail || '').trim() || null,
    contactPhone: (b.contactPhone || '').trim() || null,
    address: (b.address || '').trim() || null,
    note: (b.note || '').trim() || null,
    contacts: JSON.stringify(cleanContacts(b.contacts)),
  };
}

// This org's customer list (for the picker + the Customers tab).
router.get('/', requireAuth, (req, res) => {
  const org = ownerOrg(req);
  if (!org) return res.json({ customers: [] });
  const rows = db.prepare(`SELECT * FROM customers WHERE ownerOrgId = ? ORDER BY name COLLATE NOCASE`).all(org);
  res.json({ customers: rows.map(cOut) });
});

// Dedup lookup: near-name matches already in THIS org's list, so we don't create a second "Brown Strauss".
router.get('/match', requireAuth, (req, res) => {
  const org = ownerOrg(req);
  const q = norm(req.query.name);
  if (!org || !q) return res.json({ matches: [] });
  const rows = db.prepare(`SELECT * FROM customers WHERE ownerOrgId = ?`).all(org);
  const matches = rows.filter(r => { const n = norm(r.name); return n === q || n.indexOf(q) >= 0 || q.indexOf(n) >= 0; }).slice(0, 6);
  res.json({ matches: matches.map(cOut) });
});

// Add a customer to this org's list. Exact-name dedup: if one already exists, return it (existed:true)
// instead of creating a duplicate — unless force is set (the user confirmed it's a different company).
router.post('/', requireAuth, (req, res) => {
  const org = ownerOrg(req);
  if (!org) return res.status(400).json({ error: 'No organization on this login' });
  const b = req.body || {};
  const name = (b.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Customer name is required' });
  const q = norm(name);
  const existing = db.prepare(`SELECT * FROM customers WHERE ownerOrgId = ?`).all(org).find(r => norm(r.name) === q);
  if (existing && !b.force) return res.json({ customer: cOut(existing), existed: true });
  const id = crypto.randomUUID();
  const f = fieldsFrom(b);
  db.prepare(`INSERT INTO customers (id, ownerOrgId, name, mcNumber, dotNumber, contactName, contactEmail, contactPhone, address, contacts, note, createdAt)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, org, name, f.mcNumber, f.dotNumber, f.contactName, f.contactEmail, f.contactPhone, f.address, f.contacts, f.note, Date.now());
  res.status(201).json({ customer: cOut(db.prepare(`SELECT * FROM customers WHERE id = ?`).get(id)), existed: false });
});

// Edit a customer in this org's list — details + the signed-doc contacts.
router.put('/:id', requireAuth, (req, res) => {
  const org = ownerOrg(req);
  if (!org) return res.status(400).json({ error: 'No organization on this login' });
  const row = db.prepare(`SELECT * FROM customers WHERE id = ? AND ownerOrgId = ?`).get(req.params.id, org);
  if (!row) return res.status(404).json({ error: 'Customer not found in your list' });
  const b = req.body || {};
  const name = (b.name !== undefined) ? (b.name || '').trim() : row.name;
  if (!name) return res.status(400).json({ error: 'Customer name is required' });
  // Guard against renaming onto another entry's name.
  if (norm(name) !== norm(row.name)) {
    const clash = db.prepare(`SELECT id FROM customers WHERE ownerOrgId = ? AND id != ?`).all(org, row.id).find(r => norm(r.name) === norm(name));
    if (clash) return res.status(409).json({ error: 'Another customer in your list already uses that name' });
  }
  const f = fieldsFrom(b);
  db.prepare(`UPDATE customers SET name = ?, mcNumber = ?, dotNumber = ?, contactName = ?, contactEmail = ?, contactPhone = ?, address = ?, contacts = ?, note = ? WHERE id = ?`)
    .run(name, f.mcNumber, f.dotNumber, f.contactName, f.contactEmail, f.contactPhone, f.address, f.contacts, f.note, row.id);
  // Keep the snapshot name on any of this org's loads pointing here in sync.
  try { db.prepare(`UPDATE loads SET customer = ? WHERE customerId = ? AND orgId IS ?`).run(name, row.id, org); } catch (e) {}
  res.json({ customer: cOut(db.prepare(`SELECT * FROM customers WHERE id = ?`).get(row.id)) });
});

// Remove a customer from this org's list. The load's snapshot name stays, so past loads still read fine.
router.delete('/:id', requireAuth, (req, res) => {
  const org = ownerOrg(req);
  if (!org) return res.status(400).json({ error: 'No organization on this login' });
  const row = db.prepare(`SELECT * FROM customers WHERE id = ? AND ownerOrgId = ?`).get(req.params.id, org);
  if (!row) return res.status(404).json({ error: 'Customer not found in your list' });
  db.prepare(`DELETE FROM customers WHERE id = ?`).run(row.id);
  // Unlink any of this org's loads that pointed at it (keep the name snapshot on the load).
  try { db.prepare(`UPDATE loads SET customerId = NULL WHERE customerId = ? AND orgId IS ?`).run(row.id, org); } catch (e) {}
  res.json({ ok: true });
});

// Used by the signed-doc email flow: the customer's contacts flagged to receive documents.
function customerDocEmails(customerId) {
  if (!customerId) return [];
  try {
    const row = db.prepare(`SELECT contacts FROM customers WHERE id = ?`).get(customerId);
    if (!row) return [];
    return parseContacts(row.contacts).filter(c => c && c.email && c.receiveDocs !== false).map(c => String(c.email).trim()).filter(Boolean);
  } catch (e) { return []; }
}

module.exports = router;
module.exports.customerDocEmails = customerDocEmails;
