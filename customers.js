// Each org's PRIVATE customer list — the companies a carrier/broker/customer hauls for. Modeled on the
// receivers list: you pick from your own list or add to it. De-duplicated so the same company isn't
// entered twice. (Linking an entry to a real customer tenant account is a later, approval-gated step.)
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
function cOut(c) { return { id: c.id, name: c.name, mcNumber: c.mcNumber, dotNumber: c.dotNumber, contactName: c.contactName, contactEmail: c.contactEmail, linkedOrgId: c.linkedOrgId }; }

// This org's customer list (for the picker).
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
  db.prepare(`INSERT INTO customers (id, ownerOrgId, name, mcNumber, dotNumber, contactName, contactEmail, note, createdAt)
     VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(id, org, name, (b.mcNumber || '').trim() || null, (b.dotNumber || '').trim() || null,
      (b.contactName || '').trim() || null, (b.contactEmail || '').trim() || null, (b.note || '').trim() || null, Date.now());
  res.status(201).json({ customer: cOut(db.prepare(`SELECT * FROM customers WHERE id = ?`).get(id)), existed: false });
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

module.exports = router;
