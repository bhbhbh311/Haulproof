// Loads: dispatch/sales create and look up loads by PO# or load#. Scoped to the caller's customer.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth } = require('./auth');

const router = express.Router();
function myOrg(req) { return req.user.role === 'superadmin' ? ((req.query.orgId || req.body && req.body.orgId || '').trim() || null) : (req.user.orgId || null); }

// Create/name a load. The customer's PO# is the primary business identifier (unique per customer).
router.post('/', requireAuth, (req, res) => {
  const orgId = myOrg(req);
  const { loadNumber, poNumber, customer, consignee, origin, destination } = req.body || {};
  if (!poNumber && !loadNumber) return res.status(400).json({ error: 'Provide a PO number or a load number' });
  if (poNumber) {
    const existing = db.prepare(`SELECT * FROM loads WHERE orgId IS ? AND poNumber = ?`).get(orgId, poNumber);
    if (existing) return res.json({ load: existing, existed: true });
  }
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO loads (id, orgId, loadNumber, poNumber, customer, consignee, origin, destination, status, createdBy, createdAt)
     VALUES (?,?,?,?,?,?,?,?, 'open', ?, ?)`
  ).run(id, orgId, loadNumber || null, poNumber || null, customer || null, consignee || null, origin || null, destination || null, req.user.email, Date.now());
  res.json({ load: db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id), existed: false });
});

// Search loads within this customer.
router.get('/', requireAuth, (req, res) => {
  const orgId = myOrg(req);
  const { q, po, load } = req.query;
  const where = [`orgId IS ?`], args = [orgId];
  if (po)   { where.push(`poNumber LIKE ?`);   args.push(`%${po}%`); }
  if (load) { where.push(`loadNumber LIKE ?`); args.push(`%${load}%`); }
  if (q)    { where.push(`(poNumber LIKE ? OR loadNumber LIKE ? OR customer LIKE ? OR consignee LIKE ?)`);
              args.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
  const rows = db.prepare(
    `SELECT * FROM loads WHERE ${where.join(' AND ')} ORDER BY createdAt DESC LIMIT 200`
  ).all(...args);
  res.json({ count: rows.length, results: rows });
});

// One load plus all its documents (same customer only).
router.get('/:id', requireAuth, (req, res) => {
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(req.params.id);
  const ok = load && (req.user.role === 'superadmin' || (load.orgId || null) === (req.user.orgId || null));
  if (!ok) return res.status(404).json({ error: 'Load not found' });
  const pods = db.prepare(`SELECT id, docType, filename, consignee, signedAt, uploadedAt, status FROM pods WHERE loadId = ? ORDER BY uploadedAt DESC`).all(load.id)
    .map(p => ({ ...p, fileUrl: `/api/pods/${p.id}/file` }));
  res.json({ load, pods });
});

module.exports = router;
