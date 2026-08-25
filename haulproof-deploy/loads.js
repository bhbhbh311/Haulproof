// Loads: dispatch/sales create and look up loads by PO# or load#.
const express = require('express');
const crypto = require('crypto');
const { db } = require('./db');
const { requireAuth } = require('./auth');

const router = express.Router();

// Create/name a load. The customer's PO# is the primary business identifier.
router.post('/', requireAuth, (req, res) => {
  const { loadNumber, poNumber, customer, consignee, origin, destination } = req.body || {};
  if (!poNumber && !loadNumber) return res.status(400).json({ error: 'Provide a PO number or a load number' });
  // De-dupe on PO#, so the same customer PO maps to one load.
  if (poNumber) {
    const existing = db.prepare(`SELECT * FROM loads WHERE poNumber = ?`).get(poNumber);
    if (existing) return res.json({ load: existing, existed: true });
  }
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO loads (id, loadNumber, poNumber, customer, consignee, origin, destination, status, createdBy, createdAt)
     VALUES (?,?,?,?,?,?,?, 'open', ?, ?)`
  ).run(id, loadNumber || null, poNumber || null, customer || null, consignee || null, origin || null, destination || null, req.user.email, Date.now());
  res.json({ load: db.prepare(`SELECT * FROM loads WHERE id = ?`).get(id), existed: false });
});

// Search loads by PO#, load#, customer, or consignee.
router.get('/', requireAuth, (req, res) => {
  const { q, po, load } = req.query;
  const where = [], args = [];
  if (po)   { where.push(`poNumber LIKE ?`);   args.push(`%${po}%`); }
  if (load) { where.push(`loadNumber LIKE ?`); args.push(`%${load}%`); }
  if (q)    { where.push(`(poNumber LIKE ? OR loadNumber LIKE ? OR customer LIKE ? OR consignee LIKE ?)`);
              args.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
  const rows = db.prepare(
    `SELECT * FROM loads ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY createdAt DESC LIMIT 200`
  ).all(...args);
  res.json({ count: rows.length, results: rows });
});

// One load plus all its documents.
router.get('/:id', requireAuth, (req, res) => {
  const load = db.prepare(`SELECT * FROM loads WHERE id = ?`).get(req.params.id);
  if (!load) return res.status(404).json({ error: 'Load not found' });
  const pods = db.prepare(`SELECT id, docType, filename, consignee, signedAt, uploadedAt, status FROM pods WHERE loadId = ? ORDER BY uploadedAt DESC`).all(load.id)
    .map(p => ({ ...p, fileUrl: `/api/pods/${p.id}/file` }));
  res.json({ load, pods });
});

module.exports = router;
