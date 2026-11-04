// Headquarters view: a parent company's logins see every one of its locations (child companies) in one place —
// counts per location, all loads, and the signed documents. Read-only: changing a load is done at the location.
const express = require('express');
const fs = require('fs');
const { requireAuth } = require('./auth');
const { db } = require('./db');
const { descendantOrgIds } = require('./hierarchy');

const DAY = 864e5;

// The locations this login can see: every active customer/carrier/broker company under its own company.
function locationsFor(req) {
  const root = req.user.role === 'superadmin' ? ((req.query.orgId || '').trim() || null) : (req.user.orgId || null);
  if (!root) return { root: null, ids: [] };
  const ids = descendantOrgIds(root).filter(id => id !== root);
  if (!ids.length) return { root, ids: [] };
  const ph = ids.map(() => '?').join(',');
  const live = db.prepare(`SELECT id FROM orgs WHERE id IN (${ph}) AND active = 1 AND kind IN ('customer','carrier','broker')`).all(...ids).map(r => r.id);
  return { root, ids: live };
}
const inList = ids => ids.map(() => '?').join(',');

const LOAD_COLS = `l.id, l.orgId, l.poNumber, l.loadNumber, l.customer, l.consignee, l.carrierName, l.brokerName, l.driverName, l.createdAt, l.pickedUpAt, o.name AS location,
  (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.status NOT IN ('parked','not_used')) AS total,
  (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.status IN ('signed','emailed')) AS done,
  (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.status = 'awaiting_build') AS setup,
  (SELECT COUNT(*) FROM pods p WHERE p.loadId = l.id AND p.emailFailedTo IS NOT NULL AND p.emailFailedTo NOT IN ('', '[]')) AS mailfail,
  (SELECT MAX(signedAt) FROM pods p WHERE p.loadId = l.id AND p.status IN ('signed','emailed')) AS lastSigned`;
function stateOf(l) {
  if (l.setup > 0) return 'setup';
  if (l.total > 0 && l.done >= l.total) return 'done';
  if (l.pickedUpAt || l.done > 0) return 'road';
  return 'open';
}

const router = express.Router();

// Per-location counts for the last 30 days and right now.
router.get('/summary', requireAuth, (req, res) => {
  const { ids } = locationsFor(req);
  if (!ids.length) return res.json({ applies: false });
  const since = Date.now() - 30 * DAY, week = Date.now() - 7 * DAY;
  const loads = db.prepare(`SELECT ${LOAD_COLS} FROM loads l LEFT JOIN orgs o ON o.id = l.orgId WHERE l.orgId IN (${inList(ids)}) AND l.createdAt >= ?`).all(...ids, since);
  const names = {}; db.prepare(`SELECT id, name FROM orgs WHERE id IN (${inList(ids)})`).all(...ids).forEach(o => { names[o.id] = o.name; });
  const by = {}; ids.forEach(id => { by[id] = { orgId: id, name: names[id] || '?', road: 0, setup: 0, mailfail: 0, doneWeek: 0, loads30: 0 }; });
  loads.forEach(l => { const b = by[l.orgId]; if (!b) return; const st = stateOf(l);
    b.loads30++; if (st === 'road') b.road++; if (st === 'setup') b.setup++; if (l.mailfail > 0) b.mailfail++;
    if (st === 'done' && l.lastSigned >= week) b.doneWeek++; });
  const list = Object.keys(by).map(k => by[k]).sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const t = list.reduce((a, b) => ({ road: a.road + b.road, setup: a.setup + b.setup, mailfail: a.mailfail + b.mailfail, doneWeek: a.doneWeek + b.doneWeek, loads30: a.loads30 + b.loads30 }), { road: 0, setup: 0, mailfail: 0, doneWeek: 0, loads30: 0 });
  res.json({ applies: true, locations: list, totals: t });
});

// Loads across every location, newest first (search by PO / load / customer / consignee / carrier / driver).
router.get('/loads', requireAuth, (req, res) => {
  const { ids } = locationsFor(req);
  if (!ids.length) return res.json({ results: [] });
  let use = ids;
  if (req.query.location) { use = ids.filter(id => id === req.query.location); if (!use.length) return res.json({ results: [] }); }
  const where = [`l.orgId IN (${inList(use)})`], args = [...use];
  const q = String(req.query.q || '').trim();
  if (q) { where.push(`(l.poNumber LIKE ? OR l.loadNumber LIKE ? OR l.customer LIKE ? OR l.consignee LIKE ? OR l.carrierName LIKE ? OR l.driverName LIKE ?)`); for (let i = 0; i < 6; i++) args.push('%' + q + '%'); }
  else { where.push(`l.createdAt >= ?`); args.push(Date.now() - 90 * DAY); }
  const rows = db.prepare(`SELECT ${LOAD_COLS} FROM loads l LEFT JOIN orgs o ON o.id = l.orgId WHERE ${where.join(' AND ')} ORDER BY l.createdAt DESC LIMIT 300`).all(...args);
  res.json({ results: rows.map(l => ({ id: l.id, location: l.location, locationId: l.orgId, poNumber: l.poNumber, loadNumber: l.loadNumber, customer: l.customer, consignee: l.consignee,
    carrierName: l.carrierName, brokerName: l.brokerName || null, driverName: l.driverName, createdAt: l.createdAt, stopsTotal: l.total, stopsDone: l.done, lastSignedAt: l.lastSigned || null, emailFailed: l.mailfail, state: stateOf(l) })) });
});

// The signed documents on one load (only loads at this company's locations).
router.get('/loads/:id/docs', requireAuth, (req, res) => {
  const { ids } = locationsFor(req);
  const l = db.prepare(`SELECT id, orgId, poNumber FROM loads WHERE id = ?`).get(req.params.id);
  if (!l || !ids.includes(l.orgId)) return res.status(404).json({ error: 'Load not found' });
  const docs = db.prepare(`SELECT id, stopNumber, docType, receiverName, consignee, signedAt FROM pods WHERE loadId = ? AND status IN ('signed','emailed') ORDER BY (stopNumber IS NULL), stopNumber, signedAt`).all(l.id);
  res.json({ poNumber: l.poNumber, docs });
});

// A signed document's PDF (with its proof photos), for a load at one of this company's locations.
router.get('/pods/:id/file', requireAuth, async (req, res) => {
  const { ids } = locationsFor(req);
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!row || !ids.includes(row.orgId) || ['signed', 'emailed'].indexOf(row.status) < 0 || !row.filepath || !fs.existsSync(row.filepath)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${(row.filename || 'BOL').replace(/[^\w.\- ]+/g, '_')}.pdf"`);
  res.setHeader('Cache-Control', 'no-store');
  let combined = null;
  try { combined = await require('./pods').combinedPodBytes(row); } catch (e) {}
  if (combined && combined.length) { const buf = Buffer.from(combined); res.setHeader('Content-Length', buf.length); return res.end(buf); }
  fs.createReadStream(row.filepath).pipe(res);
});

module.exports = { router, locationsFor };
