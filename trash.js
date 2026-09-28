// Recovery bin: recoverable delete for documents and loads.
// When a document or a whole load is deleted, its row is snapshotted into deleted_docs / deleted_loads and
// the PDF file is KEPT on disk, so an admin can restore it. Rows past purgeAfter are permanently purged
// (row removed + file unlinked). Restore is available to admins (and master admins); the truly destructive
// "delete permanently" action is master-admin only.
const express = require('express');
const fs = require('fs');
const { db } = require('./db');
const { requireAuth, requireAdmin, requireSuper } = require('./auth');
const { logEvent } = require('./events');

const router = express.Router();

// Retention window: how long a deleted item stays restorable before it is purged for good.
const RETENTION_DAYS = 365;
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;
function purgeAfterFrom(ts) { return ts + RETENTION_MS; }

// Which org's recovery bin this caller sees. A master admin sees everything (or one org via ?orgId=).
function myOrg(req) { return req.user.role === 'superadmin' ? ((req.query.orgId || '').trim() || null) : (req.user.orgId || null); }
function orgWhere(req) {
  const o = myOrg(req);
  if (req.user.role === 'superadmin' && !o) return { sql: '1 = 1', args: [] };
  return { sql: 'orgId IS ?', args: [o] };
}

// Re-insert a snapshotted row back into its table. Built from the row's own keys so it survives schema growth
// (a column added since deletion is simply left at its default; older extra columns are ignored on insert).
function restoreRow(table, obj) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  const keys = Object.keys(obj).filter(k => cols.includes(k));
  const sql = `INSERT OR REPLACE INTO ${table} (${keys.join(', ')}) VALUES (${keys.map(k => '@' + k).join(', ')})`;
  const clean = {}; keys.forEach(k => { clean[k] = obj[k]; });
  db.prepare(sql).run(clean);
}

// Permanently remove any trash past its purge date (DB row + PDF file). Cheap; run lazily on reads.
function purgeExpired() {
  const now = Date.now();
  try {
    const goneDocs = db.prepare(`SELECT id, filepath FROM deleted_docs WHERE purgeAfter <= ?`).all(now);
    const delDoc = db.prepare(`DELETE FROM deleted_docs WHERE id = ?`);
    for (const g of goneDocs) { try { if (g.filepath && fs.existsSync(g.filepath)) fs.unlinkSync(g.filepath); } catch (_) {} delDoc.run(g.id); }
    const goneLoads = db.prepare(`SELECT id FROM deleted_loads WHERE purgeAfter <= ?`).all(now);
    for (const gl of goneLoads) { try { db.prepare(`DELETE FROM load_subscribers WHERE loadId = ?`).run(gl.id); } catch (_) {} }
    db.prepare(`DELETE FROM deleted_loads WHERE purgeAfter <= ?`).run(now);
  } catch (e) { console.error('purgeExpired', e.message); }
}

// ---- The delete side (called by pods.js / loads.js so the snapshot logic lives in one place) ----
// Snapshot a single pod into the recovery bin. `kind` is 'doc' (deleted on its own) or 'load' (part of a
// load delete). Does NOT touch the pods table or the file — the caller removes the row and keeps the file.
function stashDoc(pod, kind, actorEmail) {
  const now = Date.now();
  db.prepare(`INSERT OR REPLACE INTO deleted_docs
     (id, loadId, orgId, poNumber, loadNumber, docType, filename, filepath, stopNumber, status, snapshot, deletedKind, deletedAt, deletedBy, purgeAfter)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    pod.id, pod.loadId || null, pod.orgId || null, pod.poNumber || null, pod.loadNumber || null,
    pod.docType || null, pod.filename || null, pod.filepath || null, pod.stopNumber != null ? pod.stopNumber : null,
    pod.status || null, JSON.stringify(pod), kind, now, actorEmail || null, purgeAfterFrom(now));
}
// Snapshot a load into the recovery bin. The caller removes the load row and keeps the files.
function stashLoad(load, docCount, actorEmail) {
  const now = Date.now();
  db.prepare(`INSERT OR REPLACE INTO deleted_loads
     (id, orgId, poNumber, loadNumber, snapshot, docCount, deletedAt, deletedBy, purgeAfter)
     VALUES (?,?,?,?,?,?,?,?,?)`).run(
    load.id, load.orgId || null, load.poNumber || null, load.loadNumber || null,
    JSON.stringify(load), docCount || 0, now, actorEmail || null, purgeAfterFrom(now));
}

// ---- The recovery side (the portal's Recovery bin UI) ----

// List recoverable loads + standalone documents for this org. Admin / master admin only.
router.get('/', requireAuth, requireAdmin, (req, res) => {
  purgeExpired();
  const w = orgWhere(req);
  const loads = db.prepare(`SELECT id, poNumber, loadNumber, docCount, deletedAt, deletedBy, purgeAfter
     FROM deleted_loads WHERE ${w.sql} ORDER BY deletedAt DESC LIMIT 500`).all(...w.args);
  // Documents deleted ON THEIR OWN. Ones removed as part of a load delete live under their load, not here.
  const docs = db.prepare(`SELECT id, loadId, poNumber, loadNumber, docType, filename, stopNumber, status, deletedAt, deletedBy, purgeAfter
     FROM deleted_docs WHERE ${w.sql} AND deletedKind = 'doc' ORDER BY deletedAt DESC LIMIT 500`).all(...w.args);
  res.json({ loads, docs, retentionDays: RETENTION_DAYS });
});

// Restore a single deleted document back onto its load. Admin / master admin.
router.post('/doc/:id/restore', requireAuth, requireAdmin, (req, res) => {
  const w = orgWhere(req);
  const row = db.prepare(`SELECT * FROM deleted_docs WHERE id = ? AND ${w.sql}`).get(req.params.id, ...w.args);
  if (!row) return res.status(404).json({ error: 'That document is not in the recovery bin.' });
  const load = db.prepare(`SELECT id FROM loads WHERE id = ?`).get(row.loadId);
  if (!load) return res.status(409).json({ error: 'The load this document belonged to no longer exists — restore the load instead.' });
  try {
    restoreRow('pods', JSON.parse(row.snapshot));
    db.prepare(`DELETE FROM deleted_docs WHERE id = ?`).run(row.id);
    try { logEvent({ orgId: row.orgId, loadId: row.loadId, poNumber: row.poNumber, type: 'document_restored',
      detail: (row.docType || 'Document') + ' restored from the recovery bin' + (row.stopNumber ? ' (Stop ' + row.stopNumber + ')' : '') + (row.filename ? ': ' + row.filename : ''), actor: req.user.email }); } catch (_) {}
    res.json({ ok: true });
  } catch (e) { console.error('restore doc', e); res.status(500).json({ error: 'Could not restore this document.' }); }
});

// Restore a whole deleted load together with every document that was removed with it. Admin / master admin.
router.post('/load/:id/restore', requireAuth, requireAdmin, (req, res) => {
  const w = orgWhere(req);
  const lrow = db.prepare(`SELECT * FROM deleted_loads WHERE id = ? AND ${w.sql}`).get(req.params.id, ...w.args);
  if (!lrow) return res.status(404).json({ error: 'That load is not in the recovery bin.' });
  try {
    restoreRow('loads', JSON.parse(lrow.snapshot));
    const docs = db.prepare(`SELECT * FROM deleted_docs WHERE loadId = ? AND deletedKind = 'load'`).all(lrow.id);
    let restored = 0;
    for (const d of docs) { try { restoreRow('pods', JSON.parse(d.snapshot)); db.prepare(`DELETE FROM deleted_docs WHERE id = ?`).run(d.id); restored++; } catch (_) {} }
    db.prepare(`DELETE FROM deleted_loads WHERE id = ?`).run(lrow.id);
    try { logEvent({ orgId: lrow.orgId, loadId: lrow.id, poNumber: lrow.poNumber, type: 'load_restored',
      detail: 'Load and its ' + restored + ' document(s) restored from the recovery bin', actor: req.user.email }); } catch (_) {}
    res.json({ ok: true, restoredDocs: restored });
  } catch (e) { console.error('restore load', e); res.status(500).json({ error: 'Could not restore this load.' }); }
});

// Permanently delete a single document from the recovery bin (row + file). MASTER ADMIN ONLY — irreversible.
router.delete('/doc/:id', requireAuth, requireSuper, (req, res) => {
  const row = db.prepare(`SELECT * FROM deleted_docs WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not in the recovery bin.' });
  try { if (row.filepath && fs.existsSync(row.filepath)) fs.unlinkSync(row.filepath); } catch (_) {}
  db.prepare(`DELETE FROM deleted_docs WHERE id = ?`).run(row.id);
  try { logEvent({ orgId: row.orgId, loadId: row.loadId, poNumber: row.poNumber, type: 'document_purged',
    detail: (row.docType || 'Document') + ' permanently deleted from the recovery bin', actor: req.user.email }); } catch (_) {}
  res.json({ ok: true });
});

// Permanently delete a whole load from the recovery bin (load + all its docs + files). MASTER ADMIN ONLY.
router.delete('/load/:id', requireAuth, requireSuper, (req, res) => {
  const lrow = db.prepare(`SELECT * FROM deleted_loads WHERE id = ?`).get(req.params.id);
  if (!lrow) return res.status(404).json({ error: 'Not in the recovery bin.' });
  const docs = db.prepare(`SELECT id, filepath FROM deleted_docs WHERE loadId = ? AND deletedKind = 'load'`).all(lrow.id);
  for (const d of docs) { try { if (d.filepath && fs.existsSync(d.filepath)) fs.unlinkSync(d.filepath); } catch (_) {} db.prepare(`DELETE FROM deleted_docs WHERE id = ?`).run(d.id); }
  try { db.prepare(`DELETE FROM load_subscribers WHERE loadId = ?`).run(lrow.id); } catch (_) {}
  db.prepare(`DELETE FROM deleted_loads WHERE id = ?`).run(lrow.id);
  try { logEvent({ orgId: lrow.orgId, loadId: lrow.id, poNumber: lrow.poNumber, type: 'load_purged',
    detail: 'Load and its ' + docs.length + ' document(s) permanently deleted from the recovery bin', actor: req.user.email }); } catch (_) {}
  res.json({ ok: true, purgedDocs: docs.length });
});

module.exports = { router, stashDoc, stashLoad, purgeExpired, RETENTION_DAYS };
