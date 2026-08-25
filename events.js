// One place to append to a load's recorded history timeline.
const crypto = require('crypto');
const { db } = require('./db');

function logEvent({ orgId, loadId, poNumber, type, detail, actor }) {
  try {
    db.prepare(`INSERT INTO load_events (id, orgId, loadId, poNumber, type, detail, actor, createdAt) VALUES (?,?,?,?,?,?,?,?)`)
      .run(crypto.randomUUID(), orgId || null, loadId || null, poNumber || null, type, detail || null, actor || null, Date.now());
  } catch (e) { /* history is best-effort; never block the main action */ }
}

module.exports = { logEvent };
