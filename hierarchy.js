// Parent → child org rollup. A parent-company login can see all of its child locations.
const { db } = require('./db');

// Every org id in the subtree rooted at rootId (inclusive). Cycle-safe.
function descendantOrgIds(rootId) {
  if (!rootId) return [];
  const seen = new Set([rootId]);
  let frontier = [rootId];
  const stmt = db.prepare(`SELECT id FROM orgs WHERE parentId = ?`);
  while (frontier.length) {
    const next = [];
    for (const pid of frontier) {
      for (const row of stmt.all(pid)) {
        if (!seen.has(row.id)) { seen.add(row.id); next.push(row.id); }
      }
    }
    frontier = next;
  }
  return Array.from(seen);
}

module.exports = { descendantOrgIds };
