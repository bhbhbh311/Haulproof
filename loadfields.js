// The company's own load fields, set up by an admin: rename a built-in field (call "Load #" "Trip #"), or add
// fields that stay with every load ("Release #", "Pickup #", "Trailer #"). Dispatch fills them in on the load; each
// can be required (the load shows it's missing) and shown to the driver (read-only on their load card).
const crypto = require('crypto');
const { db } = require('./db');
const { logEvent } = require('./events');
const WF = require('./wordfilter');

// Any of the standard fields can be called what the company calls it
const RENAMABLE = { poNumber: 'PO #', loadNumber: 'Load #', customer: 'Customer', receiver: 'Delivered to', salesRep: 'Sales rep', driver: 'Driver', truck: 'Truck' };
const KINDS = { text: 'Text', number: 'Number', date: 'Date' };

db.exec(`CREATE TABLE IF NOT EXISTS org_labels (orgId TEXT NOT NULL, field TEXT NOT NULL, label TEXT NOT NULL, PRIMARY KEY (orgId, field));
CREATE TABLE IF NOT EXISTS load_field_defs (
  id TEXT PRIMARY KEY, orgId TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'text',
  required INTEGER NOT NULL DEFAULT 0, showDriver INTEGER NOT NULL DEFAULT 0, sort INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1, createdBy TEXT, createdAt INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS load_field_defs_org ON load_field_defs(orgId);
CREATE TABLE IF NOT EXISTS load_field_values (
  loadId TEXT NOT NULL, fieldId TEXT NOT NULL, value TEXT, updatedBy TEXT, updatedAt INTEGER NOT NULL, PRIMARY KEY (loadId, fieldId));`);

class FieldError extends Error { constructor(m, status = 400) { super(m); this.status = status; } }
const clean = (v, n) => String(v == null ? '' : v).trim().replace(/\s+/g, ' ').slice(0, n);

// What this company calls the built-in fields
function labels(orgId) {
  const out = { ...RENAMABLE };
  if (orgId) for (const r of db.prepare('SELECT field, label FROM org_labels WHERE orgId = ?').all(orgId)) if (RENAMABLE[r.field]) out[r.field] = r.label;
  return out;
}
function setLabel(orgId, field, label, by, via) {
  if (!RENAMABLE[field]) throw new FieldError('That field can’t be renamed');
  const l = clean(label, 30);
  guard(orgId, l, `the new name for "${RENAMABLE[field]}"`, by, via);
  const was = labels(orgId)[field];
  if (!l || l === RENAMABLE[field]) db.prepare('DELETE FROM org_labels WHERE orgId = ? AND field = ?').run(orgId, field);
  else db.prepare('INSERT INTO org_labels (orgId, field, label) VALUES (?,?,?) ON CONFLICT(orgId, field) DO UPDATE SET label = excluded.label').run(orgId, field, l);
  if (was !== (l || RENAMABLE[field])) logChange(orgId, `Renamed "${was}" to "${l || RENAMABLE[field]}"`, by, via);
  return settings(orgId);
}

const defs = (orgId, all = false) => db.prepare(`SELECT * FROM load_field_defs WHERE orgId = ? ${all ? '' : 'AND active = 1'} ORDER BY sort, createdAt`).all(orgId)
  .map(d => ({ id: d.id, name: d.name, kind: d.kind, required: !!d.required, showDriver: !!d.showDriver, active: !!d.active }));

function addField(orgId, { name, kind, required, showDriver }, by, via) {
  const n = clean(name, 40);
  guard(orgId, n, 'the field name', by, via);
  if (!n) throw new FieldError('Name the field (for example "Release #" or "Trailer #")');
  const k = KINDS[kind] ? kind : 'text';
  if (Object.values(labels(orgId)).concat(Object.values(RENAMABLE)).some(x => x.toLowerCase() === n.toLowerCase())) throw new FieldError(`"${n}" is already a field`);
  if (db.prepare('SELECT 1 FROM load_field_defs WHERE orgId = ? AND active = 1 AND LOWER(name) = LOWER(?)').get(orgId, n)) throw new FieldError(`"${n}" is already a field`);
  if (db.prepare('SELECT COUNT(*) n FROM load_field_defs WHERE orgId = ? AND active = 1').get(orgId).n >= 15) throw new FieldError('Up to 15 of your own fields');
  const id = 'lf_' + crypto.randomBytes(6).toString('hex');
  const sort = (db.prepare('SELECT MAX(sort) m FROM load_field_defs WHERE orgId = ?').get(orgId).m || 0) + 1;
  db.prepare('INSERT INTO load_field_defs (id, orgId, name, kind, required, showDriver, sort, createdBy, createdAt) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(id, orgId, n, k, required ? 1 : 0, showDriver ? 1 : 0, sort, by, Date.now());
  logChange(orgId, `Added load field "${n}"${required ? ' (required)' : ''}${showDriver ? ', shown to drivers' : ''}`, by, via);
  return { id, ...settings(orgId) };
}
function updateField(orgId, id, b, by, via) {
  const d = db.prepare('SELECT * FROM load_field_defs WHERE id = ? AND orgId = ? AND active = 1').get(id, orgId);
  if (!d) throw new FieldError('That field was not found', 404);
  const name = b.name !== undefined ? clean(b.name, 40) : d.name;
  if (!name) throw new FieldError('Name the field');
  guard(orgId, name, 'the field name', by, via);
  if (name.toLowerCase() !== d.name.toLowerCase() && db.prepare('SELECT 1 FROM load_field_defs WHERE orgId = ? AND active = 1 AND LOWER(name) = LOWER(?)').get(orgId, name)) throw new FieldError(`"${name}" is already a field`);
  const req = b.required !== undefined ? (b.required ? 1 : 0) : d.required, drv = b.showDriver !== undefined ? (b.showDriver ? 1 : 0) : d.showDriver;
  db.prepare('UPDATE load_field_defs SET name = ?, required = ?, showDriver = ? WHERE id = ?').run(name, req, drv, id);
  const what = [name !== d.name && `renamed "${d.name}" to "${name}"`, req !== d.required && (req ? 'now required' : 'now optional'), drv !== d.showDriver && (drv ? 'now shown to drivers' : 'now hidden from drivers')].filter(Boolean);
  if (what.length) logChange(orgId, `Load field "${name}": ${what.join(', ')}`, by, via);
  return settings(orgId);
}
// Removing keeps the values already on loads (shown as a removed field)
function removeField(orgId, id, by, via) {
  const d = db.prepare('SELECT * FROM load_field_defs WHERE id = ? AND orgId = ? AND active = 1').get(id, orgId);
  if (!d) throw new FieldError('That field was not found', 404);
  db.prepare('UPDATE load_field_defs SET active = 0 WHERE id = ?').run(id);
  logChange(orgId, `Removed load field "${d.name}"`, by, via);
  return settings(orgId);
}

// ---------- values on a load ----------
function valuesFor(load) {
  const vals = Object.fromEntries(db.prepare('SELECT fieldId, value FROM load_field_values WHERE loadId = ?').all(load.id).map(v => [v.fieldId, v.value]));
  return defs(load.orgId).map(d => ({ ...d, value: vals[d.id] || '' }));
}
const missingFor = load => valuesFor(load).filter(f => f.required && !f.value).map(f => f.name);
// Save several values at once; values = { fieldId or name: value }
function setValues(load, values, by, via = 'screen') {
  const ds = defs(load.orgId);
  const changed = [];
  for (const [k, raw] of Object.entries(values || {})) {
    const d = ds.find(x => x.id === k) || ds.find(x => x.name.toLowerCase() === String(k).trim().toLowerCase());
    if (!d) throw new FieldError(`"${k}" isn't one of this company's load fields`);
    let v = clean(raw, 120);
    if (WF.findBad(v)) {
      logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'blocked', detail: `Blocked a word that isn't allowed in ${d.name}` + (via === 'connector' ? ' (AI connector)' : ''), actor: by });
      throw new FieldError(`${d.name} has a word that isn't allowed in HaulProof. Please reword it.`);
    }
    if (v && d.kind === 'number' && isNaN(Number(v.replace(/[, $]/g, '')))) throw new FieldError(`${d.name}: enter a number`);
    if (v && d.kind === 'date' && !/^\d{4}-\d{2}-\d{2}$/.test(v)) throw new FieldError(`${d.name}: enter a date`);
    const was = (db.prepare('SELECT value FROM load_field_values WHERE loadId = ? AND fieldId = ?').get(load.id, d.id) || {}).value || '';
    if (was === v) continue;
    if (v) db.prepare('INSERT INTO load_field_values (loadId, fieldId, value, updatedBy, updatedAt) VALUES (?,?,?,?,?) ON CONFLICT(loadId, fieldId) DO UPDATE SET value = excluded.value, updatedBy = excluded.updatedBy, updatedAt = excluded.updatedAt')
      .run(load.id, d.id, v, by, Date.now());
    else db.prepare('DELETE FROM load_field_values WHERE loadId = ? AND fieldId = ?').run(load.id, d.id);
    changed.push(`${d.name}: ${was || '(blank)'} → ${v || '(blank)'}`);
  }
  if (changed.length) logEvent({ orgId: load.orgId, loadId: load.id, poNumber: load.poNumber, type: 'fields', detail: changed.join('; ') + (via === 'connector' ? ' (AI connector)' : ''), actor: by });
  return valuesFor(load);
}

// A field's name for messages and documents another company may read: the owner's name with the standard one after
// it when they differ ("BOL # (PO #)"); short drops the "#" for lines like "BOL 1234 (PO)".
function term(orgId, field, short = false) {
  const std = RENAMABLE[field] || field;
  let own = std; try { own = labels(orgId)[field] || std; } catch (e) {}
  const cut = s => short ? s.replace(/\s*#\s*$/, '') : s;
  return own === std ? cut(std) : `${cut(own)} (${cut(std)})`;
}
// Standard names next to the owner's on screens where two companies meet: { field: "BOL # (PO #)" } for renamed ones only
function shared(orgId) { const l = labels(orgId), out = {}; Object.keys(RENAMABLE).forEach(k => { if (l[k] !== RENAMABLE[k]) out[k] = `${l[k]} (${RENAMABLE[k]})`; }); return out; }

// ---------- settings + who changed them ----------
db.exec(`CREATE TABLE IF NOT EXISTS load_field_changes (id INTEGER PRIMARY KEY, orgId TEXT NOT NULL, detail TEXT NOT NULL, byName TEXT, at INTEGER NOT NULL)`);
try { db.exec('ALTER TABLE load_field_changes ADD COLUMN via TEXT'); } catch (e) {}   // screen | connector
function logChange(orgId, detail, by, via = 'screen') { db.prepare('INSERT INTO load_field_changes (orgId, detail, byName, at, via) VALUES (?,?,?,?,?)').run(orgId, detail, by || null, Date.now(), via || 'screen'); }
// No slurs or curse words: refused, and the attempt is kept in the change history (who, how, where)
function guard(orgId, text, where, by, via) {
  if (!WF.findBad(text)) return;
  logChange(orgId, `Blocked: a word that isn't allowed in ${where}`, by, via);
  throw new FieldError(`${where[0].toUpperCase() + where.slice(1)} has a word that isn't allowed in HaulProof. Please reword it.`);
}
function settings(orgId) {
  return { labels: labels(orgId), defaults: RENAMABLE, fields: defs(orgId), kinds: KINDS,
    changes: db.prepare('SELECT detail, byName, via, at FROM load_field_changes WHERE orgId = ? ORDER BY id DESC LIMIT 30').all(orgId) };
}

module.exports = { RENAMABLE, KINDS, FieldError, labels, term, shared, setLabel, defs, addField, updateField, removeField, valuesFor, missingFor, setValues, settings };
