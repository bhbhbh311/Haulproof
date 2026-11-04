// What a driver has to do on a load, set per company and changeable per customer.
// Each step is Off / Optional / Required:
//   enRoute       "On my way to pickup" tap
//   stopTimes     Check in / check out at pickup and each delivery stop
//   pickupPhoto   photos at pickup
//   deliveryPhoto photos with the signed delivery paperwork
// plus the company's own steps ("Seal #", "Trailer temp", "Straps checked"…), each at pickup or delivery,
// answered with a check box, a short text or a number.
// The four built-in steps are kept in the existing uiFlags booleans (so older screens keep working);
// customer exceptions and the company's own steps are stored here.
const crypto = require('crypto');
const { db } = require('./db');
const { resolveUiFlags, setUiFlags } = require('./uiflags');

const LEVELS = ['off', 'optional', 'required'];
const BUILTIN = {
  enRoute: { name: 'On my way to pickup', when: 'pickup', help: 'Driver taps "On my way" when leaving for the pickup.' },
  stopTimes: { name: 'Check in / check out times', when: 'both', help: 'Driver taps Check in on arriving at the pickup and each delivery; check-out records itself.' },
  pickupPhoto: { name: 'Pickup photos', when: 'pickup', help: 'Photos of the freight at pickup (up to 6).' },
  deliveryPhoto: { name: 'Delivery photos', when: 'delivery', help: 'Photos sent with the signed paperwork (up to 6).' },
};
const KINDS = { check: 'Check box', text: 'Short answer', number: 'Number' };

db.exec(`CREATE TABLE IF NOT EXISTS driver_steps (
  id TEXT PRIMARY KEY, orgId TEXT NOT NULL, name TEXT NOT NULL, whenAt TEXT NOT NULL, kind TEXT NOT NULL, level TEXT NOT NULL,
  sort INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, createdBy TEXT, createdAt INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS driver_steps_org ON driver_steps(orgId);
CREATE TABLE IF NOT EXISTS customer_step_rules (
  customerId TEXT NOT NULL, step TEXT NOT NULL, level TEXT NOT NULL, updatedBy TEXT, updatedAt INTEGER NOT NULL, PRIMARY KEY (customerId, step));
CREATE TABLE IF NOT EXISTS step_answers (
  id INTEGER PRIMARY KEY, loadId TEXT NOT NULL, stepId TEXT NOT NULL, stopNumber INTEGER NOT NULL DEFAULT 0, value TEXT,
  driverId TEXT, gps TEXT, at INTEGER NOT NULL, UNIQUE(loadId, stepId, stopNumber));
CREATE TABLE IF NOT EXISTS step_changes (
  id INTEGER PRIMARY KEY, orgId TEXT NOT NULL, customerId TEXT, step TEXT NOT NULL, stepName TEXT, fromLevel TEXT, toLevel TEXT, byName TEXT, via TEXT, at INTEGER NOT NULL);`);

class StepError extends Error { constructor(m, status = 400) { super(m); this.status = status; } }
const level = (allow, require) => require ? 'required' : allow ? 'optional' : 'off';

// The company's own levels for the built-in steps
function builtinLevels(orgId) {
  const f = resolveUiFlags(orgId);
  return { enRoute: level(f.enRoute, f.requireEnRoute), stopTimes: level(f.stopTimes, f.requireStopTimes),
    pickupPhoto: level(f.allowPickupPhoto, f.requirePickupPhoto), deliveryPhoto: level(f.allowDeliveryPhoto, f.requireDeliveryPhoto) };
}
const customSteps = (orgId, all = false) => db.prepare(`SELECT * FROM driver_steps WHERE orgId = ? ${all ? '' : 'AND active = 1'} ORDER BY sort, createdAt`).all(orgId)
  .map(s => ({ id: s.id, name: s.name, when: s.whenAt, kind: s.kind, level: s.level, active: !!s.active }));
const customerRules = customerId => customerId ? Object.fromEntries(db.prepare('SELECT step, level FROM customer_step_rules WHERE customerId = ?').all(customerId).map(r => [r.step, r.level])) : {};

// Everything a driver has to do for this company (and this customer, when given)
function effective(orgId, customerId = null) {
  const base = builtinLevels(orgId), rules = customerRules(customerId);
  const levels = {}; for (const k of Object.keys(BUILTIN)) levels[k] = rules[k] || base[k];
  const custom = customSteps(orgId).map(s => ({ ...s, level: rules[s.id] || s.level })).filter(s => s.level !== 'off');
  return { levels, custom };
}
// The same, as the uiFlags-style booleans the driver app reads
function flagsFor(orgId, customerId = null) {
  const { levels, custom } = effective(orgId, customerId);
  const on = k => levels[k] !== 'off', req = k => levels[k] === 'required';
  return { ...resolveUiFlags(orgId), enRoute: on('enRoute'), requireEnRoute: req('enRoute'), stopTimes: on('stopTimes'), requireStopTimes: req('stopTimes'),
    allowPickupPhoto: on('pickupPhoto'), requirePickupPhoto: req('pickupPhoto'), allowDeliveryPhoto: on('deliveryPhoto'), requireDeliveryPhoto: req('deliveryPhoto'), customSteps: custom };
}

const checkLevel = l => { if (!LEVELS.includes(l)) throw new StepError('Pick Off, Optional or Required'); return l; };
function stepName(orgId, step) {
  if (BUILTIN[step]) return BUILTIN[step].name;
  const s = db.prepare('SELECT name FROM driver_steps WHERE id = ? AND orgId = ?').get(step, orgId);
  if (!s) throw new StepError('That step was not found');
  return s.name;
}
function logChange(orgId, customerId, step, from, to, by, via) {
  if (from === to) return;
  db.prepare('INSERT INTO step_changes (orgId, customerId, step, stepName, fromLevel, toLevel, byName, via, at) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(orgId, customerId || null, step, stepName(orgId, step), from || null, to || null, by || null, via || 'screen', Date.now());
}
const ownCustomer = (orgId, customerId) => { const c = db.prepare('SELECT id, name FROM customers WHERE id = ? AND ownerOrgId = ?').get(customerId, orgId); if (!c) throw new StepError('Customer not found'); return c; };

// Set a step for the whole company, or (with customerId) an exception for one customer. level null = use the company setting.
function setLevel(orgId, { step, level: l, customerId }, by, via = 'screen') {
  stepName(orgId, step);
  if (customerId) {
    ownCustomer(orgId, customerId);
    const was = customerRules(customerId)[step] || null;
    if (l == null || l === '' || l === 'company') db.prepare('DELETE FROM customer_step_rules WHERE customerId = ? AND step = ?').run(customerId, step);
    else db.prepare('INSERT INTO customer_step_rules (customerId, step, level, updatedBy, updatedAt) VALUES (?,?,?,?,?) ON CONFLICT(customerId, step) DO UPDATE SET level = excluded.level, updatedBy = excluded.updatedBy, updatedAt = excluded.updatedAt')
      .run(customerId, step, checkLevel(l), by, Date.now());
    logChange(orgId, customerId, step, was || 'company setting', (l == null || l === '' || l === 'company') ? 'company setting' : l, by, via);
    return settings(orgId);
  }
  checkLevel(l);
  if (BUILTIN[step]) {
    const was = builtinLevels(orgId)[step];
    const on = l !== 'off', req = l === 'required';
    const patch = { enRoute: { enRoute: on, requireEnRoute: req }, stopTimes: { stopTimes: on, requireStopTimes: req },
      pickupPhoto: { allowPickupPhoto: on, requirePickupPhoto: req }, deliveryPhoto: { allowDeliveryPhoto: on, requireDeliveryPhoto: req } }[step];
    setUiFlags(orgId, patch);
    logChange(orgId, null, step, was, l, by, via);
  } else {
    const was = db.prepare('SELECT level FROM driver_steps WHERE id = ?').get(step).level;
    db.prepare('UPDATE driver_steps SET level = ? WHERE id = ? AND orgId = ?').run(l, step, orgId);
    logChange(orgId, null, step, was, l, by, via);
  }
  return settings(orgId);
}

// The company names its own step and chooses whether to add it, and whether it's required
function addStep(orgId, { name, when, kind, level: l }, by, via = 'screen') {
  const n = String(name || '').trim().replace(/\s+/g, ' ').slice(0, 60);
  if (!n) throw new StepError('Name the step (for example "Seal #" or "Trailer temperature")');
  if (!['pickup', 'delivery'].includes(when)) throw new StepError('Pick when: at pickup or at delivery');
  if (!KINDS[kind]) throw new StepError('Pick how the driver answers: check box, short answer or number');
  checkLevel(l || 'optional');
  if (db.prepare('SELECT 1 FROM driver_steps WHERE orgId = ? AND active = 1 AND LOWER(name) = LOWER(?) AND whenAt = ?').get(orgId, n, when)) throw new StepError(`"${n}" is already a step at ${when}`);
  if (db.prepare('SELECT COUNT(*) n FROM driver_steps WHERE orgId = ? AND active = 1').get(orgId).n >= 20) throw new StepError('Up to 20 of your own steps');
  const id = 'st_' + crypto.randomBytes(6).toString('hex');
  const sort = (db.prepare('SELECT MAX(sort) m FROM driver_steps WHERE orgId = ?').get(orgId).m || 0) + 1;
  db.prepare('INSERT INTO driver_steps (id, orgId, name, whenAt, kind, level, sort, createdBy, createdAt) VALUES (?,?,?,?,?,?,?,?,?)').run(id, orgId, n, when, kind, l || 'optional', sort, by, Date.now());
  logChange(orgId, null, id, null, l || 'optional', by, via);
  return { id, ...settings(orgId) };
}
// Removing keeps the answers already given (they stay on those loads)
function removeStep(orgId, id, by, via = 'screen') {
  const s = db.prepare('SELECT * FROM driver_steps WHERE id = ? AND orgId = ? AND active = 1').get(id, orgId);
  if (!s) throw new StepError('That step was not found');
  logChange(orgId, null, id, s.level, 'removed', by, via);
  db.prepare('UPDATE driver_steps SET active = 0 WHERE id = ?').run(id);
  db.prepare('DELETE FROM customer_step_rules WHERE step = ?').run(id);
  return settings(orgId);
}

// For the Settings screen and the connector
function settings(orgId) {
  const base = builtinLevels(orgId);
  const builtin = Object.entries(BUILTIN).map(([id, b]) => ({ id, ...b, level: base[id], builtin: true }));
  const exceptions = db.prepare(`SELECT r.customerId, c.name customerName, r.step, r.level FROM customer_step_rules r JOIN customers c ON c.id = r.customerId
    WHERE c.ownerOrgId = ? ORDER BY c.name`).all(orgId);
  return { steps: [...builtin, ...customSteps(orgId).map(s => ({ ...s, builtin: false, help: `${KINDS[s.kind]} at ${s.when}` }))], exceptions, kinds: KINDS,
    changes: db.prepare('SELECT s.*, c.name customerName FROM step_changes s LEFT JOIN customers c ON c.id = s.customerId WHERE s.orgId = ? ORDER BY s.id DESC LIMIT 50').all(orgId) };
}

// ---------- the driver's answers to the company's own steps ----------
function answer(load, { stepId, stopNumber, value, gps }, driverId) {
  const s = db.prepare('SELECT * FROM driver_steps WHERE id = ? AND orgId = ?').get(stepId, load.orgId);
  if (!s) throw new StepError('That step was removed by dispatch');
  let v = value == null ? '' : String(value).trim().slice(0, 200);
  if (s.kind === 'check') v = v && v !== 'false' && v !== '0' ? 'Done' : '';
  if (s.kind === 'number' && v && isNaN(Number(v.replace(/[, ]/g, '')))) throw new StepError(`${s.name}: enter a number`);
  const stop = s.whenAt === 'pickup' ? 0 : Math.max(1, Number(stopNumber) || 1);
  if (!v) { db.prepare('DELETE FROM step_answers WHERE loadId = ? AND stepId = ? AND stopNumber = ?').run(load.id, stepId, stop); return null; }
  db.prepare(`INSERT INTO step_answers (loadId, stepId, stopNumber, value, driverId, gps, at) VALUES (?,?,?,?,?,?,?)
    ON CONFLICT(loadId, stepId, stopNumber) DO UPDATE SET value = excluded.value, driverId = excluded.driverId, gps = excluded.gps, at = excluded.at`)
    .run(load.id, stepId, stop, v, driverId || null, gps ? JSON.stringify(gps) : null, Date.now());
  return { stepId, name: s.name, stopNumber: stop, value: v };
}
const answersFor = loadId => db.prepare(`SELECT a.*, s.name, s.whenAt, s.kind FROM step_answers a LEFT JOIN driver_steps s ON s.id = a.stepId WHERE a.loadId = ? ORDER BY a.stopNumber, a.at`).all(loadId);
// Required steps still missing before the driver can finish this part of the load
function missing(load, when, stopNumber = 0) {
  const { custom } = effective(load.orgId, load.customerId || null);
  const done = new Set(answersFor(load.id).filter(a => a.stopNumber === (when === 'pickup' ? 0 : stopNumber)).map(a => a.stepId));
  return custom.filter(s => s.when === when && s.level === 'required' && !done.has(s.id)).map(s => s.name);
}

module.exports = { LEVELS, BUILTIN, KINDS, StepError, effective, flagsFor, settings, setLevel, addStep, removeStep, answer, answersFor, missing };
