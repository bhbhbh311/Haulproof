// Plans & billing (master admin): each company's subscription — free trial, paid, or free — and what it would be billed
// this month. HaulProof tracks it here; payment itself is collected outside the app (invoice / card processor).
const express = require('express');
const { requireAuth, requireSuper } = require('./auth');
const { db } = require('./db');

const DEFAULTS = { trialDays: 90, priceUsd: 20, includedDrivers: 5, extraDriverUsd: 0 };
const PLANS = ['trial', 'paid', 'free', 'paused'];
const DAY = 864e5;

function monthStart(d) { d = d || new Date(); return new Date(d.getFullYear(), d.getMonth(), 1).getTime(); }
// Show Me Trucking is HaulProof's own test account: never billed (same rule as its AI plan).
try { db.prepare(`UPDATE orgs SET billingPlan = 'free' WHERE billingPlan IS NULL AND UPPER(name) LIKE 'SHOW ME TRUCKING%'`).run(); } catch (e) {}

function billingOf(o, now) {
  now = now || Date.now();
  const plan = o.billingPlan || 'trial';
  const trialEndsAt = o.trialEndsAt || ((o.createdAt || now) + DEFAULTS.trialDays * DAY);
  const price = o.priceUsd != null ? Number(o.priceUsd) : DEFAULTS.priceUsd;
  const included = o.includedDrivers != null ? Number(o.includedDrivers) : DEFAULTS.includedDrivers;
  const extra = o.extraDriverUsd != null ? Number(o.extraDriverUsd) : DEFAULTS.extraDriverUsd;
  const drivers = Number(o.drivers) || 0, over = Math.max(0, drivers - included);
  const aiCharge = (o.aiPlan === 'paid' || (!o.aiPlan && o.aiEnabled)) ? (Number(o.aiDocs) || 0) * (Number(o.aiPricePerDocUsd) || 0) : 0;
  const base = plan === 'paid' ? price + over * extra : 0;
  const daysLeft = plan === 'trial' ? Math.ceil((trialEndsAt - now) / DAY) : null;
  return { plan, trialEndsAt: plan === 'trial' ? trialEndsAt : (o.trialEndsAt || null), trialDaysLeft: daysLeft, priceUsd: price, includedDrivers: included, extraDriverUsd: extra,
    drivers, overDrivers: over, aiChargeUsd: plan === 'free' ? 0 : aiCharge, monthUsd: base + (plan === 'free' ? 0 : aiCharge), note: o.billingNote || '' };
}
function listBilling() {
  const from = monthStart();
  return db.prepare(`SELECT o.id, o.name, o.kind, o.createdAt, o.billingPlan, o.trialEndsAt, o.priceUsd, o.includedDrivers, o.extraDriverUsd, o.billingNote,
      o.aiPlan, o.aiEnabled, o.aiPricePerDocUsd,
      (SELECT COUNT(*) FROM drivers d WHERE d.orgId = o.id AND d.active = 1) AS drivers,
      (SELECT COUNT(DISTINCT podId) FROM ai_usage u WHERE u.orgId = o.id AND u.createdAt >= ?) AS aiDocs,
      (SELECT MAX(createdAt) FROM loads l WHERE l.orgId = o.id OR l.brokerId = o.id) AS lastLoadAt
    FROM orgs o WHERE o.active = 1 AND o.kind IN ('customer','carrier','broker') ORDER BY o.name COLLATE NOCASE`).all(from)
    .map(o => Object.assign({ orgId: o.id, name: o.name, kind: o.kind, createdAt: o.createdAt, lastLoadAt: o.lastLoadAt || null }, billingOf(o)));
}
function summary(rows) {
  rows = rows || listBilling();
  const paid = rows.filter(r => r.plan === 'paid'), trial = rows.filter(r => r.plan === 'trial');
  return { monthlyUsd: paid.reduce((a, r) => a + r.monthUsd, 0), paying: paid.length, onTrial: trial.length,
    endingSoon: trial.filter(r => r.trialDaysLeft >= 0 && r.trialDaysLeft <= 14).map(r => ({ orgId: r.orgId, name: r.name, daysLeft: r.trialDaysLeft })),
    ended: trial.filter(r => r.trialDaysLeft < 0).map(r => ({ orgId: r.orgId, name: r.name, daysLeft: r.trialDaysLeft })) };
}

const router = express.Router();
router.get('/', requireAuth, requireSuper, (_req, res) => {
  const rows = listBilling();
  res.json({ defaults: DEFAULTS, orgs: rows, summary: summary(rows) });
});
router.put('/org/:id', requireAuth, requireSuper, express.json(), (req, res) => {
  const o = db.prepare(`SELECT id FROM orgs WHERE id = ?`).get(req.params.id);
  if (!o) return res.status(404).json({ error: 'Company not found' });
  const b = req.body || {}, set = (col, v) => db.prepare(`UPDATE orgs SET ${col} = ? WHERE id = ?`).run(v, o.id);
  const money = v => (v === '' || v == null) ? null : (Number.isFinite(Number(v)) && Number(v) >= 0 ? Math.round(Number(v) * 100) / 100 : undefined);
  if (b.plan !== undefined) { if (PLANS.indexOf(b.plan) < 0) return res.status(400).json({ error: 'Unknown plan' }); set('billingPlan', b.plan); }
  if (b.trialEndsAt !== undefined) {
    if (b.trialEndsAt === '' || b.trialEndsAt == null) set('trialEndsAt', null);
    else { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(b.trialEndsAt)); if (!m) return res.status(400).json({ error: 'Pick a date' });
      set('trialEndsAt', new Date(+m[1], +m[2] - 1, +m[3], 23, 59).getTime()); }
  }
  if (b.priceUsd !== undefined) { const v = money(b.priceUsd); if (v === undefined) return res.status(400).json({ error: 'Price must be a dollar amount' }); set('priceUsd', v); }
  if (b.extraDriverUsd !== undefined) { const v = money(b.extraDriverUsd); if (v === undefined) return res.status(400).json({ error: 'Extra-driver price must be a dollar amount' }); set('extraDriverUsd', v); }
  if (b.includedDrivers !== undefined) {
    const v = (b.includedDrivers === '' || b.includedDrivers == null) ? null : Number(b.includedDrivers);
    if (v !== null && !(Number.isInteger(v) && v >= 0)) return res.status(400).json({ error: 'Included drivers must be a whole number' });
    set('includedDrivers', v);
  }
  if (b.note !== undefined) set('billingNote', String(b.note || '').slice(0, 300) || null);
  res.json({ ok: true });
});

module.exports = { router, summary, listBilling, DEFAULTS };
