// Plans & billing (master admin): each company's subscription — free trial, paid, or free — and what it would be billed
// this month. HaulProof tracks it here; payment itself is collected outside the app (invoice / card processor).
const express = require('express');
const crypto = require('crypto');
const { requireAuth, requireSuper } = require('./auth');
const { db } = require('./db');

const DEFAULTS = { trialDays: 60, priceUsd: 20, includedDrivers: 5, extraDriverUsd: 0 };
const PLANS = ['trial', 'paid', 'free', 'paused'];
const DAY = 864e5;

function monthStart(d) { d = d || new Date(); return new Date(d.getFullYear(), d.getMonth(), 1).getTime(); }
function monthKey(d) { d = d || new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0'); }
const REFERRAL_WAIT_DAYS = 30;   // the invited company has paid its first month

// ---- Referrals ----
// Each company's permanent invite code (made the first time it's needed).
function referralCodeFor(orgId) {
  const o = db.prepare(`SELECT referralCode FROM orgs WHERE id = ?`).get(orgId);
  if (!o) return null;
  if (o.referralCode) return o.referralCode;
  const ABC = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  for (let i = 0; i < 20; i++) {
    let c = ''; for (let k = 0; k < 7; k++) c += ABC[crypto.randomInt(ABC.length)];
    try { db.prepare(`UPDATE orgs SET referralCode = ? WHERE id = ? AND referralCode IS NULL`).run(c, orgId); break; } catch (e) { /* taken — try another */ }
  }
  return db.prepare(`SELECT referralCode FROM orgs WHERE id = ?`).get(orgId).referralCode;
}
// Invited companies that have been Paid for a month earn their inviter one free month (once per invited company).
function processReferrals(now) {
  now = now || Date.now();
  const due = db.prepare(`SELECT o.id, o.name, o.referredBy, i.name AS inviterName FROM orgs o JOIN orgs i ON i.id = o.referredBy
    WHERE o.referralRewardedAt IS NULL AND o.billingPlan = 'paid' AND o.paidSince IS NOT NULL AND o.paidSince <= ? AND i.active = 1`).all(now - REFERRAL_WAIT_DAYS * DAY);
  due.forEach(o => {
    db.prepare(`INSERT INTO referral_credits (id, orgId, fromOrgId, earnedAt) VALUES (?,?,?,?)`).run(crypto.randomUUID(), o.referredBy, o.id, now);
    db.prepare(`UPDATE orgs SET referralRewardedAt = ? WHERE id = ?`).run(now, o.id);
    tellInviter(o.referredBy, o.name).catch(() => {});
  });
  return due.length;
}
async function tellInviter(orgId, invitedName) {
  const admins = db.prepare(`SELECT email FROM users WHERE orgId = ? AND role = 'admin'`).all(orgId).map(u => u.email).filter(e => e && !/^haulproofhelp\+/i.test(e));
  if (!admins.length) return;
  const { sendMail } = require('./mailer');
  await sendMail({ to: admins, subject: 'You earned a free month of HaulProof',
    text: 'Thanks for inviting ' + invitedName + ' to HaulProof. They have now been with us a full paid month, so you have earned a free month.\n\n'
      + 'It comes off your next monthly bill automatically. Keep sharing your invite link (Settings → Invite a company): every company that joins through it earns you another free month.\n\n— HaulProof' });
}
// Use one earned free month on this month's bill, for companies on Paid (credits wait while a company is on its trial).
function applyCredits(now) {
  const key = monthKey(now ? new Date(now) : new Date());
  db.prepare(`SELECT o.id FROM orgs o WHERE o.billingPlan = 'paid'
      AND NOT EXISTS (SELECT 1 FROM referral_credits c WHERE c.orgId = o.id AND c.usedMonth = ?)
      AND EXISTS (SELECT 1 FROM referral_credits c WHERE c.orgId = o.id AND c.usedMonth IS NULL)`).all(key)
    .forEach(o => {
      const c = db.prepare(`SELECT id FROM referral_credits WHERE orgId = ? AND usedMonth IS NULL ORDER BY earnedAt LIMIT 1`).get(o.id);
      if (c) db.prepare(`UPDATE referral_credits SET usedMonth = ? WHERE id = ?`).run(key, c.id);
    });
}
function referralStats(orgId) {
  const key = monthKey();
  const credits = db.prepare(`SELECT usedMonth FROM referral_credits WHERE orgId = ?`).all(orgId);
  const invited = db.prepare(`SELECT name, billingPlan, createdAt, paidSince, referralRewardedAt FROM orgs WHERE referredBy = ? ORDER BY createdAt DESC`).all(orgId)
    .map(o => ({ name: o.name, status: o.referralRewardedAt ? 'earned' : (o.billingPlan === 'paid' ? 'paying' : 'trial'),
      earnsOn: !o.referralRewardedAt && o.billingPlan === 'paid' && o.paidSince ? o.paidSince + REFERRAL_WAIT_DAYS * DAY : null, joinedAt: o.createdAt }));
  return { earned: credits.length, used: credits.filter(c => c.usedMonth).length, left: credits.filter(c => !c.usedMonth).length,
    freeThisMonth: credits.some(c => c.usedMonth === key), invited };
}
function tick() { try { processReferrals(); applyCredits(); } catch (e) { console.error('referrals', e.message); } }
function startReferralTimer() { setTimeout(tick, 60000).unref(); setInterval(tick, 6 * 3600000).unref(); }
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
  const credited = plan === 'paid' && !!o.creditThisMonth;
  const base = plan === 'paid' && !credited ? price + over * extra : 0;
  const daysLeft = plan === 'trial' ? Math.ceil((trialEndsAt - now) / DAY) : null;
  return { plan, trialEndsAt: plan === 'trial' ? trialEndsAt : (o.trialEndsAt || null), trialDaysLeft: daysLeft, priceUsd: price, includedDrivers: included, extraDriverUsd: extra,
    drivers, overDrivers: over, referralCredit: credited, freeMonthsLeft: Number(o.creditsLeft) || 0, invitedBy: o.inviterName || null, invitedCount: Number(o.invitedCount) || 0, aiChargeUsd: plan === 'free' ? 0 : aiCharge, monthUsd: base + (plan === 'free' ? 0 : aiCharge), note: o.billingNote || '' };
}
function listBilling() {
  const from = monthStart(), key = monthKey();
  processReferrals(); applyCredits();
  return db.prepare(`SELECT o.id, o.name, o.kind, o.createdAt, o.billingPlan, o.trialEndsAt, o.priceUsd, o.includedDrivers, o.extraDriverUsd, o.billingNote,
      o.aiPlan, o.aiEnabled, o.aiPricePerDocUsd,
      (SELECT COUNT(*) FROM drivers d WHERE d.orgId = o.id AND d.active = 1) AS drivers,
      (SELECT COUNT(DISTINCT podId) FROM ai_usage u WHERE u.orgId = o.id AND u.createdAt >= ?) AS aiDocs,
      (SELECT MAX(createdAt) FROM loads l WHERE l.orgId = o.id OR l.brokerId = o.id) AS lastLoadAt,
      (SELECT COUNT(*) FROM referral_credits c WHERE c.orgId = o.id AND c.usedMonth = ?) AS creditThisMonth,
      (SELECT COUNT(*) FROM referral_credits c WHERE c.orgId = o.id AND c.usedMonth IS NULL) AS creditsLeft,
      (SELECT COUNT(*) FROM orgs x WHERE x.referredBy = o.id) AS invitedCount,
      (SELECT name FROM orgs x WHERE x.id = o.referredBy) AS inviterName
    FROM orgs o WHERE o.active = 1 AND o.kind IN ('customer','carrier','broker') ORDER BY o.name COLLATE NOCASE`).all(from, key)
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
  if (b.plan !== undefined) {
    if (PLANS.indexOf(b.plan) < 0) return res.status(400).json({ error: 'Unknown plan' });
    set('billingPlan', b.plan);
    if (b.plan === 'paid') db.prepare(`UPDATE orgs SET paidSince = COALESCE(paidSince, ?) WHERE id = ?`).run(Date.now(), o.id);
  }
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

// Company side: their invite link and what it has earned. Any login in the company can see and share it.
router.get('/mine', requireAuth, (req, res) => {
  const orgId = req.user.orgId;
  if (!orgId) return res.json({ applies: false });
  const o = db.prepare(`SELECT kind, active FROM orgs WHERE id = ?`).get(orgId) || {};
  if (['customer', 'carrier', 'broker'].indexOf(o.kind) < 0) return res.json({ applies: false });
  const proto = req.headers['x-forwarded-proto'] || req.protocol, origin = process.env.PORTAL_URL || (proto + '://' + req.get('host'));
  try { processReferrals(); applyCredits(); } catch (e) {}
  res.json(Object.assign({ applies: true, link: origin.replace(/\/$/, '') + '/request?ref=' + referralCodeFor(orgId), waitDays: REFERRAL_WAIT_DAYS }, referralStats(orgId)));
});
// Public: who sent this invite link (shown on the request page).
const publicRouter = express.Router();
publicRouter.get('/:code', (req, res) => {
  const o = db.prepare(`SELECT name FROM orgs WHERE referralCode = ? AND active = 1`).get(String(req.params.code || '').trim().toUpperCase());
  if (!o) return res.status(404).json({ error: 'Unknown invite link' });
  res.json({ name: o.name });
});

module.exports = { router, publicRouter, summary, listBilling, DEFAULTS, processReferrals, applyCredits, startReferralTimer, referralStats };
