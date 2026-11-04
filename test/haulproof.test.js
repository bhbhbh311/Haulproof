// HaulProof end-to-end checks: a real server on a throwaway database, driven the way the portal and driver app do.
// Run: npm test
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-test-'));
process.env.DATA_DIR = DATA_DIR;
const PORT = 3400 + Math.floor(Math.random() * 500);
const B = `http://127.0.0.1:${PORT}`;
const PW = crypto.randomBytes(9).toString('hex');
const { db } = require('../db');
const { createUser } = require('../auth');

const id = () => crypto.randomUUID();
function org(name, kind) { const o = id(); db.prepare('INSERT INTO orgs (id, name, kind, deviceKey, createdAt) VALUES (?,?,?,?,?)').run(o, name, kind, 'dk_' + crypto.randomBytes(12).toString('hex'), Date.now()); return o; }
const shipper = org('Test Shipper Co', 'customer');
const broker = org('Test Broker LLC', 'broker');
const carrier = org('Test Carrier Inc', 'carrier');
createUser({ email: 'ship@test.example', name: 'Ship Admin', role: 'admin', password: PW, orgId: shipper });
createUser({ email: 'brk@test.example', name: 'Broker Admin', role: 'admin', password: PW, orgId: broker });
function pod(orgId, loadId, status = 'received') { const p = id(); db.prepare("INSERT INTO pods (id, orgId, loadId, poNumber, docType, filename, filepath, status, uploadedAt, fields) VALUES (?,?,?,?,?,?,?,?,?,'[]')").run(p, orgId, loadId, 'X', 'BOL', 'x.pdf', '/dev/null', status, Date.now()); return p; }

let server;
test.before(async () => {
  server = spawn(process.execPath, ['server.js'], { cwd: path.join(__dirname, '..'), env: { ...process.env, DATA_DIR, PORT: String(PORT), JWT_SECRET: 'test-only-' + PW }, stdio: 'ignore' });
  for (let i = 0; i < 60; i++) { try { const r = await fetch(B + '/api/app-version'); if (r.ok) return; } catch (e) {} await new Promise(r => setTimeout(r, 250)); }
  throw new Error('server did not start');
});
test.after(() => { if (server) server.kill(); });

async function login(email) {
  const r = await fetch(B + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: PW }) });
  assert.equal(r.status, 200, 'login');
  const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
  return async (method, url, body) => {
    const x = await fetch(B + url, { method, headers: { cookie, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    return { status: x.status, body: await x.json().catch(() => ({})) };
  };
}
const asDriver = token => async (method, url, body) => {
  const x = await fetch(B + url, { method, headers: { 'X-Api-Key': token, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  return { status: x.status, body: await x.json().catch(() => ({})) };
};

test('every page script parses', () => {
  for (const f of ['index.html', 'haulproof_driver.html', 'prepare.html']) {
    const s = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    for (const m of s.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g)) assert.doesNotThrow(() => new Function(m[1]), f);
  }
});

test('special instructions: the owner saves them on the load', async () => {
  const api = await login('ship@test.example');
  const l = (await api('POST', '/api/loads', { poNumber: 'INS-1', instructions: 'Forklift side unload' })).body.load;
  assert.equal(l.instructions, 'Forklift side unload');
  const u = (await api('PUT', '/api/loads/' + l.id, { instructions: '  NO UNLOAD APPT NEEDED  ' })).body.load;
  assert.equal(u.instructions, 'NO UNLOAD APPT NEEDED');
});

test('a load given to a driver shows on their phone before any paperwork, with its instructions; it drops off once signed', async () => {
  const api = await login('ship@test.example');
  const d = (await api('POST', '/api/drivers', { name: 'Fleet Driver' })).body.driver;
  const tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token;
  const l = (await api('POST', '/api/loads', { poNumber: 'OWN-1', instructions: 'Tarps required' })).body.load;
  assert.equal((await api('POST', `/api/loads/${l.id}/assign-driver`, { driverId: d.id })).status, 200);
  const drv = asDriver(tok);
  let mine = (await drv('GET', '/api/drivers/my-loads')).body.loads.filter(x => x.loadId === l.id);
  assert.equal(mine.length, 1); assert.equal(mine[0].noDoc, true); assert.equal(mine[0].instructions, 'Tarps required');
  // the driver's buttons work on it
  assert.equal((await drv('POST', `/api/drivers/my-loads/${l.id}/en-route`, {})).status, 200);
  pod(shipper, l.id, 'signed');
  mine = (await drv('GET', '/api/drivers/my-loads')).body.loads.filter(x => x.loadId === l.id);
  assert.equal(mine.length, 0, 'a signed load drops off the list');
});

test('signature layouts: a load with no customer saves and reuses the company layout', async () => {
  const api = await login('ship@test.example');
  const a = (await api('POST', '/api/loads', { poNumber: 'LAY-1' })).body.load, b = (await api('POST', '/api/loads', { poNumber: 'LAY-2' })).body.load;
  const p1 = pod(shipper, a.id), p2 = pod(shipper, b.id);
  const before = (await api('GET', `/api/pods/${p1}/template`)).body;
  assert.deepEqual([before.exists, before.companyWide, before.customerName], [false, true, 'Test Shipper Co (all loads)']);
  const fields = [{ role: 'Consignee', type: 'sigdate', page: 1, x: 0.4, y: 0.8, w: 0.2, h: 0.04 }];
  assert.equal((await api('POST', `/api/pods/${p1}/save-template`, { fields })).status, 200);
  const next = (await api('GET', `/api/pods/${p2}/template`)).body;
  assert.equal(next.exists, true); assert.deepEqual(next.fields, fields);
});

test('a company that owns a load and gave it to a carrier can add that carrier\'s driver and assign them', async () => {
  const api = await login('brk@test.example');
  const l = (await api('POST', '/api/loads', { poNumber: 'BRK-1' })).body.load;
  // no load with that carrier yet: not allowed
  assert.equal((await api('POST', `/api/drivers/for-carrier/${carrier}`, { name: 'Early Driver' })).status, 403);
  db.prepare('UPDATE loads SET carrierId = ?, carrierName = ? WHERE id = ?').run(carrier, 'Test Carrier Inc', l.id);
  const add = await api('POST', `/api/drivers/for-carrier/${carrier}`, { name: 'Carrier Driver', phone: '555-0100' });
  assert.equal(add.status, 201); assert.match(add.body.driver.link, /\/driver\?k=/);
  assert.equal((await api('POST', `/api/loads/${l.id}/assign-driver`, { driverId: add.body.driver.id })).status, 200);
  const tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(add.body.driver.id).token;
  const mine = (await asDriver(tok)('GET', '/api/drivers/my-loads')).body.loads;
  assert.ok(mine.some(x => x.loadId === l.id && x.noDoc), 'the carrier\'s driver sees the load');
});
