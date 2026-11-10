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
  for (let i = 0; i < 160; i++) { try { const r = await fetch(B + '/api/app-version'); if (r.ok) return; } catch (e) {} await new Promise(r => setTimeout(r, 250)); }
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

// ---- AI connector: a token for a login, then tools/call the way Claude does ----
function mcpToken(email) {
  const u = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  const tok = 'test_' + crypto.randomBytes(12).toString('hex');
  db.prepare("INSERT INTO oauth_tokens (tokenHash, kind, clientId, userId, expiresAt, createdAt) VALUES (?, 'access', ?, ?, ?, ?)")
    .run(crypto.createHash('sha256').update(tok).digest('hex'), 'test-client-' + email, u.id, Date.now() + 3600e3, Date.now());
  return async (name, args) => {
    const r = await fetch(B + '/mcp', { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
    const j = await r.json(); const res = j.result || {};
    const text = (res.content || [{}])[0].text || (j.error && j.error.message) || '';
    let out = text; try { out = JSON.parse(text); } catch (e) {}
    return { err: !!(res.isError || j.error), out };
  };
}

test('connector: a company deletes its own load — preview first, then only with confirm, and it can be restored', async () => {
  const api = await login('ship@test.example');
  const l = (await api('POST', '/api/loads', { poNumber: 'DEL-1' })).body.load;
  pod(shipper, l.id, 'signed');
  const call = mcpToken('ship@test.example');
  const preview = await call('delete_load', { load: 'DEL-1' });
  assert.equal(preview.err, false, JSON.stringify(preview.out));
  assert.deepEqual([preview.out.would_delete, preview.out.documents, preview.out.signed_documents], [true, 1, 1]);
  assert.ok(db.prepare('SELECT 1 FROM loads WHERE id = ?').get(l.id), 'nothing deleted without confirm');
  const done = await call('delete_load', { load: 'DEL-1', confirm: true });
  assert.equal(done.out.deleted, true);
  assert.equal(db.prepare('SELECT 1 FROM loads WHERE id = ?').get(l.id), undefined);
  const bin = db.prepare('SELECT docCount FROM deleted_loads WHERE id = ?').get(l.id);
  assert.ok(bin, 'the load is in the recovery bin'); assert.equal(bin.docCount, 1);
  // another company's load can't be deleted through the connector
  const other = (await (await login('brk@test.example'))('POST', '/api/loads', { poNumber: 'NOT-MINE' })).body.load;
  const no = await call('delete_load', { load: other.id, confirm: true });
  assert.equal(no.err, true);
  assert.ok(db.prepare('SELECT 1 FROM loads WHERE id = ?').get(other.id));
});

test('connector: the master admin turns a company off and back on; others never see the tool', async () => {
  createUser({ email: 'master@test.example', name: 'Master', role: 'superadmin', password: PW, orgId: null });
  const master = mcpToken('master@test.example');
  const off = await master('set_company_active', { company: 'Test Carrier Inc', active: false });
  assert.equal(off.err, false, JSON.stringify(off.out));
  assert.deepEqual([off.out.changed, off.out.active], [true, false]);
  assert.equal(db.prepare('SELECT active FROM orgs WHERE id = ?').get(carrier).active, 0);
  const again = await master('set_company_active', { company: 'Test Carrier Inc', active: false });
  assert.equal(again.out.changed, false, 'already off: nothing to do');
  const on = await master('set_company_active', { company: 'Test Carrier Inc', active: true });
  assert.equal(on.out.active, true); assert.equal(db.prepare('SELECT active FROM orgs WHERE id = ?').get(carrier).active, 1);
  const notMaster = await mcpToken('ship@test.example')('set_company_active', { company: 'Test Carrier Inc', active: false });
  assert.equal(notMaster.err, true, 'a company login can not use it');
  assert.equal(db.prepare('SELECT active FROM orgs WHERE id = ?').get(carrier).active, 1);
});

// ---- driver buttons: the path a driver takes on a load, and what they can't touch ----
test('driver buttons: on my way, pickup with a photo, delivery photos, undo; another company\'s driver is turned away', async () => {
  const api = await login('ship@test.example');
  const d = (await api('POST', '/api/drivers', { name: 'Button Driver' })).body.driver;
  const drv = asDriver(db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token);
  const l = (await api('POST', '/api/loads', { poNumber: 'BTN-1' })).body.load;
  assert.equal((await api('POST', `/api/loads/${l.id}/assign-driver`, { driverId: d.id })).status, 200);
  const gps = { lat: 36.15, lng: -95.99, acc: 12 };
  const jpg = 'data:image/jpeg;base64,' + Buffer.from('not really a jpeg').toString('base64');
  assert.equal((await drv('POST', `/api/drivers/my-loads/${l.id}/en-route`, { gps })).status, 200);
  assert.ok(db.prepare('SELECT enRouteAt FROM loads WHERE id = ?').get(l.id).enRouteAt);
  const pu = await drv('POST', `/api/drivers/my-loads/${l.id}/pickup`, { gps, photos: [jpg] });
  assert.equal(pu.status, 200); assert.equal(pu.body.photoCount, 1);
  assert.equal((await drv('POST', `/api/drivers/my-loads/${l.id}/en-route`, {})).status, 400, 'already picked up');
  const dp = await drv('POST', `/api/drivers/my-loads/${l.id}/delivery-photos`, { stopNumber: 1, photos: [jpg, jpg] });
  assert.deepEqual([dp.status, dp.body.added], [200, 2]);
  assert.equal((await drv('POST', `/api/drivers/my-loads/${l.id}/delivery-photos`, { photos: [] })).status, 400);
  // an accidental pickup tap can be undone, and the record says so
  assert.equal((await drv('POST', `/api/drivers/my-loads/${l.id}/pickup/undo`, {})).status, 200);
  assert.equal(db.prepare('SELECT pickedUpAt FROM loads WHERE id = ?').get(l.id).pickedUpAt, null);
  const types = db.prepare('SELECT type FROM load_events WHERE loadId = ?').all(l.id).map(e => e.type);
  for (const t of ['en_route', 'picked_up', 'delivery_photos', 'pickup_cleared']) assert.ok(types.includes(t), 'logged: ' + t);
  // a driver from another company can't press buttons on this load
  const other = await login('brk@test.example');
  const od = (await other('POST', '/api/drivers', { name: 'Stranger Driver' })).body.driver;
  const stranger = asDriver(db.prepare('SELECT token FROM drivers WHERE id = ?').get(od.id).token);
  assert.equal((await stranger('POST', `/api/drivers/my-loads/${l.id}/en-route`, {})).status, 403);
  assert.equal((await stranger('POST', `/api/drivers/my-loads/${l.id}/pickup`, {})).status, 403);
  assert.ok(!(await stranger('GET', '/api/drivers/my-loads')).body.loads.some(x => x.loadId === l.id), 'not on their list');
  // a bad link gets nothing
  assert.deepEqual((await asDriver('nope')('GET', '/api/drivers/my-loads')).body.loads, [], 'an empty list, nothing leaked');
  assert.equal((await asDriver('nope')('POST', `/api/drivers/my-loads/${l.id}/en-route`, {})).status, 401);
});

test('driver upload: a PO # already in use is flagged before upload, with the next free number', async () => {
  const api = await login('ship@test.example');
  await api('POST', '/api/loads', { poNumber: 'DUP-7' });
  const d = (await api('POST', '/api/drivers', { name: 'PO Driver' })).body.driver;
  const drv = asDriver(db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token);
  assert.deepEqual((await drv('GET', '/api/drivers/po-check?po=DUP-7')).body, { exists: true, suggestion: 'DUP-7.1' });
  assert.deepEqual((await drv('GET', '/api/drivers/po-check?po=' + encodeURIComponent(' dup-7 '))).body.exists, true, 'spaces and case do not matter');
  assert.deepEqual((await drv('GET', '/api/drivers/po-check?po=FRESH-1')).body, { exists: false, suggestion: 'FRESH-1' });
});

test('driver signs: the signed PDF lands on the load by PO #, a retry is not filed twice, and the load drops off the list', async () => {
  const { PDFDocument } = require('pdf-lib');
  const doc = await PDFDocument.create(); doc.addPage([612, 792]); const pdf = Buffer.from(await doc.save());
  const api = await login('ship@test.example');
  const d = (await api('POST', '/api/drivers', { name: 'Signing Driver' })).body.driver;
  const tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token;
  const l = (await api('POST', '/api/loads', { poNumber: 'SIGN-1' })).body.load;
  await api('POST', `/api/loads/${l.id}/assign-driver`, { driverId: d.id });
  const send = () => fetch(B + '/api/pods/ingest', { method: 'POST', body: pdf, headers: { 'X-Api-Key': tok, 'Content-Type': 'application/pdf',
    'X-POD-PO': 'SIGN-1', 'X-POD-Type': 'BOL', 'X-POD-Name': 'Signed BOL', 'X-POD-ClientId': 'phone-doc-1', 'X-POD-SignedAt': String(Date.now()) } });
  const r1 = await send(); assert.ok(r1.status < 300, 'upload ok: ' + r1.status + ' ' + await r1.text());
  const r2 = await send(); assert.ok(r2.status < 300, 'retry ok');
  const pods = db.prepare('SELECT status, driver FROM pods WHERE loadId = ?').all(l.id);
  assert.equal(pods.length, 1, 'filed once, on the load');
  assert.ok(['signed', 'emailed'].includes(pods[0].status)); assert.equal(pods[0].driver, 'Signing Driver');
  assert.ok(!(await asDriver(tok)('GET', '/api/drivers/my-loads')).body.loads.some(x => x.loadId === l.id), 'done: off the driver\'s list');
  // no PO #, no upload
  const bad = await fetch(B + '/api/pods/ingest', { method: 'POST', body: pdf, headers: { 'X-Api-Key': tok, 'Content-Type': 'application/pdf' } });
  assert.equal(bad.status, 422);
});

test('connector: the master admin can list receivers already merged into another, with where they went', async () => {
  const keep = org('Merge Test Steel', 'receiver'), old = org('MERGE TEST STEEL', 'receiver');
  db.prepare('UPDATE orgs SET active = 0, mergedInto = ?, city = ? WHERE id = ?').run(keep, 'Denver', old);
  const master = mcpToken('master@test.example');
  const plain = await master('list_receivers', { search: 'merge test' });
  assert.equal(plain.err, false, JSON.stringify(plain.out));
  assert.deepEqual(plain.out.receivers.map(r => r.id), [keep], 'merged ones hidden by default');
  const all = (await master('list_receivers', { search: 'merge test', include_merged: true })).out.receivers;
  const m = all.find(r => r.id === old);
  assert.ok(m, 'merged one listed'); assert.equal(m.merged_into, 'Merge Test Steel'); assert.equal(m.active, false); assert.match(m.address, /Denver/);
});

// ---- first-time setup: nobody types a PIN or password for someone else ----
test('new driver: no PIN from dispatch; they make their own on first open; Reset PIN lets them pick a new one', async () => {
  const api = await login('ship@test.example');
  const d = (await api('POST', '/api/drivers', { name: 'Fresh Driver' })).body.driver;
  assert.equal(d.hasPin, false);
  const drv = asDriver(db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token);
  assert.equal((await drv('GET', '/api/drivers/link-info')).body.needsPinCreate, true, 'the app asks them to create a PIN');
  const made = await drv('POST', '/api/drivers/change-pin', { newPin: '4821' });
  assert.equal(made.status, 200); assert.ok(made.body.unlock);
  assert.equal((await drv('GET', '/api/drivers/link-info')).body.requiresPin, true);
  assert.equal((await drv('GET', '/api/drivers/notices')).status, 401, 'locked without the PIN now');
  // dispatch resets it: no PIN to type, the driver picks a new one next time
  const rs = await api('PUT', '/api/drivers/' + d.id, { resetPin: true });
  assert.equal(rs.status, 200); assert.equal(rs.body.driver.hasPin, false);
  assert.equal((await drv('GET', '/api/drivers/link-info')).body.needsPinCreate, true);
  assert.equal((await drv('POST', '/api/drivers/change-pin', { newPin: '7713' })).status, 200);
  // an edit without resetPin leaves the PIN alone
  await api('PUT', '/api/drivers/' + d.id, { name: 'Fresh Driver', phone: '555-0199' });
  assert.equal((await drv('GET', '/api/drivers/link-info')).body.requiresPin, true);
});

const linkToken = link => new URL(link).searchParams.get('t');
async function setPassword(t, password) {
  const r = await fetch(B + '/api/auth/set-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ t, password }) });
  return { status: r.status, body: await r.json().catch(() => ({})), cookie: (r.headers.get('set-cookie') || '').split(';')[0] };
}
const canSignIn = async (email, password) => (await fetch(B + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) })).status === 200;

test('new login: no temp password; the link opens "choose your password", signs them in, and works once', async () => {
  const api = await login('ship@test.example');
  const made = await api('POST', '/api/users', { email: 'newbie@test.example', name: 'New Person', role: 'dispatcher' });
  assert.equal(made.status, 201);
  const t = linkToken(made.body.link);
  const info = await (await fetch(B + '/api/auth/login-info?t=' + t)).json();
  assert.equal(info.email, 'newbie@test.example'); assert.equal(info.tempPassword, undefined, 'no temporary password shown');
  assert.equal((await setPassword(t, 'abc')).status, 400, 'too short');
  const set = await setPassword(t, 'my-own-pass-1');
  assert.equal(set.status, 200); assert.equal(set.body.signedIn, true); assert.match(set.cookie, /^hp_session=/);
  const me = await fetch(B + '/api/me', { headers: { cookie: set.cookie } });
  assert.equal(me.status, 200); assert.equal((await me.json()).user.mustChangePassword, false, 'no second "change your password" step');
  assert.ok(await canSignIn('newbie@test.example', 'my-own-pass-1'));
  assert.equal((await setPassword(t, 'someone-else-1')).status, 404, 'the link is used up');
});

test('forgot password and Send password link: the old password works until they choose a new one', async () => {
  const api = await login('ship@test.example');
  const u = (await api('POST', '/api/users', { email: 'forgets@test.example', name: 'Forgetful', role: 'sales' })).body;
  await setPassword(linkToken(u.link), 'first-pass-1');
  // a stranger asks to reset it: nothing changes until the link is used
  await fetch(B + '/api/auth/forgot-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'forgets@test.example' }) });
  const uid = db.prepare('SELECT id FROM users WHERE email = ?').get('forgets@test.example').id;
  const t = db.prepare('SELECT token FROM login_links WHERE userId = ? AND pendingReset = 1').get(uid).token;
  const info = await (await fetch(B + '/api/auth/login-info?t=' + t)).json();
  assert.equal(info.reset, true);
  assert.ok(await canSignIn('forgets@test.example', 'first-pass-1'), 'opening the link changes nothing');
  assert.equal((await setPassword(t, 'second-pass-2')).status, 200);
  assert.ok(!(await canSignIn('forgets@test.example', 'first-pass-1'))); assert.ok(await canSignIn('forgets@test.example', 'second-pass-2'));
  // the admin's "Send password link" doesn't lock them out either
  const sent = await api('POST', `/api/users/${uid}/login-link`, {});
  assert.equal(sent.status, 200);
  assert.ok(await canSignIn('forgets@test.example', 'second-pass-2'), 'current password still works');
  assert.equal((await setPassword(linkToken(sent.body.link), 'third-pass-3')).status, 200);
  assert.ok(await canSignIn('forgets@test.example', 'third-pass-3'));
});
