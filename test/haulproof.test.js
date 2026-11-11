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
  assert.equal(add.status, 201); assert.match(add.body.driver.link, /\/go\/[2-9A-HJKMNP-Z]{10}$/, 'a short link to text');
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

test('master admin adds a company: no admin password; the first admin gets a link to choose their own', async () => {
  const master = await login('master@test.example');
  const c = await master('POST', '/api/orgs', { name: 'Invite Customer Co', adminEmail: 'boss@invite-cust.example', adminName: 'Cust Boss' });
  assert.equal(c.status, 201, JSON.stringify(c.body)); assert.match(c.body.adminLink, /\/login-info\?t=/);
  assert.ok(!(await canSignIn('boss@invite-cust.example', '')), 'no usable password until they choose one');
  assert.equal((await setPassword(linkToken(c.body.adminLink), 'cust-boss-pass')).body.signedIn, true);
  assert.ok(await canSignIn('boss@invite-cust.example', 'cust-boss-pass'));
  const car = await master('POST', '/api/carriers', { name: 'Invite Carrier LLC', adminEmail: 'boss@invite-carrier.example' });
  assert.equal(car.status, 201, JSON.stringify(car.body)); assert.ok(car.body.adminLink);
  assert.equal((await setPassword(linkToken(car.body.adminLink), 'carrier-boss-1')).status, 200);
  const rcv = await master('POST', '/api/receivers', { name: 'Invite Receiver Yard', adminEmail: 'dock@invite-recv.example' });
  assert.equal(rcv.status, 201, JSON.stringify(rcv.body)); assert.ok(rcv.body.adminLink);
  const noLogin = await master('POST', '/api/receivers', { name: 'Receiver Without Login' });
  assert.equal(noLogin.status, 201); assert.equal(noLogin.body.adminLink, null);
});

// ---- Paper BOL (tracking) loads: status taps + a photo of the BOL the receiver signed on paper ----
test('paper BOL load: the driver sees it as paper; each stop\'s photo is its signed POD; the load stays until every stop has one', async () => {
  const { PDFDocument } = require('pdf-lib');
  const doc = await PDFDocument.create(); doc.addPage([612, 792]); const pdf = Buffer.from(await doc.save());
  const api = await login('ship@test.example');
  const d = (await api('POST', '/api/drivers', { name: 'Paper Driver' })).body.driver;
  const tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token, drv = asDriver(tok);
  const l = (await api('POST', '/api/loads', { poNumber: 'PAPER-1', podMode: 'paper', deliveryStops: 2 })).body.load;
  assert.deepEqual([l.podMode, l.paperStops], ['paper', 2]);
  await api('POST', `/api/loads/${l.id}/assign-driver`, { driverId: d.id });
  const card = () => drv('GET', '/api/drivers/my-loads').then(r => r.body.loads.filter(x => x.loadId === l.id));
  let mine = await card();
  assert.equal(mine.length, 1); assert.deepEqual([mine[0].podMode, mine[0].paperStops, mine[0].noDoc], ['paper', 2, true]);
  const photo = (stop, cid, key = tok, loadId = l.id) => fetch(B + '/api/pods/ingest', { method: 'POST', body: pdf, headers: { 'X-Api-Key': key, 'Content-Type': 'application/pdf',
    'X-POD-PO': 'PAPER-1', 'X-POD-Paper': '1', 'X-POD-LoadId': loadId, 'X-POD-Stop': String(stop), 'X-POD-ClientId': cid, 'X-POD-Name': 'Signed BOL - PO PAPER-1' } });
  assert.ok((await photo(1, 'paper-s1')).status < 300);
  const p1 = db.prepare('SELECT status, paperSigned, stopNumber FROM pods WHERE loadId = ?').all(l.id);
  assert.deepEqual(p1.map(p => [p.status, p.paperSigned, p.stopNumber]), [['signed', 1, 1]], 'filed on the load as stop 1, signed on paper');
  mine = await card();
  assert.equal(mine.length, 1, 'still on the list: stop 2 needs its photo'); assert.equal(mine[0].loadSigned, 1);
  assert.ok((await photo(2, 'paper-s2')).status < 300);
  assert.equal((await card()).length, 0, 'every stop has its photo: done');
  // the load page shows the photo as signed on paper; the history says so
  const hist = db.prepare('SELECT detail FROM load_events WHERE loadId = ?').all(l.id).map(e => e.detail).join('\n');
  assert.match(hist, /Photo of the paper BOL signed by the receiver \(Stop 2\)/);
  // dispatch can switch a load's delivery type, and nonsense is ignored
  assert.equal((await api('PUT', '/api/loads/' + l.id, { podMode: 'epod' })).body.load.podMode, 'epod');
  assert.equal((await api('PUT', '/api/loads/' + l.id, { podMode: 'banana' })).body.load.podMode, null);
});

test('paper BOL photo: another company\'s driver can\'t file onto someone else\'s load by its id', async () => {
  const { PDFDocument } = require('pdf-lib');
  const doc = await PDFDocument.create(); doc.addPage([612, 792]); const pdf = Buffer.from(await doc.save());
  const api = await login('ship@test.example');
  const l = (await api('POST', '/api/loads', { poNumber: 'PAPER-OWN', podMode: 'paper' })).body.load;
  const other = await login('brk@test.example');
  const od = (await other('POST', '/api/drivers', { name: 'Outside Driver' })).body.driver;
  const otok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(od.id).token;
  await fetch(B + '/api/pods/ingest', { method: 'POST', body: pdf, headers: { 'X-Api-Key': otok, 'Content-Type': 'application/pdf',
    'X-POD-PO': 'SOMETHING-ELSE', 'X-POD-Paper': '1', 'X-POD-LoadId': l.id, 'X-POD-ClientId': 'outside-1' } });
  assert.equal(db.prepare('SELECT COUNT(*) n FROM pods WHERE loadId = ?').get(l.id).n, 0, 'nothing landed on the other company\'s load');
});

test('short driver link: /go/<code> opens the driver app with that driver\'s key; a switched-off driver\'s link stops', async () => {
  const api = await login('ship@test.example');
  const d = (await api('POST', '/api/drivers', { name: 'Short Link Sue', phone: '816-555-0177' })).body.driver;
  const code = d.link.split('/go/')[1];
  assert.equal(code.length, 10);
  const r = await fetch(B + '/go/' + code, { redirect: 'manual' });
  const tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token;
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/driver?k=' + encodeURIComponent(tok));
  assert.equal((await fetch(B + '/go/' + code.toLowerCase(), { redirect: 'manual' })).status, 302, 'typed in lower case still works');
  assert.equal((await api('GET', '/api/drivers')).body.drivers.find(x => x.id === d.id).link, d.link, 'the same link every time');
  await api('POST', `/api/drivers/${d.id}/active`, { active: false });
  assert.equal((await fetch(B + '/go/' + code, { redirect: 'manual' })).status, 404);
  assert.equal((await fetch(B + '/go/NOTAREALONE', { redirect: 'manual' })).status, 404);
  const html = await (await fetch(B + '/driver')).text();
  assert.match(html, /property="og:title" content="HaulProof Driver"/, 'a tidy preview when the link is texted');
});

test('how drivers deliver: new loads start with the company setting, a customer\'s own setting wins, and a hand-picked one stays put', async () => {
  const api = await login('brk@test.example');   // a broker, like Callahan: its loads carry a customer
  const cust = (await api('POST', '/api/customers', { name: 'Delivery Default Steel' })).body.customer;
  const other = (await api('POST', '/api/customers', { name: 'Plain Customer Co' })).body.customer;
  assert.equal((await api('PUT', '/api/delivery-defaults', { company: 'paper' })).body.company, 'paper');
  const set = await api('PUT', '/api/delivery-defaults', { customerId: cust.id, podMode: 'epod' });
  assert.equal(set.body.customers.find(c => c.id === cust.id).podMode, 'epod');
  // a new load starts as the company's Paper BOL; picking the ePOD customer switches it; picking another customer goes back
  const l = (await api('POST', '/api/loads', { poNumber: 'DEF-1' })).body.load;
  assert.deepEqual([l.podMode, l.paperStops], ['paper', 1]);
  assert.equal((await api('PUT', '/api/loads/' + l.id, { customerId: cust.id })).body.load.podMode, 'epod');
  assert.equal((await api('PUT', '/api/loads/' + l.id, { customerId: other.id })).body.load.podMode, 'paper');
  // chosen by hand: a customer change no longer moves it
  await api('PUT', '/api/loads/' + l.id, { podMode: 'epod' });
  assert.equal((await api('PUT', '/api/loads/' + l.id, { customerId: '' })).body.load.podMode, 'epod');
  // chosen when the load is made: kept
  assert.equal((await api('POST', '/api/loads', { poNumber: 'DEF-2', podMode: 'epod' })).body.load.podMode, 'epod');
  // back to not set
  await api('PUT', '/api/delivery-defaults', { company: '' });
  assert.equal((await api('POST', '/api/loads', { poNumber: 'DEF-3' })).body.load.podMode, null);
  // another company's customer can't be changed from here
  const ship = await login('ship@test.example');
  assert.equal((await ship('PUT', '/api/delivery-defaults', { customerId: cust.id, podMode: 'paper' })).status, 404);
});

test('new load form: Delivery picked with the upload is set on the load, ahead of the account setting', async () => {
  const { PDFDocument } = require('pdf-lib');
  const doc = await PDFDocument.create(); doc.addPage([612, 792]); const pdf = Buffer.from(await doc.save());
  const lr = await fetch(B + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'ship@test.example', password: PW }) });
  const cookie = (lr.headers.get('set-cookie') || '').split(';')[0];
  const up = (po, extra) => fetch(B + '/api/pods/upload', { method: 'POST', body: pdf, headers: Object.assign({ cookie, 'Content-Type': 'application/pdf', 'X-Enc': 'uri', 'X-PO': po, 'X-DocType': 'BOL', 'X-Filename': 'bol.pdf' }, extra) });
  assert.equal((await up('FORM-PAPER', { 'X-PodMode': 'paper', 'X-DeliveryStops': '3' })).status, 200);
  assert.deepEqual(Object.values(db.prepare('SELECT podMode, paperStops, podModeAuto FROM loads WHERE poNumber = ?').get('FORM-PAPER')), ['paper', 3, 0]);
  assert.equal((await up('FORM-EPOD', { 'X-PodMode': 'epod' })).status, 200);
  assert.equal(db.prepare('SELECT podMode FROM loads WHERE poNumber = ?').get('FORM-EPOD').podMode, 'epod');
  assert.equal((await up('FORM-NONE', {})).status, 200);
  assert.equal(db.prepare('SELECT podMode FROM loads WHERE poNumber = ?').get('FORM-NONE').podMode, null, 'nothing picked: the account setting (none here)');
});

test('require ePOD: with Paper BOL turned off every load is ePOD, whatever asks for paper; turning it back on restores the choice', async () => {
  const api = await login('brk@test.example');
  const off = await api('PUT', '/api/delivery-defaults', { allowPaper: false });
  assert.equal(off.body.allowPaper, false); assert.equal(off.body.fields.allowPaperBol, false);
  assert.equal((await api('POST', '/api/loads', { poNumber: 'REQ-1' })).body.load.podMode, 'epod', 'a new load is ePOD');
  const asked = (await api('POST', '/api/loads', { poNumber: 'REQ-2', podMode: 'paper' })).body.load;
  assert.equal(asked.podMode, 'epod', 'asking for paper (FMS, connector) still gives ePOD');
  assert.equal((await api('PUT', '/api/loads/' + asked.id, { podMode: 'paper' })).body.load.podMode, 'epod');
  assert.equal((await api('PUT', '/api/delivery-defaults', { company: 'paper' })).status, 400);
  // back on: the choice is there again
  assert.equal((await api('PUT', '/api/delivery-defaults', { allowPaper: true })).body.allowPaper, true);
  assert.equal((await api('PUT', '/api/loads/' + asked.id, { podMode: 'paper' })).body.load.podMode, 'paper');
  await api('PUT', '/api/delivery-defaults', { company: '' });
});

test('FMCSA authority from SAFER: "AUTHORIZED FOR" with a new 8-digit MC reads as active carrier authority', () => {
  const { parseSaferAuthority } = require('../carriers');
  const page = (auth, mc) => `<TR><TH><A class="querylabel">Operating Authority Status:</A></TH> <TD colspan="4" class="queryfield">${auth} <br><br> <b>For Licensing and Insurance details </b> <a href="http://motus.dot.gov/customer/1/account">click here.</a></TD></TR>
    <TR><TH><A class="querylabel">MC/MX/FF Number(s):</A></TH> <TD colspan="4" class="queryfield"> ${mc}<br> &nbsp;</TD></TR>`;
  const a = parseSaferAuthority(page('AUTHORIZED FOR: <br> Motor Carrier of Property (Except Household Goods)', '<A href="x"> MC-67543984</A>'));
  assert.deepEqual([a.state.carrier, a.state.broker, a.mc], ['active', 'none', '67543984']);
  const b = parseSaferAuthority(page('AUTHORIZED FOR: <br> Broker of Property (Except Household Goods)', '<A href="x"> MC-123456</A>'));
  assert.deepEqual([b.state.carrier, b.state.broker], ['none', 'active']);
  const both = parseSaferAuthority(page('AUTHORIZED FOR: <br> Motor Carrier of Property, Broker of Property', 'MC-1'));
  assert.deepEqual([both.state.carrier, both.state.broker], ['active', 'active']);
  const not = parseSaferAuthority(page('NOT AUTHORIZED', 'None'));
  assert.deepEqual([not.state.carrier, not.state.broker, not.mc], ['none', 'none', null]);
  assert.equal(parseSaferAuthority('<html>nothing here</html>'), null, 'a page without the line is "couldn\'t read", not "none"');
});

test('connector: a broker creates a load with an approved carrier and that carrier\'s driver in one step', async () => {
  const c2 = org('Roster Carrier LLC', 'carrier');
  db.prepare('UPDATE orgs SET mcNumber = ? WHERE id = ?').run('7654321', c2);
  const drvId = id();
  db.prepare("INSERT INTO drivers (id, orgId, name, phone, token, active, mustChangePin, createdAt) VALUES (?,?,?,?,?,1,1,?)").run(drvId, c2, 'Roster Bob', '5550109', 'tok_' + crypto.randomBytes(8).toString('hex'), Date.now());
  const call = mcpToken('brk@test.example');
  // not on the broker's approved list yet
  const no = await call('create_load', { po_number: 'CAR-0', carrier: 'Roster Carrier' });
  assert.equal(no.err, true, 'only approved carriers');
  db.prepare('INSERT INTO broker_carriers (brokerId, carrierId, createdAt) VALUES (?,?,?)').run(broker, c2, Date.now());
  const list = await call('list_carriers', { search: '7654321' });
  assert.deepEqual(list.out.carriers.map(c => c.name), ['Roster Carrier LLC']);
  assert.match(list.out.carriers[0].drivers[0], /Roster Bob/);
  const r = await call('create_load', { po_number: 'CAR-1', carrier: 'MC 7654321', driver: 'Roster Bob', delivery: 'paper' });
  assert.equal(r.err, false, JSON.stringify(r.out));
  assert.equal(r.out.warning, undefined, JSON.stringify(r.out));
  const row = db.prepare('SELECT carrierId, assignedDriverId AS driverId FROM loads WHERE poNumber = ? AND orgId = ?').get('CAR-1', broker);
  assert.deepEqual([row.carrierId, row.driverId], [c2, drvId]);
  // and on an existing load: assign_carrier, then assign_driver by phone
  await call('create_load', { po_number: 'CAR-2' });
  const ac = await call('assign_carrier', { load: 'CAR-2', carrier: 'Roster Carrier LLC' });
  assert.deepEqual(ac.out.carrier_drivers, ['Roster Bob']);
  const ad = await call('assign_driver', { load: 'CAR-2', driver: '555-0109' });
  assert.equal(ad.err, false, JSON.stringify(ad.out));
  assert.equal(db.prepare('SELECT assignedDriverId FROM loads WHERE poNumber = ?').get('CAR-2').assignedDriverId, drvId);
});
