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
// A stand-in for Twilio, so "Text link" is tested end to end without texting anyone
const http = require('http');
const smsSent = [];
const TW_PORT = PORT + 1000;
const twilioFake = http.createServer((req, res) => {
  let body = ''; req.on('data', c => body += c); req.on('end', () => {
    const f = new URLSearchParams(body); smsSent.push({ url: req.url, auth: req.headers.authorization, to: f.get('To'), from: f.get('From'), body: f.get('Body'), statusCallback: f.get('StatusCallback') });
    res.writeHead(201, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ sid: 'SM' + smsSent.length, status: 'queued' }));
  });
}).listen(TW_PORT, '127.0.0.1');
Object.assign(process.env, { TWILIO_ACCOUNT_SID: 'ACtest', TWILIO_AUTH_TOKEN: 'tok-test', TWILIO_FROM: '+18884017286', TWILIO_API_BASE: 'http://127.0.0.1:' + TW_PORT });
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
test.after(() => { if (server) server.kill(); twilioFake.close(); });

async function login(email) {
  const r = await fetch(B + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: PW }) });
  assert.equal(r.status, 200, 'login');
  const cookie = (r.headers.get('set-cookie') || '').split(';')[0];
  return async (method, url, body) => {
    const x = await fetch(B + url, { method, headers: { cookie, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    return { status: x.status, body: await x.json().catch(() => ({})) };
  };
}
// A text a driver sends back to the HaulProof number, as Twilio posts it (signed with the auth token)
async function inbound(fields, sig) {
  const url = B + '/api/twilio/inbound';
  const good = crypto.createHmac('sha1', 'tok-test').update(url + Object.keys(fields).sort().map(k => k + fields[k]).join('')).digest('base64');
  return (await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Twilio-Signature': sig === undefined ? good : sig }, body: new URLSearchParams(fields).toString() })).status;
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

test('a broker helps an approved carrier: adds and edits its drivers and adds its team logins, no load needed', async () => {
  const api = await login('brk@test.example');
  const helped = org('Helped Carrier LLC', 'carrier'), stranger = org('Stranger Carrier LLC', 'carrier');
  db.prepare('INSERT INTO broker_carriers (brokerId, carrierId, createdAt) VALUES (?,?,?)').run(broker, helped, Date.now());
  // not on the approved list: no access
  assert.equal((await api('GET', `/api/drivers/for-carrier/${stranger}`)).status, 403);
  assert.equal((await api('POST', `/api/users/for-carrier/${stranger}`, { email: 'x@stranger.example' })).status, 403);
  // approved: drivers
  const add = await api('POST', `/api/drivers/for-carrier/${helped}`, { name: 'Helped Driver', phone: '555-0101' });
  assert.equal(add.status, 201, JSON.stringify(add.body));
  const ed = await api('PUT', `/api/drivers/for-carrier/${helped}/${add.body.driver.id}`, { phone: '555-0202', email: 'hd@helped.example' });
  assert.equal(ed.status, 200, JSON.stringify(ed.body)); assert.equal(ed.body.driver.phone, '555-0202');
  assert.equal((await api('PUT', `/api/drivers/for-carrier/${helped}/${add.body.driver.id}`, { email: 'nope' })).status, 400);
  // approved: team logins (in the carrier's account, not the broker's)
  const u = await api('POST', `/api/users/for-carrier/${helped}`, { email: 'Owner@Helped.example', name: 'Owner', role: 'admin' });
  assert.equal(u.status, 201, JSON.stringify(u.body)); assert.match(u.body.link, /\/login-info\?t=/);
  assert.equal(db.prepare('SELECT orgId, role FROM users WHERE email = ?').get('owner@helped.example').orgId, helped);
  assert.equal((await api('POST', `/api/users/for-carrier/${helped}`, { email: 'owner@helped.example' })).status, 409, 'one login per email');
  const list = (await api('GET', `/api/users/for-carrier/${helped}`)).body.users;
  assert.deepEqual(list.map(x => [x.email, x.role, x.signedIn]), [['owner@helped.example', 'admin', false]]);
  // a carrier that turns the option off manages its own people
  db.prepare('UPDATE orgs SET uiFlags = ? WHERE id = ?').run(JSON.stringify({ allowBrokerDrivers: false }), helped);
  assert.equal((await api('POST', `/api/users/for-carrier/${helped}`, { email: 'late@helped.example' })).status, 403);
  // the one-time switch-on for every existing carrier ran
  assert.ok(db.prepare("SELECT 1 FROM app_once WHERE key = '2026-11-18-carriers-allow-broker-help'").get());
});

test('carrier cancels: unassigning the carrier also takes its driver off, and the load leaves that driver’s phone', async () => {
  const api = await login('brk@test.example');
  const l = (await api('POST', '/api/loads', { poNumber: 'CANCEL-1' })).body.load;
  db.prepare('UPDATE loads SET carrierId = ?, carrierName = ? WHERE id = ?').run(carrier, 'Test Carrier Inc', l.id);
  const p = pod(broker, l.id, 'prepared');
  const drv = (await api('POST', `/api/drivers/for-carrier/${carrier}`, { name: 'Cancel Driver', phone: '555-0199' })).body.driver;
  assert.equal((await api('POST', `/api/loads/${l.id}/assign-driver`, { driverId: drv.id, truck: '14' })).status, 200);
  const tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(drv.id).token;
  assert.ok((await asDriver(tok)('GET', '/api/drivers/my-loads')).body.loads.some(x => x.loadId === l.id), 'on the driver’s phone');
  const u = await api('POST', `/api/loads/${l.id}/unassign-carrier`, {});
  assert.equal(u.status, 200, JSON.stringify(u.body));
  const row = db.prepare('SELECT carrierId, driverName, truck, assignedDriverId FROM loads WHERE id = ?').get(l.id);
  assert.deepEqual([row.carrierId, row.driverName, row.truck, row.assignedDriverId], [null, null, null, null]);
  assert.equal(db.prepare('SELECT assignedDriverId FROM pods WHERE id = ?').get(p).assignedDriverId, null);
  assert.equal(db.prepare('SELECT status FROM pods WHERE id = ?').get(p).status, 'prepared', 'the BOL stays set up for the next carrier');
  assert.ok(!(await asDriver(tok)('GET', '/api/drivers/my-loads')).body.loads.some(x => x.loadId === l.id), 'gone from the driver’s phone');
  const hist = (await api('GET', `/api/loads/${l.id}/history`)).body.events;
  assert.ok(hist.some(e => /Carrier unassigned \(Test Carrier Inc\); driver Cancel Driver taken off too/.test(e.detail)));
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

test('connector: a broker dispatcher works an approved carrier’s drivers and logins (carrier option)', async () => {
  createUser({ email: 'brkdisp@test.example', name: 'Broker Dispatcher', role: 'dispatcher', password: PW, orgId: broker });
  const car = org('Connector Carrier LLC', 'carrier');
  const call = mcpToken('brkdisp@test.example');
  assert.equal((await call('add_drivers', { carrier: 'Connector Carrier', drivers: [{ name: 'Nope' }] })).err, true, 'not approved yet');
  db.prepare('INSERT INTO broker_carriers (brokerId, carrierId, createdAt) VALUES (?,?,?)').run(broker, car, Date.now());
  const add = await call('add_drivers', { carrier: 'Connector Carrier', drivers: [{ name: 'Cora Driver', phone: '555-0303' }, { name: 'Cora Driver' }] });
  assert.equal(add.err, false, JSON.stringify(add.out));
  assert.deepEqual([add.out.carrier, add.out.added, add.out.skipped], ['Connector Carrier LLC', 1, 1]);
  assert.match(add.out.drivers[0].link, /\/go\//);
  assert.equal(db.prepare('SELECT orgId FROM drivers WHERE name = ?').get('Cora Driver').orgId, car, 'in the carrier’s account');
  const ls = await call('list_drivers', { carrier: 'Connector Carrier' });
  assert.deepEqual(ls.out.drivers.map(d => [d.name, d.phone, !!d.link, d.opened_link]), [['Cora Driver', '555-0303', true, false]], 'not opened yet: no PIN');
  const up = await call('update_driver', { carrier: 'Connector Carrier', driver: '555-0303', phone: '913-488-0404' });
  assert.equal(up.err, false, JSON.stringify(up.out)); assert.equal(up.out.now.phone, '913-488-0404');
  assert.equal((await call('update_driver', { carrier: 'Connector Carrier', driver: 'Cora Driver', reset_pin: true })).err, true, 'PIN stays the carrier’s');
  const tx = await call('text_driver_link', { carrier: 'Connector Carrier', driver: 'Cora Driver' });
  assert.equal(tx.err, false, JSON.stringify(tx.out)); assert.equal(smsSent[smsSent.length - 1].to, '+19134880404');
  const lg = await call('add_team_logins', { carrier: 'Connector Carrier', logins: [{ email: 'boss@connector.example', name: 'Boss', role: 'admin' }] });
  assert.equal(lg.err, false, JSON.stringify(lg.out)); assert.deepEqual([lg.out.created, lg.out.logins[0].role], [1, 'admin']);
  assert.equal(db.prepare('SELECT orgId FROM users WHERE email = ?').get('boss@connector.example').orgId, car);
  assert.equal((await call('add_team_logins', { carrier: 'Connector Carrier', logins: [{ email: 'boss@connector.example' }] })).out.skipped, 1);
});

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

test('where the driver signed shows on the load: the stop carries the spot and the history line links to it', async () => {
  const { PDFDocument } = require('pdf-lib');
  const doc = await PDFDocument.create(); doc.addPage([612, 792]); const pdf = Buffer.from(await doc.save());
  const api = await login('ship@test.example');
  const d = (await api('POST', '/api/drivers', { name: 'Gps Driver' })).body.driver;
  const tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token;
  const l = (await api('POST', '/api/loads', { poNumber: 'SIGN-GPS-1' })).body.load;
  await api('POST', `/api/loads/${l.id}/assign-driver`, { driverId: d.id });
  const r = await fetch(B + '/api/pods/ingest', { method: 'POST', body: pdf, headers: { 'X-Api-Key': tok, 'Content-Type': 'application/pdf',
    'X-POD-PO': 'SIGN-GPS-1', 'X-POD-Type': 'BOL', 'X-POD-Name': 'Signed BOL', 'X-POD-ClientId': 'phone-gps-1', 'X-POD-SignedAt': String(Date.now()),
    'X-POD-GPS': '37.555525229,-90.165122819', 'X-POD-GPS-Source': 'gps' } });
  assert.ok(r.status < 300, 'upload ok: ' + r.status);
  const one = (await api('GET', `/api/loads/${l.id}`)).body;
  assert.deepEqual(one.pods[0].gps, { lat: 37.555525229, lng: -90.165122819 });
  assert.equal(one.pods[0].gpsSource, 'gps');
  const hist = (await api('GET', `/api/loads/${l.id}/history`)).body.events;
  assert.ok(hist.some(e => e.type === 'signed' && / near 37\.55553, -90\.16512$/.test(e.detail)), 'signed line ends with where');
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

test('access request for a carrier already on HaulProof (same MC #) joins that account instead of making a second one', async () => {
  const master = await login('master@test.example');
  const real = org('JOINME TRANSPORT LLC', 'carrier');
  db.prepare('UPDATE orgs SET mcNumber = ?, active = 1 WHERE id = ?').run('937175', real);
  const sub = await fetch(B + '/api/requests', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'company', orgType: 'carrier', contactName: 'Ed Dispatch', email: 'ed@joinme.example', company: 'JOINME TRANSPORT LLC', mcNumber: 'MC 937175' }) });
  assert.equal(sub.status, 200, 'request submitted');
  const list = (await master('GET', '/api/requests')).body;
  const req = (list.requests || list).find(x => x.email === 'ed@joinme.example');
  assert.equal(req.existingCompany, 'JOINME TRANSPORT LLC', 'the inbox says it will join the existing account');
  const g = await master('POST', '/api/requests/' + req.id + '/grant', {});
  assert.equal(g.status, 200, JSON.stringify(g.body));
  assert.equal(g.body.joined, true); assert.equal(g.body.orgId, real);
  assert.equal(db.prepare('SELECT orgId, role FROM users WHERE email = ?').get('ed@joinme.example').orgId, real);
  assert.equal(db.prepare(`SELECT COUNT(*) n FROM orgs WHERE name = 'JOINME TRANSPORT LLC'`).get().n, 1, 'no second company');
});

test('merge a duplicate company: its logins and drivers move to the real one, it is turned off; one with loads is refused', async () => {
  const master = await login('master@test.example');
  const keep = org('DUPE CARRIER LLC', 'carrier'), dupe = org('DUPE CARRIER LLC', 'carrier');
  createUser({ email: 'ed@dupe.example', name: 'Ed', role: 'admin', password: PW, orgId: dupe });
  createUser({ email: 'haulproofhelp+dupe@haulproofepod.com', name: 'HaulProof Help', role: 'admin', password: PW, orgId: dupe });
  db.prepare('INSERT INTO drivers (id, orgId, name, token, active, createdAt) VALUES (?,?,?,?,1,?)').run(id(), dupe, 'Dupe Driver', 'drv_' + id(), Date.now());
  const m = await master('POST', '/api/orgs/' + dupe + '/merge-into', { intoId: keep });
  assert.equal(m.status, 200, JSON.stringify(m.body));
  assert.deepEqual(m.body.movedLogins, ['ed@dupe.example']); assert.deepEqual(m.body.movedDrivers, ['Dupe Driver']);
  assert.equal(db.prepare('SELECT orgId FROM users WHERE email = ?').get('ed@dupe.example').orgId, keep);
  assert.equal(db.prepare('SELECT orgId FROM users WHERE email = ?').get('haulproofhelp+dupe@haulproofepod.com').orgId, dupe, 'support login stays behind');
  const d = db.prepare('SELECT active, mergedInto FROM orgs WHERE id = ?').get(dupe);
  assert.deepEqual([d.active, d.mergedInto], [0, keep]);
  assert.equal((await master('POST', '/api/orgs/' + dupe + '/merge-into', { intoId: keep })).status, 400, 'not twice');
  const busy = org('BUSY CARRIER', 'carrier');
  db.prepare("INSERT INTO loads (id, orgId, poNumber, carrierId, status, createdAt) VALUES (?,?,?,?, 'open', ?)").run(id(), broker, 'BUSY-1', busy, Date.now());
  const refused = await master('POST', '/api/orgs/' + busy + '/merge-into', { intoId: keep });
  assert.equal(refused.status, 400); assert.match(refused.body.error, /already has 1 load/);
  assert.equal((await (await login('brk@test.example'))('POST', '/api/orgs/' + dupe + '/merge-into', { intoId: keep })).status, 403, 'master admin only');
});

test('Text link: with Twilio set up, the server texts the driver their link from the HaulProof number; no phone or texting off is said plainly', async () => {
  const brk = await login('brk@test.example');
  assert.equal((await brk('GET', '/api/me')).body.textingOn, true, 'the portal knows texting is on');
  const drv = id(), bare = id();
  db.prepare('INSERT INTO drivers (id, orgId, name, phone, token, active, createdAt) VALUES (?,?,?,?,?,1,?)').run(drv, broker, 'Shaun Test', '970-596-3477', 'drv_' + id(), Date.now());
  db.prepare('INSERT INTO drivers (id, orgId, name, token, active, createdAt) VALUES (?,?,?,?,1,?)').run(bare, broker, 'No Phone', 'drv_' + id(), Date.now());
  const before = smsSent.length;
  // the driver hasn't agreed to our texts yet: one "reply YES" text, and the link waits
  const r = await brk('POST', '/api/drivers/' + drv + '/text-link', {});
  assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.sentTo, '+19705963477'); assert.equal(r.body.askedYes, true);
  const m = smsSent[before];
  assert.equal(m.to, '+19705963477'); assert.equal(m.from, '+18884017286'); assert.match(m.url, /\/Accounts\/ACtest\/Messages\.json$/);
  assert.equal(m.auth, 'Basic ' + Buffer.from('ACtest:tok-test').toString('base64'));
  assert.match(m.body, /^Test Broker LLC: we have this number to text you .*Reply YES to get them\..*Reply STOP to opt out, HELP for help\.$/); assert.doesNotMatch(m.body, /\/go\//, 'no link before YES');
  assert.equal(db.prepare('SELECT status, kind FROM sms_log WHERE driverId = ?').get(drv).kind, 'optin', 'logged');
  // pressing it again the same day doesn't ask twice
  assert.equal((await brk('POST', '/api/drivers/' + drv + '/text-link', {})).body.askedYes, true);
  assert.equal(smsSent.length, before + 1);
  // a reply that isn't signed by Twilio is refused; the driver's YES sends the held link (once, though pressed twice)
  assert.equal(await inbound({ From: '+19705963477', Body: 'YES' }, 'forged'), 403);
  assert.equal(await inbound({ From: '+19705963477', Body: ' yes! ' }), 200);
  assert.equal(smsSent.length, before + 2);
  const link = smsSent[before + 1];
  assert.equal(link.to, '+19705963477'); assert.match(link.body, /Test Broker LLC: here's your HaulProof driver app, Shaun\./); assert.match(link.body, /\/go\/[A-Z0-9]{10}$/);
  assert.equal(db.prepare('SELECT source FROM sms_consent WHERE phone = ?').get('9705963477').source, 'sms-reply');
  // now agreed: Text link sends the link right away
  const now = await brk('POST', '/api/drivers/' + drv + '/text-link', {});
  assert.equal(now.body.askedYes, false); assert.match(smsSent[before + 2].body, /here's your HaulProof driver app, Shaun/);
  // STOP: nothing more goes out, and the button says so
  assert.equal(await inbound({ From: '+19705963477', Body: 'Stop' }), 200);
  const stopped = await brk('POST', '/api/drivers/' + drv + '/text-link', {});
  assert.equal(stopped.status, 502); assert.match(stopped.body.error, /replied STOP/);
  const none = await brk('POST', '/api/drivers/' + bare + '/text-link', {});
  assert.equal(none.status, 400); assert.match(none.body.error, /no phone number/);
  assert.equal((await (await login('ship@test.example'))('POST', '/api/drivers/' + drv + '/text-link', {})).status, 404, 'another company can’t text our driver');
  assert.equal(smsSent.length, before + 3, 'nothing else was sent');
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

test('driver uploaded the signed BOL on his own load: dispatch files it on the load he was given, as its signed paper BOL with the upload\'s GPS', async () => {
  const { PDFDocument } = require('pdf-lib');
  const doc = await PDFDocument.create(); doc.addPage([612, 792]); const pdf = Buffer.from(await doc.save());
  createUser({ email: 'car-fs@test.example', name: 'Carrier Admin', role: 'admin', password: PW, orgId: carrier });
  const car = await login('car-fs@test.example');
  const d = (await car('POST', '/api/drivers', { name: 'Stray Driver' })).body.driver;
  const tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token;
  // the broker's load, given to the carrier, not set up yet
  const target = id();
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, carrierId, carrierName, status, createdBy, createdAt) VALUES (?,?,?,?,?,?,'assigned','brk@test.example',?)`)
    .run(target, broker, '9351', '9351-0', carrier, 'Test Carrier Inc', Date.now());
  // the driver starts his own load with the receiver's BL # and hands the signed BOL to dispatch
  const up = await fetch(B + '/api/pods/ingest', { method: 'POST', body: pdf, headers: { 'X-Api-Key': tok, 'Content-Type': 'application/pdf',
    'X-POD-PO': 'BL-541', 'X-POD-Status': 'prepared', 'X-POD-Build': 'dispatch', 'X-POD-GPS': '38.10000,-97.20000', 'X-POD-ClientId': 'stray-1', 'X-POD-Name': 'PO BL-541' } });
  const { podId, loadId: strayLoad } = await up.json();
  assert.equal(db.prepare('SELECT status FROM pods WHERE id = ?').get(podId).status, 'awaiting_build');
  // a company that isn't on either load can't move it
  assert.equal((await (await login('ship@test.example'))('POST', `/api/pods/${podId}/file-as-signed`, { loadId: target })).status, 404);
  // not onto a load another carrier hauls
  const elsewhere = id();
  db.prepare(`INSERT INTO loads (id, orgId, poNumber, status, createdAt) VALUES (?,?,?,'open',?)`).run(elsewhere, carrier, 'OWN-X', Date.now());
  db.prepare(`UPDATE loads SET carrierId = ? WHERE id = ?`).run(broker, elsewhere);
  db.prepare(`UPDATE loads SET orgId = ? WHERE id = ?`).run(broker, elsewhere);
  assert.equal((await car('POST', `/api/pods/${podId}/file-as-signed`, { loadId: elsewhere })).status, 404);
  const r = await car('POST', `/api/pods/${podId}/file-as-signed`, { loadId: target });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.removedLoad, 'BL-541', 'the driver\'s empty load is removed');
  const p = db.prepare('SELECT * FROM pods WHERE id = ?').get(podId);
  assert.deepEqual([p.loadId, p.orgId, p.poNumber, p.stopNumber, p.paperSigned, p.gps], [target, broker, '9351-0', 1, 1, '38.10000,-97.20000']);
  assert.ok(['signed', 'emailed'].includes(p.status));
  assert.equal(db.prepare('SELECT podMode FROM loads WHERE id = ?').get(target).podMode, 'paper');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM loads WHERE id = ?').get(strayLoad).n, 0);
  const hist = db.prepare('SELECT detail FROM load_events WHERE loadId = ?').all(target).map(e => e.detail).join('\n');
  assert.match(hist, /Photo of the paper BOL signed by the receiver — driver Stray Driver near 38\.10*, -97\.20* · filed by car-fs@test\.example from the driver’s upload on load BL-541/);
  // the broker sees it completed on its load
  const bl = (await (await login('brk@test.example'))('GET', '/api/loads/' + target)).body;
  assert.ok((bl.pods || []).some(x => x.id === podId && ['signed', 'emailed'].includes(x.status)));
  // once filed it can't be filed again
  assert.equal((await car('POST', `/api/pods/${podId}/file-as-signed`, { loadId: target })).status, 409);
});

test('connector: the stray signed BOL playbook is offered as a prompt and named in the instructions', async () => {
  const u = db.prepare('SELECT id FROM users WHERE email = ?').get('brk@test.example');
  const tok = 'test_' + crypto.randomBytes(12).toString('hex');
  db.prepare("INSERT INTO oauth_tokens (tokenHash, kind, clientId, userId, expiresAt, createdAt) VALUES (?, 'access', ?, ?, ?, ?)")
    .run(crypto.createHash('sha256').update(tok).digest('hex'), 'test-client-prompts', u.id, Date.now() + 3600e3, Date.now());
  const rpc = async (method, params) => (await (await fetch(B + '/mcp', { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) })).json());
  const init = (await rpc('initialize', { protocolVersion: '2025-06-18' })).result;
  assert.ok(init.capabilities.prompts); assert.match(init.instructions, /fix_stray_signed_bol/); assert.match(init.instructions, /never add a carrier’s driver to the broker’s own roster/);
  assert.ok((await rpc('prompts/list')).result.prompts.some(p => p.name === 'fix_stray_signed_bol'));
  const got = (await rpc('prompts/get', { name: 'fix_stray_signed_bol', arguments: { carrier: '3 BS', load: '125351' } })).result;
  assert.match(got.messages[0].content.text, /for carrier 3 BS \(our load 125351\)[\s\S]*file_signed_bol/);
  assert.ok((await rpc('prompts/get', { name: 'nope' })).error);
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
  assert.match(html, /og:image" content="[^"]+\/icons\/share-card\.png"/);
  const card = await fetch(B + '/icons/share-card.png');
  assert.equal(card.status, 200); assert.equal(card.headers.get('content-type'), 'image/png');
});

test('texted driver link preview: iMessage gets the HaulProof card saying whose paper BOL upload it is, and never the driver\'s key', async () => {
  const carrier = org('Preview Carrier LLC', 'carrier');
  createUser({ email: 'car-prev@test.example', name: 'Carrier Prev', role: 'admin', password: PW, orgId: carrier });
  const car = await login('car-prev@test.example');
  const d = (await car('POST', '/api/drivers', { name: 'Preview Pete' })).body.driver;
  const code = d.link.split('/go/')[1], tok = db.prepare('SELECT token FROM drivers WHERE id = ?').get(d.id).token;
  const imsg = { 'User-Agent': 'Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 facebookexternalhit/1.1 Facebot Twitterbot/1.0' };
  let r = await fetch(B + '/go/' + code, { redirect: 'manual', headers: imsg });
  let html = await r.text();
  assert.equal(r.status, 200); assert.ok(!html.includes(tok), 'the preview never carries the driver\'s key');
  assert.match(html, /share-card\.png/); assert.match(html, /og:title" content="HaulProof Driver"/);
  db.prepare(`INSERT INTO loads (id, orgId, poNumber, carrierId, podMode, status, createdAt) VALUES (?,?,?,?,?,'assigned',?)`).run(id(), broker, 'PREV-1', carrier, 'paper', Date.now() + 5000);
  html = await (await fetch(B + '/go/' + code, { headers: imsg })).text();
  assert.match(html, /og:title" content="Test Broker · HaulProof Driver"/);
  assert.match(html, /Test Broker’s paper BOL upload: once the paperwork is signed, send a photo of the BOL here and it goes to your company and Test Broker\./);
  // a person tapping the link still goes straight into the app
  assert.equal((await fetch(B + '/go/' + code, { redirect: 'manual' })).status, 302);
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

test('connector: change a driver — rename, new phone, reset PIN; the link stays the same', async () => {
  const call = mcpToken('ship@test.example');
  const add = await call('add_drivers', { drivers: [{ name: 'Bruce', phone: '5550142' }] });
  const link = add.out.drivers[0].link;
  const dId = db.prepare('SELECT id FROM drivers WHERE orgId = ? AND name = ?').get(shipper, 'Bruce').id;
  db.prepare("UPDATE drivers SET pinHash = 'x', mustChangePin = 0 WHERE id = ?").run(dId);
  const r = await call('update_driver', { driver: '555-0142', name: 'Bruce Foster', reset_pin: true });
  assert.equal(r.err, false, JSON.stringify(r.out));
  assert.deepEqual([r.out.now.name, r.out.now.has_pin, r.out.now.link], ['Bruce Foster', false, link]);
  const row = db.prepare('SELECT name, phone, mustChangePin FROM drivers WHERE id = ?').get(dId);
  assert.deepEqual([row.name, row.phone, row.mustChangePin], ['Bruce Foster', '5550142', 1]);
  assert.equal((await call('update_driver', { driver: 'Bruce Foster' })).err, true, 'nothing to change');
  // another company's driver can't be changed
  assert.equal((await mcpToken('brk@test.example')('update_driver', { driver: dId, name: 'X' })).err, true);
});

test('owner-operator: a login that also drives gets a driver record, sees "My driver app", and the driver sees Office', async () => {
  const api = await login('ship@test.example');
  const r = await api('POST', '/api/users', { email: 'Owner.Op@test.example', name: 'Owen Operator', role: 'admin', alsoDrives: true, phone: '5550177' });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.ok(r.body.driver && /\/go\//.test(r.body.driver.link), 'a driver link came back');
  const d = db.prepare('SELECT * FROM drivers WHERE id = ?').get(r.body.driver.id);
  assert.deepEqual([d.orgId, d.name, d.phone, d.email], [shipper, 'Owen Operator', '5550177', 'owner.op@test.example']);
  const team = (await api('GET', '/api/users')).body.users;
  assert.equal(team.find(u => u.email === 'owner.op@test.example').alsoDrives, true);
  assert.equal(team.find(u => u.email === 'ship@test.example').alsoDrives, false);
  // the driver's link says they also have an office login; a plain driver's doesn't
  assert.equal((await asDriver(d.token)('GET', '/api/drivers/link-info')).body.office, true);
  // signed in as the owner-operator: their own driver record (and only theirs)
  db.prepare('UPDATE users SET passHash = (SELECT passHash FROM users WHERE email = ?), mustChangePassword = 0 WHERE email = ?').run('ship@test.example', 'owner.op@test.example');
  const me = (await (await login('owner.op@test.example'))('GET', '/api/drivers/me')).body;
  assert.equal(me.driver.id, d.id);
  assert.equal((await api('GET', '/api/drivers/me')).body.driver, null, 'a login that does not drive has no driver');
  // an existing driver with the same email is linked, not duplicated
  const r2 = await api('POST', '/api/drivers', { name: 'Pat Two', email: 'pat2@test.example' });
  const before = db.prepare('SELECT COUNT(*) n FROM drivers WHERE orgId = ?').get(shipper).n;
  const r3 = await api('POST', '/api/users', { email: 'pat2@test.example', name: 'Pat Two', alsoDrives: true });
  assert.equal(r3.status, 201); assert.equal(db.prepare('SELECT COUNT(*) n FROM drivers WHERE orgId = ?').get(shipper).n, before);
  assert.equal(r3.body.driver.id, r2.body.driver.id);
});

test('connector: new team logins are emailed their set-up link; send_password_link resends one', async () => {
  const call = mcpToken('brk@test.example');
  const r = await call('add_team_logins', { logins: [{ email: 'New.Disp@test.example', name: 'New Disp' }] });
  assert.equal(r.err, false, JSON.stringify(r.out));
  assert.equal(r.out.logins[0].emailed, true);
  assert.equal(r.out.logins[0].setup_link, undefined, 'an emailed link is not handed back');
  assert.ok(db.prepare("SELECT 1 FROM login_links l JOIN users u ON u.id = l.userId WHERE u.email = 'new.disp@test.example'").get());
  const quiet = await call('add_team_logins', { logins: [{ email: 'quiet@test.example' }], send_invite: false });
  assert.match(quiet.out.logins[0].setup_link, /\/login-info\?t=/);
  assert.equal(quiet.out.logins[0].emailed, undefined);
  const re = await call('send_password_link', { login: 'New Disp' });
  assert.equal(re.err, false, JSON.stringify(re.out));
  assert.equal(re.out.emailed_to, 'new.disp@test.example'); assert.equal(re.out.setup_link, undefined);
  // only this account's logins
  assert.equal((await mcpToken('ship@test.example')('send_password_link', { login: 'new.disp@test.example' })).err, true);
});

test('ask the carrier who’s driving: the carrier answers on the form, the driver goes on the load and is texted the link, and the carrier gets its first login', async () => {
  createUser({ email: 'askdisp@test.example', name: 'Ask Dispatcher', role: 'dispatcher', password: PW, orgId: broker });
  const car = org('Ask Carrier LLC', 'carrier');
  const lid = id();
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, carrierId, carrierName, status, origin, consignee, createdAt) VALUES (?,?,?,?,?,?,'assigned',?,?,?)`)
    .run(lid, broker, '125302', '125302-0', car, 'Ask Carrier LLC', 'Joplin, MO', 'Dana Inc, Tulsa, OK', Date.now());
  const call = mcpToken('askdisp@test.example');
  const r = await call('ask_carrier_for_driver', { load: '125302', email: 'Dispatch@AskCarrier.example' });
  assert.equal(r.err, false, JSON.stringify(r.out));
  assert.equal(r.out.sent_to, 'dispatch@askcarrier.example'); assert.equal(r.out.carrier_admin_login_created, true);
  const admin = db.prepare('SELECT orgId, role FROM users WHERE email = ?').get('dispatch@askcarrier.example');
  assert.deepEqual([admin.orgId, admin.role], [car, 'admin'], 'carrier’s first login, its admin');
  const again = await call('ask_carrier_for_driver', { load: '125302', email: 'dispatch@askcarrier.example' });
  assert.equal(again.out.form_link, r.out.form_link, 'asked once a day, not twice');
  // the carrier's form (no sign-in)
  const t = new URL(r.out.form_link).searchParams.get('t');
  const page = await (await fetch(B + '/api/driver-request/' + t)).json();
  assert.deepEqual([page.broker, page.loadNumber, page.origin, page.destination, page.driver], ['Test Broker', '125302', 'Joplin, MO', 'Dana Inc, Tulsa, OK', null]);
  assert.equal((await fetch(B + '/driver-request?t=' + t)).status, 200);
  const post = (body) => fetch(B + '/api/driver-request/' + t, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(async x => ({ status: x.status, body: await x.json() }));
  assert.equal((await post({ name: 'Ned Driver', phone: '555-01' })).status, 400, 'needs a 10-digit cell');
  // the carrier didn't check "the driver agreed to texts": the driver goes on the load but isn't texted
  const noConsent = await post({ name: 'Ned Driver', phone: '(417) 260-5588' });
  assert.equal(noConsent.status, 200, JSON.stringify(noConsent.body));
  assert.deepEqual([noConsent.body.texted, noConsent.body.consent], [false, false], 'no text without consent');
  const before = smsSent.length;
  const ok = await post({ name: 'Ned Driver', phone: '(417) 260-5588', consent: true });
  assert.equal(ok.status, 200, JSON.stringify(ok.body)); assert.deepEqual([ok.body.texted, ok.body.askedYes], [false, true]);
  assert.equal(smsSent.length, before + 1, 'one text: the YES ask');
  assert.match(db.prepare('SELECT consentText, source FROM sms_consent WHERE phone = ?').get('4172605588').source, /^carrier-form:dispatch@askcarrier\.example$/);
  assert.equal(smsSent[before].to, '+14172605588');
  assert.match(smsSent[before].body, /^Test Broker: Ask Carrier gave us this number to text you about loads you haul for us \(HaulProof Driver Text Alerts: .*\)\. Reply YES to get them\./);
  const d = db.prepare('SELECT * FROM drivers WHERE orgId = ? AND name = ?').get(car, 'Ned Driver');
  assert.equal(d.phone, '4172605588');
  const l = db.prepare('SELECT driverName, assignedDriverId FROM loads WHERE id = ?').get(lid);
  assert.deepEqual([l.driverName, l.assignedDriverId], ['Ned Driver', d.id]);
  // the driver replies YES: the held link goes out
  assert.equal(await inbound({ From: '+14172605588', Body: 'Yes' }), 200);
  assert.equal(smsSent.length, before + 2);
  assert.match(smsSent[before + 1].body, /Test Broker: here's your HaulProof driver app for load 125302 \(PO 125302-0\), Ned\./);
  // a later carrier form doesn't overwrite the driver's own YES
  assert.equal(db.prepare('SELECT source FROM sms_consent WHERE phone = ?').get('4172605588').source, 'sms-reply');
  // answering again with the same cell keeps the same driver (no duplicate)
  await post({ name: 'Ned D.', phone: '4172605588' });
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM drivers WHERE orgId = ?').get(car).n, 1);
  // only the broker's own loads; a bad link says so
  assert.equal((await mcpToken('ship@test.example')('ask_carrier_for_driver', { load: '125302', email: 'x@y.example' })).err, true);
  assert.equal((await fetch(B + '/api/driver-request/nope')).status, 404);
  const hist = db.prepare('SELECT detail FROM load_events WHERE loadId = ? ORDER BY createdAt').all(lid).map(e => e.detail).join('\n');
  assert.match(hist, /Asked Ask Carrier LLC \(dispatch@askcarrier\.example\) for the driver's name and cell #; set up dispatch@askcarrier\.example/);
  assert.match(hist, /Driver Ned Driver \(417-260-5588\) given by Ask Carrier LLC; driver texted to reply YES/);
});


test('text delivery tracking: Twilio reports back (signed); a text that did not get through goes on the load and emails the dispatcher with the link', async () => {
  const car = org('Track Carrier LLC', 'carrier');
  const lid = id();
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, carrierId, carrierName, status, createdAt) VALUES (?,?,?,?,?,?,'assigned',?)`)
    .run(lid, broker, '125999', '125999-0', car, 'Track Carrier LLC', Date.now());
  const call = mcpToken('brk@test.example');
  const ask = await call('ask_carrier_for_driver', { load: '125999', email: 'office@trackcarrier.example', notify_email: 'disp@test.example' });
  assert.equal(ask.err, false, JSON.stringify(ask.out));
  const t = new URL(ask.out.form_link).searchParams.get('t');
  const before = smsSent.length;
  const ok = await fetch(B + '/api/driver-request/' + t, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Tess Track', phone: '913-555-0177', consent: true }) }).then(r => r.json());
  assert.equal(ok.askedYes, true);
  // the text asks Twilio to report its result to us
  const sent = smsSent[before];
  assert.equal(sent.statusCallback, B + '/api/twilio/status');
  const sid = 'SM' + (before + 1);
  const row = () => db.prepare('SELECT * FROM sms_log WHERE twilioSid = ?').get(sid);
  assert.equal(row().loadId, lid); assert.equal(row().notifyEmail, 'disp@test.example');
  const report = async (fields, sig) => {
    const url = B + '/api/twilio/status';
    const good = crypto.createHmac('sha1', 'tok-test').update(url + Object.keys(fields).sort().map(k => k + fields[k]).join('')).digest('base64');
    return (await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Twilio-Signature': sig === undefined ? good : sig }, body: new URLSearchParams(fields).toString() })).status;
  };
  assert.equal(await report({ MessageSid: sid, MessageStatus: 'undelivered', ErrorCode: '30032' }, 'forged'), 403, 'only Twilio can report');
  assert.equal(row().status, 'queued');
  assert.equal(await report({ MessageSid: sid, MessageStatus: 'sent' }), 200);
  assert.equal(row().status, 'sent');
  assert.equal(await report({ MessageSid: sid, MessageStatus: 'undelivered', ErrorCode: '30032' }), 200);
  assert.deepEqual([row().status, row().errorCode], ['undelivered', '30032']);
  const hist = () => db.prepare('SELECT detail FROM load_events WHERE loadId = ? ORDER BY createdAt').all(lid).map(e => e.detail).join('\n');
  assert.match(hist(), /NOT delivered to Tess Track \(913-555-0177\): the HaulProof texting number is still waiting on Twilio’s toll-free verification\. Send the driver the link from your phone: http.*\/go\//);
  // a late repeat of the final status doesn't log twice
  await report({ MessageSid: sid, MessageStatus: 'undelivered', ErrorCode: '30032' });
  assert.equal((hist().match(/NOT delivered/g) || []).length, 1);
  assert.equal(await report({ MessageSid: 'SMnotours', MessageStatus: 'delivered' }), 200);
});

test('check-on list: pickup close and the driver not "On my way" (or no driver, or past pickup) lists the load with numbers to call; emailed once per reason', async () => {
  const CO = require('../checkon');
  // reading pickup times (Central)
  assert.equal(CO.parsePickup('11/20/2026 8:00 AM').at, Date.UTC(2026, 10, 20, 14, 0));
  assert.deepEqual(CO.parsePickup('11/20/2026 7-3'), { at: Date.UTC(2026, 10, 20, 13, 0), note: '7-3' });
  assert.deepEqual(CO.parsePickup('2026-11-20'), { at: Date.UTC(2026, 10, 20, 14, 0), note: 'date only' });
  assert.equal(CO.parsePickup('2026-11-20T14:30').at, Date.UTC(2026, 10, 20, 20, 30));
  assert.equal(CO.parsePickup('2026-07-01 0630').at, Date.UTC(2026, 6, 1, 11, 30), 'summer is CDT');
  assert.equal(CO.parsePickup('next tuesday'), null);
  const brk = await login('brk@test.example');
  const car = org('Check Carrier LLC', 'carrier');
  db.prepare('UPDATE orgs SET contactPhone = ? WHERE id = ?').run('8165550111', car);
  const drv = id();
  db.prepare('INSERT INTO drivers (id, orgId, name, phone, token, active, createdAt) VALUES (?,?,?,?,?,1,?)').run(drv, car, 'Carl Check', '9135550122', 'drv_' + id(), Date.now());
  const H = 3600e3, now = Date.now();
  const mk = async (po, pickup, withDriver) => {
    const l = (await brk('POST', '/api/loads', { poNumber: po, pickup })).body.load;
    db.prepare('UPDATE loads SET carrierId = ?, carrierName = ?, status = ? WHERE id = ?').run(car, 'Check Carrier LLC', 'assigned', l.id);
    if (withDriver) db.prepare('UPDATE loads SET driverName = ?, assignedDriverId = ? WHERE id = ?').run('Carl Check', drv, l.id);
    return l;
  };
  const soon = await mk('CHK-SOON', now + 1 * H, true);       // within 2h, not on the way
  const later = await mk('CHK-LATER', now + 5 * H, true);     // not yet
  const nod = await mk('CHK-NODRV', now + 3 * H, false);      // no driver, within 4h
  const late = await mk('CHK-LATE', now - 2 * H, true);       // past pickup, not picked up
  assert.ok(soon.pickupAt, 'pickup saved on create');
  const list = async () => (await brk('GET', '/api/loads/check-on')).body;
  let r = await list();
  const by = Object.fromEntries(r.items.map(i => [i.poNumber, i]));
  assert.equal(by['CHK-SOON'].stage, 'not_en_route'); assert.equal(by['CHK-SOON'].driverPhone, '913-555-0122'); assert.equal(by['CHK-SOON'].carrierPhone, '816-555-0111');
  assert.equal(by['CHK-NODRV'].stage, 'no_driver'); assert.equal(by['CHK-LATE'].stage, 'late_pickup');
  assert.equal(by['CHK-LATER'], undefined, 'five hours out is not due yet');
  assert.deepEqual(r.items.slice(0, 1).map(i => i.poNumber), ['CHK-LATE'], 'past pickup first');
  // the driver taps "On my way": off the list
  db.prepare('UPDATE loads SET enRouteAt = ? WHERE id = ?').run(Date.now(), soon.id);
  r = await list(); assert.ok(!r.items.some(i => i.poNumber === 'CHK-SOON'));
  // emails: set who gets them, then each due load is emailed once
  assert.equal((await brk('PUT', '/api/loads/check-on/settings', { emails: 'nope' })).status, 400);
  assert.deepEqual((await brk('PUT', '/api/loads/check-on/settings', { emails: 'Disp@Test.example, ops@test.example' })).body.emails, ['disp@test.example', 'ops@test.example']);
  const first = (await CO.tick(Date.now(), { anyHour: true })).find(s => s.org === 'Test Broker LLC');
  assert.ok(first && first.loads.includes('CHK-NODRV') && first.loads.includes('CHK-LATE'), JSON.stringify(first));
  const second = (await CO.tick(Date.now(), { anyHour: true })).find(s => s.org === 'Test Broker LLC');
  assert.equal(second, undefined, 'nothing new: no second email');
  assert.match(db.prepare("SELECT detail FROM load_events WHERE loadId = ? AND detail LIKE 'Check-on reminder%'").get(late.id).detail, /Past the pickup time and not picked up/);
  // edit: change the pickup on the load; an unreadable one is refused
  assert.equal((await brk('PUT', '/api/loads/' + later.id, { pickup: 'whenever' })).status, 400);
  const ed = await brk('PUT', '/api/loads/' + later.id, { pickup: '', pickupNote: '' });
  assert.equal(ed.body.load.pickupAt, null);
});

test('add signed BOL: an already-signed paper BOL is filed on the stop as signed (upload link or portal), the unsigned BOL leaves the driver, nothing emailed; a second one is refused', async () => {
  const lid = id(), unsigned = id();
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, status, podMode, createdAt) VALUES (?,?,?,?,'assigned','epod',?)`).run(lid, broker, '125361', '125361', Date.now());
  db.prepare("INSERT INTO pods (id, orgId, loadId, poNumber, stopNumber, docType, filename, filepath, status, uploadedAt, fields) VALUES (?,?,?,?,1,'BOL','BOL 125361.pdf','/dev/null','prepared',?,'[]')").run(unsigned, broker, lid, '125361', Date.now());
  const call = mcpToken('brk@test.example');
  const link = await call('get_upload_link', { load: '125361', filename: '125361 MASONMADE.pdf', signed: true, signed_date: '2026-11-18', note: 'from the AP inbox' });
  assert.equal(link.err, false, JSON.stringify(link.out)); assert.match(link.out.files_as, /signed paper BOL \(not emailed\)/);
  const pdf = Buffer.from('%PDF-1.4\n% signed BOL\n%%EOF\n');
  const up = await fetch(link.out.upload_url, { method: 'POST', headers: { 'Content-Type': 'application/pdf' }, body: pdf }).then(async r => ({ status: r.status, body: await r.json() }));
  assert.equal(up.status, 200, JSON.stringify(up.body));
  assert.deepEqual([up.body.status, up.body.unsigned_set_aside, up.body.emailed], ['signed', 1, false]);
  const pods = db.prepare('SELECT id, status, paperSigned, signedAt FROM pods WHERE loadId = ? ORDER BY uploadedAt').all(lid);
  assert.equal(pods.find(p => p.id === unsigned).status, 'not_used', 'the unsigned ePOD BOL is set aside');
  const signed = pods.find(p => p.id !== unsigned);
  assert.deepEqual([signed.status, signed.paperSigned, signed.signedAt], ['signed', 1, Date.UTC(2026, 10, 18, 18)]);
  const hist = db.prepare('SELECT detail FROM load_events WHERE loadId = ?').all(lid).map(e => e.detail).join('\n');
  assert.match(hist, /Signed BOL filed by the office: 125361 MASONMADE\.pdf · from the AP inbox · the unsigned BOL on this stop was set aside as not used · not emailed/);
  // the same stop again is refused, from the portal too
  const brk = await login('brk@test.example');
  const again = await fetch(B + '/api/pods/office-signed', { method: 'POST', headers: { cookie: (await (await fetch(B + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'brk@test.example', password: PW }) })).headers.get('set-cookie')).split(';')[0],
    'Content-Type': 'application/pdf', 'X-Load': lid, 'X-No-Email': '1' }, body: pdf });
  assert.equal(again.status, 409);
  // portal: stop 2 works; not a PDF is refused; another company can't
  const cookie = (await (await fetch(B + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'brk@test.example', password: PW }) })).headers.get('set-cookie')).split(';')[0];
  const post = (body, extra, ck = cookie) => fetch(B + '/api/pods/office-signed', { method: 'POST', headers: Object.assign({ cookie: ck, 'Content-Type': 'application/pdf', 'X-Load': lid, 'X-No-Email': '1' }, extra || {}), body }).then(r => r.status);
  assert.equal(await post(Buffer.from('not a pdf'), { 'X-Stop': '2' }), 415);
  assert.equal(await post(pdf, { 'X-Stop': '2' }), 200);
  const shipCk = (await (await fetch(B + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'ship@test.example', password: PW }) })).headers.get('set-cookie')).split(';')[0];
  assert.equal(await post(pdf, { 'X-Stop': '3' }, shipCk), 404);
  assert.ok(brk);
});

test('call notes: a note on a load shows as its latest note (connector and check-on list) and stays in the history; empty clears it', async () => {
  const lid = id();
  db.prepare(`INSERT INTO loads (id, orgId, loadNumber, poNumber, status, pickupAt, createdAt) VALUES (?,?,?,?,'assigned',?,?)`).run(lid, broker, '125999N', '125999N-0', Date.now() - 2 * 3600e3, Date.now());
  const call = mcpToken('brk@test.example');
  const r = await call('add_load_note', { load: '125999N', note: 'Called Kenny at J5, driver is Mike, ETA 2 PM' });
  assert.equal(r.err, false, JSON.stringify(r.out)); assert.match(r.out.last_note, /^Called Kenny at J5, driver is Mike, ETA 2 PM \(Broker, /);
  const brk = await login('brk@test.example');
  const item = (await brk('GET', '/api/loads/check-on')).body.items.find(i => i.poNumber === '125999N-0');
  assert.equal(item.lastNote, 'Called Kenny at J5, driver is Mike, ETA 2 PM');
  assert.match(db.prepare("SELECT detail FROM load_events WHERE loadId = ? AND type = 'note'").get(lid).detail, /📝 Called Kenny/);
  await brk('POST', '/api/loads/' + lid + '/note', { note: '' });
  assert.equal(db.prepare('SELECT lastNote FROM loads WHERE id = ?').get(lid).lastNote, null);
  assert.equal((await (await login('ship@test.example'))('POST', '/api/loads/' + lid + '/note', { note: 'x' })).status, 404, 'another company can’t');
});

test('HaulProof Driver Text Alerts: public opt-in page with terms, consent required and recorded', async () => {
  for (const p of ['/sms', '/sms-terms']) {
    const r = await fetch(B + p); assert.equal(r.status, 200);
    const html = await r.text();
    assert.match(html, /HaulProof Driver Text Alerts/); assert.match(html, /Callahan Transportation, Inc\./);
    assert.match(html, /Reply <b>STOP<\/b>/); assert.match(html, /Message and data rates may apply/);
    assert.match(html, /do not sell, rent or share your mobile number/);
  }
  const optin = body => fetch(B + '/api/sms/optin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(async x => ({ status: x.status, body: await x.json() }));
  assert.equal((await optin({ name: 'Opt Driver', phone: '816-555-0142' })).status, 400, 'the box must be checked');
  assert.equal((await optin({ name: 'Opt Driver', phone: '555', consent: true })).status, 400);
  const ok = await optin({ name: 'Opt Driver', phone: '+1 (816) 555-0142', consent: true });
  assert.equal(ok.status, 200, JSON.stringify(ok.body)); assert.equal(ok.body.phone, '8165550142');
  const row = db.prepare('SELECT * FROM sms_consent WHERE phone = ?').get('8165550142');
  assert.equal(row.source, 'sms-page'); assert.match(row.consentText, /Reply STOP to opt out/); assert.ok(row.confirmedAt, 'the driver agreed themselves');
  assert.match(await (await fetch(B + '/sms')).text(), /href="\/privacy"/, 'privacy policy on the same site');
  for (const p of ['/privacy', '/privacy-policy']) {
    const r = await fetch(B + p); assert.equal(r.status, 200);
    const html = await r.text();
    assert.match(html, /Privacy policy/); assert.match(html, /do not sell, rent or share mobile numbers, text-message opt-in or consent/);
  }
});
