// The deploy-retry script (in <head> of the portal, signature setup and driver app) waits out a 502/503/504 while
// HaulProof is being updated, instead of failing the request. Run: npm test
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PAGES = ['index.html', 'prepare.html', 'haulproof_driver.html'];
const START = '<!-- hp-deploy-retry:';
function snippet(file) {
  const t = fs.readFileSync(path.join(__dirname, '..', file), 'utf8').replace(/\r\n/g, '\n');
  const i = t.indexOf(START); assert.ok(i >= 0, file + ' has the deploy-retry script');
  const j = t.indexOf('</script>', i); assert.ok(j > i);
  assert.ok(i < t.indexOf('</head>'), file + ': the script is in <head>, before any page code runs');
  return t.slice(i, j + 9);
}

test('the three pages carry the same copy of the deploy-retry script', () => {
  const [a, ...rest] = PAGES.map(snippet);
  rest.forEach((s, k) => assert.strictEqual(s, a, PAGES[k + 1] + ' differs from index.html'));
});

// Run the script against a fake fetch. setTimeout fires at once, Date.now is controlled.
function harness(responses) {
  const js = snippet('index.html').replace(/^[\s\S]*?<script>/, '').replace(/<\/script>$/, '');
  const calls = [], notes = [];
  let now = 0;
  const win = {
    location: { href: 'https://haulproofepod.com/app', origin: 'https://haulproofepod.com' },
    fetch: async (input) => { calls.push(String(input)); const r = responses.shift(); if (r instanceof Error) throw r; return { status: r, ok: r < 400 }; },
    hpRetryNote: on => notes.push(on),
  };
  const ctx = { window: win, location: win.location, URL, Promise, Date: { now: () => now },
    setTimeout: (fn, ms) => { now += ms; fn(); }, document: {} };
  vm.runInNewContext(js, ctx);
  return { fetch: win.fetch, calls, notes, advance: ms => { now += ms; } };
}

test('a 502/503 while HaulProof updates is retried until it answers, with the note shown then hidden', async () => {
  const h = harness([503, 502, 200]);
  const r = await h.fetch('/api/loads', { method: 'POST' });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(h.calls.length, 3);
  assert.deepStrictEqual(h.notes, [true, false]);
});

test('a normal answer, an error the server meant (500/404) and another site are not retried', async () => {
  let h = harness([200]); assert.strictEqual((await h.fetch('/api/x')).status, 200); assert.strictEqual(h.calls.length, 1);
  h = harness([500]); assert.strictEqual((await h.fetch('/api/x')).status, 500); assert.strictEqual(h.calls.length, 1);
  h = harness([503]); assert.strictEqual((await h.fetch('https://api.example.com/x')).status, 503); assert.strictEqual(h.calls.length, 1);
  assert.deepStrictEqual(h.notes, []);
});

test('no signal (a network error) goes straight to the page, so its offline handling still works', async () => {
  const h = harness([new TypeError('Failed to fetch')]);
  await assert.rejects(h.fetch('/api/x'), /Failed to fetch/);
  assert.strictEqual(h.calls.length, 1);
});

test('it gives up after about 3 minutes and hands the page the 503', async () => {
  const h = harness(Array(200).fill(503));
  const r = await h.fetch('/api/x');
  assert.strictEqual(r.status, 503);
  assert.ok(h.calls.length > 10 && h.calls.length < 40, 'retried ' + h.calls.length + ' times');
  assert.deepStrictEqual(h.notes, [true, false]);
});
