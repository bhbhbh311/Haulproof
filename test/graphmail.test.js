const test = require('node:test');
const assert = require('node:assert');

// Microsoft Graph sending, with fetch stubbed: which request shape a message of each size uses.
function setup(responder) {
  Object.assign(process.env, { MS_TENANT_ID: 't', MS_CLIENT_ID: 'c', MS_CLIENT_SECRET: 's', MS_SENDER: 'dispatch@example.com' });
  const calls = [];
  global.fetch = async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    if (/oauth2/.test(url)) return { ok: true, status: 200, json: async () => ({ access_token: 'x', expires_in: 3600 }), text: async () => '' };
    const r = responder(String(url), opts) || { status: 202, body: '' };
    return { ok: r.status < 300, status: r.status, text: async () => r.body || '', json: async () => JSON.parse(r.body || '{}') };
  };
  delete require.cache[require.resolve('../graphmail')];
  return { g: require('../graphmail'), calls };
}
const msg = size => ({ to: 'ap@example.com', subject: 'POD', text: 'hi', html: '<p>hi</p>', attachments: [{ filename: 'pod.pdf', content: Buffer.alloc(size, 7) }] });

test('a 2.6 MB signed BOL goes as one JSON sendMail (Mail.Send only), not a draft', async () => {
  const { g, calls } = setup(() => null);
  const r = await g.sendMail(msg(2645503));
  assert.equal(r.via, 'graph-json');
  const send = calls.filter(c => /sendMail$/.test(c.url));
  assert.equal(send.length, 1); assert.ok(!calls.some(c => /\/messages$/.test(c.url)), 'no draft');
  const j = JSON.parse(send[0].opts.body);
  assert.equal(j.message.toRecipients[0].emailAddress.address, 'ap@example.com');
  assert.equal(Buffer.from(j.message.attachments[0].contentBytes, 'base64').length, 2645503);
});

test('too big even for that: the draft is refused (403) and marked so the mailer can send a link', async () => {
  const { g } = setup(url => /\/messages$/.test(url) ? { status: 403, body: JSON.stringify({ error: { message: 'Access is denied. Check credentials and try again.' } }) } : null);
  await assert.rejects(g.sendMail(msg(4 * 1024 * 1024)), e => e.code === 'ATTACH_TOO_BIG' && /403/.test(e.message));
});

test('the login email has a button (and the plain-text link as a fallback)', () => {
  const m = require('../mailer').loginInviteMail('Callahan set you up on HaulProof, Cory for J5 & Co.', 'https://haulproofepod.com/login-info?t=abc');
  assert.match(m.html, /<a href="https:\/\/haulproofepod.com\/login-info\?t=abc"[^>]*>Choose your password and sign in<\/a>/);
  assert.match(m.html, /J5 &amp; Co\./, 'names are escaped');
  assert.match(m.text, /\nhttps:\/\/haulproofepod.com\/login-info\?t=abc\n/);
});

test('small messages still go as MIME (keeps List-Unsubscribe)', async () => {
  const { g, calls } = setup(() => null);
  const r = await g.sendMail(msg(100 * 1024));
  assert.equal(r.via, 'graph');
  assert.equal(calls.find(c => /sendMail$/.test(c.url)).opts.headers['Content-Type'], 'text/plain');
});
