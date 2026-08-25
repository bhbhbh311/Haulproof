// Self-check for the Microsoft SSO setup.  Run:  npm run verify
//
// It reads your .env + sso-allowlist.json, checks everything is shaped right, and then makes ONE
// real call to Microsoft to confirm your Tenant ID + Client ID + Client secret actually work
// together. It never prints your secret. Green = good, red = fix this.

require('dotenv').config();
const fs = require('fs');
const path = require('path');

const G = (s) => `\x1b[32m${s}\x1b[0m`;   // green
const R = (s) => `\x1b[31m${s}\x1b[0m`;   // red
const Y = (s) => `\x1b[33m${s}\x1b[0m`;   // yellow
const B = (s) => `\x1b[1m${s}\x1b[0m`;    // bold
const PASS = G('PASS');
const FAIL = R('FAIL');
const WARN = Y('WARN');

const isGuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s || '').trim());

const TENANT = (process.env.MS_TENANT_ID || '').trim();
const CLIENT_ID = (process.env.MS_CLIENT_ID || '').trim();
const CLIENT_SECRET = (process.env.MS_CLIENT_SECRET || '').trim();
const PORTAL_URL = (process.env.PORTAL_URL || 'http://localhost:4000').replace(/\/+$/, '');
const REDIRECT_URI = (process.env.MS_REDIRECT_URI || (PORTAL_URL + '/api/auth/microsoft/callback')).trim();

let hardFail = 0;
const line = (label, status, detail) => console.log(` ${status}  ${B(label)}${detail ? ' — ' + detail : ''}`);

(async () => {
  console.log(B('\nHaulProof — Microsoft SSO check\n'));

  // 1. Required values present
  if (CLIENT_ID) line('Client ID present', PASS); else { line('Client ID present', FAIL, 'MS_CLIENT_ID is empty in .env'); hardFail++; }
  if (CLIENT_SECRET) line('Client secret present', PASS); else { line('Client secret present', FAIL, 'MS_CLIENT_SECRET is empty in .env'); hardFail++; }
  if (TENANT) line('Tenant ID present', PASS); else { line('Tenant ID present', FAIL, 'MS_TENANT_ID is empty in .env'); hardFail++; }

  // 2. Formats
  if (CLIENT_ID) { if (isGuid(CLIENT_ID)) line('Client ID looks like a GUID', PASS); else { line('Client ID looks like a GUID', FAIL, `got "${CLIENT_ID}" — copy the Application (client) ID from the app's Overview page`); hardFail++; } }
  if (TENANT) {
    if (isGuid(TENANT) || TENANT === 'organizations' || TENANT === 'common') line('Tenant ID looks valid', PASS, isGuid(TENANT) ? 'GUID' : `"${TENANT}"`);
    else { line('Tenant ID looks valid', FAIL, `got "${TENANT}" — use the Directory (tenant) ID GUID`); hardFail++; }
  }
  // Very common mistake: pasting the secret's ID (a GUID) instead of the secret VALUE.
  if (CLIENT_SECRET && isGuid(CLIENT_SECRET)) {
    line('Client secret is the VALUE, not the ID', WARN, 'your secret looks like a GUID — that is usually the secret ID. Copy the secret VALUE (the ~40-char string shown once, right after you create it)');
  } else if (CLIENT_SECRET) {
    line('Client secret is the VALUE, not the ID', PASS);
  }

  // 3. Redirect URI (must be registered in Entra EXACTLY)
  line('Portal URL', PASS, PORTAL_URL);
  if (PORTAL_URL.startsWith('http://') && !PORTAL_URL.includes('localhost')) {
    line('Redirect URI to register', WARN, `${REDIRECT_URI}  (use https for a real domain)`);
  } else {
    line('Redirect URI to register', PASS, REDIRECT_URI);
  }
  console.log(`       ${Y('↳ This exact string must be listed under your app registration → Authentication → Redirect URIs (Web).')}`);

  // 4. Allowlist
  try {
    const al = JSON.parse(fs.readFileSync(path.join(__dirname, 'sso-allowlist.json'), 'utf8'));
    const admins = (al.admins || []).map((e) => String(e).toLowerCase());
    const users = (al.users || []).map((e) => String(e).toLowerCase());
    if (admins.length + users.length > 0) line('Allowlist has at least one person', PASS, `${admins.length} admin(s), ${users.length} user(s)`);
    else { line('Allowlist has at least one person', FAIL, 'sso-allowlist.json is empty — nobody could sign in'); hardFail++; }
    if (admins.length) console.log(`       admins: ${admins.join(', ')}`);
    if (users.length) console.log(`       users:  ${users.join(', ')}`);
  } catch (e) {
    line('Allowlist file valid JSON', FAIL, 'sso-allowlist.json is missing or not valid JSON'); hardFail++;
  }

  // 5. THE REAL TEST — do the Tenant + Client ID + secret actually authenticate with Microsoft?
  if (hardFail === 0 || (CLIENT_ID && CLIENT_SECRET && TENANT)) {
    console.log(B('\nContacting Microsoft to verify the credentials…'));
    try {
      const body = new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'client_credentials',
        scope: 'https://graph.microsoft.com/.default',
      });
      const res = await fetch(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.access_token) {
        line('Microsoft accepted your Tenant + Client ID + secret', PASS, 'these three are correct and work together');
      } else {
        const code = (data.error_description || '').match(/AADSTS\d+/)?.[0] || data.error || `HTTP ${res.status}`;
        const hints = {
          AADSTS7000215: 'Invalid client secret. You likely pasted the secret ID or an expired/old secret — create a fresh secret and copy its VALUE.',
          AADSTS7000222: 'The client secret has EXPIRED. Create a new one in Certificates & secrets.',
          AADSTS700016: 'Application not found in this tenant. The Client ID or the Tenant ID is wrong (or the app is registered in a different tenant).',
          AADSTS90002:  'Tenant not found. Double-check MS_TENANT_ID (the Directory/tenant ID GUID).',
          AADSTS900023: 'Tenant identifier is not valid. Check MS_TENANT_ID.',
          AADSTS650057: 'Credentials are valid but a resource/permission is misconfigured — the login itself should still work.',
        };
        line('Microsoft accepted your Tenant + Client ID + secret', FAIL, `${code}`);
        if (hints[code]) console.log(`       ${Y('↳ ' + hints[code])}`);
        else if (data.error_description) console.log(`       ${Y('↳ ' + String(data.error_description).split('\n')[0])}`);
        hardFail++;
      }
    } catch (e) {
      line('Reached Microsoft login endpoint', FAIL, 'network error: ' + e.message + ' (is this machine online / behind a proxy?)');
      hardFail++;
    }
  } else {
    console.log(Y('\nSkipping the live Microsoft test until the values above are filled in.'));
  }

  console.log('');
  if (hardFail === 0) {
    console.log(G(B('✓ Your Microsoft SSO looks correctly configured.')));
    console.log(`  Last thing to confirm by eye: the redirect URI above is listed in your app registration, and you're on the sso-allowlist.`);
    console.log(`  Then start the server (npm start) and click "Sign in with Microsoft" on the portal.\n`);
  } else {
    console.log(R(B(`✗ ${hardFail} thing(s) need fixing above.`)) + ' Fix them in .env (or the Entra app registration) and run  npm run verify  again.\n');
    process.exitCode = 1;
  }
})();
