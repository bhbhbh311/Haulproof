// Nightly backups.
//  1) On the server's disk: a consistent copy of the database (the newest few kept) — protects against a bad change
//     or a corrupted database file.
//  2) Off-site: once Microsoft Graph is set up (MS_TENANT_ID / MS_CLIENT_ID / MS_CLIENT_SECRET, with the
//     Files.ReadWrite.All application permission) and BACKUP_ONEDRIVE_USER names a mailbox, tonight's database copy plus
//     every document and photo added since the last run go to that user's OneDrive under "HaulProof Backups/". That is
//     what protects against losing the Render disk itself.
// The master admin can also download a fresh copy of the database at any time (GET /api/backup/db).
const fs = require('fs');
const path = require('path');
const express = require('express');
const { db, DATA_DIR } = require('./db');
const { requireAuth } = require('./auth');

const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const STATE_FILE = path.join(DATA_DIR, 'backup-state.json');
const KEEP_LOCAL = Number(process.env.BACKUP_KEEP || 3);
const RUN_HOUR_UTC = Number(process.env.BACKUP_HOUR_UTC || 8);   // ~2–3 am Central
const ONEDRIVE_FOLDER = 'HaulProof Backups';
// Everything under DATA_DIR except the live database files, the backups themselves and small state files.
const SKIP = new Set(['app.db', 'app.db-wal', 'app.db-shm', 'app.db-journal', 'backups']);

function readState() { try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) || {}; } catch (e) { return {}; } }
function writeState(s) { try { fs.writeFileSync(STATE_FILE, JSON.stringify(s)); } catch (e) {} }
const stamp = (d) => d.toISOString().slice(0, 10);

function freeBytes() { try { const s = fs.statfsSync(DATA_DIR); return s.bavail * s.bsize; } catch (e) { return Infinity; } }
function dbBytes() { let n = 0; ['app.db', 'app.db-wal'].forEach(f => { try { n += fs.statSync(path.join(DATA_DIR, f)).size; } catch (e) {} }); return n; }

// A consistent copy of the live database (safe while the app is writing to it).
async function copyDatabase(dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  await db.backup(dest);
  return fs.statSync(dest).size;
}
function pruneLocal() {
  try {
    const files = fs.readdirSync(BACKUP_DIR).filter(f => /^haulproof-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
    files.slice(0, Math.max(0, files.length - KEEP_LOCAL)).forEach(f => { try { fs.unlinkSync(path.join(BACKUP_DIR, f)); } catch (e) {} });
  } catch (e) {}
}
// Documents and photos changed since `since` (ms), as paths relative to DATA_DIR.
function changedFiles(since) {
  const out = [];
  const walk = (rel) => {
    let names = []; try { names = fs.readdirSync(path.join(DATA_DIR, rel)); } catch (e) { return; }
    for (const n of names) {
      if (!rel && (SKIP.has(n) || /\.json$/.test(n))) continue;
      const r = rel ? rel + '/' + n : n, full = path.join(DATA_DIR, r);
      let st; try { st = fs.statSync(full); } catch (e) { continue; }
      if (st.isDirectory()) walk(r); else if (st.mtimeMs > since) out.push({ rel: r, size: st.size });
    }
  };
  walk('');
  return out;
}

// ---- OneDrive (Microsoft Graph) ----
// Where off-site copies go: a SharePoint site (BACKUP_SHAREPOINT_SITE, e.g. https://haulproofepod.sharepoint.com/sites/HaulProof —
// owned by the company, survives staff changes) or else a person's OneDrive (BACKUP_ONEDRIVE_USER).
function offsiteTarget() {
  const site = (process.env.BACKUP_SHAREPOINT_SITE || '').trim();
  if (site) return { kind: 'sharepoint', label: 'SharePoint (' + site.replace(/^https?:\/\//, '') + ')', key: 'sp:' + site };
  const u = (process.env.BACKUP_ONEDRIVE_USER || '').trim();
  if (u) return { kind: 'onedrive', label: 'OneDrive (' + u + ')', key: 'od:' + u };
  return null;
}
function offsiteConfigured() {
  return !!(process.env.MS_TENANT_ID && process.env.MS_CLIENT_ID && process.env.MS_CLIENT_SECRET && offsiteTarget());
}
const GRAPH = () => (process.env.MS_GRAPH_BASE || 'https://graph.microsoft.com/v1.0').replace(/\/+$/, '');
let tok = null;
async function token() {
  if (tok && tok.exp > Date.now() + 60000) return tok.value;
  const login = (process.env.MS_LOGIN_BASE || 'https://login.microsoftonline.com').replace(/\/+$/, '');
  const r = await fetch(login + '/' + encodeURIComponent(process.env.MS_TENANT_ID) + '/oauth2/v2.0/token', { method: 'POST',
    body: new URLSearchParams({ client_id: process.env.MS_CLIENT_ID, client_secret: process.env.MS_CLIENT_SECRET, grant_type: 'client_credentials', scope: 'https://graph.microsoft.com/.default' }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error('Microsoft sign-in failed: ' + (j.error_description || j.error || r.status));
  tok = { value: j.access_token, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000 };
  return tok.value;
}
let _drive = null;   // { key, base } — the Graph path of the drive backups go to
async function driveBase() {
  const t = offsiteTarget();
  if (_drive && _drive.key === t.key) return _drive.base;
  let base;
  if (t.kind === 'sharepoint') {
    // "https://host/sites/Name" (or "host:/sites/Name") → the site's id → its default document library.
    const m = String(process.env.BACKUP_SHAREPOINT_SITE).trim().replace(/^https?:\/\//, '').replace(/\/+$/, '').match(/^([^/:]+):?(\/.*)$/);
    if (!m) throw new Error('BACKUP_SHAREPOINT_SITE should look like https://yourcompany.sharepoint.com/sites/HaulProof');
    const r = await fetch(GRAPH() + '/sites/' + m[1] + ':' + m[2], { headers: { Authorization: 'Bearer ' + await token() } });
    if (!r.ok) throw await graphFail(r);
    base = '/sites/' + (await r.json()).id + '/drive';
  } else base = '/users/' + encodeURIComponent(process.env.BACKUP_ONEDRIVE_USER) + '/drive';
  _drive = { key: t.key, base };
  return base;
}
const itemPath = async (rel) => (await driveBase()) + '/root:/' + [ONEDRIVE_FOLDER].concat(rel.split('/')).map(encodeURIComponent).join('/');
async function graphFail(r) { const t = await r.text(); let m = t; try { const j = JSON.parse(t); m = (j.error && (j.error.message || j.error.code)) || t; } catch (e) {} return new Error('OneDrive ' + r.status + ': ' + String(m).slice(0, 200)); }
// Small files in one request; anything over 4 MB through an upload session, in ~10 MB pieces.
async function uploadFile(full, rel) {
  const size = fs.statSync(full).size;
  if (size <= 4 * 1024 * 1024) {
    const r = await fetch(GRAPH() + (await itemPath(rel)) + ':/content', { method: 'PUT', headers: { Authorization: 'Bearer ' + await token(), 'Content-Type': 'application/octet-stream' }, body: fs.readFileSync(full) });
    if (!r.ok) throw await graphFail(r);
    return;
  }
  const s = await fetch(GRAPH() + (await itemPath(rel)) + ':/createUploadSession', { method: 'POST', headers: { Authorization: 'Bearer ' + await token(), 'Content-Type': 'application/json' }, body: JSON.stringify({ item: { '@microsoft.graph.conflictBehavior': 'replace' } }) });
  if (!s.ok) throw await graphFail(s);
  const { uploadUrl } = await s.json();
  const CHUNK = 320 * 1024 * 32;   // 10 MB, a multiple of 320 KB as OneDrive requires
  const fd = fs.openSync(full, 'r');
  try {
    for (let pos = 0; pos < size; pos += CHUNK) {
      const len = Math.min(CHUNK, size - pos), buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, pos);
      const r = await fetch(uploadUrl, { method: 'PUT', headers: { 'Content-Length': String(len), 'Content-Range': 'bytes ' + pos + '-' + (pos + len - 1) + '/' + size }, body: buf });
      if (!r.ok && r.status !== 202) throw await graphFail(r);
    }
  } finally { fs.closeSync(fd); }
}

// ---- The nightly run ----
let running = false;
async function runBackup({ force } = {}) {
  if (running) return { skipped: 'already running' };
  running = true;
  const st = readState(), started = Date.now(), day = stamp(new Date());
  const out = { at: started, local: null, offsite: null };
  try {
    const dest = path.join(BACKUP_DIR, 'haulproof-' + day + '.db');
    if (freeBytes() < dbBytes() * 2 + 20 * 1024 * 1024) out.local = { error: 'Not enough free disk space for a local copy' };
    else { const size = await copyDatabase(dest); pruneLocal(); out.local = { file: path.basename(dest), size }; }
    if (offsiteConfigured()) {
      // A new destination (e.g. moving from OneDrive to SharePoint) gets everything, not just what changed.
      const target = offsiteTarget().key;
      const since = force || st.offsiteTarget !== target ? 0 : (st.offsiteFilesAt || 0);
      const files = changedFiles(since);
      let sent = 0, failed = 0, bytes = 0, lastError = null;
      if (out.local && out.local.file) { try { await uploadFile(dest, 'database/' + out.local.file); sent++; bytes += out.local.size; } catch (e) { failed++; lastError = e.message; } }
      for (const f of files) {
        try { await uploadFile(path.join(DATA_DIR, f.rel), 'files/' + f.rel); sent++; bytes += f.size; } catch (e) { failed++; lastError = e.message; }
      }
      // Only move the "since" mark forward when everything went, so a failed file is retried tomorrow.
      if (!failed) { st.offsiteFilesAt = started; st.offsiteTarget = target; }
      out.offsite = { sent, failed, bytes, error: lastError };
    } else out.offsite = { notConfigured: true };
  } catch (e) { out.error = e.message; }
  finally { running = false; }
  st.lastRunDay = day; st.last = out;
  if (out.offsite && out.offsite.sent && !out.offsite.failed) st.lastOffsiteOk = started;
  writeState(st);
  console.log('[backup] ' + JSON.stringify(out));
  return out;
}
function startNightlyBackup() {
  const tick = () => {
    const st = readState(), now = new Date();
    if (st.lastRunDay !== stamp(now) && now.getUTCHours() >= RUN_HOUR_UTC) runBackup().catch(e => console.error('[backup]', e.message));
  };
  setTimeout(tick, 5 * 60000).unref();
  setInterval(tick, 30 * 60000).unref();
}

// ---- Master admin: status, run now, download the database ----
const router = express.Router();
const superOnly = (req, res, next) => req.user && req.user.role === 'superadmin' ? next() : res.status(403).json({ error: 'HaulProof only' });
router.get('/status', requireAuth, superOnly, (req, res) => {
  const st = readState();
  let local = [];
  try { local = fs.readdirSync(BACKUP_DIR).filter(f => /\.db$/.test(f)).sort().reverse().map(f => ({ file: f, size: fs.statSync(path.join(BACKUP_DIR, f)).size })); } catch (e) {}
  res.json({ offsiteConfigured: offsiteConfigured(), onedriveUser: offsiteTarget() ? offsiteTarget().label : null, last: st.last || null, lastOffsiteOk: st.lastOffsiteOk || null, local, runHourUtc: RUN_HOUR_UTC });
});
router.post('/run', requireAuth, superOnly, async (req, res) => { res.json(await runBackup({ force: !!(req.body && req.body.full) })); });
router.get('/db', requireAuth, superOnly, async (req, res) => {
  const tmp = path.join(BACKUP_DIR, 'download-' + Date.now() + '.db');
  try {
    await copyDatabase(tmp);
    res.download(tmp, 'haulproof-' + stamp(new Date()) + '.db', () => { try { fs.unlinkSync(tmp); } catch (e) {} });
  } catch (e) { try { fs.unlinkSync(tmp); } catch (_) {} res.status(500).json({ error: 'Could not make a copy: ' + e.message }); }
});

module.exports = { router, runBackup, startNightlyBackup, changedFiles };
