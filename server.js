require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { login, requireAuth } = require('./src/auth');
const { router: msRouter, ssoConfigured, REDIRECT_URI, PORTAL_URL } = require('./src/msauth');
const loadsRouter = require('./src/routes/loads');
const podsRouter = require('./src/routes/pods');

const app = express();
// Same-origin portal + credentialed cookies: reflect the request origin and allow credentials.
app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.json({ limit: '2mb' }));

const SESSION_SECURE = (process.env.PORTAL_URL || '').startsWith('https://');

// --- auth: password login (kept as a backup alongside Microsoft SSO) ---
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const result = login(email, password);
  if (!result) return res.status(401).json({ error: 'Wrong email or password' });
  // Also set the session cookie so the portal behaves the same whether you used SSO or a password.
  res.cookie('hp_session', result.token, {
    httpOnly: true, sameSite: 'lax', secure: SESSION_SECURE, maxAge: 12 * 60 * 60 * 1000, path: '/',
  });
  res.json(result);
});

// Tells the portal which sign-in options to show (so the Microsoft button only appears when set up).
app.get('/api/auth/config', (_req, res) => res.json({ microsoft: ssoConfigured() }));

// Microsoft Entra SSO (start + callback).
app.use('/api/auth', msRouter);

// Clear the session cookie.
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('hp_session', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: req.user }));

// --- resources ---
app.use('/api/loads', loadsRouter);
app.use('/api/pods', podsRouter);

// --- signature setup screen + its pdf.js engine ---
app.get('/prepare', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'prepare.html')));
function pdfjsFile(name) {
  const roots = [path.join(__dirname, 'node_modules', 'pdfjs-dist', 'build'), path.join(__dirname, 'node_modules', 'pdfjs-dist', 'legacy', 'build')];
  for (const r of roots) { const f = path.join(r, name); if (fs.existsSync(f)) return f; }
  return null;
}
app.get('/vendor/pdf.js', (_req, res) => { const f = pdfjsFile('pdf.min.js') || pdfjsFile('pdf.js'); if (!f) return res.status(404).send('pdfjs missing — run npm install'); res.type('text/javascript'); fs.createReadStream(f).pipe(res); });
app.get('/vendor/pdf.worker.js', (_req, res) => { const f = pdfjsFile('pdf.worker.min.js') || pdfjsFile('pdf.worker.js'); if (!f) return res.status(404).send('pdfjs worker missing'); res.type('text/javascript'); fs.createReadStream(f).pipe(res); });

// --- portal (static) ---
app.use('/', express.static(path.join(__dirname, 'public')));

app.get('/api/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`HaulProof backend on http://localhost:${PORT}  (portal: ${PORTAL_URL})`);
  if (ssoConfigured()) {
    console.log(`Microsoft SSO: ON. Register this EXACT redirect URI in your Entra app registration:`);
    console.log(`   ${REDIRECT_URI}`);
  } else {
    console.log(`Microsoft SSO: off (set MS_CLIENT_ID/MS_CLIENT_SECRET to enable). When on, the redirect URI will be:`);
    console.log(`   ${REDIRECT_URI}`);
  }
});
