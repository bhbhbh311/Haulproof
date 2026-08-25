# HaulProof Backend (starter)

Dispatcher/sales portal API for the HaulProof driver app: **login**, **load identification by PO#**, **POD ingest** from driver phones, and **document lookup**.

## Run it
```bash
npm install
cp .env.example .env        # edit secrets
npm run seed                # creates the first admin (prints the login)
npm start                   # http://localhost:4000  (portal at /)
```

## What each piece does
- `server.js` — wires up the API and serves the portal (`public/index.html`).
- `src/db.js` — SQLite schema: `users`, `loads` (keyed by **poNumber** and/or loadNumber), `pods` (documents).
- `src/auth.js` — password login → JWT for dispatch/sales; a shared **X-Api-Key** gate for driver-app uploads.
- `src/routes/loads.js` — create/search loads by **PO #** or load #.
- `src/routes/pods.js` — **/ingest** (driver app posts the signed PDF), **search**, **download**.
- `src/mailer.js` — emails the consignee their copy (simulated until SMTP is set).

## How the driver app connects
In the app's Outbox, set **Upload URL** to `https://YOUR_HOST/api/pods/ingest` and paste the
**Device key** (the `INGEST_API_KEY` from your `.env`). Both are saved on the phone.

The app posts the signed PDF as the raw body plus these headers automatically:
`X-Api-Key`, `X-POD-PO` (**required — every document must carry the customer's PO #**),
`X-POD-Consignee`, `X-POD-Name`, `X-POD-Load`, `X-POD-Emails`, `X-POD-Gps`, `X-POD-SignedAt`.
Free-text headers are URL-encoded (the app sends `X-POD-Enc: uri`) so names with accents or
dashes survive HTTP; the backend decodes them. An upload with no PO # is rejected with **422**.

## Set up Microsoft sign-in (master admin SSO)

The portal shows **Sign in with Microsoft** as soon as the server has an Entra app registration
configured. The password login stays as a backup. One-time setup:

1. Go to **Microsoft Entra admin center → Identity → App registrations → New registration**
   (entra.microsoft.com, sign in as a Callahan admin).
2. Name it e.g. `HaulProof Dispatch Portal`. Under **Supported account types** pick
   *Accounts in this organizational directory only* (single tenant).
3. **Redirect URI**: platform **Web**. Add `http://localhost:4000/api/auth/microsoft/callback`
   for testing, and once you know your production domain add
   `https://YOUR_HOST/api/auth/microsoft/callback` too (Entra lets you list several). You don't
   have to pick the domain now — the server derives its redirect URI from `PORTAL_URL` and prints
   the exact string to register on startup. Register.
4. On the **Overview** page copy **Application (client) ID** and **Directory (tenant) ID**.
5. **Certificates & secrets → New client secret** → copy the secret **Value** immediately.
6. **API permissions**: the default delegated `User.Read` / `openid` `profile` `email` is enough;
   click **Grant admin consent** so no one is prompted individually.
7. In the server's `.env` set `MS_TENANT_ID`, `MS_CLIENT_ID`, `MS_CLIENT_SECRET`, and
   **`PORTAL_URL`** (your portal's address — the redirect URI is derived from it automatically;
   you only set `MS_REDIRECT_URI` if you need to override it). Restart. On boot the server prints
   the exact redirect URI to register — copy that into Entra if you haven't already. That's it.

**Changing the domain later:** edit the single `PORTAL_URL` line (e.g. to
`https://portal.callahantrans.com`), add the matching `…/api/auth/microsoft/callback` to your
Entra app's redirect URIs, and restart. Nothing else changes.

**Check your setup any time:** run `npm run verify`. It reads your `.env` + allowlist, checks the
values are shaped right, prints the exact redirect URI to register, and makes one real call to
Microsoft to confirm your Tenant ID + Client ID + secret actually work together — then prints a
plain PASS/FAIL with the fix for any common mistake (expired secret, secret ID vs. value, wrong
tenant). It never prints your secret.

**Who is allowed in** is a separate, editable list — `sso-allowlist.json`:
```json
{ "admins": ["bharris@callahantrans.com"], "users": ["dispatcher1@callahantrans.com"] }
```
`admins` get the `admin` role; `users` get `dispatcher`. Anyone not listed is denied even with a
valid Microsoft login. Edits apply on the next sign-in — no restart needed. Your account
(`BHARRIS@callahantrans.com`) is pre-seeded as the master admin.

Security notes: the auth-code flow runs server-side with PKCE; the session is an httpOnly cookie
(no token in the URL); the ID token is fetched directly from Microsoft over TLS and validated on
`aud` / `iss` / `nonce` / `exp` / tenant. To also verify the token signature against Microsoft's
JWKS, add `jose` and validate `id_token` in `src/msauth.js` — a drop-in spot is marked in comments.

## Prepare-then-sign workflow (dispatch sets up the signing, driver executes it)

1. **Dispatch uploads** a PDF in the portal with a **PO #** (required) and optional **Load #**.
2. Dispatch clicks **Set up signatures**, which opens `/prepare?id=…` — the PDF renders and they
   drag **Consignee / Driver** signature + date boxes onto the pages, then **Save**. The document's
   status becomes **prepared** and it carries a saved field template.
3. **The driver app pulls it** by PO # or Load # (`GET /api/pods/lookup`), downloads the PDF, and
   opens it with those exact boxes already placed — ready to sign. On finish it posts the signed PDF
   back to `/api/pods/ingest`, where it lands as **signed** and shows in the portal search.

The setup screen renders PDFs with pdf.js served locally from `pdfjs-dist` at `/vendor/pdf.js`
(no CDN, works offline) — that's why `pdfjs-dist` is a dependency; `npm install` pulls it in.

## Key endpoints
- `POST /api/auth/login` → `{ token, user }` (password backup; also sets the session cookie)
- `GET  /api/auth/config` → `{ microsoft: true|false }` (does the portal show the MS button)
- `GET  /api/auth/microsoft` → starts Microsoft SSO; `…/callback` completes it and sets the session
- `POST /api/auth/logout` → clears the session cookie
- `GET  /api/me` → current session user (via cookie or Bearer)
- `POST /api/loads` `{ poNumber, loadNumber, customer, consignee }` → names a load by the customer PO
- `GET  /api/loads?po=&load=&q=`
- `POST /api/pods/upload` (session; raw PDF + X-PO/X-Load/X-Consignee/X-DocType/X-Filename; **PO # required or 422**) → dispatcher files a document
- `GET  /api/pods/:id` (session) → one document plus its saved signature-field template
- `PUT  /api/pods/:id/fields` (session; `{fields:[…]}`) → save the boxes dispatch placed (status → **prepared**)
- `GET  /api/pods/lookup?po=&load=` (device key **or** session) → the driver app pulls a prepared doc + template
- `POST /api/pods/ingest` (X-Api-Key; raw PDF body + X-POD-* headers; **PO # required or 422**) → signed POD back
- `GET  /api/pods?po=&load=&consignee=&q=` → search documents
- `GET  /api/pods/:id/file` (session **or** device key) → the PDF

## Production notes (next)
Swap SQLite→Postgres and local files→S3; put it behind HTTPS; add roles/rate-limiting; and add the live route/stop tracking feed the app already records (time + GPS per stop) for a dispatcher map view.
