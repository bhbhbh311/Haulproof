---
name: haulproof-auto-refresh
description: How HaulProof's pages pick up a new deploy on their own (portal, signature setup, driver app) and how to keep that working. Use when adding or changing a screen, modal, overlay or anything with unsaved input in index.html, prepare.html or haulproof_driver.html; when touching the version endpoints or the driver service worker; when someone reports "my change didn't show up" / "it reloaded while I was working"; or before shipping a change that drivers or dispatchers must get without refreshing.
---

# HaulProof auto-refresh

Every HaulProof page that stays open for hours checks whether a newer build is live and reloads itself — but only at a
moment when a reload can't lose work. Each page decides "safe to reload" with its own checklist, so **any new screen,
dialog or editor must be added to that checklist** or an update can wipe someone's half-finished work.

## How each page does it

| Page | File | Asks the server | How often | Reloads when |
|---|---|---|---|---|
| Portal (dispatch) | `index.html` (`startUpdateWatch`, `checkForUpdate`, `updateSafeNow`, `applyUpdate`) | `GET /api/version` → `{portal}` = SHA-1 of `index.html` (`PORTAL_BUILD`, server.js) — changes only when `index.html` changes | every 5 min + on returning to the tab; re-tries the reload every 30 s | 2 min with no click/key, no field focused, no history overlay / setup wizard / document viewer / split / crop window open, no load mid-edit or dirty. Otherwise shows the "✨ HaulProof was updated · Refresh" note. Reload returns to the same tab via `sessionStorage hp_tab_after_update`. |
| Signature setup | `prepare.html` (IIFE at the end: `_verTick`, `_safeReload`) | `GET /api/app-version` → `{version}` = Render commit (`RENDER_GIT_COMMIT`, 12 chars), else newest mtime of the three pages — changes on every deploy | every 15 s + focus / visibility | `dirty` is false, AI place (`_ocrRunning`) not running, crop and layouts modals closed |
| Driver app | `haulproof_driver.html` (last-but-one `<script>`: `busy`, `tryReload`, registers `/sw.js` with scope `/driver`) + server-generated service worker (`/sw.js`, `SW_JS` in server.js) | the browser re-checks `/sw.js`; its `CACHE` name = `hp-<mtime of haulproof_driver.html>`, so a new driver file = new SW = `controllerchange` | `reg.update()` every 60 s + reopen / focus / bfcache restore | 60 s with no touch, `window.__hpBusy` false, on the home (route) screen, signature modal / camera / split sheet closed. Shows "Updating HaulProof — back in a moment…" first. First SW install on a phone is never treated as an update. |

The data on screen refreshes separately and much more often (portal `autoRefreshTick` every 12 s, driver route every
30 s) — that never reloads the page, it just re-pulls loads/stops. Keep the two ideas apart.

## Checklist when you change a page

1. **New modal, sheet, overlay or editor with input?** Add it to that page's safe check:
   - portal → `updateSafeNow()`;
   - signature setup → `_safeReload()`;
   - driver app → `busy()`; for a flow that spans screens, set `window.__hpBusy = true` while it's open and clear it after.
2. **New unsaved-changes state?** Make it visible to the check (the portal uses `_ldDirty` / `.editing`, prepare uses
   `dirty`). An in-place editor that a 12 s data refresh would redraw also needs to stop that refresh — e.g.
   `refreshOpenLoadDetail` skips while `#ldView .stSave` exists (the in/out-time editor).
3. **Driver app change?** Bump `APP_BUILD` in `haulproof_driver.html` (shown in load history as the driver's build).
   The update itself rides on the file's mtime → new SW; nothing else to do.
4. **New long-lived page?** Copy the prepare.html pattern: poll `/api/app-version`, take the first answer as the
   baseline, reload only when it changes **and** a page-specific safe check passes; also re-check on `focus` and
   `visibilitychange`.
5. **Don't** reload from a timer without a safe check, and don't compare versions across pages — each page keeps its
   own baseline from its first poll.

## Verifying after a deploy

- `GET https://haulproofepod.com/api/app-version` should return the new commit's first 12 characters once Render
  shows the deploy live (`list_deploys`). `/api/version` (the portal's probe) changes only when `index.html` changed,
  so a deploy that didn't touch `index.html` correctly leaves open portal tabs alone.
- Open portal tab: after 2 idle minutes it reloads; if you're active it shows the Refresh note.
- Driver app: reopen it on the home screen and wait about a minute without touching it — the blue "Updating
  HaulProof" strip appears, then it reloads.

## One mechanism per page — keep it that way

Until 2026-11-03 the portal also ran an older checker (`checkAppVersion` on the 12 s tick) that reloaded sooner than
the 2-minute rule, and server.js injected a second service-worker registration into the driver page that reloaded
whenever `__hpBusy` was false. Both were removed so each page has exactly one place that decides when to reload.
Don't add another update check alongside these; extend the existing one. The driver page also unregisters any
stray whole-site (`/`) registration left on older phones — the one with scope `/driver` is the one that serves it.
