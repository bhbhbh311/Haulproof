// AI signature-box placement for the signature setup page (prepare.html).
//
// The page sends, for each document page, a JPEG of the page plus the words text recognition found on it (with
// their positions). Claude reads both and returns where each box goes, in the same 0-1000 page coordinates as the
// words — so positions come from real text locations, not guesses from the picture. Two calls:
//   POST /api/pods/:id/ai-place    → suggest the boxes for a document
//   POST /api/pods/:id/ai-command  → apply a typed/spoken change ("add carrier sign and date") to the current boxes
// Without ANTHROPIC_API_KEY these answer 503 and the page falls back to its built-in rule-based placement.
const express = require('express');
const crypto = require('crypto');
const { requireAuth } = require('./auth');
const { db } = require('./db');
const podsRouter = require('./pods');

const router = express.Router();
const MODEL = process.env.AI_PLACE_MODEL || 'claude-opus-5-5';
// $ per million tokens (input, output, cache read) — used only for the cost log.
const PRICES = {
  'claude-opus-5-5': [4, 20, 0.2], 'claude-sonnet-5-5': [2, 10, 0.2], 'claude-haiku-5-5': [0.1, 0.5, 0.01],
  'claude-opus-4-8': [5, 25, 0.5],
};
const MAX_PAGES = 12;

db.exec(`CREATE TABLE IF NOT EXISTS ai_usage (
  id TEXT PRIMARY KEY, orgId TEXT, userId TEXT, podId TEXT, kind TEXT, model TEXT,
  inputTokens INTEGER, outputTokens INTEGER, cacheReadTokens INTEGER, costUsd REAL, createdAt INTEGER NOT NULL
)`);

let _client = null;
function client() {
  if (!process.env.ANTHROPIC_API_KEY) return null;
  if (!_client) { const Anthropic = require('@anthropic-ai/sdk'); _client = new (Anthropic.default || Anthropic)(); }
  return _client;
}

const KINDS = ['sigdate', 'sig', 'initials', 'date', 'pickupdate', 'puin', 'puout', 'dlin', 'dlout', 'text'];
const FIELDS_SCHEMA = {
  type: 'object',
  properties: {
    fields: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'id of an existing box being kept or moved; "" for a new box' },
          page: { type: 'integer', description: '0-based page index' },
          kind: { type: 'string', enum: KINDS },
          role: { type: 'string', description: 'Consignee, Driver, Shipper, Pickup (only for pickupdate and pickup in/out), or a custom signer name' },
          label: { type: 'string', description: 'short label for text/initials boxes, else ""' },
          x0: { type: 'number' }, y0: { type: 'number' }, x1: { type: 'number' }, y1: { type: 'number' },
        },
        required: ['id', 'page', 'kind', 'role', 'label', 'x0', 'y0', 'x1', 'y1'],
        additionalProperties: false,
      },
    },
    note: { type: 'string', description: 'one short sentence for the dispatcher about what was placed or changed' },
  },
  required: ['fields', 'note'],
  additionalProperties: false,
};

const SYSTEM = `You place signature boxes on trucking paperwork (bills of lading, delivery receipts) for HaulProof, an electronic proof-of-delivery app. A dispatcher reviews your boxes before a driver's phone shows them to sign.

Each page comes as an image plus a list of the words found on it, each with its box [x0,y0,x1,y1] in page coordinates from 0 to 1000 (x left→right, y top→bottom). Return every box in the same coordinates. Use the word positions to put boxes exactly on the blank line or empty cell next to or above a label, never over printed text.

Box kinds:
- sig: a signature. sigdate: a signature with the signing date printed beside it, for a signature line that has no separate date blank.
- date: the signing date, filled in automatically when that signer signs. When a signature line has its own nearby "Date" blank, place a sig on the signature blank and a date (same role) on the date blank.
- initials, text: only when the form clearly asks for them or the dispatcher asks.
- pickupdate: fills in with the pickup date — only on an empty "Pickup date" / "Date shipped" style blank.
- puin / puout / dlin / dlout: pickup in/out and delivery in/out times — only on empty "Time in" / "Time out" / "Arrival" / "Departure" style blanks; puin/puout belong to the pickup (shipper) side, dlin/dlout to the delivery (receiver) side.

Roles: Consignee = the receiver/consignee/customer who signs at delivery ("Signature of consignee", "Received by", "Receiver"). Driver = the carrier or driver ("Driver signature", "Carrier"). Shipper = the shipper/consignor at pickup — only add Shipper boxes when the dispatcher asks, because the shipper usually signs the paper before the driver leaves. Use role "Pickup" for pickupdate, puin and puout.

Rules:
- A blank already holding a handwritten or printed value is not empty — leave it alone.
- Multi-page documents usually repeat the signature lines on every page; place boxes on every page that has them.
- Signature boxes: as wide as the blank line (typically 200-400 wide), about 30-45 tall, bottom edge sitting on the line. Date/time boxes: at least 110 wide and about 22-30 tall.
- Prefer fewer, correct boxes over guesses. If a page has no signature lines, place nothing there.`;

function wordsText(words) {
  // Compact one-word-per-line listing: text x0 y0 x1 y1 (0-1000).
  return (words || []).slice(0, 1500).map(w => `${String(w[0]).replace(/\s+/g, ' ').slice(0, 40)} ${w.slice(1, 5).map(n => Math.round(n)).join(' ')}`).join('\n');
}

function pageBlocks(pages) {
  const out = [];
  pages.slice(0, MAX_PAGES).forEach((p, i) => {
    out.push({ type: 'text', text: `Page ${i} (0-based). Words on this page (text x0 y0 x1 y1):\n${wordsText(p.words)}` });
    if (p.image && /^[A-Za-z0-9+/=]+$/.test(p.image)) out.push({ type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: p.image } });
  });
  return out;
}

function logUsage(req, podId, kind, resp) {
  try {
    const its = (resp.usage && resp.usage.iterations) || [resp.usage || {}];
    let inTok = 0, outTok = 0, cacheTok = 0, cost = 0;
    its.forEach(u => {
      const pr = PRICES[u.model || resp.model] || PRICES[MODEL] || [0, 0, 0];
      const i = (u.input_tokens || 0) + (u.cache_creation_input_tokens || 0), o = u.output_tokens || 0, c = u.cache_read_input_tokens || 0;
      inTok += i; outTok += o; cacheTok += c;
      cost += (i * pr[0] + o * pr[1] + c * pr[2]) / 1e6;
    });
    const orgId = (req.user && req.user.orgId) || null, userId = (req.user && req.user.id) || null;
    db.prepare(`INSERT INTO ai_usage (id, orgId, userId, podId, kind, model, inputTokens, outputTokens, cacheReadTokens, costUsd, createdAt) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run(crypto.randomUUID(), orgId, userId, podId, kind, resp.model || MODEL, inTok, outTok, cacheTok, cost, Date.now());
    console.log(`[ai-place] ${kind} pod=${podId} model=${resp.model || MODEL} in=${inTok} out=${outTok} cacheRead=${cacheTok} cost=$${cost.toFixed(4)}`);
    return cost;
  } catch (e) { console.error('[ai-place] usage log failed', e.message); return null; }
}

// One structured-output request. Opts into server-side refusal fallbacks; if this account rejects that beta,
// retry once without it.
async function askJSON({ system, schema, content, effort }) {
  const c = client();
  if (!c) { const e = new Error('AI is not set up (ANTHROPIC_API_KEY missing)'); e.notConfigured = true; throw e; }
  const base = {
    model: MODEL,
    max_tokens: 16000,
    system,
    messages: [{ role: 'user', content }],
    output_config: { effort: effort || 'medium', format: { type: 'json_schema', schema } },
  };
  try {
    return await c.beta.messages.create({ ...base, betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' });
  } catch (e) {
    const Anthropic = require('@anthropic-ai/sdk'); const A = Anthropic.default || Anthropic;
    if (e instanceof A.BadRequestError && /fallback/i.test(String(e.message))) return await c.messages.create(base);
    throw e;
  }
}
const ask = (content) => askJSON({ system: SYSTEM, schema: FIELDS_SCHEMA, content });
// The JSON body of a structured-output response, or { error } for a refusal / cut-off / unreadable answer.
function readJSON(resp) {
  if (resp.stop_reason === 'refusal') return { error: 'refused' };
  if (resp.stop_reason === 'max_tokens') return { error: 'truncated' };
  const txt = (resp.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
  try { return { json: JSON.parse(txt) }; } catch (e) { return { error: 'unreadable' }; }
}

function parseFields(resp, pageCount) {
  const r = readJSON(resp); if (r.error) return r;
  const j = r.json;
  const clamp = n => Math.max(0, Math.min(1000, Number(n) || 0));
  const fields = (j.fields || []).filter(f => KINDS.includes(f.kind) && f.page >= 0 && f.page < pageCount).map(f => {
    const x0 = clamp(Math.min(f.x0, f.x1)), x1 = clamp(Math.max(f.x0, f.x1)), y0 = clamp(Math.min(f.y0, f.y1)), y1 = clamp(Math.max(f.y0, f.y1));
    return { id: String(f.id || ''), page: f.page, kind: f.kind, role: String(f.role || 'Consignee').slice(0, 40), label: String(f.label || '').slice(0, 60), x0, y0, x1, y1 };
  }).filter(f => f.x1 - f.x0 >= 5 && f.y1 - f.y0 >= 5);
  return { fields, note: String(j.note || '').slice(0, 300) };
}

function loadDoc(req, res) {
  const row = db.prepare(`SELECT * FROM pods WHERE id = ?`).get(req.params.id);
  if (!podsRouter.canAccess(req, row)) { res.status(404).json({ error: 'Not found' }); return null; }
  if (!client()) { res.status(503).json({ error: 'AI placement is not set up', fallback: true }); return null; }
  const pages = Array.isArray(req.body && req.body.pages) ? req.body.pages : [];
  if (!pages.length) { res.status(400).json({ error: 'No pages sent' }); return null; }
  return { row, pages };
}

function sendError(res, e) {
  console.error('[ai-place] request failed', e && (e.status || ''), e && e.message);
  res.status(502).json({ error: 'The AI could not place boxes right now', fallback: true });
}

// Is the real AI configured? (Lets the page label its buttons honestly.)
router.get('/ai-status', requireAuth, (req, res) => res.json({ enabled: !!client(), model: client() ? MODEL : null }));

router.post('/:id/ai-place', requireAuth, express.json({ limit: '25mb' }), async (req, res) => {
  const d = loadDoc(req, res); if (!d) return;
  const extra = String((req.body && req.body.instructions) || '').slice(0, 500);
  try {
    const content = [...pageBlocks(d.pages), { type: 'text', text: `Place the signature and date boxes this document needs for the driver to collect at delivery.${extra ? ' Dispatcher note: ' + extra : ''}` }];
    const resp = await ask(content);
    const cost = logUsage(req, d.row.id, 'place', resp);
    const out = parseFields(resp, Math.min(d.pages.length, MAX_PAGES));
    if (out.error) return res.status(422).json({ error: 'The AI could not place boxes on this document', reason: out.error, fallback: true });
    res.json({ ...out, model: resp.model, costUsd: cost });
  } catch (e) { sendError(res, e); }
});

router.post('/:id/ai-command', requireAuth, express.json({ limit: '25mb' }), async (req, res) => {
  const d = loadDoc(req, res); if (!d) return;
  const command = String((req.body && req.body.command) || '').trim().slice(0, 500);
  if (!command) return res.status(400).json({ error: 'Type or say a change first' });
  const current = (Array.isArray(req.body.fields) ? req.body.fields : []).slice(0, 200);
  try {
    const content = [...pageBlocks(d.pages), { type: 'text', text:
      `These boxes are on the document now (same coordinates):\n${JSON.stringify(current)}\n\n` +
      `The dispatcher says: "${command}"\n\nReturn the complete list of boxes after making that change — keep every box the change doesn't touch exactly as it is, with its id. New boxes get id "". If the request is unclear or impossible, return the boxes unchanged and say why in the note.` }];
    const resp = await ask(content);
    const cost = logUsage(req, d.row.id, 'command', resp);
    const out = parseFields(resp, Math.min(d.pages.length, MAX_PAGES));
    if (out.error) return res.status(422).json({ error: 'The AI could not make that change', reason: out.error, fallback: true });
    res.json({ ...out, model: resp.model, costUsd: cost });
  } catch (e) { sendError(res, e); }
});

module.exports = router;
// Shared with aidocs.js (the connector's server-side document prep).
module.exports.askJSON = askJSON;
module.exports.askFields = ask;
module.exports.readJSON = readJSON;
module.exports.parseFields = parseFields;
module.exports.logUsage = logUsage;
module.exports.wordsText = wordsText;
module.exports.enabled = () => !!client();
