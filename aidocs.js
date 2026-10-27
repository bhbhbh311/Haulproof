// Server-side document prep for the AI connector (mcp.js): read a PDF's pages, have Claude label them
// (review_pages), cut a PDF down to chosen pages (trim_document), and place signature boxes without the browser
// (place_signatures). The browser signature-setup page does the same placement with its own text recognition;
// here the words and their positions come from the PDF's own text layer, and Claude sees the PDF itself.
const { PDFDocument } = require('pdf-lib');
const aiplace = require('./aiplace');

let _pdfjs = null;
function pdfjs() { if (!_pdfjs) _pdfjs = require('pdfjs-dist/legacy/build/pdf.js'); return _pdfjs; }

// Each page's size (PDF points) and its text, as [text, x0, y0, x1, y1] in 0-1000 page coordinates (top-left origin).
async function pageInfo(buf) {
  const doc = await pdfjs().getDocument({ data: new Uint8Array(buf), verbosity: 0, isEvalSupported: false, disableFontFace: true }).promise;
  const pages = [];
  for (let n = 1; n <= doc.numPages; n++) {
    const page = await doc.getPage(n);
    const base = page.getViewport({ scale: 1 }), vp = base;   // vp handles any page rotation
    const W = vp.width, H = vp.height, words = [];
    let txt = { items: [] }; try { txt = await page.getTextContent(); } catch (e) {}
    txt.items.forEach(it => {
      const s = String(it.str || '').trim(); if (!s) return;
      const e = it.transform[4], f = it.transform[5], h = it.height || Math.abs(it.transform[3]) || 8;
      const a = vp.convertToViewportPoint(e, f), b = vp.convertToViewportPoint(e + (it.width || 0), f + h);
      const x0 = Math.min(a[0], b[0]), x1 = Math.max(a[0], b[0]), y0 = Math.min(a[1], b[1]), y1 = Math.max(a[1], b[1]);
      words.push([s.slice(0, 60), x0 * 1000 / W, y0 * 1000 / H, x1 * 1000 / W, y1 * 1000 / H]);
    });
    const raw = page.getViewport({ scale: 1, rotation: 0 });
    pages.push({ W, H, vp, baseW: raw.width, baseH: raw.height, words, text: words.map(w => w[0]).join(' ') });
  }
  return { numPages: doc.numPages, pages };
}

// ---- review_pages: label every page and suggest which to keep for the driver to sign ----
const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    pages: { type: 'array', items: { type: 'object', properties: {
      page: { type: 'integer', description: '1-based page number' },
      kind: { type: 'string', enum: ['bol', 'delivery_receipt', 'packing_list', 'terms', 'certificate', 'invoice', 'rate_confirmation', 'blank', 'other'] },
      label: { type: 'string', description: 'short description, e.g. "Brown Strauss BOL, shipment 94505"' },
      shipment: { type: 'string', description: 'shipment / BOL number printed on the page, or ""' },
      keep: { type: 'boolean', description: 'true if the driver needs this page in front of the receiver to sign' },
      reason: { type: 'string' },
    }, required: ['page', 'kind', 'label', 'shipment', 'keep', 'reason'], additionalProperties: false } },
    note: { type: 'string', description: 'one or two sentences for the dispatcher' },
  },
  required: ['pages', 'note'], additionalProperties: false,
};
const REVIEW_SYSTEM = `You help a trucking dispatcher prepare paperwork for a driver to have signed at delivery. A PDF often bundles the bill of lading with pages the receiver never signs: terms and conditions, mill test certificates / material certifications, invoices, rate confirmations, blank pages. Label every page and mark keep=true only for pages the driver needs signed at delivery — normally the bill of lading / delivery receipt pages (including every page of a multi-page BOL, which often reads "Page 1 of 2", "Page 2 of 2"). Read the page itself, not just its position. If you are unsure about a page, keep it and say why.`;

async function reviewPages(reqLike, podId, buf, info) {
  const content = [
    { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: buf.toString('base64') } },
    { type: 'text', text: 'Page text, for reference:\n' + info.pages.map((p, i) => `--- Page ${i + 1} ---\n${p.text.slice(0, 2500)}`).join('\n') },
    { type: 'text', text: `Label each of the ${info.numPages} pages and say which to keep.` },
  ];
  const resp = await aiplace.askJSON({ system: REVIEW_SYSTEM, schema: REVIEW_SCHEMA, content });
  const cost = aiplace.logUsage(reqLike, podId, 'review', resp);
  const out = aiplace.readJSON(resp);
  if (out.error) return out;
  const pages = (out.json.pages || []).filter(p => p.page >= 1 && p.page <= info.numPages);
  return { pages, keep_pages: pages.filter(p => p.keep).map(p => p.page), note: out.json.note || '', costUsd: cost };
}

// ---- trim_document: a new PDF holding only `pages` (1-based, in the order given) ----
async function subsetPdf(buf, pages) {
  const src = await PDFDocument.load(buf, { ignoreEncryption: true });
  const out = await PDFDocument.create();
  const copied = await out.copyPages(src, pages.map(p => p - 1));
  copied.forEach(pg => out.addPage(pg));
  return Buffer.from(await out.save());
}

// ---- place_signatures: fields in the shape the setup page saves ({pageIdx, kind, role, xPdf, ...}) ----
function normToField(info, nf) {
  const p = info.pages[nf.page]; if (!p) return null;
  const a = p.vp.convertToPdfPoint(nf.x0 * p.W / 1000, nf.y1 * p.H / 1000), b = p.vp.convertToPdfPoint(nf.x1 * p.W / 1000, nf.y0 * p.H / 1000);
  let role = nf.role || 'Consignee';
  if (nf.kind === 'pickupdate' || nf.kind === 'puin' || nf.kind === 'puout') role = 'Pickup';
  const f = { pageIdx: nf.page, kind: nf.kind, role, label: nf.label || '',
    xPdf: Math.min(a[0], b[0]), yPdf: Math.min(a[1], b[1]), wPdf: Math.abs(b[0] - a[0]), hPdf: Math.abs(b[1] - a[1]), baseW: p.baseW, baseH: p.baseH };
  return growAutoField(f, p.baseW);
}
// Date/time boxes must fit what gets stamped in them (same minimums as the setup page).
function growAutoField(f, baseW) {
  const m = (f.kind === 'date' || f.kind === 'pickupdate') ? { w: 64, h: 16 } : (['puin', 'puout', 'dlin', 'dlout'].includes(f.kind) ? { w: 56, h: 16 } : null);
  if (!m) return f;
  if (f.wPdf < m.w) { f.wPdf = m.w; if (baseW && f.xPdf + f.wPdf > baseW) f.xPdf = Math.max(0, baseW - f.wPdf); }
  if (f.hPdf < m.h) { f.yPdf = Math.max(0, f.yPdf - (m.h - f.hPdf) / 2); f.hPdf = m.h; }
  return f;
}
// A saved customer layout: the page with the most boxes is the pattern, stamped onto every page (as the setup page does).
function layoutToFields(layout, numPages) {
  const byPage = {};
  (layout || []).forEach(f => { const p = f.pageIdx || 0; (byPage[p] = byPage[p] || []).push(f); });
  const keys = Object.keys(byPage); if (!keys.length) return [];
  let best = keys[0];
  keys.forEach(k => { if (byPage[k].length > byPage[best].length || (byPage[k].length === byPage[best].length && (+k) < (+best))) best = k; });
  const out = [];
  for (let i = 0; i < numPages; i++) byPage[best].forEach(f => { const c = { ...f, pageIdx: i }; delete c.value; out.push(c); });
  return out;
}
async function aiFields(reqLike, podId, buf, info) {
  const content = [
    { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: buf.toString('base64') } },
    ...info.pages.map((p, i) => ({ type: 'text', text: `Page ${i} (0-based). Words on this page (text x0 y0 x1 y1):\n` + aiplace.wordsText(p.words) })),
    { type: 'text', text: 'Place the signature and date boxes this document needs for the driver to collect at delivery. The page images are the PDF above.' },
  ];
  const resp = await aiplace.askFields(content);
  const cost = aiplace.logUsage(reqLike, podId, 'place-server', resp);
  const out = aiplace.parseFields(resp, info.numPages);
  if (out.error) return out;
  return { fields: out.fields.map(nf => normToField(info, nf)).filter(Boolean), note: out.note, costUsd: cost, model: resp.model };
}

module.exports = { pageInfo, reviewPages, subsetPdf, aiFields, layoutToFields };
