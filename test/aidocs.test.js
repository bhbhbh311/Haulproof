// A saved signature layout skips blank pages (e.g. the empty 2nd page a Word export leaves behind).
// Run: npm test
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-aidocs-'));
const { PDFDocument, StandardFonts } = require('pdf-lib');
const aidocs = require('../aidocs');

const LAYOUT = [
  { pageIdx: 0, kind: 'sig', role: 'Driver', xPdf: 333, yPdf: 43, wPdf: 148, hPdf: 12, baseW: 612, baseH: 792 },
  { pageIdx: 0, kind: 'date', role: 'Driver', xPdf: 510, yPdf: 43, wPdf: 62, hPdf: 11, baseW: 612, baseH: 792 },
];

async function pdf(pages) {   // pages: array of 'text' | 'blank'
  const doc = await PDFDocument.create(), font = await doc.embedFont(StandardFonts.Helvetica);
  pages.forEach(k => { const p = doc.addPage([612, 792]); if (k === 'text') p.drawText('Bill of Lading - Carrier: ______ Date: ____', { x: 50, y: 700, size: 12, font }); });
  return Buffer.from(await doc.save());
}

test('pageInfo flags an empty page as blank, a page with text as not', async () => {
  const info = await aidocs.pageInfo(await pdf(['text', 'blank']));
  assert.deepStrictEqual(info.pages.map(p => p.blank), [false, true]);
});

test('layoutToFields skips blank pages', async () => {
  const info = await aidocs.pageInfo(await pdf(['text', 'blank', 'text']));
  const f = aidocs.layoutToFields(LAYOUT, info.numPages, info.pages.map(p => p.blank));
  assert.deepStrictEqual([...new Set(f.map(x => x.pageIdx))], [0, 2]);
  assert.strictEqual(f.length, 4);
});

test('layoutToFields stamps every page when all look blank, or when no blank info is given', () => {
  assert.strictEqual(aidocs.layoutToFields(LAYOUT, 2, [true, true]).length, 4);
  assert.strictEqual(aidocs.layoutToFields(LAYOUT, 3).length, 6);
});
