// Receiver "Comments" box on the driver's signing screen: always optional, never blocks signing, reads "Comments".
// These check the page's own code without a server, so they run even where the database module can't load.
// Run: npm test
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const read = f => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
const driver = read('haulproof_driver.html');
const prepare = read('prepare.html');

// Pull one named function's source out of a page (matching braces), so it can be run here on its own.
function fnSource(src, name) {
  const start = src.indexOf('function ' + name + '(');
  assert.ok(start >= 0, name + ' is in the page');
  let i = src.indexOf('{', start), depth = 0;
  for (; i < src.length; i++) { if (src[i] === '{') depth++; else if (src[i] === '}' && --depth === 0) break; }
  return src.slice(start, i + 1);
}
function load(src, names, extra = '') {
  const body = names.map(n => fnSource(src, n)).join('\n') + '\n' + extra + '\nreturn {' + names.join(',') + '};';
  return new Function('fields', 'updateProgress', body);
}

test('driver and signature-setup page scripts still parse', () => {
  for (const s of [driver, prepare]) for (const m of s.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g)) assert.doesNotThrow(() => new Function(m[1]));
});

test('comments box: "Notes", blank and similar labels show as "Comments"; other names stay', () => {
  const { textLabel, valueLabel } = load(driver, ['textLabel', 'valueLabel'])([]);
  for (const l of ['Notes', 'notes', ' Note ', 'Remarks', 'Comments', '', null, undefined]) assert.equal(textLabel(l), 'Comments', String(l));
  assert.equal(textLabel('Seal #'), 'Seal #');
  assert.equal(valueLabel({ kind: 'text', label: 'Notes' }), 'Comments');
  assert.equal(valueLabel({ kind: 'time', label: '' }), 'Time');
  assert.equal(valueLabel({ kind: 'initials', label: '' }), 'Initials');
});

test('comments box: an empty box says it is optional; a filled one shows what was typed', () => {
  const { valueContent } = load(driver, ['esc2', 'textLabel', 'valueLabel', 'valueContent'])([]);
  const empty = valueContent({ kind: 'text', label: 'Notes', value: '' });
  assert.match(empty, /Comments \(optional\)/);
  assert.doesNotMatch(empty, /Notes/);
  assert.match(valueContent({ kind: 'text', label: 'Notes', value: '2 bundles scratched' }), /2 bundles scratched/);
});

test('comments box: "No comments" leaves it blank, typed comments are kept on one line', () => {
  let progress = 0;
  const fakeField = () => ({ kind: 'text', label: 'Notes', value: 'old', el: { querySelector: () => ({}), classList: { toggle() {} } } });
  const fields = [fakeField()];
  const { setValue, blankTextBoxes } = load(driver, ['esc2', 'textLabel', 'valueLabel', 'valueContent', 'setValue', 'blankTextBoxes'])(fields, () => progress++);
  setValue(fields[0], '');
  assert.equal(fields[0].value, '');
  assert.equal(blankTextBoxes().length, 1);
  setValue(fields[0], '  2 bundles\nscratched ');
  assert.equal(fields[0].value, '2 bundles scratched');
  assert.equal(blankTextBoxes().length, 0);
  assert.ok(progress >= 2, 'the banner refreshes after each change');
});

test('signing never asks for comments: finish only checks the PO #, and the old "Enter Notes" prompt is gone', () => {
  const finish = fnSource(driver, 'finish');
  assert.doesNotMatch(finish, /kind\s*===?\s*"text"[^;]*!/, 'finish() does not hold back on an empty text box');
  assert.match(finish, /PO # is required/);
  const onValue = fnSource(driver, 'onValue');
  assert.match(onValue, /kind==="text"\)\{ openComments/, 'text boxes open the Comments sheet, not a bare prompt');
  assert.match(driver, /id="commentSkip"[^>]*>No comments</);
  assert.match(driver, /<em[^>]*>optional<\/em>/);
  assert.doesNotMatch(driver, /Enter Notes/);
});

test('signature setup: a new text box is named "Comments"; old "Notes" boxes show as "Comments (optional)"', () => {
  const { defaultLabel } = load(prepare, ['defaultLabel'])([]);
  assert.equal(defaultLabel('text'), 'Comments');
  const { labelText } = load(prepare, ['labelText'], 'var AUTO_TIME_KINDS = {};')([]);
  assert.equal(labelText('Consignee', 'text', 'Notes'), 'Comments (optional)');
  assert.equal(labelText('Consignee', 'text', ''), 'Comments (optional)');
  assert.equal(labelText('Consignee', 'text', 'Seal #'), 'Seal #');
});
