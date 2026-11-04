// Keeps slurs and curse words out of the names and answers people type into HaulProof (renamed fields, the company's
// own load fields and driver steps, and the values filled in on a load). The list is stored encoded so it doesn't sit
// in the code as plain text. Matching ignores case, common look-alikes (f*ck, sh1t, $hit, a$$) and spacing tricks,
// but only blocks whole words (plus a few unmistakable roots), so ordinary words like "class" or "Scunthorpe" pass.
const LIST = JSON.parse(Buffer.from('eyJ3IjogWyJzaGl0IiwgInNoaXR0eSIsICJidWxsc2hpdCIsICJhc3MiLCAiYXNzaG9sZSIsICJhcnNlIiwgImJpdGNoIiwgImJhc3RhcmQiLCAiZGlja2hlYWQiLCAiY29jayIsICJwdXNzeSIsICJwaXNzIiwgInBpc3NlZCIsICJzbHV0IiwgIndob3JlIiwgInR3YXQiLCAid2Fua2VyIiwgInByaWNrIiwgImRvdWNoZSIsICJkb3VjaGViYWciLCAiamFja2FzcyIsICJkdW1iYXNzIiwgImZhZyIsICJkeWtlIiwgInRyYW5ueSIsICJyZXRhcmQiLCAicmV0YXJkZWQiLCAic3BpYyIsICJzcGljayIsICJjaGluayIsICJnb29rIiwgImtpa2UiLCAid2V0YmFjayIsICJiZWFuZXIiLCAiY29vbiIsICJqaWdhYm9vIiwgInBvcmNobW9ua2V5IiwgInJhZ2hlYWQiLCAidG93ZWxoZWFkIiwgIm5hemkiLCAicmFwZSIsICJyYXBpc3QiLCAibW9sZXN0IiwgInBlZG8iLCAicGVkb3BoaWxlIiwgInBvcm4iLCAiYm9vYnMiLCAidGl0cyIsICJ0aXR0aWVzIiwgImN1bSIsICJqaXp6IiwgImRpbGRvIiwgImJsb3dqb2IiLCAiaGFuZGpvYiIsICJob3JueSIsICJza2FuayIsICJ0aG90IiwgImN1Y2siLCAia3lzIiwgImN1bnQiLCAiZ29kZGFtbiJdLCAiciI6IFsiZnVjayIsICJuaWdnIiwgImZhZ2dvdCIsICJtb3RoZXJmIiwgInNoaXRoZWFkIiwgImNvY2tzdWNrIiwgInNvbm9mYWJpdGNoIl19', 'base64').toString('utf8'));
const WORDS = new Set(LIST.w), ROOTS = LIST.r;
const LEET = { '0': 'o', '1': 'i', '!': 'i', '|': 'i', '3': 'e', '4': 'a', '@': 'a', '5': 's', '$': 's', '7': 't', '+': 't', '8': 'b', '9': 'g' };
const ENDINGS = ['', 's', 'es', 'ed', 'er', 'ers', 'ing', 'in'];

function normalize(text) {
  return String(text || '').toLowerCase().replace(/[0-9!|@$+]/g, c => LEET[c] || c).replace(/(.)\1{2,}/g, '$1$1');
}
// The bad word found in this text, or null
function findBad(text) {
  const n = normalize(text);
  const tokens = n.split(/[^a-z*]+/).filter(Boolean);
  for (const t0 of tokens) {
    const t = t0.replace(/\*/g, '');
    const masked = t0.includes('*');
    for (const w of WORDS) for (const e of ENDINGS) {
      if (t === w + e) return w;
      if (masked && t0.length === (w + e).length && new RegExp('^' + t0.replace(/\*/g, '.') + '$').test(w + e) && w.length >= 4) return w;
    }
    for (const r of ROOTS) {
      if (t.includes(r)) return r;
      if (masked && t0.length >= r.length && new RegExp('^' + t0.slice(0, r.length).replace(/\*/g, '.') + '$').test(r) && t0.slice(0, r.length).replace(/\*/g, '').length >= 2) return r;
    }
  }
  // spaced or dotted out: "f u c k", "s.h.i.t"
  const squeezed = n.replace(/[^a-z]/g, '');
  for (const r of ROOTS) if (squeezed.includes(r) && !tokens.some(t => t.includes(r))) {
    const singles = n.split(/[^a-z]+/).filter(Boolean);
    if (singles.length >= r.length - 1 && singles.every(s => s.length <= 2)) return r;
  }
  return null;
}
// Throw the caller's own error type with a plain message
function check(text, what, Err) {
  if (findBad(text)) throw new (Err || Error)(`${what || 'That'} has a word that isn't allowed in HaulProof. Please reword it.`);
  return text;
}
module.exports = { findBad, check };
