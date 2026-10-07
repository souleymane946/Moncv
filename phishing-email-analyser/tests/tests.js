/* ============================================================================
   Tests automatises — Phishing Email Analyser
   ----------------------------------------------------------------------------
   Ces tests servent a verifier que le moteur se comporte comme prevu.
   Ils utilisent uniquement Node.js (aucune dependance a installer).

   Pour les executer (facultatif) :
       node tests/tests.js
   Le site lui-meme n'a PAS besoin de Node.js : c'est un simple fichier HTML.
   ============================================================================ */

'use strict';

const assert = require('assert');
const path = require('path');
const m = require(path.join(__dirname, '..', 'script.js'));

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  OK   ' + name); }
  catch (e) { failed++; console.log('  ECHEC ' + name + '\n        ' + e.message); }
}

console.log('\n== 1. Classification des exemples de demonstration ==');
const expected = {
  obvious: 'high', sophisticated: 'high', m365: 'high',
  parcel: 'suspect', bec: 'high', legit: 'low'
};
for (const s of m.SAMPLES) {
  test('exemple "' + s.id + '" => ' + expected[s.id], () => {
    const r = m.runAnalysis(s.text, {});
    assert.strictEqual(r.classification.key, expected[s.id],
      'attendu ' + expected[s.id] + ', obtenu ' + r.classification.key + ' (score ' + r.score + ')');
    assert.ok(r.score >= 0 && r.score <= 100, 'le score doit rester entre 0 et 100');
  });
}

console.log('\n== 2. L\'e-mail legitime ne doit pas declencher d\'alerte forte ==');
test('score de l\'e-mail legitime <= 24', () => {
  const r = m.runAnalysis(m.SAMPLES.find(s => s.id === 'legit').text, {});
  assert.ok(r.score <= 24, 'score obtenu : ' + r.score);
});

console.log('\n== 3. Robustesse : entrees invalides ==');
test('texte vide ne plante pas', () => {
  const r = m.runAnalysis('', {});
  assert.strictEqual(r.score, 0);
  assert.strictEqual(r.findings.length, 0);
});
test('texte aleatoire ne plante pas', () => {
  const r = m.runAnalysis('aaaa bbbb cccc dddd', {});
  assert.ok(typeof r.score === 'number');
});
test('caracteres speciaux ne plantent pas', () => {
  const r = m.runAnalysis('*** [[[ <<< >>> ]]] \\u0000 \\uFFFF', {});
  assert.ok(typeof r.score === 'number');
});
test('en-tetes incomplets ne plantent pas', () => {
  const r = m.runAnalysis('From:\nReply-To:\nAuthentication-Results:', {});
  assert.ok(typeof r.score === 'number');
});

console.log('\n== 4. Securite : le contenu de l\'e-mail ne doit pas devenir du HTML ==');
test('escapeHtml neutralise les balises', () => {
  const out = m.escapeHtml('<script>alert(1)</script>');
  assert.ok(out.indexOf('<script>') === -1, 'la balise ne doit pas rester intacte');
  assert.ok(out.indexOf('&lt;script&gt;') !== -1, 'elle doit etre encodee');
});
test('un payload HTML dans l\'e-mail n\'est jamais interprete', () => {
  const r = m.runAnalysis(
    'From: a@exemple.test\nSubject: urgent\n\n<img src=x onerror=alert(1)> verifiez votre compte ' +
    'http://192.0.2.5/login et saisissez votre mot de passe', {});
  for (const f of r.findings) {
    for (const e of f.evidence) assert.strictEqual(typeof e, 'string');
  }
  assert.ok(r.score > 0, 'des signes d\'alerte doivent etre detectes');
});

console.log('\n== 5. Analyse des liens ==');
test('lien avec adresse IP detecte', () => {
  const links = m.extractLinks('voir http://192.0.2.10/connexion');
  assert.strictEqual(links.length, 1);
  assert.strictEqual(m.isIpHost(m.hostOf(links[0].url)), true);
});
test('lien raccourci detecte', () => {
  const r = m.runAnalysis('cliquez ici : https://bit.ly/abc123', {});
  assert.ok(r.findings.some(f => f.id === 'short_url'));
});
test('texte de lien trompeur detecte', () => {
  const r = m.runAnalysis('[www.banque-exemple.test](http://198.51.100.9/login)', {});
  assert.ok(r.findings.some(f => f.id === 'misleading_link'));
});
test('un lien https normal ne declenche pas ip_url', () => {
  const r = m.runAnalysis('voir https://www.groupe-exemple.test/catalogue', {});
  assert.ok(!r.findings.some(f => f.id === 'ip_url'));
});

console.log('\n== 6. Pieces jointes ==');
test('executable detecte', () => {
  const r = m.runAnalysis('Veuillez ouvrir Facture_2024.exe', {});
  assert.ok(r.findings.some(f => f.id === 'attachment_exec'));
});
test('pas de double comptage exec + inhabituel', () => {
  const r = m.runAnalysis('Veuillez ouvrir Facture_2024.exe', {});
  assert.ok(!r.findings.some(f => f.id === 'attachment_unusual'));
});
test('document Word normal non signale', () => {
  const r = m.runAnalysis('Vous trouverez le compte rendu dans CR_2024.docx', {});
  assert.ok(!r.findings.some(f => f.id === 'attachment_exec'));
});


console.log('\n== 7. En-tetes d\'authentification ==');
test('SPF / DKIM / DMARC lus correctement', () => {
  const h = m.parseHeaders(
    'Authentication-Results: mx.test; spf=fail; dkim=pass; dmarc=fail\n' +
    'From: "Support" <support@micros0ft-verification.test>\n' +
    'Reply-To: aide@autre-domaine.test\n');
  const a = m.authResults(h);
  assert.strictEqual(a.spf, 'fail');
  assert.strictEqual(a.dkim, 'pass');
  assert.strictEqual(a.dmarc, 'fail');
});
test('echec SPF genere une alerte', () => {
  const r = m.runAnalysis('Authentication-Results: mx.test; spf=fail\n\nBonjour', {});
  assert.ok(r.findings.some(f => f.id === 'spf_fail'));
});
test('ligne d\'en-tete repliee (continuation) geree', () => {
  const h = m.parseHeaders('Authentication-Results: mx.test;\n  spf=fail; dkim=pass\n');
  assert.strictEqual(m.authResults(h).spf, 'fail');
});

console.log('\n== 8. Domaine sosie ==');
test('"micros0ft" reconnu comme sosie de microsoft', () => {
  const r = m.runAnalysis('From: "MS" <x@micros0ft-verification.test>\n\nBonjour', {});
  assert.ok(r.findings.some(f => f.id === 'lookalike_domain'));
});
test('domaine normal non signale comme sosie', () => {
  const r = m.runAnalysis('From: "News" <actualites@groupe-exemple.test>\n\nBonjour', {});
  assert.ok(!r.findings.some(f => f.id === 'lookalike_domain'));
});

console.log('\n== 9. Options (cases a cocher) ==');
test('en-tetes desactives => pas d\'alerte SPF', () => {
  const r = m.runAnalysis('Authentication-Results: mx.test; spf=fail\n\nBonjour', { headers: false });
  assert.ok(!r.findings.some(f => f.id === 'spf_fail'));
});
test('liens desactives => pas d\'alerte URL', () => {
  const r = m.runAnalysis('http://192.0.2.9/login', { links: false });
  assert.ok(!r.findings.some(f => f.id === 'ip_url'));
});

console.log('\n== 10. Coherence du score ==');
test('le score est la somme des poids, plafonnee a 100', () => {
  const r = m.runAnalysis(m.SAMPLES.find(s => s.id === 'sophisticated').text, {});
  const sum = r.findings.reduce((s, f) => s + f.weight, 0);
  assert.strictEqual(r.score, Math.min(100, sum));
});
test('chaque alerte explique pourquoi (champs non vides)', () => {
  for (const s of m.SAMPLES) {
    const r = m.runAnalysis(s.text, {});
    for (const f of r.findings) {
      assert.ok(f.why && f.why.length > 20, 'regle ' + f.id + ' sans explication');
      assert.ok(f.benign && f.benign.length > 20, 'regle ' + f.id + ' sans explication benigne');
      assert.ok(f.evidence.length > 0, 'regle ' + f.id + ' sans preuve');
    }
  }
});

console.log('\n---------------------------------------------');
console.log('  Tests reussis : ' + passed);
console.log('  Tests echoues : ' + failed);
console.log('---------------------------------------------\n');
process.exit(failed ? 1 : 0);

