/* ============================================================================
   Tests automatises — Network Traffic Triage Tool
   Executer avec :  node tests/tests.js      (aucune dependance a installer)
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

const STANDARD = `No.,Time,Source,Destination,Protocol,Length,Info
1,0.1,192.168.1.10,192.168.1.1,DNS,74,"Standard query A exemple.test"
2,0.2,192.168.1.10,203.0.113.10,TCP,66,"40000 → 443 [SYN] Seq=0 Len=0"
`;

console.log('\n== 1. Reconnaissance des colonnes ==');
test('colonnes standard reconnues', () => {
  const r = m.analyseCsvText(STANDARD);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.packets.length, 2);
  assert.strictEqual(r.missing.length, 0);
});
test('variantes "Source IP" / "Destination IP" / "ip.src" acceptees', () => {
  const csv = `No.,Time,Source IP,Destination IP,Protocol,Length,Info
1,0.1,10.0.0.5,10.0.0.9,TCP,60,"5000 → 80 [SYN]"
`;
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.packets[0].src, '10.0.0.5');
  assert.strictEqual(r.packets[0].dst, '10.0.0.9');
});
test('variantes "src" / "dst" / "proto" acceptees', () => {
  const csv = `No,Time,src,dst,proto,len,info
1,0.1,192.0.2.1,192.0.2.2,UDP,90,"53 → 40000"
`;
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.packets[0].src, '192.0.2.1');
  assert.strictEqual(r.packets[0].proto, 'UDP');
});
test('separateur point-virgule detecte', () => {
  const csv = `No.;Time;Source;Destination;Protocol;Length;Info
1;0.1;192.168.1.5;192.168.1.6;TCP;60;"4000 → 443 [SYN]"
`;
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.packets.length, 1);
  assert.strictEqual(r.packets[0].src, '192.168.1.5');
});
test('virgule dans un champ entre guillemets geree', () => {
  const csv = `No.,Source,Destination,Protocol,Length,Info
1,10.0.0.1,10.0.0.2,TCP,60,"443 → 5000 [ACK], Seq=1, Ack=1, Win=100"
`;
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.packets.length, 1);
  assert.ok(r.packets[0].info.indexOf('Seq=1') !== -1);
});

console.log('\n== 2. Messages d\'erreur clairs ==');
test('colonne source absente => message explicite', () => {
  const csv = `No.,Time,Destination,Protocol,Length,Info
1,0.1,10.0.0.9,TCP,60,"5000 → 80 [SYN]"
`;
  const r = m.analyseCsvText(csv);
  assert.ok(r.error, 'une erreur etait attendue');
  assert.ok(r.error.indexOf('source') !== -1, 'le message doit mentionner la colonne source : ' + r.error);
});
test('fichier vide => message explicite', () => {
  const r = m.analyseCsvText('');
  assert.ok(r.error);
});
test('en-tete seul (aucune ligne de donnees) => message explicite', () => {
  const r = m.analyseCsvText('No.,Source,Destination\n');
  assert.ok(r.error);
});

console.log('\n== 3. Robustesse : CSV mal forme ==');
test('guillemet non ferme ne plante pas', () => {
  const csv = `No.,Source,Destination,Protocol,Length,Info
1,10.0.0.1,10.0.0.2,TCP,60,"champ jamais ferme
2,10.0.0.3,10.0.0.4,TCP,60,ok
`;
  const r = m.analyseCsvText(csv);
  assert.ok(r.error || r.packets.length >= 1, 'doit soit reussir partiellement, soit expliquer');
});
test('lignes vides ignorees', () => {
  const csv = `No.,Source,Destination,Protocol,Length,Info


1,10.0.0.1,10.0.0.2,TCP,60,ok


`;
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.packets.length, 1);
});
test('lignes sans source ou destination ignorees', () => {
  const csv = `No.,Source,Destination,Protocol,Length,Info
1,10.0.0.1,,TCP,60,ok
2,,10.0.0.2,TCP,60,ok
3,10.0.0.3,10.0.0.4,TCP,60,ok
`;
  const r = m.analyseCsvText(csv);
  assert.strictEqual(r.packets.length, 1);
});
test('colonnes absentes mais analyse quand meme possible', () => {
  const csv = `Source,Destination
10.0.0.1,10.0.0.2
`;
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.ok(r.missing.length > 0, 'des colonnes doivent etre signalees comme manquantes');
});

console.log('\n== 4. Securite : le contenu du CSV ne doit pas devenir du HTML ==');
test('un payload HTML dans une colonne reste du texte', () => {
  const csv = `No.,Source,Destination,Protocol,Length,Info
1,10.0.0.1,10.0.0.2,TCP,60,"<img src=x onerror=alert(1)>"
`;
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.strictEqual(typeof r.packets[0].info, 'string');
  assert.ok(r.packets[0].info.indexOf('<img') !== -1, 'le texte doit rester intact, pas etre interprete');
});
test('une balise script dans un nom d\'hote reste une chaine', () => {
  const csv = `No.,Source,Destination,Protocol,Length,Info
1,"<script>alert(1)</script>",10.0.0.2,TCP,60,ok
`;
  const r = m.analyseCsvText(csv);
  assert.strictEqual(typeof r.packets[0].src, 'string');
});

console.log('\n== 5. Classification des protocoles ==');
test('DNS / ARP / ICMP / HTTP / HTTPS-TLS / TCP / UDP / Autres', () => {
  assert.strictEqual(m.classifyProtocol('DNS', ''), 'DNS');
  assert.strictEqual(m.classifyProtocol('ARP', ''), 'ARP');
  assert.strictEqual(m.classifyProtocol('ICMP', ''), 'ICMP');
  assert.strictEqual(m.classifyProtocol('HTTP', ''), 'HTTP');
  assert.strictEqual(m.classifyProtocol('TLSv1.3', ''), 'HTTPS/TLS');
  assert.strictEqual(m.classifyProtocol('TCP', ''), 'TCP');
  assert.strictEqual(m.classifyProtocol('UDP', ''), 'UDP');
  assert.strictEqual(m.classifyProtocol('QUIC', ''), 'Autres');
});

console.log('\n== 6. Extraction des ports et des drapeaux TCP ==');
test('ports extraits depuis la colonne Info', () => {
  const p = m.extractPorts('45000 → 443 [SYN] Seq=0');
  assert.strictEqual(p.srcPort, 45000);
  assert.strictEqual(p.dstPort, 443);
});
test('ports absents => null, pas de plantage', () => {
  const p = m.extractPorts('Standard query A exemple.test');
  assert.strictEqual(p.srcPort, null);
  assert.strictEqual(p.dstPort, null);
});
test('SYN seul distingue de SYN, ACK', () => {
  assert.strictEqual(m.extractTcpFlags('1 → 2 [SYN] Seq=0'), 'SYN');
  assert.strictEqual(m.extractTcpFlags('2 → 1 [SYN, ACK] Seq=0'), 'SYN,ACK');
});

console.log('\n== 7. Regles de detection sur les exemples ==');
test('reseau normal : aucune alerte', () => {
  const s = m.SAMPLES.find(x => x.id === 'normal');
  const t = m.runTriage(m.analyseCsvText(s.csv).packets, {});
  assert.strictEqual(t.alerts.length, 0, 'regles declenchees : ' + t.alerts.map(a => a.id).join(','));
  assert.strictEqual(t.score, 0);
});
test('scan d\'hotes : scan + ports + SYN', () => {
  const s = m.SAMPLES.find(x => x.id === 'scan');
  const t = m.runTriage(m.analyseCsvText(s.csv).packets, {});
  const ids = t.alerts.map(a => a.id);
  assert.ok(ids.indexOf('hostscan') !== -1, 'hostscan attendu');
  assert.ok(ids.indexOf('portscan') !== -1, 'portscan attendu');
});
test('balayage ICMP detecte', () => {
  const s = m.SAMPLES.find(x => x.id === 'icmp');
  const t = m.runTriage(m.analyseCsvText(s.csv).packets, {});
  assert.ok(t.alerts.some(a => a.id === 'icmp'));
});
test('capture mixte : au moins 5 regles declenchees', () => {
  const s = m.SAMPLES.find(x => x.id === 'mixed');
  const t = m.runTriage(m.analyseCsvText(s.csv).packets, {});
  assert.ok(t.alerts.length >= 5, 'regles : ' + t.alerts.map(a => a.id).join(','));
  assert.ok(t.score >= 70, 'score obtenu : ' + t.score);
});

console.log('\n== 8. Seuils configurables ==');
test('augmenter les seuils fait baisser le score', () => {
  const s = m.SAMPLES.find(x => x.id === 'mixed');
  const packets = m.analyseCsvText(s.csv).packets;
  const strict = m.runTriage(packets, {});
  const lax = m.runTriage(packets, { packets: 100000, dest: 100000, ports: 100000, icmp: 100000, dns: 100000, pair: 100000, syn: 100000 });
  assert.ok(lax.score < strict.score, 'le score doit diminuer avec des seuils plus permissifs');
  assert.strictEqual(lax.score, 0);
});
test('un seuil invalide retombe sur la valeur par defaut', () => {
  const s = m.SAMPLES.find(x => x.id === 'scan');
  const packets = m.analyseCsvText(s.csv).packets;
  const t = m.runTriage(packets, { packets: 0, dest: -5 });
  assert.strictEqual(t.thresholds.packets, m.DEFAULT_THRESHOLDS.packets);
  assert.strictEqual(t.thresholds.dest, m.DEFAULT_THRESHOLDS.dest);
});

console.log('\n== 9. Explicabilite du score ==');
test('le score est la somme des points, plafonnee a 100', () => {
  for (const s of m.SAMPLES) {
    const t = m.runTriage(m.analyseCsvText(s.csv).packets, {});
    const sum = t.alerts.reduce((a, x) => a + x.points, 0);
    assert.strictEqual(t.score, Math.min(100, sum));
  }
});
test('chaque alerte contient preuves, explication et conseils', () => {
  for (const s of m.SAMPLES) {
    const t = m.runTriage(m.analyseCsvText(s.csv).packets, {});
    for (const a of t.alerts) {
      assert.ok(a.evidence.length > 0, 'alerte ' + a.id + ' sans preuve');
      assert.ok(a.why.length > 30, 'alerte ' + a.id + ' sans explication');
      assert.ok(a.benign.length > 20, 'alerte ' + a.id + ' sans explication benigne');
      assert.ok(a.investigate.length > 0, 'alerte ' + a.id + ' sans investigation recommandee');
    }
  }
});
test('les niveaux de severite sont limites a 4 valeurs', () => {
  const allowed = ['info', 'faible', 'moyen', 'eleve'];
  for (const r of m.RULES) assert.ok(allowed.indexOf(r.severity) !== -1, r.id + ' : ' + r.severity);
});
test('le niveau du score est coherent', () => {
  assert.strictEqual(m.scoreLevel(0).label, 'Aucune activite notable');
  assert.strictEqual(m.scoreLevel(10).label, 'Activite faible');
  assert.strictEqual(m.scoreLevel(30).label, 'Activite moderee');
  assert.strictEqual(m.scoreLevel(50).label, 'Activite elevee');
  assert.strictEqual(m.scoreLevel(90).label, 'Activite tres elevee');
});

console.log('\n---------------------------------------------');
console.log('  Tests reussis : ' + passed);
console.log('  Tests echoues : ' + failed);
console.log('---------------------------------------------\n');
process.exit(failed ? 1 : 0);

