/* ============================================================================
   Tests adversariaux (fuzzing) et de performance
   ----------------------------------------------------------------------------
   Objectif : essayer de CASSER les outils.
   On leur envoie des entrees hostiles, enormes ou mal formees, et on verifie
   qu'ils ne plantent jamais, qu'ils ne partent pas en boucle infinie, et que
   leurs scores restent toujours dans les bornes annoncees.

   Utilisation :  node tools/fuzz-test.js
   ============================================================================ */
'use strict';

const path = require('path');

const phishing = require(path.join(__dirname, '..', 'phishing-email-analyser', 'script.js'));
const network = require(path.join(__dirname, '..', 'network-traffic-triage-tool', 'script.js'));
const windows = require(path.join(__dirname, '..', 'windows-event-log-triage-tool', 'script.js'));

let checks = 0;
let failures = [];

function ok(label, fn, maxMs) {
  checks++;
  const t0 = process.hrtime.bigint();
  try {
    fn();
  } catch (e) {
    failures.push(label + ' -> EXCEPTION : ' + e.message);
    return;
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  if (maxMs && ms > maxMs) failures.push(label + ' -> TROP LENT : ' + ms.toFixed(0) + ' ms (max ' + maxMs + ' ms)');
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion echouee');
}

/* ---------------------------------------------------------------------------
   Jeux d'entrees hostiles
   --------------------------------------------------------------------------- */
const NASTY = [
  '',
  ' ',
  '\n',
  '\t\r\n',
  'a',
  '\u0000\u0001\u0002',
  '\uFEFF BOM',
  '\u202E\u202D texte inverse',
  '😀🔥💀 emoji',
  'éàüñç œ Œ ß',
  '"' .repeat(500),
  '"'.repeat(5000),
  ','.repeat(5000),
  ';'.repeat(5000),
  '\n'.repeat(5000),
  '<script>alert(1)</script>'.repeat(200),
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  'http://',
  'http://[::1]/',
  'http://user:pass@192.0.2.1:8080/a?b=c#d',
  'https://' + 'a'.repeat(5000) + '.test/',
  'a'.repeat(200000),
  'mot de passe '.repeat(5000),
  'From: ' + 'x'.repeat(100000) + '\n',
  'Authentication-Results: ' + 'spf=fail; '.repeat(1000),
  'From: a@b.test\n' + ' continuation'.repeat(2000),
  'saisissez ' + 'z'.repeat(2000) + ' mot de passe',
  '[lien](' + 'https://a.test/'.repeat(500) + ')',
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!'
];

function timeIt(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

console.log('\n############ 1. Analyseur de phishing ############');
for (let i = 0; i < NASTY.length; i++) {
  ok('phishing / entree hostile #' + i, () => {
    const r = phishing.runAnalysis(NASTY[i], {});
    assert(typeof r.score === 'number' && !isNaN(r.score), 'score NaN');
    assert(r.score >= 0 && r.score <= 100, 'score hors bornes : ' + r.score);
    assert(Array.isArray(r.findings), 'findings non tableau');
    for (const f of r.findings) {
      assert(typeof f.weight === 'number' && !isNaN(f.weight), 'poids NaN pour ' + f.id);
      assert(f.weight > 0, 'poids nul pour ' + f.id);
      assert(Array.isArray(f.evidence) && f.evidence.length > 0, 'preuve manquante pour ' + f.id);
    }
  }, 3000);
}

ok('phishing / texte de 1 Mo', () => {
  const r = phishing.runAnalysis('urgent '.repeat(140000), {});
  assert(r.score >= 0 && r.score <= 100);
}, 5000);

ok('phishing / 5000 liens', () => {
  const txt = Array.from({ length: 5000 }, (_, i) => 'https://bit.ly/x' + i + ' http://192.0.2.' + (i % 250 + 1) + '/l').join(' ');
  const r = phishing.runAnalysis(txt, {});
  assert(r.score >= 0 && r.score <= 100);
}, 5000);

ok('phishing / options desactivees', () => {
  const r = phishing.runAnalysis('http://192.0.2.1/login spf=fail Authentication-Results: x; spf=fail',
    { headers: false, links: false, attachments: false, sensitive: false });
  assert(r.score >= 0 && r.score <= 100);
});

ok('phishing / toutes les regles ont des champs valides', () => {
  for (const rule of phishing.RULES) {
    assert(typeof rule.id === 'string' && rule.id.length > 0, 'id manquant');
    assert(typeof rule.title === 'string' && rule.title.length > 5, rule.id + ' : titre trop court');
    assert(typeof rule.why === 'string' && rule.why.length > 30, rule.id + ' : explication trop courte');
    assert(typeof rule.benign === 'string' && rule.benign.length > 20, rule.id + ' : explication benigne trop courte');
    assert(['high', 'medium', 'low', 'info'].indexOf(rule.severity) !== -1, rule.id + ' : severite invalide');
    assert(typeof rule.weight === 'number' && rule.weight > 0, rule.id + ' : poids invalide');
  }
});

ok('phishing / identifiants de regles uniques', () => {
  const ids = phishing.RULES.map(r => r.id);
  assert(new Set(ids).size === ids.length, 'doublon dans les identifiants de regles');
});

ok('phishing / seuils de classification coherents', () => {
  assert(phishing.classify(0).key === 'low');
  assert(phishing.classify(24).key === 'low');
  assert(phishing.classify(25).key === 'suspect');
  assert(phishing.classify(59).key === 'suspect');
  assert(phishing.classify(60).key === 'high');
  assert(phishing.classify(100).key === 'high');
});

console.log('\n############ 2. Triage du trafic reseau ############');
const NET_HEADER = 'No.,Time,Source,Destination,Protocol,Length,Info';

for (let i = 0; i < NASTY.length; i++) {
  ok('reseau / entree hostile #' + i, () => {
    const r = network.analyseCsvText(NASTY[i]);
    assert(typeof r === 'object', 'resultat non objet');
    if (!r.error) {
      const t = network.runTriage(r.packets, {});
      assert(t.score >= 0 && t.score <= 100, 'score hors bornes : ' + t.score);
      assert(!isNaN(t.score), 'score NaN');
    }
  }, 3000);
}

ok('reseau / CSV de 50 000 paquets (performance)', () => {
  const lines = [NET_HEADER];
  for (let i = 0; i < 50000; i++) {
    lines.push((i + 1) + ',' + (i / 1000).toFixed(6) + ',192.168.1.' + (i % 250 + 1) + ',203.0.113.' + (i % 200 + 1) +
      ',TCP,66,"' + (40000 + i % 1000) + ' \u2192 ' + (i % 65535) + ' [SYN] Seq=0 Len=0"');
  }
  const csv = lines.join('\n');
  const ms = timeIt(() => {
    const r = network.analyseCsvText(csv);
    assert(!r.error, r.error);
    assert(r.packets.length === 50000, 'paquets lus : ' + r.packets.length);
    const t = network.runTriage(r.packets, {});
    assert(t.score >= 0 && t.score <= 100);
  });
  console.log('     50 000 paquets analyses en ' + ms.toFixed(0) + ' ms');
  assert(ms < 15000, 'trop lent : ' + ms + ' ms');
}, 20000);

ok('reseau / un seul paquet', () => {
  const r = network.analyseCsvText(NET_HEADER + '\n1,0.1,10.0.0.1,10.0.0.2,TCP,60,ok\n');
  assert(!r.error);
  assert(r.packets.length === 1);
});

ok('reseau / guillemets imbriques et sauts de ligne', () => {
  const csv = NET_HEADER + '\n1,0.1,10.0.0.1,10.0.0.2,TCP,60,"ligne1\nligne2 ""citee"" fin"\n';
  const r = network.analyseCsvText(csv);
  assert(!r.error, r.error);
  assert(r.packets[0].info.indexOf('ligne2') !== -1, 'contenu multiligne perdu');
});

ok('reseau / 300 colonnes inutiles', () => {
  const head = NET_HEADER + ',' + Array.from({ length: 300 }, (_, i) => 'col' + i).join(',');
  const row = '1,0.1,10.0.0.1,10.0.0.2,TCP,60,ok,' + Array(300).fill('x').join(',');
  const r = network.analyseCsvText(head + '\n' + row + '\n');
  assert(!r.error, r.error);
  assert(r.packets.length === 1);
});

ok('reseau / champ de 1 Mo dans Info', () => {
  const r = network.analyseCsvText(NET_HEADER + '\n1,0.1,10.0.0.1,10.0.0.2,TCP,60,"' + 'x'.repeat(1000000) + '"\n');
  assert(!r.error, r.error);
}, 8000);

ok('reseau / colonnes en double', () => {
  const r = network.analyseCsvText('Source,Destination,Source,Destination\n10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4\n');
  assert(!r.error, r.error);
  assert(r.packets[0].src === '10.0.0.1');
});

ok('reseau / scores toujours entiers et bornes', () => {
  for (const s of network.SAMPLES) {
    const t = network.runTriage(network.analyseCsvText(s.csv).packets, {});
    assert(Number.isFinite(t.score) && t.score >= 0 && t.score <= 100, s.id + ' : ' + t.score);
    const sum = t.alerts.reduce((a, x) => a + x.points, 0);
    assert(t.score === Math.min(100, sum), s.id + ' : score != somme');
  }
});

ok('reseau / toutes les regles sont atteignables', () => {
  const seen = new Set();
  for (const s of network.SAMPLES) {
    const t = network.runTriage(network.analyseCsvText(s.csv).packets, {});
    for (const a of t.alerts) seen.add(a.id);
  }
  const never = network.RULES.map(r => r.id).filter(id => !seen.has(id));
  assert(never.length === 0, 'regles jamais declenchees par aucun exemple : ' + never.join(', '));
});

console.log('\n############ 3. Triage des journaux Windows ############');
const WIN_HEADER = 'Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message';

for (let i = 0; i < NASTY.length; i++) {
  ok('windows / entree hostile #' + i, () => {
    const r = windows.analyseCsvText(NASTY[i]);
    assert(typeof r === 'object', 'resultat non objet');
    if (!r.error) {
      const t = windows.runTriage(r.events, {});
      assert(t.score >= 0 && t.score <= 100, 'score hors bornes : ' + t.score);
      assert(!isNaN(t.score), 'score NaN');
    }
  }, 3000);
}

ok('windows / 20 000 evenements (performance)', () => {
  const lines = [WIN_HEADER];
  for (let i = 0; i < 20000; i++) {
    const id = [4624, 4625, 4688, 4720, 4732][i % 5];
    lines.push('Information,06/10/2025 08:05:10,Security-Auditing,' + id + ',Logon,user' + (i % 50) + ',PC-' + (i % 20) +
      ',Audit Success,"Account Name:\tuser' + (i % 50) + ' Source Network Address:\t192.168.10.' + (i % 250 + 1) + '"');
  }
  const csv = lines.join('\n');
  const ms = timeIt(() => {
    const r = windows.analyseCsvText(csv);
    assert(!r.error, r.error);
    assert(r.events.length === 20000, 'evenements lus : ' + r.events.length);
    const t = windows.runTriage(r.events, {});
    assert(t.score >= 0 && t.score <= 100);
  });
  console.log('     20 000 evenements analyses en ' + ms.toFixed(0) + ' ms');
  assert(ms < 20000, 'trop lent : ' + ms + ' ms');
}, 30000);

ok('windows / tous les formats d horodatage', () => {
  const cas = ['2025-10-06T08:05:10', '06/10/2025 08:05:10', '25/10/2025 08:05:10',
    '10/06/2025 2:05:10 PM', 'October 06, 2025 08:05:10', '06.10.2025 08:05:10',
    'pas une date', '', '   ', '9999-99-99T99:99:99', '2025-10-06', '08:05:10'];
  for (const c of cas) {
    const t = windows.parseTimestamp(c);
    assert(typeof t === 'object' && t !== null, 'resultat non objet pour ' + JSON.stringify(c));
    assert(t.date === null || t.date instanceof Date, 'date invalide pour ' + JSON.stringify(c));
  }
});

ok('windows / messages pieges (regex)', () => {
  const pieges = [
    'Account Name:' + ' '.repeat(10000) + 'x',
    'Group Name: ' + 'A'.repeat(50000),
    ('Account Name: a\n').repeat(5000),
    'Source Network Address: ' + '1'.repeat(50000),
    'ScriptBlockText: ' + 'A'.repeat(100000)
  ];
  for (const p of pieges) {
    const t = windows.powershellSuspicion(p);
    assert(Array.isArray(t));
    const csv = WIN_HEADER + '\nInformation,06/10/2025 08:05:10,S,4104,T,u,PC,K,"' + p.replace(/"/g, '""') + '"\n';
    const r = windows.analyseCsvText(csv);
    assert(!r.error, r.error);
    const res = windows.runTriage(r.events, {});
    assert(res.score >= 0 && res.score <= 100);
  }
}, 10000);

ok('windows / toutes les regles sont atteignables', () => {
  const seen = new Set();
  for (const s of windows.SAMPLES) {
    const t = windows.runTriage(windows.analyseCsvText(s.csv).events, {});
    for (const f of t.findings) seen.add(f.id);
  }
  const attendues = ['repeated_failures', 'failures_then_success', 'created_then_privileged',
    'log_cleared', 'event_4720', 'event_privilege', 'event_7045', 'event_4104_suspicious'];
  const jamais = attendues.filter(id => !seen.has(id));
  assert(jamais.length === 0, 'constats jamais produits : ' + jamais.join(', '));
});

ok('windows / identifiants de constats uniques par exemple', () => {
  for (const s of windows.SAMPLES) {
    const t = windows.runTriage(windows.analyseCsvText(s.csv).events, {});
    const ids = t.findings.map(f => f.id);
    assert(new Set(ids).size === ids.length, s.id + ' : constat en double -> ' + ids.join(','));
  }
});

/* ---------------------------------------------------------------------------
   Verification des donnees de demonstration
   --------------------------------------------------------------------------- */
console.log('\n############ 4. Donnees de demonstration ############');

function ipsIn(text) {
  const out = new Set();
  const re = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  let m;
  while ((m = re.exec(text)) !== null) out.add(m[1]);
  return Array.from(out);
}

function isReserved(ip) {
  const p = ip.split('.').map(Number);
  if (p.some(n => n > 255)) return false;
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 192 && p[1] === 0 && p[2] === 2) return true;
  if (p[0] === 198 && p[1] === 51 && p[2] === 100) return true;
  if (p[0] === 203 && p[1] === 0 && p[2] === 113) return true;
  if (p[0] === 127) return true;
  return false;
}

ok('reseau / adresses IP des exemples toutes reservees', () => {
  const bad = [];
  for (const s of network.SAMPLES) {
    for (const ip of ipsIn(s.csv)) if (!isReserved(ip)) bad.push(s.id + ' -> ' + ip);
  }
  assert(bad.length === 0, 'IP non reservees : ' + bad.join(', '));
});

ok('windows / adresses IP des exemples toutes reservees', () => {
  const bad = [];
  for (const s of windows.SAMPLES) {
    for (const ip of ipsIn(s.csv)) if (!isReserved(ip)) bad.push(s.id + ' -> ' + ip);
  }
  assert(bad.length === 0, 'IP non reservees : ' + bad.join(', '));
});

ok('phishing / domaines des exemples tous fictifs (.test)', () => {
  const bad = [];
  for (const s of phishing.SAMPLES) {
    const re = /[a-z0-9][a-z0-9.-]*\.(?:[a-z]{2,})/gi;
    let m;
    while ((m = re.exec(s.text)) !== null) {
      const d = m[0].toLowerCase();
      if (/\.(test|click|com|net|org|fr)$/.test(d) && !/\.test$/.test(d)) bad.push(s.id + ' -> ' + d);
    }
  }
  assert(bad.length === 0, 'domaines non fictifs : ' + bad.join(', '));
});

ok('phishing / aucun lien reellement malveillant fonctionnel', () => {
  for (const s of phishing.SAMPLES) {
    const links = phishing.extractLinks(s.text);
    for (const l of links) {
      const host = phishing.hostOf(l.url);
      assert(host.endsWith('.test') || phishing.isIpHost(host),
        s.id + ' : lien vers un domaine non fictif -> ' + l.url);
    }
  }
});

/* ---------------------------------------------------------------------------
   Resultat
   --------------------------------------------------------------------------- */
console.log('\n=============================================');
console.log('  Verifications executees : ' + checks);
console.log('  Problemes detectes     : ' + failures.length);
if (failures.length) {
  console.log('\n  DETAIL DES PROBLEMES :');
  for (const f of failures) console.log('   - ' + f);
}
console.log('=============================================\n');
process.exit(failures.length ? 1 : 0);
