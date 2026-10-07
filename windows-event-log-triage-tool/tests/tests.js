/* ============================================================================
   Tests automatises — Windows Security Event Log Triage Tool
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

const STANDARD = [
  'Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message',
  'Information,06/10/2025 08:05:10,Microsoft-Windows-Security-Auditing,4624,Logon,mgarcia,PC-01,Audit Success,"An account was successfully logged on."'
].join('\n') + '\n';

console.log('\n== 1. Reconnaissance des colonnes ==');
test('colonnes standard reconnues', () => {
  const r = m.analyseCsvText(STANDARD);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.events.length, 1);
  assert.strictEqual(r.events[0].id, 4624);
  assert.strictEqual(r.missing.length, 0);
});
test('variantes EventID / event_id acceptees', () => {
  for (const header of ['EventID', 'event_id', 'ID', 'Event Code']) {
    const csv = 'Level,TimeCreated,User,Computer,' + header + ',Message\n' +
      'Information,2025-10-06T08:05:10,mgarcia,PC-01,4625,failed\n';
    const r = m.analyseCsvText(csv);
    assert.ok(!r.error, header + ' -> ' + r.error);
    assert.strictEqual(r.events[0].id, 4625);
  }
});
test('variante TimeCreated / Date acceptee', () => {
  const csv = 'Level,Date,User,Computer,Event ID,Message\nInformation,2025-10-06T08:05:10,mgarcia,PC-01,4720,created\n';
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.ok(r.events[0].date instanceof Date);
});
test('separateur point-virgule detecte', () => {
  const csv = 'Level;Date and Time;User;Computer;Event ID;Message\n' +
    'Information;06/10/2025 08:05:10;mgarcia;PC-01;4624;ok\n';
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.events.length, 1);
});

console.log('\n== 2. Messages d\'erreur clairs ==');
test('colonne Event ID absente => message explicite', () => {
  const csv = 'Level,Date and Time,User,Computer,Message\nInformation,06/10/2025 08:05:10,mgarcia,PC-01,ok\n';
  const r = m.analyseCsvText(csv);
  assert.ok(r.error, 'une erreur etait attendue');
  assert.ok(r.error.toLowerCase().indexOf('event id') !== -1, 'message : ' + r.error);
});
test('fichier vide => message explicite', () => {
  const r = m.analyseCsvText('');
  assert.ok(r.error);
});
test('en-tete seul => message explicite', () => {
  const r = m.analyseCsvText('Level,Event ID,User\n');
  assert.ok(r.error);
});
test('colonnes facultatives manquantes signalees mais analyse possible', () => {
  const csv = 'Event ID,User,Message\n4624,mgarcia,ok\n';
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.ok(r.missing.length > 0);
});

console.log('\n== 3. Robustesse : CSV mal forme ==');
test('guillemet non ferme ne plante pas', () => {
  const csv = 'Event ID,User,Message\n4624,mgarcia,"jamais ferme\n4625,jsmith,ok\n';
  const r = m.analyseCsvText(csv);
  assert.ok(r.error || r.events.length >= 1);
});
test('lignes vides ignorees', () => {
  const csv = 'Event ID,User,Message\n\n\n4624,mgarcia,ok\n\n';
  const r = m.analyseCsvText(csv);
  assert.strictEqual(r.events.length, 1);
});
test('Event ID non numerique ignore sans planter', () => {
  const csv = 'Event ID,User,Message\nabc,mgarcia,ok\n4624,mgarcia,ok\n';
  const r = m.analyseCsvText(csv);
  assert.strictEqual(r.events.length, 1);
});

console.log('\n== 4. Securite : le contenu ne doit pas devenir du HTML ==');
test('un payload HTML dans le message reste du texte', () => {
  const csv = 'Event ID,User,Message\n' +
    '4720,mgarcia,"<img src=x onerror=alert(1)> New Account Name: evil"\n';
  const r = m.analyseCsvText(csv);
  assert.ok(!r.error, r.error);
  assert.strictEqual(typeof r.events[0].message, 'string');
  assert.ok(r.events[0].message.indexOf('<img') !== -1);
});
test('un payload dans le nom de compte reste une chaine', () => {
  const csv = 'Event ID,User,Message\n4625,"<script>alert(1)</script>",failed\n';
  const r = m.analyseCsvText(csv);
  assert.strictEqual(typeof r.events[0].account, 'string');
});

console.log('\n== 5. Horodatages ==');
test('format ISO reconnu', () => {
  const t = m.parseTimestamp('2025-10-06T08:05:10.1234567Z');
  assert.ok(t.date instanceof Date);
  assert.strictEqual(t.date.getFullYear(), 2025);
  assert.strictEqual(t.date.getMonth(), 9);
  assert.strictEqual(t.date.getDate(), 6);
  assert.strictEqual(t.ambiguous, false);
});
test('format jour/mois/annee reconnu et signale comme ambigu', () => {
  const t = m.parseTimestamp('06/10/2025 08:05:10');
  assert.ok(t.date instanceof Date);
  assert.strictEqual(t.ambiguous, true);
});
test('jour > 12 => non ambigu', () => {
  const t = m.parseTimestamp('25/10/2025 08:05:10');
  assert.ok(t.date instanceof Date);
  assert.strictEqual(t.ambiguous, false);
  assert.strictEqual(t.date.getDate(), 25);
});
test('horodatage illisible => null, pas de plantage', () => {
  assert.strictEqual(m.parseTimestamp('pas une date').date, null);
  assert.strictEqual(m.parseTimestamp('').date, null);
});

console.log('\n== 6. Extraction du contexte depuis le message ==');
test('compte extrait (anglais)', () => {
  const msg = 'A user account was created.\nSubject:\n\tAccount Name:\t\tadmin.local\nNew Account:\n\tAccount Name:\t\ttemp-admin\n';
  assert.strictEqual(m.extractAccount(msg), 'temp-admin');
});
test('compte extrait (francais)', () => {
  const msg = 'Un compte utilisateur a ete cree.\nSujet :\n\tNom du compte :\t\tadmin.local\nNouveau compte :\n\tNom du compte :\t\ttemp-admin\n';
  assert.strictEqual(m.extractAccount(msg), 'temp-admin');
});
test('adresse IP source extraite', () => {
  const msg = 'Network Information:\n\tSource Network Address:\t192.168.10.25\n';
  assert.strictEqual(m.extractIp(msg), '192.168.10.25');
});
test('adresse IP source extraite (francais)', () => {
  const msg = 'Informations reseau :\n\tAdresse reseau source :\t10.0.0.5\n';
  assert.strictEqual(m.extractIp(msg), '10.0.0.5');
});
test('groupe extrait', () => {
  const msg = 'Group:\n\tGroup Name:\t\tAdministrators\n';
  assert.strictEqual(m.extractGroup(msg), 'Administrators');
});
test('valeur vide "-" ignoree', () => {
  assert.strictEqual(m.extractIp('Source Network Address:\t-\n'), '');
});

console.log('\n== 7. Groupes privilegies ==');
test('Administrators reconnu comme privilegie', () => {
  assert.strictEqual(m.isPrivilegedGroup('Administrators'), true);
  assert.strictEqual(m.isPrivilegedGroup('Administrateurs'), true);
  assert.strictEqual(m.isPrivilegedGroup('Domain Admins'), true);
});
test('groupe ordinaire non privilegie', () => {
  assert.strictEqual(m.isPrivilegedGroup('Utilisateurs du domaine'), false);
  assert.strictEqual(m.isPrivilegedGroup(''), false);
});

console.log('\n== 8. Detection PowerShell ==');
test('commande encodee detectee', () => {
  const hits = m.powershellSuspicion('powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3');
  assert.ok(hits.length > 0);
});
test('commande PowerShell normale non signalee', () => {
  const hits = m.powershellSuspicion('Get-Service | Where-Object {$_.Status -eq "Running"}');
  assert.strictEqual(hits.length, 0);
});

console.log('\n== 9. Regles de correlation sur les exemples ==');
test('activite normale : pas de constat de correlation', () => {
  const s = m.SAMPLES.find(x => x.id === 'normal');
  const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
  const corr = t.findings.filter(f => f.type === 'correlation');
  assert.strictEqual(corr.length, 0, 'constats : ' + corr.map(f => f.id).join(','));
});
test('echecs repetes detectes', () => {
  const s = m.SAMPLES.find(x => x.id === 'guessing');
  const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
  const ids = t.findings.map(f => f.id);
  assert.ok(ids.indexOf('repeated_failures') !== -1);
  assert.ok(ids.indexOf('failures_then_success') !== -1);
});
test('compte cree puis privileges detecte', () => {
  const s = m.SAMPLES.find(x => x.id === 'persistence');
  const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
  assert.ok(t.findings.some(f => f.id === 'created_then_privileged'));
});
test('journal efface (1102) prioritaire', () => {
  const s = m.SAMPLES.find(x => x.id === 'mixed');
  const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
  const f = t.findings.find(x => x.id === 'log_cleared');
  assert.ok(f, 'constat log_cleared attendu');
  assert.strictEqual(f.severity, 'eleve');
});
test('capture mixte : au moins 6 constats notes', () => {
  const s = m.SAMPLES.find(x => x.id === 'mixed');
  const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
  assert.ok(t.findings.filter(f => f.points > 0).length >= 6, 'score : ' + t.score);
});
test('activite administrative regroupee (regle 5)', () => {
  const s = m.SAMPLES.find(x => x.id === 'mixed');
  const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
  assert.ok(t.adminActivity.length > 0);
  for (const e of t.adminActivity) {
    assert.ok([4672, 4720, 4726, 4728, 4732, 7045, 1102].indexOf(e.id) !== -1);
  }
});


console.log('\n== 10. Seuils configurables ==');
test('seuil eleve => plus de constat d\'echecs repetes', () => {
  const s = m.SAMPLES.find(x => x.id === 'guessing');
  const events = m.analyseCsvText(s.csv).events;
  const strict = m.runTriage(events, { failed: 5, window: 10 });
  const lax = m.runTriage(events, { failed: 999, window: 10 });
  assert.ok(strict.findings.some(f => f.id === 'repeated_failures'));
  assert.ok(!lax.findings.some(f => f.id === 'repeated_failures'));
  assert.ok(lax.score < strict.score);
});
test('fenetre temporelle courte => correlation desactivee', () => {
  const s = m.SAMPLES.find(x => x.id === 'guessing');
  const events = m.analyseCsvText(s.csv).events;
  const t = m.runTriage(events, { failed: 5, window: 1 });
  assert.ok(!t.findings.some(f => f.id === 'failures_then_success'));
});
test('seuil invalide => valeur par defaut', () => {
  const t = m.runTriage([], { failed: 0, window: -3 });
  assert.strictEqual(t.thresholds.failed, m.DEFAULT_THRESHOLDS.failed);
  assert.strictEqual(t.thresholds.window, m.DEFAULT_THRESHOLDS.window);
});

console.log('\n== 11. Explicabilite ==');
test('le score est la somme des points, plafonnee a 100', () => {
  for (const s of m.SAMPLES) {
    const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
    const sum = t.findings.reduce((a, f) => a + f.points, 0);
    assert.strictEqual(t.score, Math.min(100, sum));
  }
});
test('chaque constat explique pourquoi et propose une piste benigne', () => {
  for (const s of m.SAMPLES) {
    const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
    for (const f of t.findings) {
      assert.ok(f.why && f.why.length > 40, 'constat ' + f.id + ' sans explication');
      assert.ok(f.benign && f.benign.length > 20, 'constat ' + f.id + ' sans explication benigne');
      assert.ok(f.evidence.length > 0, 'constat ' + f.id + ' sans preuve');
    }
  }
});
test('les severites restent dans les 4 niveaux autorises', () => {
  const allowed = ['info', 'faible', 'moyen', 'eleve'];
  for (const s of m.SAMPLES) {
    const t = m.runTriage(m.analyseCsvText(s.csv).events, {});
    for (const f of t.findings) assert.ok(allowed.indexOf(f.severity) !== -1, f.id + ' : ' + f.severity);
  }
});
test('le niveau du score est coherent', () => {
  assert.strictEqual(m.scoreLevel(0).label, 'Aucune activite notable');
  assert.strictEqual(m.scoreLevel(10).label, 'Priorite faible');
  assert.strictEqual(m.scoreLevel(30).label, 'Priorite moyenne');
  assert.strictEqual(m.scoreLevel(60).label, 'Priorite elevee');
  assert.strictEqual(m.scoreLevel(95).label, 'Priorite tres elevee');
});
test('tous les Event IDs de reference ont une explication', () => {
  for (const id of m.EVENT_ID_REFERENCE) {
    assert.ok(m.EVENT_IDS[id], 'Event ID ' + id + ' sans fiche');
    assert.ok(m.EVENT_IDS[id].explain.length > 30);
  }
});

console.log('\n---------------------------------------------');
console.log('  Tests reussis : ' + passed);
console.log('  Tests echoues : ' + failed);
console.log('---------------------------------------------\n');
process.exit(failed ? 1 : 0);

