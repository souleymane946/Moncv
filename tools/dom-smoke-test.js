/* ============================================================================
   Test de fumee "faux navigateur"
   ----------------------------------------------------------------------------
   Objectif : verifier que les trois outils s'executent REELLEMENT, comme dans
   un navigateur, sans avoir besoin d'un navigateur.

   Ce test simule les API minimales du navigateur (document, elements, URL,
   Blob, FileReader), charge le script de chaque outil, appelle son
   initialisation, puis charge tous les exemples de demonstration.

   Il a permis de detecter un vrai bug d'initialisation lors de sa premiere
   execution. Il sert donc de garde-fou.

   Utilisation :  node tools/dom-smoke-test.js
   ============================================================================ */
'use strict';

const fs = require('fs');
const path = require('path');
const Module = require('module');

let problems = 0;

/* ---------------------------------------------------------------------------
   Simulateur minimal de navigateur
   --------------------------------------------------------------------------- */
function makeEl(id) {
  const el = {
    id: id || '',
    tagName: 'DIV',
    className: '',
    textContent: '',
    value: '',
    checked: true,
    hidden: false,
    type: '',
    href: '',
    download: '',
    style: {},
    children: [],
    options: [],
    classList: { add() {}, remove() {}, contains() { return false; } },
    appendChild(c) { this.children.push(c); return c; },
    removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); },
    insertBefore(c) { this.children.push(c); return c; },
    remove() {},
    setAttribute() {},
    getAttribute() { return null; },
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return true; },
    click() {},
    focus() {},
    scrollIntoView() {}
  };
  Object.defineProperty(el, 'childNodes', { get() { return this.children; } });
  /* Garde-fou : le code ne doit JAMAIS utiliser innerHTML (risque d'injection). */
  Object.defineProperty(el, 'innerHTML', {
    get() { return ''; },
    set(v) { throw new Error('innerHTML interdit pour raison de securite : ' + String(v).slice(0, 60)); }
  });
  return el;
}

function makeDocument() {
  const cache = new Map();
  return {
    readyState: 'complete',
    body: makeEl('body'),
    createElement(tag) { const e = makeEl(); e.tagName = String(tag).toUpperCase(); return e; },
    getElementById(id) { if (!cache.has(id)) cache.set(id, makeEl(id)); return cache.get(id); },
    addEventListener() {},
    _cache: cache
  };
}

function installStubs() {
  const doc = makeDocument();
  global.document = doc;
  global.window = { scrollTo() {}, addEventListener() {}, document: doc };
  global.URL = { createObjectURL() { return 'blob:local'; }, revokeObjectURL() {} };
  global.Blob = function Blob() { this.size = 0; };
  global.FileReader = function FileReader() { this.readAsText = function () {}; };
  global.Event = function Event(type, opts) { this.type = type; Object.assign(this, opts || {}); };
  return doc;
}

/* ---------------------------------------------------------------------------
   Execution d'un outil dans le faux navigateur
   --------------------------------------------------------------------------- */
const TOOLS = [
  { dir: 'phishing-email-analyser', kind: 'phishing' },
  { dir: 'network-traffic-triage-tool', kind: 'network' },
  { dir: 'windows-event-log-triage-tool', kind: 'windows' }
];

const EXTRA_EXPORTS = {
  phishing: '\nmodule.exports.__ui = { init, renderResults, renderSampleCards };\n',
  network: '\nmodule.exports.__ui = { init, processCsv, renderSampleCards };\n',
  windows: '\nmodule.exports.__ui = { init, processCsv, renderReferenceTable, renderSampleCards };\n'
};

const root = path.join(__dirname, '..');

function run(kind, dir, label) {
  const file = path.join(dir, 'script.js');
  let src = fs.readFileSync(file, 'utf8') + (EXTRA_EXPORTS[kind] || '');
  const doc = installStubs();
  const m = new Module(file, null);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));

  console.log('\n=== ' + label + ' ===');
  m._compile(src, file);
  const api = m.exports;
  console.log('  chargement du module ......................... OK');

  api.__ui.init();
  console.log('  initialisation de la page .................... OK');

  const samples = api.SAMPLES || [];
  for (const s of samples) {
    if (kind === 'phishing') api.__ui.renderResults(api.runAnalysis(s.text, {}));
    else api.__ui.processCsv(s.csv, s.file);
  }
  console.log('  rendu des ' + samples.length + ' exemples ...................... OK');
  console.log('  elements DOM manipules : ' + doc._cache.size);

  /* Verification supplementaire : les seuils et le score restent coherents. */
  if (kind === 'phishing') {
    const r = api.runAnalysis(samples[samples.length - 1].text, {});
    if (!(r.score >= 0 && r.score <= 100)) throw new Error('score hors bornes : ' + r.score);
  } else {
    const res = kind === 'network'
      ? api.analyseCsvText(samples[0].csv)
      : api.analyseCsvText(samples[0].csv);
    if (res.error) throw new Error('exemple 0 en erreur : ' + res.error);
  }
}

for (const tool of TOOLS) {
  try {
    run(tool.kind, path.join(root, tool.dir), tool.dir);
  } catch (e) {
    problems++;
    console.log('  ERREUR : ' + e.message);
    console.log('  ' + String(e.stack || '').split('\n').slice(1, 4).join('\n  '));
  }
}

console.log('\n---------------------------------------------');
console.log(problems === 0
  ? "  TOUT EST OK : les 3 outils s'executent sans erreur"
  : '  ' + problems + ' outil(s) en erreur');
console.log('---------------------------------------------\n');
process.exit(problems ? 1 : 0);
