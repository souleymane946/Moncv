/* ============================================================================
   Fabrique des versions "fichier unique" (standalone)
   ----------------------------------------------------------------------------
   Objectif : permettre a quelqu'un qui ne programme pas de telecharger UN SEUL
   fichier .html et de l'ouvrir en double-cliquant, sans se soucier des dossiers.

   Le script lit index.html, puis remplace :
     <link rel="stylesheet" href="styles.css">   ->   <style> ...tout le CSS... </style>
     <script src="script.js"></script>           ->   <script> ...tout le JS... </script>

   Utilisation :  node tools/build-standalone.js
   ============================================================================ */
'use strict';
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const outDir = path.join(root, 'standalone');

const TOOLS = [
  { dir: 'phishing-email-analyser', out: 'Phishing-Email-Analyser.html' },
  { dir: 'network-traffic-triage-tool', out: 'Network-Traffic-Triage-Tool.html' },
  { dir: 'windows-event-log-triage-tool', out: 'Windows-Event-Log-Triage-Tool.html' }
];

/* Empeche toute sequence </script> dans le JS de casser la page. */
function safeScript(js) {
  return js.replace(/<\/script/gi, '<\\/script');
}

function inline(html, css, js) {
  let out = html;
  out = out.replace(/<link\s+rel="stylesheet"\s+href="styles\.css"\s*>/i,
    '<style>\n' + css + '\n</style>');
  out = out.replace(/<script\s+src="script\.js"\s*><\/script>/i,
    '<script>\n' + safeScript(js) + '\n</script>');
  return out;
}

function countExternal(out) {
  /* On ne compte que les ressources REELLEMENT chargees par le navigateur :
     attributs src/href situes dans une balise (script, link, img, iframe...).
     Cela evite de compter une URL citee dans un commentaire ou un exemple. */
  const m = out.match(/<(?:script|link|img|iframe|source|video|audio|embed|object)\b[^>]*?(?:src|href)="(?:https?:)?\/\//gi);
  return m ? m.length : 0;
}

if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

let report = [];

/* --- Les trois outils --- */
for (const tool of TOOLS) {
  const base = path.join(root, tool.dir);
  let html = fs.readFileSync(path.join(base, 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(base, 'styles.css'), 'utf8');
  const js = fs.readFileSync(path.join(base, 'script.js'), 'utf8');

  // Dans la version autonome, le lien "Autres outils" pointe vers la page d'accueil
  // du meme dossier.
  html = html.replace(/href="\.\.\/index\.html"/g, 'href="index.html"');
  html = html.replace('<title>', '<!-- Version autonome : un seul fichier, aucune dependance -->\n<title>');

  const out = inline(html, css, js);
  fs.writeFileSync(path.join(outDir, tool.out), out, 'utf8');
  report.push(tool.out + ' : ' + Math.round(out.length / 1024) + ' Ko, '
    + countExternal(out) + ' ressource(s) externe(s)');
}

/* --- La page d'accueil (hub) --- */
const hubCss = fs.readFileSync(path.join(root, 'styles.css'), 'utf8');
let hub = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
for (const tool of TOOLS) {

  hub = hub.replace('href="' + tool.dir + '/index.html"', 'href="' + tool.out + '"');
}
hub = hub.replace('<title>', '<!-- Version autonome : un seul fichier, aucune dependance -->\n<title>');
const hubOut = inline(hub, hubCss, '/* page d\'accueil : aucun JavaScript necessaire */\n');
fs.writeFileSync(path.join(outDir, 'index.html'), hubOut, 'utf8');
report.push('index.html : ' + Math.round(hubOut.length / 1024) + ' Ko, '
  + countExternal(hubOut) + ' ressource(s) externe(s)');

console.log('Versions autonomes generees dans standalone/ :');
for (const line of report) console.log('  - ' + line);
