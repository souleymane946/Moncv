/* ============================================================================
   Windows Security Event Log Triage Tool — moteur d'analyse local
   ----------------------------------------------------------------------------
   PRINCIPE : tout se passe dans le navigateur. Aucune requete reseau.

   ETAPES :
     1) Lecture du CSV exporte par l'Observateur d'evenements Windows.
     2) Reconnaissance tolerante des colonnes (Event ID / EventID / event_id...).
     3) Reconnaissance des Event IDs importants et extraction du contexte
        (compte, adresse IP source, groupe, type de session...).
     4) CORRELATION : plusieurs evenements sont relies entre eux (c'est le coeur
        du projet) plutot que juges isolement.
     5) Score d'investigation explicable + rapport de triage.
   ============================================================================ */

'use strict';

/* ---------------------------------------------------------------------------
   RECONNAISSANCE DES COLONNES
   Un export de l'Observateur d'evenements peut contenir :
     Level, Date and Time, Source, Event ID, Task Category, User, Computer,
     Keywords, Message
   Selon la version de Windows et la langue, les noms varient : on normalise
   (minuscules, sans espaces ni ponctuation) puis on compare a des variantes.
   --------------------------------------------------------------------------- */
const COLUMN_CANDIDATES = {
  level: ['level', 'leveldisplayname', 'niveau', 'severity', 'severite', 'type'],
  time: ['dateandtime', 'timecreated', 'date', 'datetime', 'dateheure', 'horodatage',
    'timestamp', 'time', 'dateetheure'],
  source: ['source', 'providername', 'fournisseur', 'sourceName'.toLowerCase(), 'origine'],
  eventid: ['eventid', 'id', 'eventcode', 'identifiant', 'identifiantdelevenement', 'evenement', 'event'],
  task: ['taskcategory', 'task', 'categorie', 'categoriedetache', 'tache'],
  user: ['user', 'utilisateur', 'account', 'compte', 'userid', 'username', 'nomducompte', 'subjectusername'],
  computer: ['computer', 'computername', 'ordinateur', 'machine', 'nomdelordinateur', 'machineName'.toLowerCase()],
  keywords: ['keywords', 'motscles', 'motsclefs', 'audit'],
  message: ['message', 'description', 'details', 'detail', 'contenu', 'texte']
};

const COLUMN_LABELS = {
  level: 'niveau',
  time: "date et heure",
  source: 'source (fournisseur)',
  eventid: "identifiant d'evenement (Event ID)",
  task: 'categorie de tache',
  user: 'utilisateur / compte',
  computer: 'nom de la machine',
  keywords: 'mots-cles',
  message: 'message / description'
};

function normaliseName(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function mapColumns(headers) {
  const map = {};
  headers.forEach((h, idx) => {
    const n = normaliseName(h);
    if (!n) return;
    for (const key of Object.keys(COLUMN_CANDIDATES)) {
      if (map[key] !== undefined) continue;
      if (COLUMN_CANDIDATES[key].indexOf(n) !== -1) map[key] = idx;
    }
  });
  return map;
}

/* ---------------------------------------------------------------------------
   LECTURE DU CSV (guillemets respectes, separateur detecte)
   --------------------------------------------------------------------------- */
function detectDelimiter(line) {
  const candidates = [[',', 0], [';', 0], ['\t', 0]];
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQuotes = !inQuotes; continue; }
    if (inQuotes) continue;
    for (const c of candidates) if (ch === c[0]) c[1]++;
  }
  candidates.sort((a, b) => b[1] - a[1]);
  return candidates[0][1] > 0 ? candidates[0][0] : ',';
}

function parseCsv(text) {
  let s = String(text || '');
  if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  const firstLine = s.split(/\r?\n/)[0] || '';
  const delimiter = detectDelimiter(firstLine);
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (inQuotes) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQuotes = false; i++; continue;
      }
      field += c; i++; continue;
    }
    if (c === '"') { inQuotes = true; i++; continue; }
    if (c === delimiter) { row.push(field); field = ''; i++; continue; }
    if (c === '\r') { i++; continue; }
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
    field += c; i++;
  }
  row.push(field);
  rows.push(row);
  return { rows: rows.filter(r => r.some(f => String(f).trim() !== '')), delimiter };
}

/* ---------------------------------------------------------------------------
   BASE DE CONNAISSANCE DES EVENT IDs
   Objectif : expliquer en langage simple ce que signifie chaque evenement.
   On reste volontairement sur une petite liste : trop d'identifiants noierait
   un debutant.
   --------------------------------------------------------------------------- */
const EVENT_IDS = {
  4624: {
    name: 'Connexion reussie', severity: 'info', type: 'logon',
    explain: "Un compte Windows a ouvert une session avec succes. Une connexion reussie n'est PAS suspecte en soi : elle sert surtout de contexte quand on la rapproche d'autres evenements."
  },
  4625: {
    name: 'Echec de connexion', severity: 'faible', type: 'logon',
    explain: "Une tentative de connexion a echoue. Un echec isole est banal (mot de passe mal saisi). Ce sont les ECHECS REPETES qui deviennent interessants."
  },
  4634: {
    name: 'Fermeture de session', severity: 'info', type: 'logon',
    explain: "Un compte a ferme sa session. Utile pour reconstituer une chronologie."
  },
  4672: {
    name: 'Privileges speciaux attribues', severity: 'faible', type: 'privilege',
    explain: "Le compte connecte a recu des privileges particuliers (souvent un compte administrateur). Frequent et souvent normal, mais a garder en tete."
  },
  4720: {
    name: 'Compte utilisateur cree', severity: 'moyen', type: 'account',
    explain: "Un nouveau compte Windows a ete cree. Cela peut etre une administration totalement legitime... ou la creation d'un compte de persistance. A verifier."
  },
  4726: {
    name: 'Compte utilisateur supprime', severity: 'faible', type: 'account',
    explain: "Un compte utilisateur a ete supprime. Souvent une tache administrative, mais a mettre en relation avec le reste du journal."
  },
  4728: {
    name: 'Membre ajoute a un groupe de securite global', severity: 'moyen', type: 'privilege',
    explain: "Un utilisateur a ete ajoute a un groupe de securite global (souvent lie au domaine). Si le groupe est privilegie, la priorite augmente."
  },
  4732: {
    name: 'Membre ajoute a un groupe de securite local', severity: 'moyen', type: 'privilege',
    explain: "Un utilisateur a ete ajoute a un groupe local. Si le groupe est 'Administrateurs', c'est un evenement a examiner en priorite."
  },
  1102: {
    name: "Journal d'audit de securite efface", severity: 'eleve', type: 'log',
    explain: "Le journal de securite Windows a ete vide. Cela arrive lors d'une maintenance legitime, mais comme un attaquant peut effacer les journaux pour supprimer ses traces, cet evenement est generalement a investiguer."
  },
  4688: {
    name: 'Processus cree', severity: 'info', type: 'process',
    explain: "Un nouveau processus a ete lance (si l'audit de creation de processus est active). Sert de contexte : nom du processus, processus parent, ligne de commande."
  },
  4104: {
    name: 'Journalisation des blocs de script PowerShell', severity: 'info', type: 'process',
    explain: "PowerShell a enregistre un bloc de script execute sur la machine. La journalisation des blocs de script offre une excellente visibilite sur les commandes utilisees. PowerShell n'est PAS suspect en soi."
  },
  7045: {
    name: 'Service installe', severity: 'moyen', type: 'service',
    explain: "Un nouveau service Windows a ete installe. Cela correspond souvent a l'installation d'un logiciel legitime, mais un service peut aussi servir de mecanisme de persistance."
  }
};

const EVENT_ID_REFERENCE = [4624, 4625, 4688, 4720, 4726, 4728, 4732, 1102, 4104, 7045];

const TYPE_LABELS = {
  logon: 'Connexions',
  account: 'Comptes',
  privilege: 'Privileges',
  log: 'Journaux',
  process: 'Processus',
  service: 'Services',
  other: 'Autres'
};

/* ---------------------------------------------------------------------------
   HORODATAGES
   Les exports varient beaucoup selon la langue et la version de Windows.
   LIMITE ASSUMEE : quand la date est ecrite "03/04/2025", on ne peut pas
   savoir avec certitude s'il s'agit du 3 avril ou du 4 mars. On retient une
   hypothese (jour/mois, usage courant en France) et on le SIGNALE a
   l'utilisateur, au lieu de faire semblant d'etre precis.
   --------------------------------------------------------------------------- */
function parseTimestamp(raw) {
  const s = String(raw || '').trim();
  if (!s) return { date: null, ambiguous: false };

  let m = /(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})(?::(\d{2}))?/.exec(s);
  if (m) {
    return { date: new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], m[6] ? +m[6] : 0), ambiguous: false };
  }

  m = /(\d{1,2})[\/\.](\d{1,2})[\/\.](\d{2,4})[ ,]*?(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?/i.exec(s);
  if (m) {
    const a = +m[1];
    const b = +m[2];
    let y = +m[3];
    if (y < 100) y += 2000;
    let day, month, ambiguous = false;
    if (a > 12) { day = a; month = b; }
    else if (b > 12) { month = a; day = b; }
    else { day = a; month = b; ambiguous = true; }
    let hh = +m[4];
    const mm = +m[5];
    const ss = m[6] ? +m[6] : 0;
    if (m[7]) {
      const p = m[7].toUpperCase();
      if (p === 'PM' && hh < 12) hh += 12;
      if (p === 'AM' && hh === 12) hh = 0;
    }
    return { date: new Date(y, month - 1, day, hh, mm, ss), ambiguous };
  }

  m = /(\d{1,2})\s+([A-Za-z]+)\.?\s+(\d{4})[ ,]*?(\d{1,2}):(\d{2})(?::(\d{2}))?/.exec(s);
  if (m) {
    const months = ['january', 'february', 'march', 'april', 'may', 'june', 'july',
      'august', 'september', 'october', 'november', 'december'];
    const idx = months.indexOf(m[2].toLowerCase());
    if (idx !== -1) {
      return { date: new Date(+m[3], idx, +m[1], +m[4], +m[5], m[6] ? +m[6] : 0), ambiguous: false };
    }
  }
  return { date: null, ambiguous: false };
}

/* ---------------------------------------------------------------------------
   EXTRACTION DU CONTEXTE DEPUIS LA COLONNE MESSAGE
   Les exports ne contiennent pas toujours des colonnes pour le compte ou
   l'adresse IP : ces informations sont souvent noyees dans le texte du message.
   On tente donc de les retrouver (francais et anglais).
   --------------------------------------------------------------------------- */
function firstMatch(text, patterns) {
  for (const re of patterns) {
    const m = re.exec(text);
    if (m && m[1]) {
      const v = m[1].trim().replace(/\s+$/, '');
      if (v && v !== '-' && v !== 'N/A') return v;
    }
  }
  return '';
}

function extractAccount(message) {
  /* 1) Motifs explicites de "nouveau compte" / "compte cible" */
  const specific = firstMatch(message, [
    /(?:New Account Name|Nom du nouveau compte|Target Account Name|Nom du compte cible|New Target User Name)\s*:\s*([^\r\n]+)/i
  ]);
  if (specific) return specific;

  /* 2) Sinon : on prend le DERNIER "Account Name" du message.
     Les journaux Windows listent d'abord le compte demandeur (souvent SYSTEM
     ou la machine) puis le compte concerne. Le dernier est donc le bon. */
  const all = [];
  const re = /(?:Account Name|Nom du compte|Nom de compte|Utilisateur|User Name)\s*:\s*([^\r\n]+)/gi;
  let m;
  while ((m = re.exec(message)) !== null) {
    const v = m[1].trim();
    if (v && v !== '-' && v !== 'N/A' && v.toUpperCase() !== 'SYSTEM') all.push(v);
  }
  return all.length ? all[all.length - 1] : '';
}

function extractIp(message) {
  return firstMatch(message, [
    /(?:Source Network Address|Adresse reseau source|Adresse r[eé]seau source|Source IP Address|Adresse IP source|IpAddress|Client Address)\s*:\s*([^\r\n]+)/i
  ]);
}

function extractLogonType(message) {
  return firstMatch(message, [
    /(?:Logon Type|Type d'ouverture de session|Type de connexion)\s*:\s*([^\r\n]+)/i
  ]);
}

function extractGroup(message) {
  return firstMatch(message, [
    /(?:Group Name|Nom du groupe|Target Group Name|Nom du groupe cible|Nom du groupe de securite)\s*:\s*([^\r\n]+)/i
  ]);
}

function extractWorkstation(message) {
  return firstMatch(message, [
    /(?:Workstation Name|Nom de la station|Nom du poste|Source Workstation)\s*:\s*([^\r\n]+)/i
  ]);
}

function extractService(message) {
  return firstMatch(message, [
    /(?:Service Name|Nom du service)\s*:\s*([^\r\n]+)/i
  ]);
}

function extractProcess(message) {
  return firstMatch(message, [
    /(?:New Process Name|Nom du nouveau processus|Process Name|Nom du processus)\s*:\s*([^\r\n]+)/i
  ]);
}

function extractParentProcess(message) {
  return firstMatch(message, [
    /(?:Creator Process Name|Nom du processus parent|Parent Process Name|Nom du processus createur)\s*:\s*([^\r\n]+)/i
  ]);
}

function extractCommandLine(message) {
  return firstMatch(message, [
    /(?:Process Command Line|Ligne de commande du processus|CommandLine|Command Line)\s*:\s*([^\r\n]+)/i
  ]);
}

const PRIVILEGED_GROUPS = ['administrators', 'administrateurs', 'domain admins', 'admins du domaine',
  'enterprise admins', 'schema admins', 'account operators', 'backup operators', 'server operators',
  'hyper-v administrators', 'administrateurs hyper-v', 'remote desktop users', 'utilisateurs du bureau a distance',
  'administrateurs du domaine', 'groupe administrateurs'];

function isPrivilegedGroup(name) {
  const n = String(name || '').toLowerCase().trim();
  if (!n) return false;
  return PRIVILEGED_GROUPS.some(g => n === g || n.indexOf(g) !== -1);
}

/* Indices de commande PowerShell encodee ou obfusquee (indice, pas preuve). */
const ENCODED_PS_PATTERNS = [
  /-enc(?:odedcommand)?\b/i,
  /FromBase64String/i,
  /\s-e\s+[A-Za-z0-9+\/]{40,}/,
  /[A-Za-z0-9+\/]{120,}={0,2}/,
  /-nop\b|-noprofile\b|-w\s+hidden\b|-windowstyle\s+hidden/i,
  /IEX\s*\(|Invoke-Expression/i,
  /DownloadString|DownloadFile|Invoke-WebRequest|IWR\b|curl\s+http/i,
  /-ExecutionPolicy\s+Bypass/i
];

function powershellSuspicion(message) {
  const hits = [];
  for (const re of ENCODED_PS_PATTERNS) {
    const m = re.exec(message);
    if (m) hits.push(m[0].length > 60 ? m[0].slice(0, 60) + '…' : m[0]);
  }
  return hits;
}

/* ---------------------------------------------------------------------------
   CONSTRUCTION DES EVENEMENTS
   --------------------------------------------------------------------------- */
function cleanAccount(v) {
  const s = String(v || '').trim();
  if (!s) return '';
  if (s === '-' || s === 'N/A' || s === 'NA') return '';
  if (/^(system|local service|network service|service local|service reseau|syst[eè]me)$/i.test(s)) return '';
  return s;
}

function buildEvents(rows, map) {
  const events = [];
  let ambiguousCount = 0;
  const dataRows = rows.slice(1);

  dataRows.forEach((r, i) => {
    const cell = (key) => (map[key] !== undefined ? String(r[map[key]] || '').trim() : '');
    const message = cell('message');
    const idRaw = cell('eventid');
    const id = parseInt(idRaw.replace(/[^0-9]/g, ''), 10);
    if (isNaN(id)) return;

    const ts = parseTimestamp(cell('time'));
    if (ts.ambiguous) ambiguousCount++;

    let account = cleanAccount(cell('user'));
    if (!account) account = extractAccount(message);

    events.push({
      index: i,
      id: id,
      idRaw: idRaw,
      message: message,
      timeRaw: cell('time'),
      date: ts.date,
      timeAmbiguous: ts.ambiguous,
      level: cell('level'),
      source: cell('source'),
      computer: cell('computer'),
      account: account || '',
      ip: extractIp(message),
      logonType: extractLogonType(message),
      group: extractGroup(message),
      workstation: extractWorkstation(message),
      service: extractService(message),
      process: extractProcess(message),
      parentProcess: extractParentProcess(message),
      commandLine: extractCommandLine(message),
      meta: EVENT_IDS[id] || null
    });
  });

  events.sort((a, b) => {
    if (a.date && b.date) return a.date - b.date || a.index - b.index;
    return a.index - b.index;
  });

  return { events, ambiguousCount };
}

function missingColumns(map) {
  const missing = [];
  for (const key of ['eventid', 'time', 'user', 'computer', 'level', 'source', 'message']) {
    if (map[key] === undefined) missing.push(key);
  }
  return missing;
}

function analyseCsvText(text) {
  const parsed = parseCsv(text);
  if (!parsed.rows.length) return { error: 'Le fichier est vide ou illisible.' };
  const headers = parsed.rows[0].map(h => String(h).trim());
  const map = mapColumns(headers);
  const missing = missingColumns(map);

  if (map.eventid === undefined) {
    return {
      error: "Ce fichier CSV ne semble pas contenir de colonne d'identifiant d'evenement (Event ID).",
      headers, map, missing, delimiter: parsed.delimiter
    };
  }

  const built = buildEvents(parsed.rows, map);
  if (!built.events.length) {
    return { error: "Aucun evenement exploitable : la colonne Event ID est vide ou illisible.", headers, map, missing };
  }
  return {
    events: built.events,
    ambiguousCount: built.ambiguousCount,
    missing, headers, map, delimiter: parsed.delimiter
  };
}

/* ===========================================================================
   MOTEUR DE TRIAGE
   ---------------------------------------------------------------------------
   Deux familles de constats :
     - 'event'       : un type d'evenement present dans le jeu de donnees
                       (avec explication en langage simple) ;
     - 'correlation' : une SEQUENCE d'evenements relies entre eux.
   Les constats de correlation S'AJOUTENT aux constats individuels : c'est
   volontaire, car une sequence est plus parlante qu'un evenement isole.
   =========================================================================== */
const DEFAULT_THRESHOLDS = { failed: 5, window: 10 };

const SEVERITY_LABEL = { eleve: 'Eleve', moyen: 'Moyen', faible: 'Faible', info: 'Informationnel' };

function minutesBetween(a, b) {
  if (!a || !b) return null;
  return Math.abs(b - a) / 60000;
}

function fmtDateTime(d) {
  if (!d) return '';
  const p = (n) => String(n).padStart(2, '0');
  return p(d.getDate()) + '/' + p(d.getMonth() + 1) + '/' + d.getFullYear() +
    ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

function groupBy(events, keyFn) {
  const map = new Map();
  for (const e of events) {
    const k = keyFn(e);
    if (!k) continue;
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(e);
  }
  return map;
}

function timeRangeOf(events) {
  const dates = events.map(e => e.date).filter(Boolean);
  if (!dates.length) return null;
  return { from: new Date(Math.min.apply(null, dates.map(d => d.getTime()))),
           to: new Date(Math.max.apply(null, dates.map(d => d.getTime()))) };
}

function baseFinding(props) {
  return Object.assign({
    type: 'event', severity: 'info', points: 0, account: '', eventIds: [],
    timeRange: null, ip: '', workstation: '', activity: '', why: '', benign: '',
    investigate: [], evidence: [], sequence: [], window: ''
  }, props);
}

/* ---------------------------------------------------------------------------
   REGLE DE CORRELATION 1 — ECHECS DE CONNEXION REPETES
   --------------------------------------------------------------------------- */
function ruleRepeatedFailures(events, th) {
  const byAccount = groupBy(events.filter(e => e.id === 4625), e => e.account);
  const findings = [];
  for (const entry of byAccount) {
    const account = entry[0];
    const list = entry[1];
    if (list.length < th.failed) continue;
    const ips = Array.from(new Set(list.map(e => e.ip).filter(Boolean)));
    const stations = Array.from(new Set(list.map(e => e.workstation).filter(Boolean)));
    findings.push(baseFinding({
      id: 'repeated_failures',
      name: 'Echecs de connexion repetes',
      severity: 'moyen', points: 10, type: 'correlation',
      account: account, eventIds: [4625],
      timeRange: timeRangeOf(list), ip: ips.join(', '), workstation: stations.join(', '),
      activity: list.length + ' echecs de connexion (4625) pour le compte ' + account + '.',
      why: "Des echecs d'authentification repetes peuvent indiquer une tentative de devinette de mot de passe (brute force). Mais cela peut aussi venir d'un mot de passe mal saisi, d'un ancien mot de passe conserve dans un service ou d'une application mal configuree.",
      benign: "Un utilisateur qui se trompe plusieurs fois de mot de passe, un service Windows avec des identifiants perimes, un appareil mobile qui reessaie en boucle.",
      investigate: [
        "Identifier le systeme source de ces tentatives.",
        "Verifier le compte concerne et son proprietaire.",
        "Chercher si ces echecs sont suivis d'une connexion reussie.",
        "Verifier si d'autres comptes sont vises de la meme facon.",
        "Consulter les journaux MFA ou les donnees EDR si disponibles."
      ],
      evidence: [
        'Compte : ' + account,
        'Nombre d\'echecs : ' + list.length + ' (seuil ' + th.failed + ')',
        'Adresse(s) source : ' + (ips.length ? ips.join(', ') : 'non disponible dans l\'export')
      ]
    }));
  }
  return findings;
}

/* ---------------------------------------------------------------------------
   REGLE DE CORRELATION 2 — ECHECS SUIVIS D'UNE CONNEXION REUSSIE
   --------------------------------------------------------------------------- */
function ruleFailuresThenSuccess(events, th) {
  const byAccount = groupBy(events, e => e.account);
  const findings = [];
  for (const entry of byAccount) {
    const account = entry[0];
    const list = entry[1];
    const failures = list.filter(e => e.id === 4625);
    if (failures.length < th.failed) continue;
    const success = list.filter(e => e.id === 4624 && e.index > failures[failures.length - 1].index);
    if (!success.length) continue;
    const firstSuccess = success[0];
    const gap = minutesBetween(failures[failures.length - 1].date, firstSuccess.date);
    const withinWindow = gap === null ? null : gap <= th.window;
    if (withinWindow === false) continue;

    const seq = failures.slice(-6).map(() => '4625').concat(['4624']);
    findings.push(baseFinding({
      id: 'failures_then_success',
      name: 'Echecs repetes suivis d\'une connexion reussie',
      severity: 'eleve', points: 20, type: 'correlation',
      account: account, eventIds: [4625, 4624],
      timeRange: timeRangeOf(failures.concat([firstSuccess])),
      ip: firstSuccess.ip || failures[failures.length - 1].ip || '',
      workstation: firstSuccess.workstation || '',
      activity: 'Le compte ' + account + ' a echoue ' + failures.length +
        ' fois, puis s\'est connecte avec succes.',
      why: "Plusieurs echecs suivis d'une connexion reussie peuvent signifier qu'un mot de passe a fini par etre trouve. Mais cela peut aussi etre un utilisateur legitime qui a fini par saisir le bon mot de passe.",
      benign: "Un utilisateur qui retrouve son mot de passe, une saisie avec une mauvaise disposition de clavier, un mot de passe change sur un autre appareil.",
      investigate: [
        "Verifier l'adresse IP source de la connexion reussie.",
        "Determiner si la machine source appartient bien a l'utilisateur.",
        "Examiner ce qui s'est passe APRES la connexion reussie.",
        "Chercher des tentatives similaires sur d'autres comptes.",
        "Verifier si une double authentification etait active."
      ],
      sequence: seq,
      window: (withinWindow === null
        ? "Horodatages indisponibles : la correlation repose sur l'ordre des evenements dans le fichier."
        : 'Ecart entre le dernier echec et la reussite : ' + gap.toFixed(1) + ' minute(s) (fenetre de ' + th.window + ' min).'),
      evidence: [
        'Compte : ' + account,
        'Echecs avant la reussite : ' + failures.length,
        'Connexion reussie : oui' + (firstSuccess.timeRaw ? ' (' + firstSuccess.timeRaw + ')' : ''),
        'Adresse IP : ' + (firstSuccess.ip || 'non disponible')
      ]
    }));
  }
  return findings;
}

/* ---------------------------------------------------------------------------
   REGLE DE CORRELATION 3 — COMPTE CREE PUIS PRIVILEGES AJOUTES
   --------------------------------------------------------------------------- */
function ruleCreatedThenPrivileged(events) {
  const creations = events.filter(e => e.id === 4720);
  const privs = events.filter(e => e.id === 4728 || e.id === 4732);
  const findings = [];
  for (const c of creations) {
    const acct = c.account;
    if (!acct) continue;
    const after = privs.filter(p => p.account === acct && p.index > c.index);
    if (!after.length) continue;
    const p = after[0];
    const seq = ['4720'].concat(after.slice(0, 4).map(x => String(x.id)));
    const privileged = isPrivilegedGroup(p.group);
    findings.push(baseFinding({
      id: 'created_then_privileged',
      name: 'Nouveau compte ayant recu des privileges',
      severity: 'eleve', points: 25, type: 'correlation',
      account: acct, eventIds: [4720, p.id],
      timeRange: timeRangeOf([c, p]),
      ip: p.ip || c.ip || '', workstation: p.workstation || c.workstation || '',
      activity: 'Le compte ' + acct + ' a ete cree (4720) puis ajoute au groupe "' +
        (p.group || 'inconnu') + '" (' + p.id + ').',
      why: "Creer un compte puis lui donner rapidement des privileges eleves peut etre une administration normale, mais c'est aussi une technique classique de persistance ou d'elevation de privileges.",
      benign: "Un administrateur qui prepare un compte de service, un compte temporaire pour un prestataire, un deploiement automatise.",
      investigate: [
        "Confirmer que la creation du compte etait autorisee (ticket de changement).",
        "Identifier l'administrateur a l'origine de ces actions.",
        "Examiner ce que le compte a fait apres avoir recu ses privileges.",
        "Verifier si le compte est toujours necessaire.",
        "Controler si le compte est utilise depuis une machine inattendue."
      ],
      sequence: seq,
      window: privileged ? 'Groupe privilegie detecte : priorite augmentee.' : '',
      evidence: [
        'Compte : ' + acct,
        'Creation (4720) puis ajout au groupe (ID ' + p.id + ') : ' + (p.group || 'groupe inconnu'),
        'Groupe privilegie : ' + (privileged ? 'oui' : 'non')
      ]
    }));
  }
  return findings;
}

/* ---------------------------------------------------------------------------
   REGLE DE CORRELATION 4 — JOURNAL DE SECURITE EFFACE (1102)
   --------------------------------------------------------------------------- */
function ruleLogCleared(events) {
  const cleared = events.filter(e => e.id === 1102);
  if (!cleared.length) return [];
  const who = Array.from(new Set(cleared.map(e => e.account).filter(Boolean)));
  return [baseFinding({
    id: 'log_cleared',
    name: "Journal d'audit de securite efface",
    severity: 'eleve', points: 30, type: 'correlation',
    account: who.join(', '), eventIds: [1102],
    timeRange: timeRangeOf(cleared),
    ip: cleared[0].ip || '', workstation: cleared[0].workstation || '',
    activity: 'Cet evenement signifie que le journal d\'audit de securite Windows a ete vide (' +
      cleared.length + ' occurrence(s)).',
    why: "Cet evenement signifie que le journal de securite Windows a ete efface. Cela peut arriver lors d'une maintenance legitime, mais comme un attaquant peut vider les journaux pour supprimer ses traces, il doit normalement etre investigue.",
    benign: "Maintenance du systeme, nettoyage du journal arrive a sa taille maximale, script d'administration, reinitialisation d'un poste de test.",
    investigate: [
      "Identifier le compte et la machine a l'origine de l'effacement.",
      "Verifier si une maintenance etait planifiee a ce moment-la.",
      "Chercher d'autres evenements suspects juste AVANT l'effacement.",
      "Verifier si les journaux sont centralises ailleurs (SIEM, serveur de journaux).",
      "Conserver une copie des journaux disponibles avant toute manipulation."
    ],
    evidence: [
      'Evenement 1102 detecte : ' + cleared.length + ' fois',
      'Compte associe : ' + (who.length ? who.join(', ') : 'non disponible'),
      'Date : ' + (cleared[0].timeRaw || 'non disponible')
    ]
  })];
}

/* ---------------------------------------------------------------------------
   CONSTATS PAR TYPE D'EVENEMENT (avec explication en langage simple)
   --------------------------------------------------------------------------- */
function ruleEventLevel(events) {
  const findings = [];
  const of = (id) => events.filter(e => e.id === id);

  /* --- 4720 : compte cree --- */
  const created = of(4720);
  if (created.length) {
    findings.push(baseFinding({
      id: 'event_4720', name: 'Compte utilisateur cree', severity: 'moyen', points: 15,
      account: Array.from(new Set(created.map(e => e.account).filter(Boolean))).join(', '),
      eventIds: [4720], timeRange: timeRangeOf(created), type: 'event',
      activity: created.length + ' creation(s) de compte detectee(s).',
      why: EVENT_IDS[4720].explain,
      benign: "Creation d'un compte pour un nouvel employe, un prestataire, un compte de service ou un test.",
      investigate: ["Verifier que la creation etait autorisee.",
        "Identifier qui a cree le compte.",
        "Verifier si le compte a ensuite recu des privileges."],
      evidence: created.slice(0, 5).map(e => 'Compte : ' + (e.account || 'inconnu') + ' | ' + (e.timeRaw || 'date inconnue'))
    }));
  }

  /* --- 4726 : compte supprime --- */
  const deleted = of(4726);
  if (deleted.length) {
    findings.push(baseFinding({
      id: 'event_4726', name: 'Compte utilisateur supprime', severity: 'faible', points: 10,
      account: Array.from(new Set(deleted.map(e => e.account).filter(Boolean))).join(', '),
      eventIds: [4726], timeRange: timeRangeOf(deleted), type: 'event',
      activity: deleted.length + ' suppression(s) de compte detectee(s).',
      why: EVENT_IDS[4726].explain,
      benign: "Depart d'un employe, nettoyage de comptes de test, fin de contrat d'un prestataire.",
      investigate: ["Verifier que la suppression etait prevue.",
        "Chercher si des donnees ont disparu avec le compte."],
      evidence: deleted.slice(0, 5).map(e => 'Compte : ' + (e.account || 'inconnu') + ' | ' + (e.timeRaw || 'date inconnue'))
    }));
  }

  /* --- 4728 / 4732 : changement de groupe --- */
  const privs = events.filter(e => e.id === 4728 || e.id === 4732);
  if (privs.length) {
    const privilegedOnes = privs.filter(e => isPrivilegedGroup(e.group));
    const isPriv = privilegedOnes.length > 0;
    findings.push(baseFinding({
      id: 'event_privilege',
      name: 'Changement d\'appartenance a un groupe de securite',
      severity: isPriv ? 'eleve' : 'moyen', points: isPriv ? 25 : 15, type: 'event',
      account: Array.from(new Set(privs.map(e => e.account).filter(Boolean))).join(', '),
      eventIds: Array.from(new Set(privs.map(e => e.id))),
      timeRange: timeRangeOf(privs),
      activity: privs.length + ' ajout(s) a un groupe de securite, dont ' + privilegedOnes.length + ' sur un groupe privilegie.',
      why: "L'ajout d'un utilisateur a un groupe de securite modifie ses droits. Si le groupe est privilegie (par exemple Administrateurs), l'impact potentiel est beaucoup plus important. On ne peut pas en deduire une compromission : il faut verifier l'autorisation.",
      benign: "Promotion interne, delegation temporaire, mise en place d'un compte d'administration, deploiement automatise.",
      investigate: [
        "Verifier que l'ajout correspond a une demande officielle.",
        "Identifier qui a effectue l'ajout.",
        "Verifier si le compte a ensuite effectue des actions sensibles.",
        "Retirer le privilege s'il n'est pas justifie."
      ],
      evidence: privs.slice(0, 6).map(e => 'Compte : ' + (e.account || 'inconnu') + ' -> groupe "' +
        (e.group || 'inconnu') + '" (' + e.id + ')' + (isPrivilegedGroup(e.group) ? ' [PRIVILEGIE]' : ''))
    }));
  }

  /* --- 7045 : service installe --- */
  const services = of(7045);
  if (services.length) {
    findings.push(baseFinding({
      id: 'event_7045', name: 'Installation d\'un service Windows', severity: 'moyen', points: 15,
      account: Array.from(new Set(services.map(e => e.account).filter(Boolean))).join(', '),
      eventIds: [7045], timeRange: timeRangeOf(services), type: 'event',
      activity: services.length + ' installation(s) de service detectee(s).',
      why: EVENT_IDS[7045].explain,
      benign: "Installation d'un logiciel legitime, agent de supervision, antivirus, pilote materiel.",
      investigate: ["Identifier le logiciel a l'origine du service.",
        "Verifier le chemin du binaire du service.",
        "Confirmer que l'installation etait planifiee."],
      evidence: services.slice(0, 5).map(e => 'Service : ' + (e.service || 'inconnu') + ' | ' + (e.timeRaw || 'date inconnue'))
    }));
  }

  /* --- 4104 : PowerShell --- */
  const ps = of(4104);
  if (ps.length) {
    const flagged = [];
    for (const e of ps) {
      const hits = powershellSuspicion(e.message);
      if (hits.length) flagged.push({ event: e, hits: hits });
    }
    if (flagged.length) {
      findings.push(baseFinding({
        id: 'event_4104_suspicious', name: 'Commande PowerShell encodee ou obfusquee',
        severity: 'moyen', points: 10, type: 'event', eventIds: [4104],
        account: Array.from(new Set(flagged.map(f => f.event.account).filter(Boolean))).join(', '),
        timeRange: timeRangeOf(flagged.map(f => f.event)),
        activity: flagged.length + ' bloc(s) de script PowerShell contenant des indices d\'encodage ou d\'obfuscation.',
        why: "Les commandes PowerShell encodees en base64 ou lancees avec des options de dissimulation sont frequemment utilisees pour masquer une action malveillante. Cela reste un INDICE : des outils d'administration legitimes peuvent produire le meme style de commande.",
        benign: "Script de deploiement, outil d'administration, logiciel de gestion de parc qui encode ses commandes.",
        investigate: [
          "Decoder la commande pour comprendre ce qu'elle fait.",
          "Identifier l'utilisateur et la machine concernes.",
          "Verifier si le script correspond a un outil connu de l'entreprise.",
          "Correler avec les evenements 4688 (processus crees)."
        ],
        evidence: flagged.slice(0, 5).map(f => 'Indices : ' + f.hits.slice(0, 3).join(' | '))
      }));
    } else {
      findings.push(baseFinding({
        id: 'event_4104_info', name: 'Journalisation des blocs de script PowerShell',
        severity: 'info', points: 0, type: 'event', eventIds: [4104],
        timeRange: timeRangeOf(ps),
        activity: ps.length + ' bloc(s) de script PowerShell journalise(s), sans indice d\'obfuscation evident.',
        why: EVENT_IDS[4104].explain,
        benign: "PowerShell est un outil d'administration parfaitement normal, present sur tous les systemes Windows.",
        investigate: ["Utiliser ces enregistrements comme source de contexte lors d'une enquete."],
        evidence: ['Blocs journalises : ' + ps.length]
      }));
    }
  }

  /* --- 4688 : creation de processus (contexte) --- */
  const procs = of(4688);
  if (procs.length) {
    findings.push(baseFinding({
      id: 'event_4688', name: 'Creation de processus (contexte)', severity: 'info', points: 0,
      type: 'event', eventIds: [4688], timeRange: timeRangeOf(procs),
      account: Array.from(new Set(procs.map(e => e.account).filter(Boolean))).join(', '),
      activity: procs.length + ' creation(s) de processus enregistree(s).',
      why: EVENT_IDS[4688].explain,
      benign: "Toute activite normale du systeme genere des creations de processus.",
      investigate: ["Utiliser le nom du processus, le processus parent et la ligne de commande comme contexte."],
      evidence: procs.slice(0, 5).map(e => (e.process || 'processus inconnu') +
        (e.parentProcess ? ' (parent : ' + e.parentProcess + ')' : ''))
    }));
  }

  /* --- 4624 : connexions reussies (contexte) --- */
  const ok = of(4624);
  if (ok.length) {
    findings.push(baseFinding({
      id: 'event_4624', name: 'Connexions reussies (contexte)', severity: 'info', points: 0,
      type: 'event', eventIds: [4624], timeRange: timeRangeOf(ok),
      account: Array.from(new Set(ok.map(e => e.account).filter(Boolean))).join(', '),
      activity: ok.length + ' connexion(s) reussie(s).',
      why: EVENT_IDS[4624].explain,
      benign: "Une connexion reussie est le fonctionnement normal d'un systeme.",
      investigate: ["Ne pas traiter ces evenements isolement : les rapprocher des echecs et des changements de privileges."],
      evidence: ok.slice(0, 5).map(e => (e.account || 'compte inconnu') + ' | ' + (e.timeRaw || 'date inconnue') +
        (e.ip ? ' | ' + e.ip : '') + (e.logonType ? ' | type ' + e.logonType : ''))
    }));
  }

  return findings;
}

/* ---------------------------------------------------------------------------
   REGLE 5 — ACTIVITE ADMINISTRATIVE / PRIVILEGES
   On regroupe ces evenements dans une section dediee plutot que de les
   melanger a tout le reste. On ne correle PAS automatiquement des utilisateurs
   differents : la logique reste explicable.
   --------------------------------------------------------------------------- */
const ADMIN_EVENT_IDS = [4672, 4720, 4726, 4728, 4732, 7045, 1102];

function adminActivityOf(events) {
  return events.filter(e => ADMIN_EVENT_IDS.indexOf(e.id) !== -1);
}

function sanitizeThresholds(input) {
  const out = {};
  for (const key of Object.keys(DEFAULT_THRESHOLDS)) {
    const v = parseInt(input ? input[key] : NaN, 10);
    out[key] = (isNaN(v) || v < 1) ? DEFAULT_THRESHOLDS[key] : v;
  }
  return out;
}

function computeScore(findings) {
  return Math.min(100, findings.reduce((s, f) => s + f.points, 0));
}

function scoreLevel(score) {
  if (score === 0) return { label: 'Aucune activite notable', css: 'level-normal' };
  if (score < 20) return { label: 'Priorite faible', css: 'level-normal' };
  if (score < 50) return { label: 'Priorite moyenne', css: 'level-moderate' };
  if (score < 80) return { label: 'Priorite elevee', css: 'level-elevated' };
  return { label: 'Priorite tres elevee', css: 'level-veryhigh' };
}

function buildStats(events, findings) {
  const count = (id) => events.filter(e => e.id === id).length;
  const accountCount = new Map();
  const failedCount = new Map();
  const idCount = new Map();
  for (const e of events) {
    if (e.account) accountCount.set(e.account, (accountCount.get(e.account) || 0) + 1);
    if (e.id === 4625 && e.account) failedCount.set(e.account, (failedCount.get(e.account) || 0) + 1);
    idCount.set(e.id, (idCount.get(e.id) || 0) + 1);
  }
  const sortDesc = (m, n) => Array.from(m.entries())
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))).slice(0, n || 10);

  const noteworthy = events.filter(e => e.id === 4625 || (e.meta && e.meta.severity !== 'info'));
  const timeline = noteworthy.slice(0, 40).map(e => ({
    time: e.timeRaw || 'date inconnue',
    id: e.id,
    text: (e.meta ? e.meta.name : 'Evenement') +
      (e.account ? ' — ' + e.account : '') +
      (e.group ? ' (groupe : ' + e.group + ')' : '') +
      (e.ip ? ' — ' + e.ip : ''),
    severity: e.id === 1102 ? 'eleve' : (e.meta ? e.meta.severity : 'info')
  }));

  return {
    total: events.length,
    successfulLogons: count(4624),
    failedLogons: count(4625),
    accountsCreated: count(4720),
    accountsDeleted: count(4726),
    privilegeChanges: count(4728) + count(4732),
    logCleared: count(1102),
    processCreated: count(4688),
    servicesInstalled: count(7045),
    powershellBlocks: count(4104),
    requiresInvestigation: findings.filter(f => f.severity === 'eleve' || f.severity === 'moyen').length,
    topAccounts: sortDesc(accountCount, 10),
    topFailed: sortDesc(failedCount, 10),
    topEventIds: sortDesc(idCount, 10),
    timeline: timeline
  };
}

function runTriage(events, thresholds) {
  const th = sanitizeThresholds(thresholds);
  const findings = [];
  findings.push.apply(findings, ruleRepeatedFailures(events, th));
  findings.push.apply(findings, ruleFailuresThenSuccess(events, th));
  findings.push.apply(findings, ruleCreatedThenPrivileged(events));
  findings.push.apply(findings, ruleLogCleared(events));
  findings.push.apply(findings, ruleEventLevel(events));

  const order = { eleve: 0, moyen: 1, faible: 2, info: 3 };
  findings.sort((a, b) => (order[a.severity] - order[b.severity]) || (b.points - a.points));

  const score = computeScore(findings);
  return {
    events: events,
    findings: findings,
    score: score,
    level: scoreLevel(score),
    thresholds: th,
    stats: buildStats(events, findings),
    adminActivity: adminActivityOf(events)
  };
}

/* ===========================================================================
   RENDU DANS LA PAGE
   Securite : tout texte issu du fichier est insere avec textContent,
   jamais avec innerHTML. Un CSV ne peut donc pas executer de JavaScript.
   =========================================================================== */
function byId(id) { return document.getElementById(id); }

function el(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function formatNumber(n) {
  if (n === null || n === undefined || isNaN(n)) return '\u2014';
  return Number(n).toLocaleString('fr-FR');
}

function addMessage(kind, text) {
  const icons = { ok: '\u2714', warn: '\u26A0', err: '\u2716' };
  const div = el('div', 'msg ' + kind);
  div.appendChild(el('span', 'msg-ico', icons[kind] || '\u2022'));
  div.appendChild(el('span', null, text));
  byId('parse-messages').appendChild(div);
}

function clearMessages() { byId('parse-messages').textContent = ''; }

function kpi(label, value, sub) {
  const card = el('div', 'kpi');
  card.appendChild(el('span', 'kpi-label', label));
  card.appendChild(el('span', 'kpi-value', value));
  if (sub) card.appendChild(el('span', 'kpi-sub', sub));
  return card;
}

function renderBarList(container, entries, unit) {
  container.textContent = '';
  if (!entries.length) { container.appendChild(el('p', 'muted', 'Aucune donnee.')); return; }
  const max = entries[0][1] || 1;
  for (const entry of entries) {
    const row = el('div', 'bar-row');
    row.appendChild(el('span', 'bar-name', entry[0]));
    const track = el('div', 'bar-track');
    const fill = el('div', 'bar-fill');
    fill.style.width = Math.max(3, Math.round((entry[1] / max) * 100)) + '%';
    track.appendChild(fill);
    row.appendChild(track);
    row.appendChild(el('span', 'bar-val', entry[1] + ' ' + (unit || 'evenements')));
    container.appendChild(row);
  }
}

function renderDashboard(result) {
  const s = result.stats;
  const grid = byId('kpi-grid');
  grid.textContent = '';
  grid.appendChild(kpi('Evenements au total', formatNumber(s.total)));
  grid.appendChild(kpi('Connexions reussies (4624)', formatNumber(s.successfulLogons)));
  grid.appendChild(kpi('Echecs de connexion (4625)', formatNumber(s.failedLogons)));
  grid.appendChild(kpi('Comptes crees (4720)', formatNumber(s.accountsCreated)));
  grid.appendChild(kpi('Comptes supprimes (4726)', formatNumber(s.accountsDeleted)));
  grid.appendChild(kpi('Changements de privileges', formatNumber(s.privilegeChanges)));
  grid.appendChild(kpi("Effacements de journal (1102)", formatNumber(s.logCleared)));
  grid.appendChild(kpi('Creations de processus (4688)', formatNumber(s.processCreated)));
  grid.appendChild(kpi('Services installes (7045)', formatNumber(s.servicesInstalled)));
  grid.appendChild(kpi('Blocs PowerShell (4104)', formatNumber(s.powershellBlocks)));
  grid.appendChild(kpi("Constats a investiguer", formatNumber(s.requiresInvestigation),
    result.score + '/100 (score d\'investigation)'));

  renderBarList(byId('top-accounts'), s.topAccounts);
  renderBarList(byId('top-failed'), s.topFailed, 'echecs');
  renderBarList(byId('top-eventids'), s.topEventIds);

  const tl = byId('timeline');
  tl.textContent = '';
  if (!s.timeline.length) {
    tl.appendChild(el('p', 'muted', 'Aucun evenement notable a afficher.'));
  } else {
    for (const item of s.timeline) {
      const row = el('div', 'tl-item sev-' + item.severity);
      row.appendChild(el('span', 'tl-time', item.time));
      const body = el('div', 'tl-body');
      body.appendChild(el('strong', null, item.id + ' — '));
      body.appendChild(el('span', null, item.text));
      row.appendChild(body);
      tl.appendChild(row);
    }
  }
}

function renderReferenceTable() {
  const tbody = byId('eventid-reference');
  if (!tbody) return;
  tbody.textContent = '';
  for (const id of EVENT_ID_REFERENCE) {
    const meta = EVENT_IDS[id];
    const tr = el('tr');
    tr.appendChild(el('td', null, String(id)));
    tr.appendChild(el('td', null, meta.name));
    tr.appendChild(el('td', null, meta.explain));
    tbody.appendChild(tr);
  }
}

/* ---------------- Carte d'un constat ---------------- */
function renderFinding(f) {
  const card = el('article', 'alert sev-' + f.severity);
  const head = el('div', 'alert-head');
  head.appendChild(el('span', 'alert-title', f.name));
  head.appendChild(el('span', 'sev-tag ' + (f.severity === 'eleve' ? 'high' : f.severity === 'moyen' ? 'medium' : f.severity === 'faible' ? 'low' : 'info'), SEVERITY_LABEL[f.severity]));
  head.appendChild(el('span', 'alert-pts', f.points > 0 ? '+' + f.points + ' pts' : 'hors score'));
  card.appendChild(head);

  const facts = el('div', 'alert-facts');
  const addFact = (k, v) => {
    if (!v) return;
    const box = el('div', 'fact');
    box.appendChild(el('span', 'fact-k', k));
    box.appendChild(el('span', 'fact-v', v));
    facts.appendChild(box);
  };
  addFact('Compte', f.account);
  addFact('Event ID', f.eventIds.join(' / '));
  addFact('Adresse IP source', f.ip);
  addFact('Machine', f.workstation);
  if (f.timeRange) {
    addFact('Periode', fmtDateTime(f.timeRange.from) + '\n' + fmtDateTime(f.timeRange.to));
  }
  if (facts.childNodes.length) card.appendChild(facts);

  if (f.sequence && f.sequence.length) {
    const seq = el('div', 'sequence');
    f.sequence.forEach((s, i) => {
      if (i > 0) seq.appendChild(el('span', 'seq-arrow', '\u2192'));
      seq.appendChild(el('span', 'seq-chip' + (s === '4624' ? ' bad' : ''), s));
    });
    card.appendChild(seq);
    card.appendChild(el('p', 'alert-window', 'Sequence : ' + f.sequence.join(' \u2192 ')));
  }

  const act = el('div', 'ind-block');
  act.appendChild(el('h4', null, 'Activite observee'));
  act.appendChild(el('p', null, f.activity));
  card.appendChild(act);

  if (f.evidence && f.evidence.length) {
    const ev = el('div', 'ind-block');
    ev.appendChild(el('h4', null, 'Preuves observees'));
    const ul = el('ul', 'evidence');
    for (const e of f.evidence) ul.appendChild(el('li', null, e));
    ev.appendChild(ul);
    card.appendChild(ev);
  }

  const why = el('div', 'ind-block');
  why.appendChild(el('h4', null, 'Pourquoi cela compte'));
  why.appendChild(el('p', null, f.why));
  card.appendChild(why);

  const ben = el('div', 'ind-block');
  ben.appendChild(el('h4', null, 'Explication benigne possible'));
  ben.appendChild(el('p', null, f.benign));
  card.appendChild(ben);

  if (f.investigate && f.investigate.length) {
    const inv = el('div', 'ind-block');
    inv.appendChild(el('h4', null, 'Investigation recommandee'));
    const ul = el('ul', 'evidence');
    f.investigate.forEach((t, i) => ul.appendChild(el('li', null, (i + 1) + '. ' + t)));
    inv.appendChild(ul);
    card.appendChild(inv);
  }

  if (f.window) card.appendChild(el('p', 'alert-window', f.window));
  return card;
}

function renderScore(result) {
  byId('invest-score').textContent = String(result.score);
  const lvl = byId('invest-level');
  lvl.textContent = result.level.label;
  lvl.className = 'score-level ' + result.level.css;

  const list = byId('score-breakdown');
  list.textContent = '';
  const scored = result.findings.filter(f => f.points > 0);
  if (!scored.length) {
    const li = el('li');
    li.appendChild(el('span', 'sb-empty', 'Aucun point attribue.'));
    list.appendChild(li);
  } else {
    for (const f of scored) {
      const li = el('li');
      li.appendChild(el('span', null, '+' + f.points + '  ' + f.name + (f.type === 'correlation' ? ' (correlation)' : '')));
      li.appendChild(el('span', 'sb-pts', '+' + f.points));
      list.appendChild(li);
    }
    const li = el('li');
    li.appendChild(el('strong', null, "Score d'investigation"));
    li.appendChild(el('span', 'sb-pts', String(result.score)));
    list.appendChild(li);
  }
}

function renderSummary(result) {
  const list = byId('summary-list');
  list.textContent = '';
  const rows = [
    ['Evenements analyses', formatNumber(result.stats.total)],
    ['Constats (tous niveaux)', String(result.findings.length)],
    ['Constats de severite elevee', String(result.findings.filter(f => f.severity === 'eleve').length)],
    ['Constats issus de correlation', String(result.findings.filter(f => f.type === 'correlation').length)],
    ['Evenements administratifs', String(result.adminActivity.length)],
    ['Horodatages ambigus', String(result.ambiguousCount || 0)]
  ];
  for (const r of rows) {
    const li = el('li');
    li.appendChild(el('span', 'stat-label', r[0]));
    li.appendChild(el('span', 'stat-val', r[1]));
    list.appendChild(li);
  }
}

/* ---------------- Filtres ---------------- */
let currentResult = null;

function fillSelect(id, values) {
  const sel = byId(id);
  const previous = sel.value;
  while (sel.options.length > 1) sel.remove(1);
  for (const v of values) {
    const opt = document.createElement('option');
    opt.value = String(v);
    opt.textContent = String(v);
    sel.appendChild(opt);
  }
  if (values.map(String).indexOf(previous) !== -1) sel.value = previous;
}

function populateFilters(result) {
  const ids = new Set();
  const accounts = new Set();
  const ips = new Set();
  for (const e of result.events) {
    ids.add(e.id);
    if (e.account) accounts.add(e.account);
    if (e.ip) ips.add(e.ip);
  }
  fillSelect('f-eventid', Array.from(ids).sort((a, b) => a - b));
  fillSelect('f-account', Array.from(accounts).sort());
  fillSelect('f-ip', Array.from(ips).sort());
}

function findingMatches(f, fFilters) {
  if (fFilters.eventId && f.eventIds.map(String).indexOf(fFilters.eventId) === -1) return false;
  if (fFilters.severity && f.severity !== fFilters.severity) return false;
  if (fFilters.account && String(f.account || '').toLowerCase().indexOf(fFilters.account.toLowerCase()) === -1) {
    const inEvidence = f.evidence.some(e => e.toLowerCase().indexOf(fFilters.account.toLowerCase()) !== -1);
    if (!inEvidence) return false;
  }
  if (fFilters.ip && String(f.ip || '').indexOf(fFilters.ip) === -1) return false;
  if (fFilters.type) {
    const match = f.eventIds.some(id => EVENT_IDS[id] && EVENT_IDS[id].type === fFilters.type);
    if (!match) return false;
  }
  if (fFilters.search) {
    const hay = (f.name + ' ' + f.activity + ' ' + f.why + ' ' + f.account + ' ' +
      f.ip + ' ' + f.evidence.join(' ') + ' ' + f.eventIds.join(' ')).toLowerCase();
    if (hay.indexOf(fFilters.search.toLowerCase()) === -1) return false;
  }
  return true;
}

function readFilters() {
  return {
    eventId: byId('f-eventid').value,
    account: byId('f-account').value,
    severity: byId('f-severity').value,
    ip: byId('f-ip').value,
    type: byId('f-type').value,
    search: byId('f-search').value.trim()
  };
}

function renderAdminActivity(result) {
  if (!result.adminActivity.length) return null;
  const card = el('article', 'alert sev-info');
  const head = el('div', 'alert-head');
  head.appendChild(el('span', 'alert-title', 'Activite administrative / privileges'));
  head.appendChild(el('span', 'sev-tag info', 'Synthese'));
  head.appendChild(el('span', 'alert-pts', 'hors score'));
  card.appendChild(head);
  card.appendChild(el('p', 'muted',
    'Regroupement des evenements administratifs et de privileges presents dans le jeu de donnees. ' +
    'Ces evenements ne sont pas correles automatiquement entre utilisateurs differents : la logique reste explicable.'));
  const ul = el('ul', 'evidence');
  for (const e of result.adminActivity.slice(0, 30)) {
    ul.appendChild(el('li', null, (e.timeRaw || 'date inconnue') + ' | ' + e.id + ' ' +
      (e.meta ? e.meta.name : '') + (e.account ? ' | ' + e.account : '') +
      (e.group ? ' | groupe : ' + e.group : '') + (e.service ? ' | service : ' + e.service : '')));
  }
  card.appendChild(ul);
  return card;
}

function renderFindings() {
  if (!currentResult) return;
  const box = byId('alerts');
  box.textContent = '';
  const fFilters = readFilters();
  const shown = currentResult.findings.filter(f => findingMatches(f, fFilters));
  for (const f of shown) box.appendChild(renderFinding(f));
  const adminCard = renderAdminActivity(currentResult);
  if (adminCard) box.appendChild(adminCard);
  byId('no-alerts').hidden = shown.length > 0 || !!adminCard;
}

/* ===========================================================================
   ORCHESTRATION
   =========================================================================== */
function intVal(id, def) {
  const v = parseInt(byId(id).value, 10);
  return (isNaN(v) || v < 1) ? def : v;
}

function readThresholds() {
  return { failed: intVal('th-failed', DEFAULT_THRESHOLDS.failed),
           window: intVal('th-window', DEFAULT_THRESHOLDS.window) };
}

function writeThresholds(th) {
  byId('th-failed').value = th.failed;
  byId('th-window').value = th.window;
}

function resetDashboard() {
  byId('tableau-de-bord').hidden = true;
  byId('resultats').hidden = true;
  currentResult = null;
}

function updateWindowNote(result) {
  const withDate = result.events.filter(e => e.date).length;
  const note = byId('window-note');
  if (withDate === 0) {
    note.textContent = "Aucun horodatage exploitable : la correlation repose sur l'ordre des lignes du fichier. " +
      "La fenetre temporelle n'est donc pas appliquee.";
  } else if (result.ambiguousCount > 0) {
    note.textContent = result.ambiguousCount + " horodatage(s) au format ambigu (jour/mois ou mois/jour) : " +
      "l'hypothese jour/mois a ete retenue. Verifiez ce point si vos dates vous semblent inversees.";
  } else {
    note.textContent = 'Horodatages lus avec succes : la fenetre temporelle est appliquee a la correlation.';
  }
}

function processCsv(text, fileName) {
  clearMessages();
  const res = analyseCsvText(text);

  if (res.error) {
    byId('st-file').textContent = fileName || '\u2014';
    byId('st-events').textContent = '0';
    byId('st-parse').textContent = 'Echec';
    byId('st-time').textContent = '\u2014';
    addMessage('err', res.error);
    if (res.headers && res.headers.length) addMessage('warn', 'Colonnes trouvees : ' + res.headers.join(', '));
    addMessage('warn', 'Colonnes attendues : Level, Date and Time, Source, Event ID, Task Category, User, Computer, Keywords, Message (des variantes sont acceptees).');
    resetDashboard();
    return null;
  }

  byId('st-file').textContent = fileName || '\u2014';
  byId('st-events').textContent = formatNumber(res.events.length);
  byId('st-parse').textContent = 'Reussie';
  const withDate = res.events.filter(e => e.date).length;
  byId('st-time').textContent = withDate + ' / ' + res.events.length;

  addMessage('ok', 'Analyse du fichier reussie : ' + res.events.length + ' evenements lus.');
  if (res.missing.length) {
    addMessage('warn', "Colonnes absentes qui limitent l'analyse : " + res.missing.map(k => COLUMN_LABELS[k] || k).join(', ') + '.');
  } else {
    addMessage('ok', 'Toutes les colonnes attendues ont ete reconnues.');
  }

  const result = runTriage(res.events, readThresholds());
  result.ambiguousCount = res.ambiguousCount;
  currentResult = result;

  updateWindowNote(result);
  renderDashboard(result);
  renderScore(result);
  renderSummary(result);
  populateFilters(result);
  renderFindings();

  byId('tableau-de-bord').hidden = false;
  byId('resultats').hidden = false;
  return result;
}

function recompute() {
  if (!currentResult) return;
  const result = runTriage(currentResult.events, readThresholds());
  result.ambiguousCount = currentResult.ambiguousCount;
  currentResult = result;
  updateWindowNote(result);
  renderDashboard(result);
  renderScore(result);
  renderSummary(result);
  populateFilters(result);
  renderFindings();
  byId('resultats').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function loadFile(file) {
  if (!file) return;
  const name = file.name || 'evenements.csv';
  clearMessages();
  if (!/\.(csv|txt)$/i.test(name)) {
    addMessage('warn', 'Extension inattendue : "' + name + '". L\'outil essaie quand meme de lire le contenu comme du texte.');
  }
  const reader = new FileReader();
  reader.onload = () => processCsv(String(reader.result || ''), name);
  reader.onerror = () => addMessage('err', 'Impossible de lire ce fichier localement.');
  reader.readAsText(file);
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ===========================================================================
   INITIALISATION (uniquement dans un navigateur)
   =========================================================================== */
function renderSampleCards() {
  const grid = byId('sample-grid');
  if (!grid) return;
  grid.textContent = '';
  for (const s of SAMPLES) {
    const card = el('article', 'sample-card');
    card.appendChild(el('span', 'demo-badge', 'Donnees de demonstration'));
    card.appendChild(el('h3', null, s.name));
    card.appendChild(el('p', null, s.desc));
    const actions = el('div', 'sample-actions');
    const load = el('button', 'btn btn-ghost', 'Charger cet exemple');
    load.type = 'button';
    load.addEventListener('click', () => {
      processCsv(s.csv, s.file);
      byId('tableau-de-bord').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    const dl = el('button', 'btn btn-ghost', 'Telecharger le CSV');
    dl.type = 'button';
    dl.addEventListener('click', () => downloadText(s.file, s.csv));
    actions.appendChild(load);
    actions.appendChild(dl);
    card.appendChild(actions);
    grid.appendChild(card);
  }
}

function init() {
  renderReferenceTable();
  renderSampleCards();
  updateWindowNote({ events: [], ambiguousCount: 0 });

  const dz = byId('dropzone');
  const input = byId('file-input');

  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); dz.classList.add('is-drag');
  }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); dz.classList.remove('is-drag');
  }));
  dz.addEventListener('drop', (e) => {
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) loadFile(files[0]);
  });
  input.addEventListener('change', () => {
    if (input.files && input.files.length) loadFile(input.files[0]);
  });

  byId('btn-reset').addEventListener('click', () => {
    clearMessages();
    byId('st-file').textContent = '\u2014';
    byId('st-events').textContent = '0';
    byId('st-parse').textContent = '\u2014';
    byId('st-time').textContent = '\u2014';
    resetDashboard();
    input.value = '';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  byId('btn-recompute').addEventListener('click', recompute);
  byId('btn-defaults').addEventListener('click', () => {
    writeThresholds(DEFAULT_THRESHOLDS);
    if (currentResult) recompute();
  });

  ['f-eventid', 'f-account', 'f-severity', 'f-ip', 'f-type'].forEach((id) => {
    byId(id).addEventListener('change', renderFindings);
  });
  byId('f-search').addEventListener('input', renderFindings);
  byId('btn-clear-filters').addEventListener('click', () => {
    ['f-eventid', 'f-account', 'f-severity', 'f-ip', 'f-type'].forEach((id) => { byId(id).value = ''; });
    byId('f-search').value = '';
    renderFindings();
  });
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}

/* ===========================================================================
   EXEMPLES DE DEMONSTRATION (journaux entierement fictifs)
   ---------------------------------------------------------------------------
   Comptes, machines et adresses IP sont inventes (plages privees :
   192.168.10.x, 10.0.0.x) ou reservees a la documentation (203.0.113.x).
   Les memes fichiers existent dans samples/ pour inspection manuelle.
   =========================================================================== */
const SAMPLES = [
  {
    id: 'normal', file: 'normal-windows-events.csv',
    name: '1. Activite Windows normale',
    desc: "Connexions reussies, creations de processus, un service legitime et un seul echec de connexion. Attendu : peu ou pas de constat prioritaire.",
    csv: `Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message
Information,06/10/2025 08:05:10,Microsoft-Windows-Security-Auditing,4624,Logon,mgarcia,PC-COMPTA-01,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		PC-COMPTA-01$
Logon Information:
	Logon Type:		2
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		mgarcia
Network Information:
	Workstation Name:	PC-COMPTA-01
	Source Network Address:	192.168.10.40"
Information,06/10/2025 08:06:40,Microsoft-Windows-Security-Auditing,4688,Process Creation,mgarcia,PC-COMPTA-01,Audit Success,"A new process has been created.

New Process Name:		C:\Program Files\Microsoft Office\WINWORD.EXE
Creator Process Name:	C:\Windows\explorer.exe
Process Command Line:	C:\Program Files\Microsoft Office\WINWORD.EXE
Account Name:		mgarcia"
Information,06/10/2025 08:06:10,Microsoft-Windows-Security-Auditing,4624,Logon,mgarcia,PC-COMPTA-01,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		PC-COMPTA-01$
Logon Information:
	Logon Type:		2
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		mgarcia
Network Information:
	Workstation Name:	PC-COMPTA-01
	Source Network Address:	192.168.10.40"
Information,06/10/2025 08:07:40,Microsoft-Windows-Security-Auditing,4688,Process Creation,mgarcia,PC-COMPTA-01,Audit Success,"A new process has been created.

New Process Name:		C:\Program Files\Microsoft Office\WINWORD.EXE
Creator Process Name:	C:\Windows\explorer.exe
Process Command Line:	C:\Program Files\Microsoft Office\WINWORD.EXE
Account Name:		mgarcia"
Information,06/10/2025 08:07:10,Microsoft-Windows-Security-Auditing,4624,Logon,mgarcia,PC-COMPTA-01,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		PC-COMPTA-01$
Logon Information:
	Logon Type:		2
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		mgarcia
Network Information:
	Workstation Name:	PC-COMPTA-01
	Source Network Address:	192.168.10.40"
Information,06/10/2025 08:08:40,Microsoft-Windows-Security-Auditing,4688,Process Creation,mgarcia,PC-COMPTA-01,Audit Success,"A new process has been created.

New Process Name:		C:\Program Files\Microsoft Office\WINWORD.EXE
Creator Process Name:	C:\Windows\explorer.exe
Process Command Line:	C:\Program Files\Microsoft Office\WINWORD.EXE
Account Name:		mgarcia"
Information,06/10/2025 08:08:10,Microsoft-Windows-Security-Auditing,4624,Logon,mgarcia,PC-COMPTA-01,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		PC-COMPTA-01$
Logon Information:
	Logon Type:		2
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		mgarcia
Network Information:
	Workstation Name:	PC-COMPTA-01
	Source Network Address:	192.168.10.40"
Information,06/10/2025 08:09:40,Microsoft-Windows-Security-Auditing,4688,Process Creation,mgarcia,PC-COMPTA-01,Audit Success,"A new process has been created.

New Process Name:		C:\Program Files\Microsoft Office\WINWORD.EXE
Creator Process Name:	C:\Windows\explorer.exe
Process Command Line:	C:\Program Files\Microsoft Office\WINWORD.EXE
Account Name:		mgarcia"
Information,06/10/2025 08:09:10,Microsoft-Windows-Security-Auditing,4624,Logon,mgarcia,PC-COMPTA-01,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		PC-COMPTA-01$
Logon Information:
	Logon Type:		2
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		mgarcia
Network Information:
	Workstation Name:	PC-COMPTA-01
	Source Network Address:	192.168.10.40"
Information,06/10/2025 08:10:40,Microsoft-Windows-Security-Auditing,4688,Process Creation,mgarcia,PC-COMPTA-01,Audit Success,"A new process has been created.

New Process Name:		C:\Program Files\Microsoft Office\WINWORD.EXE
Creator Process Name:	C:\Windows\explorer.exe
Process Command Line:	C:\Program Files\Microsoft Office\WINWORD.EXE
Account Name:		mgarcia"
Information,06/10/2025 09:12:05,Microsoft-Windows-Security-Auditing,4634,Logoff,mgarcia,PC-COMPTA-01,Audit Success,"An account was logged off.

Account Name:		mgarcia"
Information,06/10/2025 10:03:22,Microsoft-Windows-Security-Auditing,4624,Logon,svc-backup,SRV-FICHIER-02,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		SRV-FICHIER-02$
Logon Information:
	Logon Type:		5
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		svc-backup
Network Information:
	Workstation Name:	SRV-FICHIER-02
	Source Network Address:	10.0.0.5"
Information,06/10/2025 11:30:00,Microsoft-Windows-Security-Auditing,4672,Special Logon,admin.local,SRV-AD-01,Audit Success,"Special privileges assigned to new logon.

Account Name:		admin.local"
Error,06/10/2025 14:02:11,Microsoft-Windows-Security-Auditing,4625,Logon,mgarcia,PC-COMPTA-01,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-COMPTA-01$
Logon Type:		2
Account For Which Logon Failed:
	Account Name:		mgarcia
Network Information:
	Workstation Name:	PC-COMPTA-01
	Source Network Address:	192.168.10.40"
Information,06/10/2025 14:02:30,Microsoft-Windows-Security-Auditing,4624,Logon,mgarcia,PC-COMPTA-01,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		PC-COMPTA-01$
Logon Information:
	Logon Type:		2
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		mgarcia
Network Information:
	Workstation Name:	PC-COMPTA-01
	Source Network Address:	192.168.10.40"
Information,07/10/2025 09:00:00,Service Control Manager,7045,Service Installation,admin.local,SRV-FICHIER-02,Classic,"A service was installed in the system.

Service Name:	ExempleBackupAgent
Service File Name:	C:\Program Files\Exemple\ExempleBackupAgent.exe
Account Name:	admin.local"
Information,07/10/2025 09:15:00,Microsoft-Windows-PowerShell,4104,Execute a Remote Command,admin.local,SRV-FICHIER-02,Classic,"Creating Scriptblock text (1 of 1):
Get-Service | Where-Object {$_.Status -eq ""Running""}
Account Name:	admin.local"
`
  },
  {
    id: 'guessing', file: 'password-guessing.csv',
    name: '2. Echecs de connexion repetes',
    desc: "12 echecs (4625) pour le compte jsmith depuis la meme adresse IP, puis une connexion reussie (4624).",
    csv: `Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message
Error,08/10/2025 02:10:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:11:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:12:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:13:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:14:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:15:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:16:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:17:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:18:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:19:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:20:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Error,08/10/2025 02:21:05,Microsoft-Windows-Security-Auditing,4625,Logon,jsmith,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Information,08/10/2025 02:24:40,Microsoft-Windows-Security-Auditing,4624,Logon,jsmith,PC-DEV-07,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		PC-DEV-07$
Logon Information:
	Logon Type:		3
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		jsmith
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	192.168.10.25"
Information,08/10/2025 02:26:00,Microsoft-Windows-Security-Auditing,4688,Process Creation,jsmith,PC-DEV-07,Audit Success,"A new process has been created.

New Process Name:		C:\Windows\System32\cmd.exe
Creator Process Name:	C:\Windows\explorer.exe
Process Command Line:	C:\Windows\System32\cmd.exe
Account Name:		jsmith"
`
  },
  {
    id: 'persistence', file: 'account-persistence.csv',
    name: '3. Creation de compte puis privileges',
    desc: "Creation du compte temp-admin (4720) puis ajout au groupe Administrators (4732).",
    csv: `Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message
Information,09/10/2025 15:40:10,Microsoft-Windows-Security-Auditing,4720,User Account Management,admin.local,SRV-AD-01,Audit Success,"A user account was created.

Subject:
	Account Name:		admin.local
New Account:
	Account Name:		temp-admin
Computer:	SRV-AD-01"
Information,09/10/2025 15:41:30,Microsoft-Windows-Security-Auditing,4732,Security Group Management,admin.local,SRV-AD-01,Audit Success,"A member was added to a security-enabled local group.

Subject:
	Account Name:		admin.local
Member:
	Account Name:		temp-admin
Group:
	Group Name:		Administrators"
Information,09/10/2025 15:50:00,Microsoft-Windows-Security-Auditing,4624,Logon,temp-admin,SRV-AD-01,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		SRV-AD-01$
Logon Information:
	Logon Type:		10
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		temp-admin
Network Information:
	Workstation Name:	SRV-AD-01
	Source Network Address:	192.168.10.99"
Information,09/10/2025 16:05:00,Microsoft-Windows-Security-Auditing,4688,Process Creation,temp-admin,SRV-AD-01,Audit Success,"A new process has been created.

New Process Name:		C:\Windows\System32\whoami.exe
Creator Process Name:	C:\Windows\System32\cmd.exe
Process Command Line:	C:\Windows\System32\whoami.exe
Account Name:		temp-admin"
`
  },
  {
    id: 'mixed', file: 'suspicious-admin-activity.csv',
    name: '4. Activite administrative suspecte (mixte)',
    desc: "Echecs de connexion, connexion reussie, creation de compte, elevation de privileges, service installe, PowerShell encode et journal efface.",
    csv: `Level,Date and Time,Source,Event ID,Task Category,User,Computer,Keywords,Message
Error,10/10/2025 03:12:02,Microsoft-Windows-Security-Auditing,4625,Logon,r.dubois,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		r.dubois
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	203.0.113.77"
Error,10/10/2025 03:13:02,Microsoft-Windows-Security-Auditing,4625,Logon,r.dubois,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		r.dubois
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	203.0.113.77"
Error,10/10/2025 03:14:02,Microsoft-Windows-Security-Auditing,4625,Logon,r.dubois,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		r.dubois
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	203.0.113.77"
Error,10/10/2025 03:15:02,Microsoft-Windows-Security-Auditing,4625,Logon,r.dubois,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		r.dubois
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	203.0.113.77"
Error,10/10/2025 03:16:02,Microsoft-Windows-Security-Auditing,4625,Logon,r.dubois,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		r.dubois
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	203.0.113.77"
Error,10/10/2025 03:17:02,Microsoft-Windows-Security-Auditing,4625,Logon,r.dubois,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		r.dubois
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	203.0.113.77"
Error,10/10/2025 03:18:02,Microsoft-Windows-Security-Auditing,4625,Logon,r.dubois,PC-DEV-07,Audit Failure,"An account failed to log on.

Subject:
	Account Name:		PC-DEV-07$
Logon Type:		3
Account For Which Logon Failed:
	Account Name:		r.dubois
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	203.0.113.77"
Information,10/10/2025 03:22:15,Microsoft-Windows-Security-Auditing,4624,Logon,r.dubois,PC-DEV-07,Audit Success,"An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		PC-DEV-07$
Logon Information:
	Logon Type:		3
New Logon:
	Security ID:		S-1-5-21-0000
	Account Name:		r.dubois
Network Information:
	Workstation Name:	PC-DEV-07
	Source Network Address:	203.0.113.77"
Information,10/10/2025 03:25:00,Microsoft-Windows-Security-Auditing,4720,User Account Management,r.dubois,SRV-AD-01,Audit Success,"A user account was created.

Subject:
	Account Name:		r.dubois
New Account:
	Account Name:		support-temp
Computer:	SRV-AD-01"
Information,10/10/2025 03:26:10,Microsoft-Windows-Security-Auditing,4728,Security Group Management,r.dubois,SRV-AD-01,Audit Success,"A member was added to a security-enabled global group.

Subject:
	Account Name:		r.dubois
Member:
	Account Name:		support-temp
Group:
	Group Name:		Domain Admins"
Information,10/10/2025 03:30:00,Service Control Manager,7045,Service Installation,r.dubois,SRV-AD-01,Classic,"A service was installed in the system.

Service Name:	WinUpdateHelper
Service File Name:	C:\Program Files\Exemple\WinUpdateHelper.exe
Account Name:	r.dubois"
Information,10/10/2025 03:34:00,Microsoft-Windows-PowerShell,4104,Execute a Remote Command,r.dubois,SRV-AD-01,Classic,"Creating Scriptblock text (1 of 1):
powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
Account Name:	r.dubois"
Warning,10/10/2025 03:36:00,Microsoft-Windows-Security-Auditing,1102,Audit Log Cleared,r.dubois,SRV-AD-01,Audit Success,"The audit log was cleared.

Subject:
	Account Name:		r.dubois
Computer:	SRV-AD-01"
`
  },
];

/* Export reserve aux tests automatises (Node.js). Le navigateur ignore ce bloc. */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    EVENT_IDS, EVENT_ID_REFERENCE, DEFAULT_THRESHOLDS, SAMPLES,
    parseCsv, detectDelimiter, mapColumns, missingColumns, buildEvents, analyseCsvText,
    parseTimestamp, extractAccount, extractIp, extractGroup, isPrivilegedGroup,
    powershellSuspicion, runTriage, computeScore, scoreLevel, sanitizeThresholds,
    ruleRepeatedFailures, ruleFailuresThenSuccess, ruleCreatedThenPrivileged, ruleLogCleared
  };
}
