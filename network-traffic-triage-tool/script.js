/* ============================================================================
   Network Traffic Triage Tool — moteur de triage local
   ----------------------------------------------------------------------------
   PRINCIPE : tout se passe dans le navigateur. Aucune requete reseau n'est
   effectuee (pas de fetch, pas de XHR, pas de WebSocket). Aucun cookie.

   ETAPES :
     1) Lecture du CSV (Wireshark) avec detection du separateur.
     2) Reconnaissance tolerante des colonnes (Source / src / ip.src...).
     3) Agregation : qui parle a qui, avec quel protocole, combien de fois.
     4) Regles de detection explicables + score d'investigation.
   ============================================================================ */

'use strict';

/* ---------------------------------------------------------------------------
   RECONNAISSANCE DES COLONNES
   On normalise chaque entete (minuscules, sans espaces ni ponctuation) puis on
   compare a une liste de variantes : "Source", "Source IP", "src", "ip.src"
   donnent tous "source".
   --------------------------------------------------------------------------- */
const COLUMN_CANDIDATES = {
  no: ['no', 'n', 'num', 'number', 'numero', 'numerodepaquet', 'packetno', 'index', 'id'],
  time: ['time', 'timestamp', 'heure', 'temps', 'duree', 'relative', 'relativetime', 'seconde'],
  source: ['source', 'sourceip', 'src', 'ipsrc', 'ipv4src', 'ipv6src', 'adressesource',
    'sourceaddress', 'srcip', 'srchost', 'originesource'],
  destination: ['destination', 'destinationip', 'dst', 'ipdst', 'ipv4dst', 'ipv6dst',
    'adressedestination', 'destinationaddress', 'dstip', 'dsthost', 'cible'],
  protocol: ['protocol', 'protocole', 'proto', 'protocolname'],
  length: ['length', 'longueur', 'len', 'size', 'taille', 'framelength', 'packetlength', 'bytes', 'octets'],
  info: ['info', 'information', 'informations', 'details', 'detail', 'resume', 'description', 'comment']
};

const COLUMN_LABELS = {
  no: 'numero de paquet',
  time: 'horodatage',
  source: 'adresse source',
  destination: 'adresse destination',
  protocol: 'protocole',
  length: 'taille du paquet',
  info: 'colonne Info'
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
   LECTURE DU CSV
   Les exports Wireshark contiennent des champs entre guillemets qui peuvent
   eux-memes contenir des virgules (la colonne Info, par exemple).
   On utilise donc un lecteur CSV qui respecte les guillemets.
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
   CONSTRUCTION DES PAQUETS
   --------------------------------------------------------------------------- */
function classifyProtocol(raw, info) {
  const p = String(raw || '').toUpperCase();
  const t = String(info || '').toUpperCase();
  if (p.indexOf('DNS') !== -1) return 'DNS';
  if (p.indexOf('ARP') !== -1) return 'ARP';
  if (p.indexOf('ICMP') !== -1) return 'ICMP';
  if (p.indexOf('TLS') !== -1 || p.indexOf('SSL') !== -1 || p.indexOf('HTTPS') !== -1) return 'HTTPS/TLS';
  if (p.indexOf('HTTP') !== -1) return 'HTTP';
  if (p.indexOf('TCP') !== -1) return 'TCP';
  if (p.indexOf('UDP') !== -1) return 'UDP';
  if (/STANDARD QUERY|DNS/.test(t)) return 'DNS';
  if (/ICMP/.test(t)) return 'ICMP';
  return 'Autres';
}

/** Essaie d'extraire les ports depuis la colonne Info (tres variable). */
function extractPorts(info) {
  const out = { srcPort: null, dstPort: null };
  const s = String(info || '');
  const arrow = /(\d{1,5})\s*(?:\u2192|->|=>|>)\s*(\d{1,5})/.exec(s);
  if (arrow) { out.srcPort = parseInt(arrow[1], 10); out.dstPort = parseInt(arrow[2], 10); return out; }
  const dst = /(?:dst\s*port|destination\s*port|port\s*destination)\s*[=:]\s*(\d{1,5})/i.exec(s);
  if (dst) out.dstPort = parseInt(dst[1], 10);
  return out;
}

function extractTcpFlags(info) {
  const m = /\[([A-Za-z, ]{1,40})\]/.exec(String(info || ''));
  return m ? m[1].toUpperCase().replace(/\s+/g, '') : '';
}

function buildPackets(rows, map) {
  const packets = [];
  const dataRows = rows.slice(1);
  for (const r of dataRows) {
    const src = String(r[map.source] || '').trim();
    const dst = String(r[map.destination] || '').trim();
    if (!src || !dst) continue;
    const info = map.info !== undefined ? String(r[map.info] || '') : '';
    const protoRaw = map.protocol !== undefined ? String(r[map.protocol] || '') : '';
    const lenRaw = map.length !== undefined ? String(r[map.length] || '') : '';
    const timeRaw = map.time !== undefined ? String(r[map.time] || '') : '';
    const ports = extractPorts(info);
    const flags = extractTcpFlags(info);
    packets.push({
      no: map.no !== undefined ? String(r[map.no] || '') : '',
      time: timeRaw ? parseFloat(timeRaw.replace(',', '.')) : null,
      src: src,
      dst: dst,
      proto: classifyProtocol(protoRaw, info),
      protoRaw: protoRaw,
      length: lenRaw ? parseFloat(lenRaw.replace(',', '.')) : null,
      info: info,
      srcPort: ports.srcPort,
      dstPort: ports.dstPort,
      flags: flags,
      synOnly: flags.indexOf('SYN') !== -1 && flags.indexOf('ACK') === -1,
      rst: flags.indexOf('RST') !== -1
    });
  }
  return packets;
}

/** Liste les colonnes importantes qui n'ont pas ete trouvees. */
function missingColumns(map) {
  const missing = [];
  for (const key of ['source', 'destination', 'protocol', 'length', 'info', 'time', 'no']) {
    if (map[key] === undefined) missing.push(key);
  }
  return missing;
}

/* ---------------------------------------------------------------------------
   AGREGATION : que retient-on d'une capture ?
   On compte, pour chaque source et chaque couple (source, destination), les
   volumes, les protocoles et les ports. C'est la base de toutes les regles.
   --------------------------------------------------------------------------- */
function inc(map, key, n) { map.set(key, (map.get(key) || 0) + (n || 1)); }

function aggregate(packets) {
  const srcCount = new Map();
  const dstCount = new Map();
  const protoCount = new Map();
  const srcDests = new Map();
  const pairCount = new Map();
  const pairProto = new Map();
  const pairPorts = new Map();
  const icmpBySrc = new Map();
  const dnsBySrc = new Map();
  const synBySrc = new Map();
  const rstBySrc = new Map();
  let totalLen = 0;
  let lenCount = 0;
  let firstTime = null;
  let lastTime = null;

  for (const p of packets) {
    inc(srcCount, p.src);
    inc(dstCount, p.dst);
    inc(protoCount, p.proto);

    if (!srcDests.has(p.src)) srcDests.set(p.src, new Set());
    srcDests.get(p.src).add(p.dst);

    const pair = p.src + '\u0000' + p.dst;
    inc(pairCount, pair);
    if (!pairProto.has(pair)) pairProto.set(pair, new Map());
    inc(pairProto.get(pair), p.proto);

    if (p.dstPort !== null && !isNaN(p.dstPort)) {
      if (!pairPorts.has(pair)) pairPorts.set(pair, new Set());
      pairPorts.get(pair).add(p.dstPort);
    }

    if (p.proto === 'ICMP') inc(icmpBySrc, p.src);
    if (p.proto === 'DNS') inc(dnsBySrc, p.src);
    if (p.synOnly) inc(synBySrc, p.src);
    if (p.rst) inc(rstBySrc, p.src);

    if (p.length !== null && !isNaN(p.length)) { totalLen += p.length; lenCount++; }
    if (p.time !== null && !isNaN(p.time)) {
      if (firstTime === null || p.time < firstTime) firstTime = p.time;
      if (lastTime === null || p.time > lastTime) lastTime = p.time;
    }
  }

  const sortDesc = (map, limit) => Array.from(map.entries())
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, limit || 10);

  return {
    packets: packets,
    total: packets.length,
    srcCount: srcCount,
    dstCount: dstCount,
    protoCount: protoCount,
    srcDests: srcDests,
    pairCount: pairCount,
    pairProto: pairProto,
    pairPorts: pairPorts,
    icmpBySrc: icmpBySrc,
    dnsBySrc: dnsBySrc,
    synBySrc: synBySrc,
    rstBySrc: rstBySrc,
    avgLength: lenCount ? totalLen / lenCount : null,
    duration: (firstTime !== null && lastTime !== null) ? (lastTime - firstTime) : null,
    topSources: sortDesc(srcCount, 10),
    topDestinations: sortDesc(dstCount, 10),
    protocolList: Array.from(protoCount.entries()).sort((a, b) => b[1] - a[1]),
    uniqueSources: srcCount.size,
    uniqueDestinations: dstCount.size
  };
}

/* ===========================================================================
   LES 7 REGLES DE DETECTION
   ---------------------------------------------------------------------------
   Aucune n'utilise d'apprentissage automatique : ce sont des seuils lisibles.
   Chaque regle renvoie : preuves observees, pourquoi c'est interessant,
   explication benigne possible, et investigation recommandee.
   Une regle ne se declenche qu'UNE fois, meme si plusieurs hotes depassent le
   seuil : la liste des hotes concernes apparait dans les preuves.
   =========================================================================== */
const DEFAULT_THRESHOLDS = { packets: 50, dest: 10, ports: 10, icmp: 30, dns: 30, pair: 40, syn: 20 };

const RULES = [
  {
    id: 'volume', name: 'Hote tres actif (volume de paquets eleve)', severity: 'moyen', points: 20,
    why: "Un hote qui genere beaucoup plus de trafic que les autres attire l'attention. Un volume anormal peut correspondre a un transfert de donnees non prevu, a une machine compromise qui communique vers l'exterieur, ou simplement a une tache planifiee.",
    benign: "Transfert de fichiers legitime, mises a jour logicielles, sauvegarde, machine virtuelle, script automatise, erreur de configuration.",
    investigate: [
      "Verifier ce que fait cet hote a cet instant (taches planifiees, sauvegardes, antivirus).",
      "Identifier la destination principale de ce trafic.",
      "Comparer avec l'activite habituelle de cette machine."
    ],
    run(agg, th) {
      const off = Array.from(agg.srcCount.entries()).filter(e => e[1] > th.packets)
        .sort((a, b) => b[1] - a[1]).slice(0, 5);
      if (!off.length) return null;
      return {
        summary: off.length + ' source(s) depassent le seuil de ' + th.packets + ' paquets.',
        facts: [{ k: 'Hote le plus actif', v: off[0][0] }, { k: 'Paquets', v: off[0][1] }, { k: 'Seuil', v: th.packets }],
        evidence: off.map(e => e[0] + ' : ' + e[1] + ' paquets (seuil ' + th.packets + ')')
      };
    }
  },

  {
    id: 'hostscan', name: 'Scan d\'hotes possible (nombreuses destinations)', severity: 'eleve', points: 15,
    why: "Une meme source qui contacte beaucoup d'adresses differentes en peu de temps ressemble a une phase de decouverte reseau : on cherche a savoir quelles machines existent avant de choisir une cible.",
    benign: "Outils d'administration, inventaire automatise, supervision, serveur DHCP, DNS, antivirus qui balaye le reseau.",
    investigate: [
      "Identifier si la source est un outil d'administration connu (inventaire, supervision).",
      "Verifier si ces destinations existent reellement dans votre reseau.",
      "Regarder si des ports varies sont cibles sur ces destinations."
    ],
    run(agg, th) {
      const off = Array.from(agg.srcDests.entries()).map(e => [e[0], e[1].size])
        .filter(e => e[1] > th.dest).sort((a, b) => b[1] - a[1]).slice(0, 5);
      if (!off.length) return null;
      return {
        summary: off.length + ' source(s) contactent plus de ' + th.dest + ' destinations differentes.',
        facts: [{ k: 'Source', v: off[0][0] }, { k: 'Destinations uniques', v: off[0][1] }, { k: 'Seuil', v: th.dest }],
        evidence: off.map(e => e[0] + ' : ' + e[1] + ' destinations uniques (seuil ' + th.dest + ')')
      };
    }
  },

  {
    id: 'portscan', name: 'Scan de ports possible', severity: 'eleve', points: 15,
    why: "Contacter de nombreux ports sur une meme destination ressemble a une recherche de services ouverts. C'est ainsi qu'un attaquant cherche un point d'entree.",
    benign: "Decouverte legitime de services, client qui teste plusieurs ports, application mal configuree, outil de diagnostic.",
    investigate: [
      "Verifier quels ports sont cibles et s'ils correspondent a des services reels.",
      "Regarder si les connexions ont ete refusees (RST) ou acceptees (SYN, ACK).",
      "Identifier le processus a l'origine du trafic sur la machine source."
    ],
    run(agg, th) {
      const off = Array.from(agg.pairPorts.entries()).map(e => [e[0].split('\u0000'), e[1].size])
        .filter(e => e[1] > th.ports).sort((a, b) => b[1] - a[1]).slice(0, 5);
      if (!off.length) return null;
      return {
        summary: off.length + ' couple(s) source/destination depassent ' + th.ports + ' ports differents.',
        facts: [{ k: 'Source', v: off[0][0][0] }, { k: 'Destination', v: off[0][0][1] },
                { k: 'Ports uniques', v: off[0][1] }, { k: 'Seuil', v: th.ports }],
        evidence: off.map(e => e[0][0] + ' \u2192 ' + e[0][1] + ' : ' + e[1] + ' ports differents (seuil ' + th.ports + ')')
      };
    }
  },

  {
    id: 'icmp', name: 'Activite ICMP elevee', severity: 'moyen', points: 15,
    why: "Un volume important de messages ICMP (ping) peut correspondre a un balayage de reseau : on teste rapidement quelles machines repondent. Cela peut aussi etre un simple outil de supervision.",
    benign: "Depannage reseau, supervision, ping sweep d'inventaire, decouverte de reseau, test de disponibilite.",
    investigate: [
      "Identifier l'outil qui emet ces pings (supervision, inventaire, script).",
      "Verifier si le nombre de destinations differentes est inhabituel.",
      "Comparer avec le volume ICMP habituel sur ce segment."
    ],
    run(agg, th) {
      const off = Array.from(agg.icmpBySrc.entries()).filter(e => e[1] > th.icmp)
        .sort((a, b) => b[1] - a[1]).slice(0, 5);
      if (!off.length) return null;
      return {
        summary: off.length + ' source(s) depassent ' + th.icmp + ' paquets ICMP.',
        facts: [{ k: 'Source', v: off[0][0] }, { k: 'Paquets ICMP', v: off[0][1] }, { k: 'Seuil', v: th.icmp }],
        evidence: off.map(e => e[0] + ' : ' + e[1] + ' paquets ICMP (seuil ' + th.icmp + ')')
      };
    }
  },

  {
    id: 'dns', name: 'Activite DNS elevee', severity: 'moyen', points: 15,
    why: "Beaucoup de requetes DNS depuis une meme source peut correspondre a une navigation normale, mais aussi a un logiciel qui communique regulierement avec un serveur distant (\"beaconing\"). Le rythme et la regularite sont souvent plus parlants que le volume.",
    benign: "Navigation web, mises a jour, applications automatisees, mauvaise configuration DNS, antivirus, client de messagerie.",
    investigate: [
      "Verifier les domaines demandes : sont-ils connus et attendus ?",
      "Regarder la regularite des requetes (toutes les X minutes = a surveiller).",
      "Verifier si la machine devrait vraiment generer autant de DNS."
    ],
    run(agg, th) {
      const off = Array.from(agg.dnsBySrc.entries()).filter(e => e[1] > th.dns)
        .sort((a, b) => b[1] - a[1]).slice(0, 5);
      if (!off.length) return null;
      return {
        summary: off.length + ' source(s) depassent ' + th.dns + ' paquets DNS.',
        facts: [{ k: 'Source', v: off[0][0] }, { k: 'Requetes DNS', v: off[0][1] }, { k: 'Seuil', v: th.dns }],
        evidence: off.map(e => e[0] + ' : ' + e[1] + ' paquets DNS (seuil ' + th.dns + ')')
      };
    }
  },

  {
    id: 'pair', name: 'Communications repetees entre deux hotes', severity: 'faible', points: 10,
    why: "Deux machines qui echangent beaucoup de paquets forment une relation a examiner : est-ce un service applicatif attendu, ou une activite automatisee inhabituelle ?",
    benign: "Trafic applicatif normal (base de donnees, partage de fichiers, sauvegarde, flux video, synchronisation).",
    investigate: [
      "Verifier le protocole principal de cet echange.",
      "Identifier les deux machines et leur role habituel.",
      "Comparer avec le volume habituel de cette relation."
    ],
    run(agg, th) {
      const off = Array.from(agg.pairCount.entries()).filter(e => e[1] > th.pair)
        .sort((a, b) => b[1] - a[1]).slice(0, 5);
      if (!off.length) return null;
      const mainProto = (pair) => {
        const m = agg.pairProto.get(pair);
        if (!m) return 'inconnu';
        return Array.from(m.entries()).sort((a, b) => b[1] - a[1])[0][0];
      };
      const first = off[0][0].split('\u0000');
      return {
        summary: off.length + ' couple(s) source/destination depassent ' + th.pair + ' paquets.',
        facts: [{ k: 'Source', v: first[0] }, { k: 'Destination', v: first[1] },
                { k: 'Paquets', v: off[0][1] }, { k: 'Protocole principal', v: mainProto(off[0][0]) }],
        evidence: off.map(e => {
          const pr = e[0].split('\u0000');
          return pr[0] + ' \u2192 ' + pr[1] + ' : ' + e[1] + ' paquets, protocole principal ' + mainProto(e[0]);
        })
      };
    }
  },

  {
    id: 'syn', name: 'Activite TCP SYN importante', severity: 'eleve', points: 15,
    why: "Un paquet SYN seul demande l'ouverture d'une connexion. Beaucoup de SYN sans reponse (ou suivis de RST) peuvent indiquer une recherche de services ouverts ou un service indisponible.",
    benign: "Tentatives normales de connexion, service temporairement indisponible, application qui reessaie, scan d'inventaire autorise.",
    investigate: [
      "Verifier si les connexions aboutissent (presence de SYN, ACK) ou echouent (RST).",
      "Identifier les ports cibles et les services attendus.",
      "Ne jamais conclure a un \"SYN flood\" a partir du seul volume."
    ],
    run(agg, th) {
      const off = Array.from(agg.synBySrc.entries()).filter(e => e[1] > th.syn)
        .sort((a, b) => b[1] - a[1]).slice(0, 5);
      if (!off.length) return null;
      const rst = agg.rstBySrc.get(off[0][0]) || 0;
      return {
        summary: off.length + ' source(s) depassent ' + th.syn + ' paquets SYN sans reponse.',
        facts: [{ k: 'Source', v: off[0][0] }, { k: 'SYN sans ACK', v: off[0][1] },
                { k: 'RST observes', v: rst }, { k: 'Seuil', v: th.syn }],
        evidence: off.map(e => e[0] + ' : ' + e[1] + ' SYN sans ACK (seuil ' + th.syn + ')')
      };
    }
  }
];

/* ===========================================================================
   SCORE D'INVESTIGATION (explicable)
   =========================================================================== */
function computeScore(alerts) {
  let score = 0;
  for (const a of alerts) score += a.points;
  return Math.min(100, score);
}

function scoreLevel(score) {
  if (score === 0) return { label: 'Aucune activite notable', css: 'level-normal' };
  if (score < 20) return { label: 'Activite faible', css: 'level-normal' };
  if (score < 40) return { label: 'Activite moderee', css: 'level-moderate' };
  if (score < 70) return { label: 'Activite elevee', css: 'level-elevated' };
  return { label: 'Activite tres elevee', css: 'level-veryhigh' };
}

function sanitizeThresholds(input) {
  const out = {};
  for (const key of Object.keys(DEFAULT_THRESHOLDS)) {
    const v = parseInt(input ? input[key] : NaN, 10);
    out[key] = (isNaN(v) || v < 1) ? DEFAULT_THRESHOLDS[key] : v;
  }
  return out;
}

function runTriage(packets, thresholds) {
  const th = sanitizeThresholds(thresholds);
  const agg = aggregate(packets);
  const alerts = [];
  for (const rule of RULES) {
    let res = null;
    try { res = rule.run(agg, th); } catch (e) { res = null; }
    if (!res) continue;
    alerts.push({
      id: rule.id, name: rule.name, severity: rule.severity, points: rule.points,
      why: rule.why, benign: rule.benign, investigate: rule.investigate,
      summary: res.summary, facts: res.facts, evidence: res.evidence
    });
  }
  const order = { eleve: 0, moyen: 1, faible: 2, info: 3 };
  alerts.sort((a, b) => (order[a.severity] - order[b.severity]) || (b.points - a.points));
  const score = computeScore(alerts);
  return { agg, alerts, score, level: scoreLevel(score), thresholds: th };
}

/* ---------------------------------------------------------------------------
   LECTURE COMPLETE D'UN TEXTE CSV
   Renvoie soit une erreur explicative, soit les paquets + les colonnes manquantes.
   --------------------------------------------------------------------------- */
function analyseCsvText(text) {
  const parsed = parseCsv(text);
  if (!parsed.rows.length) return { error: "Le fichier est vide ou illisible." };
  const headers = parsed.rows[0].map(h => String(h).trim());
  const map = mapColumns(headers);
  const missing = missingColumns(map);
  if (map.source === undefined || map.destination === undefined) {
    const manquants = [];
    if (map.source === undefined) manquants.push("d'adresse source");
    if (map.destination === undefined) manquants.push("d'adresse destination");
    return {
      error: "Ce fichier CSV ne semble pas contenir de colonne " + manquants.join(' ni ') + ".",
      headers, map, missing, delimiter: parsed.delimiter
    };
  }
  const packets = buildPackets(parsed.rows, map);
  if (!packets.length) return { error: "Aucune ligne exploitable : les colonnes source/destination sont vides.", headers, map, missing };
  return { packets, missing, headers, map, delimiter: parsed.delimiter };
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

const SEV_LABEL = { eleve: 'Eleve', moyen: 'Moyen', faible: 'Faible', info: 'Informationnel' };

function addMessage(kind, text) {
  const box = byId('parse-messages');
  const icons = { ok: '\u2714', warn: '\u26A0', err: '\u2716' };
  const div = el('div', 'msg ' + kind);
  div.appendChild(el('span', 'msg-ico', icons[kind] || '\u2022'));
  div.appendChild(el('span', null, text));
  box.appendChild(div);
}

function clearMessages() { byId('parse-messages').textContent = ''; }

function formatNumber(n, digits) {
  if (n === null || n === undefined || isNaN(n)) return '\u2014';
  return Number(n).toLocaleString('fr-FR', { minimumFractionDigits: digits || 0, maximumFractionDigits: digits || 0 });
}

function renderLoadStatus(fileName, packetCount, state) {
  byId('st-file').textContent = fileName || '\u2014';
  byId('st-packets').textContent = formatNumber(packetCount || 0);
  byId('st-parse').textContent = state;
}

function renderBarList(container, entries, total, unit) {
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
    const pct = total ? ' (' + Math.round((entry[1] / total) * 100) + '%)' : '';
    row.appendChild(el('span', 'bar-val', entry[1] + ' ' + (unit || 'paquets') + pct));
    container.appendChild(row);
  }
}

function kpi(label, value, sub) {
  const card = el('div', 'kpi');
  card.appendChild(el('span', 'kpi-label', label));
  card.appendChild(el('span', 'kpi-value', value));
  if (sub) card.appendChild(el('span', 'kpi-sub', sub));
  return card;
}

function renderDashboard(agg) {
  const grid = byId('kpi-grid');
  grid.textContent = '';
  const topSrc = agg.topSources[0];
  const topDst = agg.topDestinations[0];
  const topProto = agg.protocolList[0];

  grid.appendChild(kpi('Paquets au total', formatNumber(agg.total)));
  grid.appendChild(kpi('Hotes sources uniques', formatNumber(agg.uniqueSources)));
  grid.appendChild(kpi('Hotes destinations uniques', formatNumber(agg.uniqueDestinations)));
  grid.appendChild(kpi('Hote source le plus actif', topSrc ? topSrc[0] : '\u2014', topSrc ? topSrc[1] + ' paquets' : ''));
  grid.appendChild(kpi('Destination la plus contactee', topDst ? topDst[0] : '\u2014', topDst ? topDst[1] + ' paquets' : ''));
  grid.appendChild(kpi('Protocole le plus utilise', topProto ? topProto[0] : '\u2014', topProto ? topProto[1] + ' paquets' : ''));
  grid.appendChild(kpi('Taille moyenne des paquets', agg.avgLength !== null ? formatNumber(agg.avgLength, 0) + ' octets' : 'indisponible'));
  grid.appendChild(kpi('Duree de la capture', agg.duration !== null ? formatNumber(agg.duration, 2) + ' s' : 'indisponible'));

  renderBarList(byId('top-sources'), agg.topSources, agg.total);
  renderBarList(byId('top-dest'), agg.topDestinations, agg.total);
  renderBarList(byId('proto-list'), agg.protocolList, agg.total);
}

function renderScore(result) {
  byId('invest-score').textContent = String(result.score);
  const lvl = byId('invest-level');
  lvl.textContent = result.level.label;
  lvl.className = 'score-level ' + result.level.css;

  const list = byId('score-breakdown');
  list.textContent = '';
  if (!result.alerts.length) {
    const li = el('li');
    li.appendChild(el('span', 'sb-empty', 'Aucune regle declenchee : aucun point ajoute.'));
    list.appendChild(li);
  } else {
    for (const a of result.alerts) {
      const li = el('li');
      li.appendChild(el('span', null, '+' + a.points + '  ' + a.name));
      li.appendChild(el('span', 'sb-pts', '+' + a.points));
      list.appendChild(li);
    }
    const li = el('li');
    li.appendChild(el('strong', null, 'Score d\'investigation'));
    li.appendChild(el('span', 'sb-pts', String(result.score)));
    list.appendChild(li);
  }
}

function renderSummary(result) {
  const list = byId('summary-list');
  list.textContent = '';
  const rows = [
    ['Paquets analyses', formatNumber(result.agg.total)],
    ['Regles declenchees', String(result.alerts.length)],
    ['Alertes de severite elevee', String(result.alerts.filter(a => a.severity === 'eleve').length)],
    ['Protocoles distincts', String(result.agg.protocolList.length)],
    ['Duree couverte', result.agg.duration !== null ? formatNumber(result.agg.duration, 2) + ' s' : 'indisponible']
  ];
  for (const r of rows) {
    const li = el('li');
    li.appendChild(el('span', 'stat-label', r[0]));
    li.appendChild(el('span', 'stat-val', r[1]));
    list.appendChild(li);
  }
}

function renderAlerts(result) {
  const box = byId('alerts');
  box.textContent = '';
  byId('no-alerts').hidden = result.alerts.length > 0;
  for (const a of result.alerts) {
    const card = el('article', 'alert sev-' + a.severity);
    const head = el('div', 'alert-head');
    head.appendChild(el('span', 'alert-title', a.name));
    head.appendChild(el('span', 'sev-tag ' + (a.severity === 'eleve' ? 'high' : a.severity === 'moyen' ? 'medium' : 'low'), SEV_LABEL[a.severity] || a.severity));
    head.appendChild(el('span', 'alert-pts', '+' + a.points + ' pts'));
    card.appendChild(head);
    card.appendChild(el('p', 'muted', a.summary));

    const facts = el('div', 'alert-facts');
    for (const f of a.facts) {
      const box2 = el('div', 'fact');
      box2.appendChild(el('span', 'fact-k', f.k));
      box2.appendChild(el('span', 'fact-v', f.v));
      facts.appendChild(box2);
    }
    card.appendChild(facts);

    const ev = el('div', 'ind-block');
    ev.appendChild(el('h4', null, 'Preuves observees'));
    const ul = el('ul', 'evidence');
    for (const e of a.evidence) ul.appendChild(el('li', null, e));
    ev.appendChild(ul);
    card.appendChild(ev);

    const why = el('div', 'ind-block');
    why.appendChild(el('h4', null, 'Pourquoi cela peut compter'));
    why.appendChild(el('p', null, a.why));
    card.appendChild(why);

    const ben = el('div', 'ind-block');
    ben.appendChild(el('h4', null, 'Explication benigne possible'));
    ben.appendChild(el('p', null, a.benign));
    card.appendChild(ben);

    const inv = el('div', 'ind-block');
    inv.appendChild(el('h4', null, 'Investigation recommandee'));
    const ol = el('ul', 'evidence');
    for (const i of a.investigate) ol.appendChild(el('li', null, i));
    inv.appendChild(ol);
    card.appendChild(inv);

    box.appendChild(card);
  }
}

/* ===========================================================================
   ORCHESTRATION : charger, analyser, afficher
   =========================================================================== */
let currentPackets = null;

function intVal(id, def) {
  const v = parseInt(byId(id).value, 10);
  return (isNaN(v) || v < 1) ? def : v;
}

function readThresholds() {
  return {
    packets: intVal('th-packets', DEFAULT_THRESHOLDS.packets),
    dest: intVal('th-dest', DEFAULT_THRESHOLDS.dest),
    ports: intVal('th-ports', DEFAULT_THRESHOLDS.ports),
    icmp: intVal('th-icmp', DEFAULT_THRESHOLDS.icmp),
    dns: intVal('th-dns', DEFAULT_THRESHOLDS.dns),
    pair: intVal('th-pair', DEFAULT_THRESHOLDS.pair),
    syn: intVal('th-syn', DEFAULT_THRESHOLDS.syn)
  };
}

function writeThresholds(th) {
  byId('th-packets').value = th.packets;
  byId('th-dest').value = th.dest;
  byId('th-ports').value = th.ports;
  byId('th-icmp').value = th.icmp;
  byId('th-dns').value = th.dns;
  byId('th-pair').value = th.pair;
  byId('th-syn').value = th.syn;
}

function resetDashboard() {
  byId('tableau-de-bord').hidden = true;
  byId('regles').hidden = true;
}

function processCsv(text, fileName) {
  clearMessages();
  const res = analyseCsvText(text);

  if (res.error) {
    renderLoadStatus(fileName, 0, 'Echec');
    addMessage('err', res.error);
    if (res.headers && res.headers.length) {
      addMessage('warn', 'Colonnes trouvees dans le fichier : ' + res.headers.join(', '));
    }
    addMessage('warn', "Colonnes attendues : No., Time, Source, Destination, Protocol, Length, Info. Des variantes comme \"Source IP\", \"src\" ou \"ip.src\" sont acceptees.");
    resetDashboard();
    return null;
  }

  currentPackets = res.packets;
  renderLoadStatus(fileName, res.packets.length, 'Reussie');
  addMessage('ok', 'Analyse du fichier reussie : ' + res.packets.length + ' paquets lus.');

  if (res.missing.length) {
    const labels = res.missing.map(k => COLUMN_LABELS[k] || k);
    addMessage('warn', "Colonnes absentes qui limitent l'analyse : " + labels.join(', ') + '.');
  } else {
    addMessage('ok', 'Toutes les colonnes utiles ont ete reconnues.');
  }

  const result = runTriage(res.packets, readThresholds());
  renderDashboard(result.agg);
  renderScore(result);
  renderSummary(result);
  renderAlerts(result);
  byId('tableau-de-bord').hidden = false;
  byId('regles').hidden = false;
  return result;
}

function recompute() {
  if (!currentPackets) return;
  const result = runTriage(currentPackets, readThresholds());
  renderDashboard(result.agg);
  renderScore(result);
  renderSummary(result);
  renderAlerts(result);
  byId('regles').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function loadFile(file) {
  if (!file) return;
  const name = file.name || 'fichier.csv';
  clearMessages();
  if (!/\.(csv|txt)$/i.test(name)) {
    addMessage('warn', 'Extension inattendue : "' + name + '". L\'outil essaie quand meme de lire le contenu comme du texte CSV.');
  }
  const reader = new FileReader();
  reader.onload = () => processCsv(String(reader.result || ''), name);
  reader.onerror = () => addMessage('err', 'Impossible de lire ce fichier localement.');
  reader.readAsText(file);
}

/* ===========================================================================
   INITIALISATION (uniquement dans un navigateur)
   =========================================================================== */
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
    currentPackets = null;
    clearMessages();
    renderLoadStatus('', 0, '\u2014');
    resetDashboard();
    input.value = '';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  byId('btn-recompute').addEventListener('click', recompute);
  byId('btn-defaults').addEventListener('click', () => {
    writeThresholds(DEFAULT_THRESHOLDS);
    if (currentPackets) recompute();
  });

  renderSampleCards();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}

/* ===========================================================================
   EXEMPLES DE DEMONSTRATION (captures entierement fictives)
   ---------------------------------------------------------------------------
   Adresses volontairement reservees a la documentation :
   192.168.x.x (prive), 10.x.x.x (prive), 203.0.113.x, 198.51.100.x, 192.0.2.x.
   Aucune de ces captures ne provient d'un reseau reel.
   Les memes fichiers existent dans le dossier samples/ pour inspection manuelle.
   =========================================================================== */
const SAMPLES = [
  {
    id: 'normal', file: 'normal-network.csv',
    name: '1. Reseau normal',
    desc: "Navigation courante : requetes DNS, connexions HTTPS, reponses ARP. Aucun seuil ne devrait etre depasse.",
    csv: `No.,Time,Source,Destination,Protocol,Length,Info
1,0.120000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0x3e8 A www.exemple-entreprise.test"
2,0.210000,192.168.1.1,192.168.1.10,DNS,90,"Standard query response 0x3e8 A www.exemple-entreprise.test A 203.0.113.10"
3,0.260000,192.168.1.10,203.0.113.10,TCP,66,"40000 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
4,0.300000,203.0.113.10,192.168.1.10,TCP,66,"443 → 40000 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
5,0.330000,192.168.1.10,203.0.113.10,TLSv1.3,571,"Application Data, Application Data"
6,0.450000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0x3e9 A www.exemple-entreprise.test"
7,0.540000,192.168.1.1,192.168.1.10,DNS,90,"Standard query response 0x3e9 A www.exemple-entreprise.test A 203.0.113.24"
8,0.590000,192.168.1.10,203.0.113.24,TCP,66,"40001 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
9,0.630000,203.0.113.24,192.168.1.10,TCP,66,"443 → 40001 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
10,0.660000,192.168.1.10,203.0.113.24,TLSv1.3,571,"Application Data, Application Data"
11,0.780000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0x3ea A www.exemple-entreprise.test"
12,0.870000,192.168.1.1,192.168.1.10,DNS,90,"Standard query response 0x3ea A www.exemple-entreprise.test A 198.51.100.7"
13,0.920000,192.168.1.10,198.51.100.7,TCP,66,"40002 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
14,0.960000,198.51.100.7,192.168.1.10,TCP,66,"443 → 40002 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
15,0.990000,192.168.1.10,198.51.100.7,TLSv1.3,571,"Application Data, Application Data"
16,1.110000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0x3eb A www.exemple-entreprise.test"
17,1.200000,192.168.1.1,192.168.1.10,DNS,90,"Standard query response 0x3eb A www.exemple-entreprise.test A 203.0.113.10"
18,1.250000,192.168.1.10,203.0.113.10,TCP,66,"40003 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
19,1.290000,203.0.113.10,192.168.1.10,TCP,66,"443 → 40003 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
20,1.320000,192.168.1.10,203.0.113.10,TLSv1.3,571,"Application Data, Application Data"
21,1.440000,192.168.1.20,192.168.1.1,DNS,74,"Standard query 0x3f2 A www.exemple-entreprise.test"
22,1.530000,192.168.1.1,192.168.1.20,DNS,90,"Standard query response 0x3f2 A www.exemple-entreprise.test A 203.0.113.10"
23,1.580000,192.168.1.20,203.0.113.10,TCP,66,"40100 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
24,1.620000,203.0.113.10,192.168.1.20,TCP,66,"443 → 40100 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
25,1.650000,192.168.1.20,203.0.113.10,TLSv1.3,571,"Application Data, Application Data"
26,1.770000,192.168.1.20,192.168.1.1,DNS,74,"Standard query 0x3f3 A www.exemple-entreprise.test"
27,1.860000,192.168.1.1,192.168.1.20,DNS,90,"Standard query response 0x3f3 A www.exemple-entreprise.test A 203.0.113.24"
28,1.910000,192.168.1.20,203.0.113.24,TCP,66,"40101 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
29,1.950000,203.0.113.24,192.168.1.20,TCP,66,"443 → 40101 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
30,1.980000,192.168.1.20,203.0.113.24,TLSv1.3,571,"Application Data, Application Data"
31,2.100000,192.168.1.20,192.168.1.1,DNS,74,"Standard query 0x3f4 A www.exemple-entreprise.test"
32,2.190000,192.168.1.1,192.168.1.20,DNS,90,"Standard query response 0x3f4 A www.exemple-entreprise.test A 198.51.100.7"
33,2.240000,192.168.1.20,198.51.100.7,TCP,66,"40102 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
34,2.280000,198.51.100.7,192.168.1.20,TCP,66,"443 → 40102 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
35,2.310000,192.168.1.20,198.51.100.7,TLSv1.3,571,"Application Data, Application Data"
36,2.430000,192.168.1.20,192.168.1.1,DNS,74,"Standard query 0x3f5 A www.exemple-entreprise.test"
37,2.520000,192.168.1.1,192.168.1.20,DNS,90,"Standard query response 0x3f5 A www.exemple-entreprise.test A 203.0.113.10"
38,2.570000,192.168.1.20,203.0.113.10,TCP,66,"40103 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
39,2.610000,203.0.113.10,192.168.1.20,TCP,66,"443 → 40103 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
40,2.640000,192.168.1.20,203.0.113.10,TLSv1.3,571,"Application Data, Application Data"
41,2.840000,192.168.1.20,192.168.1.1,ARP,42,"Who has 192.168.1.1? Tell 192.168.1.20"
`
  },
  {
    id: 'scan', file: 'host-scan.csv',
    name: "2. Scan d'hotes et de ports",
    desc: "Une meme source contacte 24 destinations et de nombreux ports sur une meme cible, avec des RST en reponse.",
    csv: `No.,Time,Source,Destination,Protocol,Length,Info
1,0.010000,192.168.1.25,192.168.1.40,TCP,58,"45000 → 22 [SYN] Seq=0 Win=1024 Len=0"
2,0.020000,192.168.1.25,192.168.1.41,TCP,58,"45001 → 80 [SYN] Seq=0 Win=1024 Len=0"
3,0.030000,192.168.1.25,192.168.1.42,TCP,58,"45002 → 139 [SYN] Seq=0 Win=1024 Len=0"
4,0.040000,192.168.1.25,192.168.1.43,TCP,58,"45003 → 445 [SYN] Seq=0 Win=1024 Len=0"
5,0.050000,192.168.1.25,192.168.1.44,TCP,58,"45004 → 3389 [SYN] Seq=0 Win=1024 Len=0"
6,0.060000,192.168.1.25,192.168.1.45,TCP,58,"45005 → 22 [SYN] Seq=0 Win=1024 Len=0"
7,0.070000,192.168.1.25,192.168.1.46,TCP,58,"45006 → 80 [SYN] Seq=0 Win=1024 Len=0"
8,0.080000,192.168.1.25,192.168.1.47,TCP,58,"45007 → 139 [SYN] Seq=0 Win=1024 Len=0"
9,0.090000,192.168.1.25,192.168.1.48,TCP,58,"45008 → 445 [SYN] Seq=0 Win=1024 Len=0"
10,0.100000,192.168.1.25,192.168.1.49,TCP,58,"45009 → 3389 [SYN] Seq=0 Win=1024 Len=0"
11,0.110000,192.168.1.25,192.168.1.50,TCP,58,"45010 → 22 [SYN] Seq=0 Win=1024 Len=0"
12,0.120000,192.168.1.25,192.168.1.51,TCP,58,"45011 → 80 [SYN] Seq=0 Win=1024 Len=0"
13,0.130000,192.168.1.25,192.168.1.52,TCP,58,"45012 → 139 [SYN] Seq=0 Win=1024 Len=0"
14,0.140000,192.168.1.25,192.168.1.53,TCP,58,"45013 → 445 [SYN] Seq=0 Win=1024 Len=0"
15,0.150000,192.168.1.25,192.168.1.54,TCP,58,"45014 → 3389 [SYN] Seq=0 Win=1024 Len=0"
16,0.160000,192.168.1.25,192.168.1.55,TCP,58,"45015 → 22 [SYN] Seq=0 Win=1024 Len=0"
17,0.170000,192.168.1.25,192.168.1.56,TCP,58,"45016 → 80 [SYN] Seq=0 Win=1024 Len=0"
18,0.180000,192.168.1.25,192.168.1.57,TCP,58,"45017 → 139 [SYN] Seq=0 Win=1024 Len=0"
19,0.190000,192.168.1.25,192.168.1.58,TCP,58,"45018 → 445 [SYN] Seq=0 Win=1024 Len=0"
20,0.200000,192.168.1.25,192.168.1.59,TCP,58,"45019 → 3389 [SYN] Seq=0 Win=1024 Len=0"
21,0.210000,192.168.1.25,192.168.1.60,TCP,58,"45020 → 22 [SYN] Seq=0 Win=1024 Len=0"
22,0.220000,192.168.1.25,192.168.1.61,TCP,58,"45021 → 80 [SYN] Seq=0 Win=1024 Len=0"
23,0.230000,192.168.1.25,192.168.1.62,TCP,58,"45022 → 139 [SYN] Seq=0 Win=1024 Len=0"
24,0.240000,192.168.1.25,192.168.1.63,TCP,58,"45023 → 445 [SYN] Seq=0 Win=1024 Len=0"
25,0.248000,192.168.1.25,192.168.1.5,TCP,54,"46000 → 1000 [SYN] Seq=0 Win=1024 Len=0"
26,0.256000,192.168.1.25,192.168.1.5,TCP,54,"46001 → 1001 [SYN] Seq=0 Win=1024 Len=0"
27,0.264000,192.168.1.25,192.168.1.5,TCP,54,"46002 → 1002 [SYN] Seq=0 Win=1024 Len=0"
28,0.272000,192.168.1.25,192.168.1.5,TCP,54,"46003 → 1003 [SYN] Seq=0 Win=1024 Len=0"
29,0.280000,192.168.1.25,192.168.1.5,TCP,54,"46004 → 1004 [SYN] Seq=0 Win=1024 Len=0"
30,0.288000,192.168.1.25,192.168.1.5,TCP,54,"46005 → 1005 [SYN] Seq=0 Win=1024 Len=0"
31,0.296000,192.168.1.25,192.168.1.5,TCP,54,"46006 → 1006 [SYN] Seq=0 Win=1024 Len=0"
32,0.304000,192.168.1.25,192.168.1.5,TCP,54,"46007 → 1007 [SYN] Seq=0 Win=1024 Len=0"
33,0.312000,192.168.1.25,192.168.1.5,TCP,54,"46008 → 1008 [SYN] Seq=0 Win=1024 Len=0"
34,0.320000,192.168.1.25,192.168.1.5,TCP,54,"46009 → 1009 [SYN] Seq=0 Win=1024 Len=0"
35,0.328000,192.168.1.25,192.168.1.5,TCP,54,"46010 → 1010 [SYN] Seq=0 Win=1024 Len=0"
36,0.336000,192.168.1.25,192.168.1.5,TCP,54,"46011 → 1011 [SYN] Seq=0 Win=1024 Len=0"
37,0.344000,192.168.1.25,192.168.1.5,TCP,54,"46012 → 1012 [SYN] Seq=0 Win=1024 Len=0"
38,0.352000,192.168.1.25,192.168.1.5,TCP,54,"46013 → 1013 [SYN] Seq=0 Win=1024 Len=0"
39,0.360000,192.168.1.25,192.168.1.5,TCP,54,"46014 → 1014 [SYN] Seq=0 Win=1024 Len=0"
40,0.368000,192.168.1.25,192.168.1.5,TCP,54,"46015 → 1015 [SYN] Seq=0 Win=1024 Len=0"
41,0.376000,192.168.1.25,192.168.1.5,TCP,54,"46016 → 1016 [SYN] Seq=0 Win=1024 Len=0"
42,0.384000,192.168.1.25,192.168.1.5,TCP,54,"46017 → 1017 [SYN] Seq=0 Win=1024 Len=0"
43,0.392000,192.168.1.25,192.168.1.5,TCP,54,"46018 → 1018 [SYN] Seq=0 Win=1024 Len=0"
44,0.400000,192.168.1.25,192.168.1.5,TCP,54,"46019 → 1019 [SYN] Seq=0 Win=1024 Len=0"
45,0.408000,192.168.1.25,192.168.1.5,TCP,54,"46020 → 1020 [SYN] Seq=0 Win=1024 Len=0"
46,0.416000,192.168.1.25,192.168.1.5,TCP,54,"46021 → 1021 [SYN] Seq=0 Win=1024 Len=0"
47,0.436000,192.168.1.25,192.168.1.5,TCP,60,"46000 → 1000 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0"
48,0.456000,192.168.1.25,192.168.1.5,TCP,60,"46001 → 1001 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0"
`
  },
  {
    id: 'icmp', file: 'icmp-sweep.csv',
    name: '3. Activite ICMP elevee (balayage)',
    desc: "45 requetes Echo (ping) depuis un seul hote vers de nombreuses adresses.",
    csv: `No.,Time,Source,Destination,Protocol,Length,Info
1,0.020000,192.168.1.30,192.168.1.1,ICMP,74,"Echo (ping) request  id=0x00, seq=1/1152, ttl=64"
2,0.040000,192.168.1.30,192.168.1.2,ICMP,74,"Echo (ping) request  id=0x01, seq=2/1152, ttl=64"
3,0.060000,192.168.1.30,192.168.1.3,ICMP,74,"Echo (ping) request  id=0x02, seq=3/1152, ttl=64"
4,0.080000,192.168.1.30,192.168.1.4,ICMP,74,"Echo (ping) request  id=0x03, seq=4/1152, ttl=64"
5,0.100000,192.168.1.30,192.168.1.5,ICMP,74,"Echo (ping) request  id=0x04, seq=5/1152, ttl=64"
6,0.120000,192.168.1.30,192.168.1.6,ICMP,74,"Echo (ping) request  id=0x05, seq=6/1152, ttl=64"
7,0.140000,192.168.1.30,192.168.1.7,ICMP,74,"Echo (ping) request  id=0x06, seq=7/1152, ttl=64"
8,0.160000,192.168.1.30,192.168.1.8,ICMP,74,"Echo (ping) request  id=0x07, seq=8/1152, ttl=64"
9,0.180000,192.168.1.30,192.168.1.9,ICMP,74,"Echo (ping) request  id=0x08, seq=9/1152, ttl=64"
10,0.200000,192.168.1.30,192.168.1.10,ICMP,74,"Echo (ping) request  id=0x00, seq=10/1152, ttl=64"
11,0.220000,192.168.1.30,192.168.1.11,ICMP,74,"Echo (ping) request  id=0x01, seq=11/1152, ttl=64"
12,0.240000,192.168.1.30,192.168.1.12,ICMP,74,"Echo (ping) request  id=0x02, seq=12/1152, ttl=64"
13,0.260000,192.168.1.30,192.168.1.13,ICMP,74,"Echo (ping) request  id=0x03, seq=13/1152, ttl=64"
14,0.280000,192.168.1.30,192.168.1.14,ICMP,74,"Echo (ping) request  id=0x04, seq=14/1152, ttl=64"
15,0.300000,192.168.1.30,192.168.1.15,ICMP,74,"Echo (ping) request  id=0x05, seq=15/1152, ttl=64"
16,0.320000,192.168.1.30,192.168.1.16,ICMP,74,"Echo (ping) request  id=0x06, seq=16/1152, ttl=64"
17,0.340000,192.168.1.30,192.168.1.17,ICMP,74,"Echo (ping) request  id=0x07, seq=17/1152, ttl=64"
18,0.360000,192.168.1.30,192.168.1.18,ICMP,74,"Echo (ping) request  id=0x08, seq=18/1152, ttl=64"
19,0.380000,192.168.1.30,192.168.1.19,ICMP,74,"Echo (ping) request  id=0x00, seq=19/1152, ttl=64"
20,0.400000,192.168.1.30,192.168.1.20,ICMP,74,"Echo (ping) request  id=0x01, seq=20/1152, ttl=64"
21,0.420000,192.168.1.30,192.168.1.21,ICMP,74,"Echo (ping) request  id=0x02, seq=21/1152, ttl=64"
22,0.440000,192.168.1.30,192.168.1.22,ICMP,74,"Echo (ping) request  id=0x03, seq=22/1152, ttl=64"
23,0.460000,192.168.1.30,192.168.1.23,ICMP,74,"Echo (ping) request  id=0x04, seq=23/1152, ttl=64"
24,0.480000,192.168.1.30,192.168.1.24,ICMP,74,"Echo (ping) request  id=0x05, seq=24/1152, ttl=64"
25,0.500000,192.168.1.30,192.168.1.25,ICMP,74,"Echo (ping) request  id=0x06, seq=25/1152, ttl=64"
26,0.520000,192.168.1.30,192.168.1.26,ICMP,74,"Echo (ping) request  id=0x07, seq=26/1152, ttl=64"
27,0.540000,192.168.1.30,192.168.1.27,ICMP,74,"Echo (ping) request  id=0x08, seq=27/1152, ttl=64"
28,0.560000,192.168.1.30,192.168.1.28,ICMP,74,"Echo (ping) request  id=0x00, seq=28/1152, ttl=64"
29,0.580000,192.168.1.30,192.168.1.29,ICMP,74,"Echo (ping) request  id=0x01, seq=29/1152, ttl=64"
30,0.600000,192.168.1.30,192.168.1.30,ICMP,74,"Echo (ping) request  id=0x02, seq=30/1152, ttl=64"
31,0.620000,192.168.1.30,192.168.1.31,ICMP,74,"Echo (ping) request  id=0x03, seq=31/1152, ttl=64"
32,0.640000,192.168.1.30,192.168.1.32,ICMP,74,"Echo (ping) request  id=0x04, seq=32/1152, ttl=64"
33,0.660000,192.168.1.30,192.168.1.33,ICMP,74,"Echo (ping) request  id=0x05, seq=33/1152, ttl=64"
34,0.680000,192.168.1.30,192.168.1.34,ICMP,74,"Echo (ping) request  id=0x06, seq=34/1152, ttl=64"
35,0.700000,192.168.1.30,192.168.1.35,ICMP,74,"Echo (ping) request  id=0x07, seq=35/1152, ttl=64"
36,0.720000,192.168.1.30,192.168.1.36,ICMP,74,"Echo (ping) request  id=0x08, seq=36/1152, ttl=64"
37,0.740000,192.168.1.30,192.168.1.37,ICMP,74,"Echo (ping) request  id=0x00, seq=37/1152, ttl=64"
38,0.760000,192.168.1.30,192.168.1.38,ICMP,74,"Echo (ping) request  id=0x01, seq=38/1152, ttl=64"
39,0.780000,192.168.1.30,192.168.1.39,ICMP,74,"Echo (ping) request  id=0x02, seq=39/1152, ttl=64"
40,0.800000,192.168.1.30,192.168.1.40,ICMP,74,"Echo (ping) request  id=0x03, seq=40/1152, ttl=64"
41,0.820000,192.168.1.30,192.168.1.41,ICMP,74,"Echo (ping) request  id=0x04, seq=41/1152, ttl=64"
42,0.840000,192.168.1.30,192.168.1.42,ICMP,74,"Echo (ping) request  id=0x05, seq=42/1152, ttl=64"
43,0.860000,192.168.1.30,192.168.1.43,ICMP,74,"Echo (ping) request  id=0x06, seq=43/1152, ttl=64"
44,0.880000,192.168.1.30,192.168.1.44,ICMP,74,"Echo (ping) request  id=0x07, seq=44/1152, ttl=64"
45,0.900000,192.168.1.30,192.168.1.45,ICMP,74,"Echo (ping) request  id=0x08, seq=45/1152, ttl=64"
46,0.950000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x00, seq=1/1152, ttl=255"
47,1.000000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x01, seq=2/1152, ttl=255"
48,1.050000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x02, seq=3/1152, ttl=255"
49,1.100000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x03, seq=4/1152, ttl=255"
50,1.150000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x04, seq=5/1152, ttl=255"
51,1.200000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x05, seq=6/1152, ttl=255"
52,1.250000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x06, seq=7/1152, ttl=255"
53,1.300000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x07, seq=8/1152, ttl=255"
54,1.350000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x08, seq=9/1152, ttl=255"
55,1.400000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x00, seq=10/1152, ttl=255"
56,1.450000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x01, seq=11/1152, ttl=255"
57,1.500000,192.168.1.1,192.168.1.30,ICMP,74,"Echo (ping) reply    id=0x02, seq=12/1152, ttl=255"
`
  },
  {
    id: 'mixed', file: 'mixed-soc-sample.csv',
    name: '4. Capture mixte (demonstration SOC)',
    desc: "Volume eleve, pic de DNS, ICMP important et connexions SYN repetees : plusieurs regles se declenchent.",
    csv: `No.,Time,Source,Destination,Protocol,Length,Info
1,0.020000,192.168.1.25,203.0.113.55,TCP,1500,"50000 → 443 [ACK] Seq=0 Win=64240 Len=1460"
2,0.040000,192.168.1.25,203.0.113.55,TCP,1500,"50001 → 443 [ACK] Seq=1460 Win=64240 Len=1460"
3,0.060000,192.168.1.25,203.0.113.55,TCP,1500,"50002 → 443 [ACK] Seq=2920 Win=64240 Len=1460"
4,0.080000,192.168.1.25,203.0.113.55,TCP,1500,"50003 → 443 [ACK] Seq=4380 Win=64240 Len=1460"
5,0.100000,192.168.1.25,203.0.113.55,TCP,1500,"50004 → 443 [ACK] Seq=5840 Win=64240 Len=1460"
6,0.120000,192.168.1.25,203.0.113.55,TCP,1500,"50005 → 443 [ACK] Seq=7300 Win=64240 Len=1460"
7,0.140000,192.168.1.25,203.0.113.55,TCP,1500,"50006 → 443 [ACK] Seq=8760 Win=64240 Len=1460"
8,0.160000,192.168.1.25,203.0.113.55,TCP,1500,"50007 → 443 [ACK] Seq=10220 Win=64240 Len=1460"
9,0.180000,192.168.1.25,203.0.113.55,TCP,1500,"50008 → 443 [ACK] Seq=11680 Win=64240 Len=1460"
10,0.200000,192.168.1.25,203.0.113.55,TCP,1500,"50009 → 443 [ACK] Seq=13140 Win=64240 Len=1460"
11,0.220000,192.168.1.25,203.0.113.55,TCP,1500,"50010 → 443 [ACK] Seq=14600 Win=64240 Len=1460"
12,0.240000,192.168.1.25,203.0.113.55,TCP,1500,"50011 → 443 [ACK] Seq=16060 Win=64240 Len=1460"
13,0.260000,192.168.1.25,203.0.113.55,TCP,1500,"50012 → 443 [ACK] Seq=17520 Win=64240 Len=1460"
14,0.280000,192.168.1.25,203.0.113.55,TCP,1500,"50013 → 443 [ACK] Seq=18980 Win=64240 Len=1460"
15,0.300000,192.168.1.25,203.0.113.55,TCP,1500,"50014 → 443 [ACK] Seq=20440 Win=64240 Len=1460"
16,0.320000,192.168.1.25,203.0.113.55,TCP,1500,"50015 → 443 [ACK] Seq=21900 Win=64240 Len=1460"
17,0.340000,192.168.1.25,203.0.113.55,TCP,1500,"50016 → 443 [ACK] Seq=23360 Win=64240 Len=1460"
18,0.360000,192.168.1.25,203.0.113.55,TCP,1500,"50017 → 443 [ACK] Seq=24820 Win=64240 Len=1460"
19,0.380000,192.168.1.25,203.0.113.55,TCP,1500,"50018 → 443 [ACK] Seq=26280 Win=64240 Len=1460"
20,0.400000,192.168.1.25,203.0.113.55,TCP,1500,"50019 → 443 [ACK] Seq=27740 Win=64240 Len=1460"
21,0.420000,192.168.1.25,203.0.113.55,TCP,1500,"50020 → 443 [ACK] Seq=29200 Win=64240 Len=1460"
22,0.440000,192.168.1.25,203.0.113.55,TCP,1500,"50021 → 443 [ACK] Seq=30660 Win=64240 Len=1460"
23,0.460000,192.168.1.25,203.0.113.55,TCP,1500,"50022 → 443 [ACK] Seq=32120 Win=64240 Len=1460"
24,0.480000,192.168.1.25,203.0.113.55,TCP,1500,"50023 → 443 [ACK] Seq=33580 Win=64240 Len=1460"
25,0.500000,192.168.1.25,203.0.113.55,TCP,1500,"50024 → 443 [ACK] Seq=35040 Win=64240 Len=1460"
26,0.520000,192.168.1.25,203.0.113.55,TCP,1500,"50025 → 443 [ACK] Seq=36500 Win=64240 Len=1460"
27,0.540000,192.168.1.25,203.0.113.55,TCP,1500,"50026 → 443 [ACK] Seq=37960 Win=64240 Len=1460"
28,0.560000,192.168.1.25,203.0.113.55,TCP,1500,"50027 → 443 [ACK] Seq=39420 Win=64240 Len=1460"
29,0.580000,192.168.1.25,203.0.113.55,TCP,1500,"50028 → 443 [ACK] Seq=40880 Win=64240 Len=1460"
30,0.600000,192.168.1.25,203.0.113.55,TCP,1500,"50029 → 443 [ACK] Seq=42340 Win=64240 Len=1460"
31,0.620000,192.168.1.25,203.0.113.55,TCP,1500,"50030 → 443 [ACK] Seq=43800 Win=64240 Len=1460"
32,0.640000,192.168.1.25,203.0.113.55,TCP,1500,"50031 → 443 [ACK] Seq=45260 Win=64240 Len=1460"
33,0.660000,192.168.1.25,203.0.113.55,TCP,1500,"50032 → 443 [ACK] Seq=46720 Win=64240 Len=1460"
34,0.680000,192.168.1.25,203.0.113.55,TCP,1500,"50033 → 443 [ACK] Seq=48180 Win=64240 Len=1460"
35,0.700000,192.168.1.25,203.0.113.55,TCP,1500,"50034 → 443 [ACK] Seq=49640 Win=64240 Len=1460"
36,0.720000,192.168.1.25,203.0.113.55,TCP,1500,"50035 → 443 [ACK] Seq=51100 Win=64240 Len=1460"
37,0.740000,192.168.1.25,203.0.113.55,TCP,1500,"50036 → 443 [ACK] Seq=52560 Win=64240 Len=1460"
38,0.760000,192.168.1.25,203.0.113.55,TCP,1500,"50037 → 443 [ACK] Seq=54020 Win=64240 Len=1460"
39,0.780000,192.168.1.25,203.0.113.55,TCP,1500,"50038 → 443 [ACK] Seq=55480 Win=64240 Len=1460"
40,0.800000,192.168.1.25,203.0.113.55,TCP,1500,"50039 → 443 [ACK] Seq=56940 Win=64240 Len=1460"
41,0.820000,192.168.1.25,203.0.113.55,TCP,1500,"50040 → 443 [ACK] Seq=58400 Win=64240 Len=1460"
42,0.840000,192.168.1.25,203.0.113.55,TCP,1500,"50041 → 443 [ACK] Seq=59860 Win=64240 Len=1460"
43,0.860000,192.168.1.25,203.0.113.55,TCP,1500,"50042 → 443 [ACK] Seq=61320 Win=64240 Len=1460"
44,0.880000,192.168.1.25,203.0.113.55,TCP,1500,"50043 → 443 [ACK] Seq=62780 Win=64240 Len=1460"
45,0.900000,192.168.1.25,203.0.113.55,TCP,1500,"50044 → 443 [ACK] Seq=64240 Win=64240 Len=1460"
46,0.920000,192.168.1.25,203.0.113.55,TCP,1500,"50045 → 443 [ACK] Seq=65700 Win=64240 Len=1460"
47,0.940000,192.168.1.25,203.0.113.55,TCP,1500,"50046 → 443 [ACK] Seq=67160 Win=64240 Len=1460"
48,0.960000,192.168.1.25,203.0.113.55,TCP,1500,"50047 → 443 [ACK] Seq=68620 Win=64240 Len=1460"
49,0.980000,192.168.1.25,203.0.113.55,TCP,1500,"50048 → 443 [ACK] Seq=70080 Win=64240 Len=1460"
50,1.000000,192.168.1.25,203.0.113.55,TCP,1500,"50049 → 443 [ACK] Seq=71540 Win=64240 Len=1460"
51,1.020000,192.168.1.25,203.0.113.55,TCP,1500,"50050 → 443 [ACK] Seq=73000 Win=64240 Len=1460"
52,1.040000,192.168.1.25,203.0.113.55,TCP,1500,"50051 → 443 [ACK] Seq=74460 Win=64240 Len=1460"
53,1.060000,192.168.1.25,203.0.113.55,TCP,1500,"50052 → 443 [ACK] Seq=75920 Win=64240 Len=1460"
54,1.080000,192.168.1.25,203.0.113.55,TCP,1500,"50053 → 443 [ACK] Seq=77380 Win=64240 Len=1460"
55,1.100000,192.168.1.25,203.0.113.55,TCP,1500,"50054 → 443 [ACK] Seq=78840 Win=64240 Len=1460"
56,1.120000,192.168.1.25,203.0.113.55,TCP,1500,"50055 → 443 [ACK] Seq=80300 Win=64240 Len=1460"
57,1.140000,192.168.1.25,203.0.113.55,TCP,1500,"50056 → 443 [ACK] Seq=81760 Win=64240 Len=1460"
58,1.160000,192.168.1.25,203.0.113.55,TCP,1500,"50057 → 443 [ACK] Seq=83220 Win=64240 Len=1460"
59,1.180000,192.168.1.25,203.0.113.55,TCP,1500,"50058 → 443 [ACK] Seq=84680 Win=64240 Len=1460"
60,1.200000,192.168.1.25,203.0.113.55,TCP,1500,"50059 → 443 [ACK] Seq=86140 Win=64240 Len=1460"
61,1.220000,192.168.1.25,203.0.113.55,TCP,1500,"50060 → 443 [ACK] Seq=87600 Win=64240 Len=1460"
62,1.240000,192.168.1.25,203.0.113.55,TCP,1500,"50061 → 443 [ACK] Seq=89060 Win=64240 Len=1460"
63,1.270000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d0 A cdn0.exemple-service.test"
64,1.300000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d1 A cdn1.exemple-service.test"
65,1.330000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d2 A cdn2.exemple-service.test"
66,1.360000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d3 A cdn3.exemple-service.test"
67,1.390000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d4 A cdn4.exemple-service.test"
68,1.420000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d5 A cdn5.exemple-service.test"
69,1.450000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d6 A cdn6.exemple-service.test"
70,1.480000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d7 A cdn7.exemple-service.test"
71,1.510000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d8 A cdn8.exemple-service.test"
72,1.540000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7d9 A cdn9.exemple-service.test"
73,1.570000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7da A cdn10.exemple-service.test"
74,1.600000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7db A cdn11.exemple-service.test"
75,1.630000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7dc A cdn12.exemple-service.test"
76,1.660000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7dd A cdn13.exemple-service.test"
77,1.690000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7de A cdn14.exemple-service.test"
78,1.720000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7df A cdn15.exemple-service.test"
79,1.750000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e0 A cdn16.exemple-service.test"
80,1.780000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e1 A cdn17.exemple-service.test"
81,1.810000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e2 A cdn18.exemple-service.test"
82,1.840000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e3 A cdn19.exemple-service.test"
83,1.870000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e4 A cdn20.exemple-service.test"
84,1.900000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e5 A cdn21.exemple-service.test"
85,1.930000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e6 A cdn22.exemple-service.test"
86,1.960000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e7 A cdn23.exemple-service.test"
87,1.990000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e8 A cdn24.exemple-service.test"
88,2.020000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7e9 A cdn25.exemple-service.test"
89,2.050000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7ea A cdn26.exemple-service.test"
90,2.080000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7eb A cdn27.exemple-service.test"
91,2.110000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7ec A cdn28.exemple-service.test"
92,2.140000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7ed A cdn29.exemple-service.test"
93,2.170000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7ee A cdn30.exemple-service.test"
94,2.200000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7ef A cdn31.exemple-service.test"
95,2.230000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7f0 A cdn32.exemple-service.test"
96,2.260000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7f1 A cdn33.exemple-service.test"
97,2.290000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7f2 A cdn34.exemple-service.test"
98,2.320000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7f3 A cdn35.exemple-service.test"
99,2.350000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7f4 A cdn36.exemple-service.test"
100,2.380000,192.168.1.40,192.168.1.1,DNS,78,"Standard query 0x7f5 A cdn37.exemple-service.test"
101,2.400000,192.168.1.30,198.51.100.10,ICMP,74,"Echo (ping) request  id=0x0101, seq=1/256, ttl=64"
102,2.420000,192.168.1.30,198.51.100.11,ICMP,74,"Echo (ping) request  id=0x0101, seq=2/256, ttl=64"
103,2.440000,192.168.1.30,198.51.100.12,ICMP,74,"Echo (ping) request  id=0x0101, seq=3/256, ttl=64"
104,2.460000,192.168.1.30,198.51.100.13,ICMP,74,"Echo (ping) request  id=0x0101, seq=4/256, ttl=64"
105,2.480000,192.168.1.30,198.51.100.14,ICMP,74,"Echo (ping) request  id=0x0101, seq=5/256, ttl=64"
106,2.500000,192.168.1.30,198.51.100.15,ICMP,74,"Echo (ping) request  id=0x0101, seq=6/256, ttl=64"
107,2.520000,192.168.1.30,198.51.100.16,ICMP,74,"Echo (ping) request  id=0x0101, seq=7/256, ttl=64"
108,2.540000,192.168.1.30,198.51.100.17,ICMP,74,"Echo (ping) request  id=0x0101, seq=8/256, ttl=64"
109,2.560000,192.168.1.30,198.51.100.18,ICMP,74,"Echo (ping) request  id=0x0101, seq=9/256, ttl=64"
110,2.580000,192.168.1.30,198.51.100.19,ICMP,74,"Echo (ping) request  id=0x0101, seq=10/256, ttl=64"
111,2.600000,192.168.1.30,198.51.100.20,ICMP,74,"Echo (ping) request  id=0x0101, seq=11/256, ttl=64"
112,2.620000,192.168.1.30,198.51.100.21,ICMP,74,"Echo (ping) request  id=0x0101, seq=12/256, ttl=64"
113,2.640000,192.168.1.30,198.51.100.10,ICMP,74,"Echo (ping) request  id=0x0101, seq=13/256, ttl=64"
114,2.660000,192.168.1.30,198.51.100.11,ICMP,74,"Echo (ping) request  id=0x0101, seq=14/256, ttl=64"
115,2.680000,192.168.1.30,198.51.100.12,ICMP,74,"Echo (ping) request  id=0x0101, seq=15/256, ttl=64"
116,2.700000,192.168.1.30,198.51.100.13,ICMP,74,"Echo (ping) request  id=0x0101, seq=16/256, ttl=64"
117,2.720000,192.168.1.30,198.51.100.14,ICMP,74,"Echo (ping) request  id=0x0101, seq=17/256, ttl=64"
118,2.740000,192.168.1.30,198.51.100.15,ICMP,74,"Echo (ping) request  id=0x0101, seq=18/256, ttl=64"
119,2.760000,192.168.1.30,198.51.100.16,ICMP,74,"Echo (ping) request  id=0x0101, seq=19/256, ttl=64"
120,2.780000,192.168.1.30,198.51.100.17,ICMP,74,"Echo (ping) request  id=0x0101, seq=20/256, ttl=64"
121,2.800000,192.168.1.30,198.51.100.18,ICMP,74,"Echo (ping) request  id=0x0101, seq=21/256, ttl=64"
122,2.820000,192.168.1.30,198.51.100.19,ICMP,74,"Echo (ping) request  id=0x0101, seq=22/256, ttl=64"
123,2.840000,192.168.1.30,198.51.100.20,ICMP,74,"Echo (ping) request  id=0x0101, seq=23/256, ttl=64"
124,2.860000,192.168.1.30,198.51.100.21,ICMP,74,"Echo (ping) request  id=0x0101, seq=24/256, ttl=64"
125,2.880000,192.168.1.30,198.51.100.10,ICMP,74,"Echo (ping) request  id=0x0101, seq=25/256, ttl=64"
126,2.900000,192.168.1.30,198.51.100.11,ICMP,74,"Echo (ping) request  id=0x0101, seq=26/256, ttl=64"
127,2.920000,192.168.1.30,198.51.100.12,ICMP,74,"Echo (ping) request  id=0x0101, seq=27/256, ttl=64"
128,2.940000,192.168.1.30,198.51.100.13,ICMP,74,"Echo (ping) request  id=0x0101, seq=28/256, ttl=64"
129,2.960000,192.168.1.30,198.51.100.14,ICMP,74,"Echo (ping) request  id=0x0101, seq=29/256, ttl=64"
130,2.980000,192.168.1.30,198.51.100.15,ICMP,74,"Echo (ping) request  id=0x0101, seq=30/256, ttl=64"
131,3.000000,192.168.1.30,198.51.100.16,ICMP,74,"Echo (ping) request  id=0x0101, seq=31/256, ttl=64"
132,3.020000,192.168.1.30,198.51.100.17,ICMP,74,"Echo (ping) request  id=0x0101, seq=32/256, ttl=64"
133,3.040000,192.168.1.30,198.51.100.18,ICMP,74,"Echo (ping) request  id=0x0101, seq=33/256, ttl=64"
134,3.060000,192.168.1.30,198.51.100.19,ICMP,74,"Echo (ping) request  id=0x0101, seq=34/256, ttl=64"
135,3.070000,192.168.1.77,192.168.1.90,TCP,54,"60000 → 20 [SYN] Seq=0 Win=1024 Len=0"
136,3.080000,192.168.1.77,192.168.1.90,TCP,54,"60001 → 21 [SYN] Seq=0 Win=1024 Len=0"
137,3.090000,192.168.1.77,192.168.1.90,TCP,54,"60002 → 22 [SYN] Seq=0 Win=1024 Len=0"
138,3.100000,192.168.1.77,192.168.1.90,TCP,54,"60003 → 23 [SYN] Seq=0 Win=1024 Len=0"
139,3.110000,192.168.1.77,192.168.1.90,TCP,54,"60004 → 24 [SYN] Seq=0 Win=1024 Len=0"
140,3.120000,192.168.1.77,192.168.1.90,TCP,54,"60005 → 25 [SYN] Seq=0 Win=1024 Len=0"
141,3.130000,192.168.1.77,192.168.1.90,TCP,54,"60006 → 26 [SYN] Seq=0 Win=1024 Len=0"
142,3.140000,192.168.1.77,192.168.1.90,TCP,54,"60007 → 27 [SYN] Seq=0 Win=1024 Len=0"
143,3.150000,192.168.1.77,192.168.1.90,TCP,54,"60008 → 28 [SYN] Seq=0 Win=1024 Len=0"
144,3.160000,192.168.1.77,192.168.1.90,TCP,54,"60009 → 29 [SYN] Seq=0 Win=1024 Len=0"
145,3.170000,192.168.1.77,192.168.1.90,TCP,54,"60010 → 30 [SYN] Seq=0 Win=1024 Len=0"
146,3.180000,192.168.1.77,192.168.1.90,TCP,54,"60011 → 31 [SYN] Seq=0 Win=1024 Len=0"
147,3.190000,192.168.1.77,192.168.1.90,TCP,54,"60012 → 32 [SYN] Seq=0 Win=1024 Len=0"
148,3.200000,192.168.1.77,192.168.1.90,TCP,54,"60013 → 33 [SYN] Seq=0 Win=1024 Len=0"
149,3.500000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0xbb8 A www.exemple-entreprise.test"
150,3.800000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0xbb9 A www.exemple-entreprise.test"
151,4.100000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0xbba A www.exemple-entreprise.test"
152,4.400000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0xbbb A www.exemple-entreprise.test"
153,4.700000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0xbbc A www.exemple-entreprise.test"
154,5.000000,192.168.1.10,192.168.1.1,DNS,74,"Standard query 0xbbd A www.exemple-entreprise.test"
`
  },
];

/* Export reserve aux tests automatises (Node.js). Le navigateur ignore ce bloc. */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    RULES, DEFAULT_THRESHOLDS, SAMPLES, parseCsv, detectDelimiter, mapColumns, missingColumns,
    buildPackets, classifyProtocol, extractPorts, extractTcpFlags, aggregate, runTriage,
    computeScore, scoreLevel, analyseCsvText, COLUMN_CANDIDATES, sanitizeThresholds
  };
}
