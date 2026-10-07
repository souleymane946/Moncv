/* ============================================================================
   Phishing Email Analyser — moteur d'analyse local
   ----------------------------------------------------------------------------
   PRINCIPE : tout se passe dans le navigateur. Aucune fonction de ce fichier
   n'effectue de requête réseau (pas de fetch, pas de XMLHttpRequest, pas de
   WebSocket, pas de balise distante). Aucun cookie n'est écrit.

   ARCHITECTURE EN 3 COUCHES :
     1) DETECTION  : des "règles" qui cherchent des signes d'alerte dans le texte.
     2) SCORING    : chaque règle a un POIDS fixe et visible, on additionne.
     3) RENDU      : affichage du rapport dans la page (fonctions pures + DOM).

   Chaque règle renvoie :
     - ce qu'elle a trouvé (preuves observées),
     - pourquoi cela peut compter,
     - ce que cela pourrait être d'autre (explication bénigne).
   ============================================================================ */

'use strict';

/* ---------------------------------------------------------------------------
   BARÈMES DE CLASSIFICATION (score 0-100)
   Volontairement simples et affichés à l'utilisateur.
   --------------------------------------------------------------------------- */
const THRESHOLDS = { suspect: 25, high: 60 };

const CLASSIFICATIONS = [
  { max: 24, key: 'low',     label: 'Faible risque',  css: 'is-low',
    note: "Peu de signes d'alerte détectés. Cela ne garantit pas que l'e-mail est sûr : jugez aussi le contexte (attendu ou non, expéditeur connu)." },
  { max: 59, key: 'suspect', label: 'Suspect',        css: 'is-suspect',
    note: "Plusieurs signes d'alerte sont présents. Ne cliquez sur rien et vérifiez l'expéditeur par un autre canal avant d'agir." },
  { max: 100, key: 'high',   label: 'Risque élevé',   css: 'is-high',
    note: "Le message cumule de nombreux signes d'alerte typiques du hameçonnage. Ne répondez pas, ne cliquez pas, ne payez pas. Vérifiez par un canal indépendant et signalez-le." }
];

function classify(score) {
  for (const c of CLASSIFICATIONS) if (score <= c.max) return c;
  return CLASSIFICATIONS[CLASSIFICATIONS.length - 1];
}

/* ---------------------------------------------------------------------------
   OUTILS INTERNES
   --------------------------------------------------------------------------- */
function uniq(arr) { return Array.from(new Set(arr)); }

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Récupère un extrait lisible autour d'une correspondance. */
function snippet(text, index, length) {
  const start = Math.max(0, index - 34);
  const end = Math.min(text.length, index + length + 34);
  let s = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) s = '… ' + s;
  if (end < text.length) s = s + ' …';
  return s;
}

/** Cherche toutes les correspondances d'une liste de motifs dans le texte. */
function matchAll(text, patterns, limit) {
  const found = [];
  for (const re of patterns) {
    const rx = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let m;
    while ((m = rx.exec(text)) !== null) {
      found.push({ match: m[0], index: m.index, length: m[0].length });
      if (m.index === rx.lastIndex) rx.lastIndex++;
      if (limit && found.length >= limit) return found;
    }
  }
  return found;
}

/* ---------------------------------------------------------------------------
   EXTRACTION DES LIENS
   On repère 3 formes :
     - les liens "markdown"      : [texte affiché](https://exemple.test)
     - les liens "HTML"          : <a href="https://exemple.test">texte</a>
     - les liens "en clair"      : https://exemple.test/chemin
   On ne visite JAMAIS ces liens : on les lit comme du simple texte.
   --------------------------------------------------------------------------- */
const URL_RE = /\bhttps?:\/\/[^\s<>"'\)\]]+/gi;

function extractLinks(texte) {
  const text = String(texte == null ? '' : texte);
  const links = [];
  const index = new Map();   /* url -> position dans links */

  /* Un meme lien peut apparaitre sous plusieurs formes :
     [texte](url), <a href="url">texte</a> et url en clair.
     On ne le garde qu'UNE fois, mais on conserve le texte affiche s'il existe. */
  const push = (url, displayText) => {
    const clean = String(url || '').replace(/[.,;:]+$/, '').trim();
    if (!clean) return;
    const texteAffiche = String(displayText || '').trim();
    if (index.has(clean)) {
      const dejaLa = links[index.get(clean)];
      if (!dejaLa.text && texteAffiche) dejaLa.text = texteAffiche;
      return;
    }
    index.set(clean, links.length);
    links.push({ url: clean, text: texteAffiche });
  };

  /* 1) Markdown : [texte](url) */
  const mdRe = /\[([^\]]{1,200})\]\(\s*(https?:\/\/[^\s)]{1,2000})\s*\)/gi;
  let m;
  while ((m = mdRe.exec(text)) !== null) push(m[2], m[1]);

  /* 2) HTML : <a href="url">texte</a>
     Parcours lineaire avec indexOf, et non une expression reguliere.
     Une regex du type <a[^>]*href... est quadratique : sur un texte contenant
     beaucoup de "<a" sans chevron fermant, elle faisait geler la page plus de
     30 secondes. Ce parcours reste proportionnel a la taille du texte. */
  const minuscules = text.toLowerCase();
  let i = 0;
  let securite = 0;
  while (securite++ < 20000) {
    const debut = minuscules.indexOf('<a', i);
    if (debut === -1) break;
    const finBalise = text.indexOf('>', debut);
    if (finBalise === -1) break;
    const balise = text.slice(debut, finBalise + 1);
    const href = /href\s*=\s*["']([^"']{1,2000})["']/i.exec(balise);
    const finLien = minuscules.indexOf('</a>', finBalise);
    if (href) {
      const label = finLien === -1 ? '' : text.slice(finBalise + 1, finLien).replace(/<[^>]*>/g, '').trim();
      push(href[1], label);
    }
    i = finLien === -1 ? finBalise + 1 : finLien + 4;
  }

  /* 3) Liens en clair */
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(text)) !== null) push(m[0], '');

  return links;
}

/** Domaine d'un hôte, en minuscules, sans "www.". */
function hostOf(url) {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch (e) {
    const m = /^https?:\/\/([^\/?#]+)/i.exec(url);
    return m ? m[1].toLowerCase() : '';
  }
}

function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/* Raccourcisseurs reconnus. Les deux derniers sont FICTIFS et en .test :
   ils servent uniquement aux e-mails de demonstration, pour ne jamais citer
   un service reel dans les exemples. Les vrais raccourcisseurs restent
   bien sur detectes dans les messages analyses par l'utilisateur. */
const SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'cutt.ly','rb.gy','shorturl.at','rebrand.ly','tiny.cc','lnkd.in','surl.li','shorte.st',
  'adf.ly','bl.ink','clck.ru','v.gd','qr.ae','u.to','x.co','mcaf.ee','po.st','trib.al',
  'lien-court.test','raccourci.test'];

const RISKY_TLDS = ['zip','mov','xyz','top','club','work','click','link','country','gq','tk',
  'ml','cf','ga','rest','cam','surf','bar','quest','monster','cyou','buzz','icu','lol','fit',
  'support','live','online','site','shop','store','info','pw','cc','su','ru','cn','ws','tk'];

/* ---------------------------------------------------------------------------
   DETECTION DES DOMAINES SOSIES ("typosquatting")
   Un attaquant remplace une lettre par un chiffre ou ajoute un mot :
   "micros0ft" (zero a la place du o), "paypa1", "app1e-support"... Le but est
   d'obtenir un domaine qui ressemble a une marque connue et inspire confiance.
   --------------------------------------------------------------------------- */
const BRANDS = ['microsoft','windows','office','outlook','onedrive','apple','icloud',
  'google','gmail','android','paypal','amazon','netflix','facebook','instagram','whatsapp',
  'linkedin','dropbox','adobe','docusign','orange','sfr','bouygues','laposte',
  'chronopost','colissimo','dhl','fedex','mondialrelay','bnpparibas','societegenerale',
  'creditagricole','lcl','caisse-epargne','banquepopulaire','creditmutuel','impots','ameli',
  'cpam','urssaf','revolut','binance','coinbase','ledger','metamask'];

function normaliseBrandToken(host) {
  return String(host || '').toLowerCase()
    .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
    .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/8/g, 'b')
    .replace(/[^a-z]/g, '');
}

/** Renvoie la marque imitee si le domaine y ressemble, sinon null. */
function lookalikeBrand(host) {
  if (!host) return null;
  const parts = String(host).toLowerCase().split('.');
  const base = parts.length > 2 ? parts[parts.length - 2] : parts[0];
  const flat = normaliseBrandToken(parts.slice(0, -1).join(''));
  for (const b of BRANDS) {
    const brand = b.replace(/[^a-z]/g, '');
    if (brand.length < 4) continue;
    if (flat.includes(brand) && normaliseBrandToken(base) !== brand) return b;
  }
  return null;
}

const EXEC_EXT = ['exe','scr','js','jse','vbs','vbe','bat','cmd','com','pif','msi','msp','cpl',
  'hta','jar','lnk','reg','wsf','wsh','ps1','psm1','iso','img','vhd','vmdk','dll','apk','app',
  'docm','xlsm','pptm','dotm','xlam','svg','htm','html','hta'];

const UNUSUAL_EXT = ['zip','rar','7z','gz','tar','ace','cab','arj','lzh','iso','img','dmg',
  'docm','xlsm','pptm','svg','hta','html','htm','js','wsf','vbs','bat','cmd','ps1','scr','jar'];

/** Analyse un lien et renvoie une liste d'anomalies. */
function analyseLink(url) {
  const host = hostOf(url);
  const issues = [];
  if (!host) return { host, issues, bad: false, severity: 'info' };

  const lowerUrl = url.toLowerCase();
  const labels = host.split('.');

  if (isIpHost(host)) {
    issues.push("L'adresse du lien est une adresse IP brute, pas un nom de domaine.");
  }
  if (SHORTENERS.includes(host) || SHORTENERS.some(s => host.endsWith('.' + s))) {
    issues.push("Service de raccourcissement de lien : la destination réelle est masquée.");
  }
  if (host.startsWith('xn--') || host.includes('.xn--')) {
    issues.push("Nom de domaine « punycode » (xn--) : peut imiter visuellement un domaine connu.");
  }
  if (lowerUrl.includes('@') && /https?:\/\/[^\/]*@/.test(lowerUrl)) {
    issues.push("Le lien contient un « @ » : tout ce qui précède peut être un leurre (astuce classique).");
  }
  if (labels.length >= 4) {
    issues.push("Domaine avec de nombreux sous-niveaux (" + labels.length + ") : structure souvent utilisée pour tromper.");
  }
  const tld = labels[labels.length - 1];
  if (RISKY_TLDS.includes(tld)) {
    issues.push("Extension de domaine peu fiable ou fréquemment abusée : ." + tld);
  }
  if (host.split('-').length >= 3) {
    issues.push("Domaine contenant de nombreux tirets : typique des domaines imitant une marque.");
  }
  if (/^http:\/\//i.test(url)) {
    issues.push("Lien non chiffré (http://) : les données saisies pourraient être interceptées.");
  }
  if (/\d{3,}/.test(labels[0] || '')) {
    issues.push("Nom d'hôte contenant une longue suite de chiffres.");
  }
  if (/(login|connexion|signin|verify|verification|secure|securite|account|compte|update|mise-a-jour|password|mot-de-passe|wallet|facture|invoice|payment|paiement)/i.test(lowerUrl)) {
    issues.push("Le chemin du lien contient des mots-clés d'authentification ou de paiement (login, verify, payment…).");
  }

  return { host, issues, bad: issues.length > 0, severity: issues.length >= 2 ? 'high' : 'medium' };
}

/** Détecte un texte de lien trompeur : le texte affiché ressemble à un domaine
    différent de celui vers lequel le lien pointe réellement. */
function detectMisleadingLink(link) {
  const text = (link.text || '').trim();
  if (!text) return null;
  const looksLikeDomain = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(\/\S*)?$/i.test(text.replace(/^https?:\/\//i, ''));
  if (!looksLikeDomain) return null;
  const shownHost = hostOf('http://' + text.replace(/^https?:\/\//i, ''));
  const realHost = hostOf(link.url);
  if (!shownHost || !realHost) return null;
  const base = h => h.split('.').slice(-2).join('.');
  if (base(shownHost) !== base(realHost)) {
    return { shown: shownHost, real: realHost };
  }
  return null;
}


/* ---------------------------------------------------------------------------
   EN-TÊTES D'E-MAIL (facultatif)
   Un "en-tête" est la partie technique du message, avant le corps. On y trouve
   qui a réellement envoyé le message et si les contrôles SPF / DKIM / DMARC
   ont réussi. Ces contrôles servent à vérifier qu'un expéditeur est bien
   autorisé à envoyer au nom d'un domaine.
   --------------------------------------------------------------------------- */
const HEADER_NAMES = ['from','reply-to','return-path','authentication-results',
  'received-spf','dkim-signature','arc-authentication-results','subject','to','date',
  'message-id','x-mailer','received'];

function parseHeaders(text) {
  const headers = {};
  const lines = text.split(/\r?\n/);
  let current = null;
  for (const line of lines) {
    if (/^\s/.test(line) && current) {
      headers[current] += ' ' + line.trim();           // ligne de continuation
      continue;
    }
    const m = /^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)$/.exec(line);
    if (m && HEADER_NAMES.includes(m[1].toLowerCase())) {
      current = m[1].toLowerCase();
      headers[current] = (headers[current] ? headers[current] + ' ' : '') + m[2].trim();
    } else {
      current = null;
    }
  }
  return headers;
}

function emailDomain(value) {
  /* Analyse MANUELLE volontaire (pas de regex).
     Une expression reguliere du type [A-Za-z0-9._%+-]+@... sur une tres longue
     ligne sans arobase provoque un ralentissement en O(n^2) : sur une en-tete
     de 100 000 caracteres, l'analyse passait de quelques millisecondes a
     plusieurs secondes. Ce parcours lineaire elimine le probleme. */
  const s = String(value || '');
  const at = s.indexOf('@');
  if (at === -1) return '';
  let i = at + 1;
  let out = '';
  while (i < s.length) {
    const c = s.charCodeAt(i);
    const estLettre = (c >= 97 && c <= 122) || (c >= 65 && c <= 90);
    const estChiffre = c >= 48 && c <= 57;
    if (estLettre || estChiffre || c === 45 || c === 46) { out += s[i]; i++; continue; }
    break;
  }
  out = out.toLowerCase().replace(/^[.-]+/, '').replace(/[.-]+$/, '');
  return /\.[a-z]{2,}$/.test(out) ? out : '';
}

function baseDomain(host) {
  if (!host) return '';
  const parts = host.split('.');
  return parts.length <= 2 ? host : parts.slice(-2).join('.');
}

/** Lit un en-tête d'authentification et renvoie le verdict SPF/DKIM/DMARC. */
function authResults(headers) {
  const blob = [headers['authentication-results'], headers['arc-authentication-results'],
    headers['received-spf'], headers['dkim-signature']].filter(Boolean).join(' ').toLowerCase();
  const out = { spf: null, dkim: null, dmarc: null, raw: blob };
  const grab = (mech) => {
    const re = new RegExp(mech + '\\s*=\\s*(pass|fail|softfail|neutral|none|permerror|temperror|policy)', 'i');
    const m = re.exec(blob);
    return m ? m[1].toLowerCase() : null;
  };
  out.spf = grab('spf');
  out.dkim = grab('dkim');
  out.dmarc = grab('dmarc');
  return out;
}

/* ---------------------------------------------------------------------------
   PIÈCES JOINTES
   On ne fait qu'analyser des NOMS de fichiers cités dans le texte
   (ex. "facture.pdf", "Facture_2024.docm"). Aucun fichier n'est ouvert.
   --------------------------------------------------------------------------- */
const ATTACH_RE = /\b([A-Za-z0-9._%+-]{1,60}\.(?:exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|msi|msp|cpl|hta|jar|lnk|reg|wsf|wsh|ps1|psm1|iso|img|vhd|vmdk|dll|apk|app|docm|xlsm|pptm|dotm|xlam|svg|htm|html|zip|rar|7z|gz|tar|cab|pdf|docx?|xlsx?|pptx?|txt|csv|rtf|eml|msg|dat|bin|xml|json|one|vbs))\b/gi;

function extractAttachments(text) {
  const found = [];
  let m;
  while ((m = ATTACH_RE.exec(text)) !== null) {
    if (!found.some(f => f.toLowerCase() === m[1].toLowerCase())) found.push(m[1]);
  }
  return found;
}

function extOf(name) {
  const m = /\.([A-Za-z0-9]+)$/.exec(name);
  return m ? m[1].toLowerCase() : '';
}

/* ---------------------------------------------------------------------------
   CONTEXTE D'ANALYSE
   On prépare une seule fois toutes les informations utiles, puis chaque règle
   les consulte. Cela évite de recalculer et rend le code lisible.
   --------------------------------------------------------------------------- */
function buildContext(rawText) {
  const text = String(rawText || '');
  const headers = parseHeaders(text);
  const links = extractLinks(text);
  const analysed = links.map(l => Object.assign({}, l, analyseLink(l.url)));
  return {
    text,
    lower: text.toLowerCase(),
    headers,
    links,
    analysed,
    attachments: extractAttachments(text),
    auth: authResults(headers),
    fromDomain: baseDomain(emailDomain(headers['from'] || '')),
    replyToDomain: baseDomain(emailDomain(headers['reply-to'] || '')),
    returnPathDomain: baseDomain(emailDomain(headers['return-path'] || ''))
  };
}


/* ===========================================================================
   LES RÈGLES DE DÉTECTION
   ---------------------------------------------------------------------------
   Chaque règle a un POIDS (weight) fixe et affiché. Le score final est
   simplement la somme des poids des règles déclenchées (plafonné à 100).
   C'est ce qui rend le score "explicable" : rien de caché, pas de hasard.
   =========================================================================== */
const RULES = [

  /* ---------------------------- 1. URGENCE ---------------------------- */
  {
    id: 'urgency', title: "Langage d'urgence ou de pression", severity: 'medium', weight: 12,
    why: "Les messages qui exigent une action immédiate cherchent à empêcher la victime de réfléchir ou de vérifier l'information. C'est l'un des leviers d'ingénierie sociale les plus utilisés.",
    benign: "De vrais messages peuvent être urgents (incident technique, échéance réelle, rappel d'une organisation).",
    detect(ctx) {
      const pats = [
        /\b(?:urgent|urgente|urgence|très urgent|tres urgent|urgence absolue)\b/gi,
        /\b(?:immédiatement|immediatement|dès que possible|des que possible|sans délai|sans delai|sous 24 ?h|dans les 24 heures|dans les 48 heures|dans l'heure|dans les plus brefs délais|dans les plus brefs delais|au plus vite|sans attendre|dès réception|des reception|aujourd'hui même|avant la fin de la journée)\b/gi,
        /\b(?:dernière mise en garde|derniere mise en garde|dernier avertissement|action requise|action immédiate|à faire maintenant|a faire maintenant)\b/gi,
        /\b(?:immediate action|act now|as soon as possible|within 24 hours|final notice|last warning|time sensitive)\b/gi,
        /\b(?:votre compte sera|sera clôturé|sera cloture|clôture imminente|cloture imminente)\b/gi
      ];
      return matchAll(ctx.text, pats, 5).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ------------- 2. MENACE DE SUSPENSION / FERMETURE ------------------ */
  {
    id: 'suspension', title: "Menace de suspension ou de fermeture de compte", severity: 'medium', weight: 15,
    why: "Menacer de bloquer un accès crée la peur de perdre quelque chose d'important. C'est un schéma très fréquent pour pousser à cliquer vite.",
    benign: "Un fournisseur légitime peut réellement signaler un problème de compte, mais il ne le fait normalement pas via un lien d'urgence inattendu.",
    detect(ctx) {
      const pats = [
        /\b(?:suspendu|suspendue|suspension|désactivé|desactive|désactivée|désactivation|desactivation|verrouillé|verrouille|bloqué|bloque)\b/gi,
        /\b(?:clôture de votre compte|cloture de votre compte|fermeture de votre compte|fermeture définitive|fermeture definitive|compte supprimé|compte supprime)\b/gi,
        /\b(?:restriction(?:s)? de (?:votre|mon) compte|accès restreint|acces restreint|compte compromis)\b/gi,
        /\b(?:will be suspended|account will be closed|will be deactivated|will be terminated|account locked|access restricted)\b/gi
      ];
      return matchAll(ctx.text, pats, 5).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ------------------- 3. DEMANDE DE MOT DE PASSE --------------------- */
  {
    id: 'password', title: "Demande de mot de passe", severity: 'high', weight: 18,
    why: "Aucun service sérieux ne demande un mot de passe par e-mail. Un mot de passe demandé par message est presque toujours une tentative de vol d'identifiants.",
    benign: "Rare : un outil interne mal conçu ou un message de test. Dans le doute, considérez cette demande comme dangereuse.",
    detect(ctx) {
      const verb = "(?:saisir|saisissez|entrer|entrez|indiquer|indiquez|confirmer|confirmez|fournir|fournissez|envoyer|envoyez|communiquer|communiquez|renseigner|renseignez|répondre|repondre|réinitialiser|reinitialiser|mettre à jour|mettre a jour|provide|confirm|enter|send|submit|update|reset|re-enter)";
      const pats = [
        new RegExp(verb + "[^.\\n]{0,45}(?:mot de passe|password|identifiants?|credentials|login)", 'gi'),
        new RegExp("(?:mot de passe|password|identifiants?|credentials)[^.\\n]{0,45}" + verb, 'gi'),
        /\b(?:votre mot de passe actuel|your current password|votre identifiant et votre mot de passe)\b/gi
      ];
      return matchAll(ctx.text, pats, 4).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ------------- 4. DEMANDE DE CODE MFA / VERIFICATION ---------------- */
  {
    id: 'mfa', title: "Demande de code MFA ou de verification", severity: 'high', weight: 18,
    why: "Un code a usage unique (MFA/2FA) est la cle qui protege le compte. Le transmettre a quelqu'un revient a lui donner l'acces, meme avec un bon mot de passe.",
    benign: "Un vrai service peut envoyer un code pour que VOUS le saisissiez sur SON site. Il ne le demande jamais par e-mail, SMS ou telephone.",
    detect(ctx) {
      const pats = [
        /\b(?:code de v[eé]rification|code de s[eé]curit[eé]|code [aà] usage unique|code [aà] 6 chiffres|code re[cç]u par sms|code mfa|code 2fa|jeton d'authentification|one[- ]time (?:code|password)|verification code|two[- ]factor|authenticator code)\b/gi,
        /\b(?:communiquez|partagez|transmettez|envoyez|indiquez)[^.\n]{0,40}\b(?:code|otp|jeton|token)\b/gi,
        /\b(?:validez|approuvez)[^.\n]{0,30}\b(?:demande|notification|connexion)\b/gi
      ];
      return matchAll(ctx.text, pats, 4).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* --------------- 5. PAIEMENT / CARTES-CADEAUX ----------------------- */
  {
    id: 'payment', title: "Demande de paiement ou de cartes-cadeaux", severity: 'high', weight: 18,
    why: "Les cartes-cadeaux et les cryptomonnaies sont des moyens de paiement difficiles a annuler et a tracer : tres utilises par les fraudeurs.",
    benign: "Un message commercial peut legitimement proposer un paiement en ligne, mais jamais par carte-cadeau ni par un lien de paiement inattendu.",
    detect(ctx) {
      const pats = [
        /\b(?:carte[- ]cadeau|carte cadeau|cartes?[- ]cadeaux?|gift cards?)\b/gi,
        /\b(?:itunes|google play|amazon card|steam card|paysafecard|neosurf|transcash)\b/gi,
        /\b(?:bitcoin|btc|ethereum|crypto|cryptomonnaie|portefeuille crypto|usdt)\b/gi,
        /\b(?:western union|moneygram|mandat cash|virement instantan[eé]|wire transfer)\b/gi,
        /\b(?:frais de douane|frais de livraison|frais de dossier|frais de d[eé]blocage|p[eé]nalit[eé])\b/gi,
        /\b(?:payez|payer maintenant|effectuer le paiement|proc[eé]der au paiement|r[eé]gler la somme|payment required)\b/gi
      ];
      return matchAll(ctx.text, pats, 5).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ---------- 6. MODIFICATION DES COORDONNEES BANCAIRES -------------- */
  {
    id: 'bank_change', title: "Demande de modification des coordonnees bancaires", severity: 'high', weight: 20,
    why: "Rediriger un virement vers un autre compte (fraude au faux fournisseur / BEC) est l'une des fraudes les plus couteuses. Un changement d'IBAN annonce par e-mail doit toujours etre verifie par telephone.",
    benign: "Un vrai changement de coordonnees arrive parfois, mais il se confirme par un appel au numero que VOUS connaissez deja.",
    detect(ctx) {
      const pats = [
        /\b(?:coordonn[eé]es bancaires|nouvelles coordonn[eé]es bancaires|coordonn[eé]es de paiement)\b/gi,
        /\b(?:iban|bic|swift|rib)\b/gi,
        /\b(?:num[eé]ro de compte|nouveau compte bancaire|changement de compte)\b/gi,
        /\b(?:bank details|account number|update (?:your )?bank|new bank account|change of bank)\b/gi,
        /\b(?:mettre [aà] jour (?:vos )?informations de paiement|modifier le compte bancaire|changer le b[eé]n[eé]ficiaire)\b/gi
      ];
      return matchAll(ctx.text, pats, 5).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ------------------- 7. URL SUSPECTES ------------------------------ */
  {
    id: 'suspicious_url', title: "URL(s) suspecte(s)", severity: 'high', weight: 15,
    why: "Les liens de phishing imitent souvent un site connu : domaine imitant une marque, extension douteuse, sous-domaines trompeurs, ou adresse IP brute au lieu d'un nom de domaine.",
    benign: "Des sites legitimes utilisent parfois http, des sous-domaines profonds ou des extensions generiques. Un seul signe ne suffit pas : c'est le cumul qui compte.",
    detect(ctx) {
      const ev = [];
      for (const l of ctx.analysed) {
        if (isIpHost(l.host)) continue;
        if (SHORTENERS.includes(l.host)) continue;
        for (const iss of l.issues) ev.push(l.host + ' \u2014 ' + iss);
        if (ev.length >= 6) break;
      }
      return uniq(ev).slice(0, 6);
    }
  },

  /* ------------------- 8. URL RACCOURCIES ---------------------------- */
  {
    id: 'short_url', title: "URL raccourcie (destination masquee)", severity: 'medium', weight: 12,
    why: "Un lien raccourci cache sa destination reelle. C'est pratique pour un message normal, mais aussi un moyen simple de faire cliquer vers un site malveillant.",
    benign: "Les entreprises utilisent legitimement des raccourcisseurs (reseaux sociaux, notifications, suivi de campagnes).",
    detect(ctx) {
      const ev = [];
      for (const l of ctx.analysed) {
        if (SHORTENERS.includes(l.host) || SHORTENERS.some(s => l.host.endsWith('.' + s))) {
          ev.push(l.host + ' : ' + l.url);
        }
      }
      return uniq(ev).slice(0, 5);
    }
  },

  /* --------------- 9. URL UTILISANT UNE ADRESSE IP ------------------- */
  {
    id: 'ip_url', title: "URL pointant directement vers une adresse IP", severity: 'high', weight: 15,
    why: "Les sites legitimes utilisent des noms de domaine. Un lien qui pointe vers une adresse IP brute (ex. http://192.0.2.10/login) evite les controles habituels et se fait passer pour autre chose.",
    benign: "Des outils internes, des equipements reseau ou des interfaces d'administration utilisent parfois des adresses IP.",
    detect(ctx) {
      const ev = [];
      for (const l of ctx.analysed) {
        if (isIpHost(l.host)) ev.push(l.host + ' : ' + l.url);
      }
      return uniq(ev).slice(0, 5);
    }
  },

  /* ---------------- 10. TEXTE DE LIEN TROMPEUR ----------------------- */
  {
    id: 'misleading_link', title: "Texte de lien trompeur", severity: 'medium', weight: 12,
    why: "Quand le texte affiche ressemble a un domaine mais que le lien pointe ailleurs, l'utilisateur croit aller sur un site de confiance alors qu'il va sur un autre. C'est une technique d'usurpation classique.",
    benign: "Un mail de suivi marketing peut afficher un libelle raccourci ; la difference se voit en survolant le lien.",
    detect(ctx) {
      const ev = [];
      for (const l of ctx.analysed) {
        const mm = detectMisleadingLink(l);
        if (mm) ev.push('Texte affiche : ' + mm.shown + ' \u2192 destination reelle : ' + mm.real);
      }
      return uniq(ev).slice(0, 5);
    }
  },

  /* --------------- 11. FORMULATIONS D'USURPATION --------------------- */
  {
    id: 'impersonation', title: "Formulations courantes d'usurpation d'identite", severity: 'medium', weight: 10,
    why: "Les formules impersonnelles (\"cher client\") et les signatures de service (support, securite, facturation) servent a donner une apparence officielle a un message generique.",
    benign: "Les newsletters et certains messages automatiques utilisent legitimement ce type de formule. A lui seul, ce signe est faible.",
    detect(ctx) {
      const pats = [
        /\b(?:cher client|ch[eè]re cliente|cher utilisateur|ch[eè]re utilisatrice|cher abonn[eé]|dear customer|dear user|dear valued customer|bonjour cher|bonjour ch[eè]re)\b/gi,
        /\b(?:service client|service technique|support technique|service de facturation|service comptabilit[eé]|[eé]quipe de s[eé]curit[eé]|[eé]quipe informatique|votre administrateur|votre banque|service des ressources humaines)\b/gi,
        /\b(?:message automatique|ne pas r[eé]pondre [aà] ce message|ceci est un message automatique|do not reply)\b/gi,
        /\b(?:microsoft account team|paypal service|apple support|google security team|amazon support)\b/gi
      ];
      return matchAll(ctx.text, pats, 5).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ------------- 12. NOMS DE PIECES JOINTES INHABITUELS --------------- */
  {
    id: 'attachment_unusual', title: "Nom de piece jointe inhabituel", severity: 'medium', weight: 10,
    why: "Certaines extensions (archives, documents a macros, scripts) sont tres utilisees pour dissimuler un programme malveillant derriere un fichier qui semble anodin.",
    benign: "Beaucoup d'echanges professionnels utilisent des fichiers .zip, .html ou des documents a macros. Le contexte compte enormement.",
    detect(ctx) {
      const ev = [];
      for (const f of ctx.attachments) {
        const e = extOf(f);
        if (UNUSUAL_EXT.includes(e) && !EXEC_EXT.includes(e)) ev.push(f + ' \u2014 extension .' + e);
      }
      return uniq(ev).slice(0, 6);
    }
  },

  /* ------------------ 13. PIECE JOINTE EXECUTABLE -------------------- */
  {
    id: 'attachment_exec', title: "Piece jointe executable ou a risque eleve", severity: 'high', weight: 20,
    why: "Un fichier executable (.exe, .js, .vbs, .bat, .lnk, .iso, .hta...) s'execute comme un programme. Un e-mail qui pousse a ouvrir ce type de fichier est un schema d'infection tres courant.",
    benign: "Des informaticiens s'echangent parfois des scripts par e-mail, mais cela se fait normalement via un canal controle, pas depuis un expediteur inconnu.",
    detect(ctx) {
      const ev = [];
      for (const f of ctx.attachments) {
        const e = extOf(f);
        if (EXEC_EXT.includes(e)) ev.push(f + ' \u2014 extension .' + e);
      }
      return uniq(ev).slice(0, 6);
    }
  },

  /* ------------------ 14. DEMANDE D'ACTIVER LES MACROS --------------- */
  {
    id: 'macro', title: "Demande d'activation des macros", severity: 'high', weight: 18,
    why: "Les macros de documents bureautiques peuvent executer du code. Demander de les activer pour \"voir le contenu\" est un classique pour declencher une infection.",
    benign: "De vrais documents professionnels utilisent des macros, mais l'activation se decide selon la politique de l'entreprise, pas parce qu'un e-mail l'exige.",
    detect(ctx) {
      const pats = [
        /\b(?:activer|activez|autoriser|autorisez|enable)[^.\n]{0,25}\bmacros?\b/gi,
        /\b(?:activer le contenu|activez le contenu|enable editing|activer la modification|activer les modifications|mode protege|mise en garde de s[eé]curit[eé])\.?[^\n]{0,30}(?:cliquez|cliquer|pour voir|pour afficher)/gi,
        /\b(?:cliquez sur|cliquer sur)[^\n]{0,20}\b(?:activer le contenu|enable content|activer les macros)\b/gi
      ];
      return matchAll(ctx.text, pats, 4).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ---------------- 15. FACTURE INATTENDUE --------------------------- */
  {
    id: 'invoice', title: "Langage lie a une facture inattendue", severity: 'medium', weight: 12,
    why: "Une facture surprise, une relance de paiement ou un rappel de solde poussent a payer vite sans verifier. C'est la base de la fraude a la facture.",
    benign: "Vous pouvez recevoir de vraies factures par e-mail. Le point a verifier est : est-ce que j'attendais ce document, et est-ce que le compte bancaire correspond ?",
    detect(ctx) {
      const pats = [
        /\b(?:facture|invoice)\b/gi,
        /\b(?:facture impay[eé]e|facture en attente|paiement en retard|relance de paiement|deuxi[eè]me relance|dernier rappel de paiement)\b/gi,
        /\b(?:bon de commande|purchase order|devis|relev[eé] de compte|statement|montant d[uû]|total [aà] payer|solde impay[eé])\b/gi,
        /\b(?:veuillez trouver ci[- ]joint la facture|ci[- ]joint votre facture|voir la facture en pi[eè]ce jointe)\b/gi
      ];
      return matchAll(ctx.text, pats, 5).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ---------------- 16. VOL D'IDENTIFIANTS --------------------------- */
  {
    id: 'credential_harvest', title: "Formulations visant a voler les identifiants", severity: 'high', weight: 15,
    why: "Verifier, confirmer, valider, securiser, reactiver : ces verbes, associes a \"compte\" ou \"acces\", servent a pousser la victime vers une fausse page de connexion.",
    benign: "Un vrai service peut demander de mettre a jour des informations, mais jamais via un lien inattendu et sans passer par votre espace personnel habituel.",
    detect(ctx) {
      const pats = [
        /\b(?:v[eé]rifiez|v[eé]rifier|confirmez|confirmer|validez|valider|s[eé]curisez|s[eé]curiser|r[eé]activez|r[eé]activer|d[eé]bloquez|d[eé]bloquer)[^.\n]{0,35}\b(?:votre compte|votre acc[eè]s|votre espace|votre profil|vos informations|votre identit[eé])\b/gi,
        /\b(?:mettre [aà] jour vos informations|mise [aà] jour de votre compte|mise [aà] jour obligatoire|revalider votre compte|confirmer votre identit[eé])\b/gi,
        /\b(?:verify your account|confirm your identity|update your information|secure your account|reactivate your account|unusual sign[- ]in activity|unusual login attempt)\b/gi,
        /\b(?:cliquez ici pour|cliquer ici pour|suivez ce lien pour|rendez[- ]vous sur le lien)[^.\n]{0,45}\b(?:v[eé]rifier|confirmer|valider|vous connecter|vous identifier|r[eé]initialiser)\b/gi
      ];
      return matchAll(ctx.text, pats, 5).map(h => snippet(ctx.text, h.index, h.length));
    }
  },

  /* ------- 17. INCOHERENCE EXPEDITEUR / REPONDRE-A ------------------- */
  {
    id: 'replyto_mismatch', title: "Incoherence entre l'expediteur et l'adresse de reponse (Reply-To)", severity: 'high', weight: 15,
    why: "Quand le nom affiche vient d'une organisation mais que les reponses partent vers un domaine totalement different, le message peut etre une usurpation. L'attaquant affiche une identite connue et recupere les reponses ailleurs.",
    benign: "Certaines entreprises legitimes utilisent un domaine de reponse distinct (outil de support, marketing). A verifier, pas a condamner.",
    detect(ctx) {
      if (!ctx.fromDomain || !ctx.replyToDomain) return [];
      if (ctx.fromDomain === ctx.replyToDomain) return [];
      return ['Expediteur : ' + ctx.fromDomain + ' \u2192 reponses vers : ' + ctx.replyToDomain];
    }
  },

  /* ------------------- 18. ECHEC SPF --------------------------------- */
  {
    id: 'spf_fail', title: "Echec SPF (authentification de l'expediteur)", severity: 'high', weight: 15,
    why: "SPF verifie que le serveur qui a envoye le message est autorise a le faire pour ce domaine. Un echec signifie que le message n'aurait pas du partir de ce serveur.",
    benign: "Des configurations mail mal reglees et surtout des messages TRANSFERES (redirection automatique) provoquent de faux echecs SPF.",
    detect(ctx) {
      const v = ctx.auth.spf;
      if (v === 'fail' || v === 'softfail' || v === 'permerror') {
        return ['Resultat SPF : ' + v.toUpperCase()];
      }
      return [];
    }
  },

  /* ------------------- 19. ECHEC DKIM -------------------------------- */
  {
    id: 'dkim_fail', title: "Echec DKIM (signature du message)", severity: 'medium', weight: 10,
    why: "DKIM est une signature numerique qui prouve que le message n'a pas ete modifie en route et qu'il vient bien du domaine annonce. Un echec remet en cause cette garantie.",
    benign: "Une signature absente ou invalide arrive quand un message est modifie par une liste de diffusion ou un transfert automatique.",
    detect(ctx) {
      const v = ctx.auth.dkim;
      if (v === 'fail' || v === 'permerror') return ['Resultat DKIM : ' + v.toUpperCase()];
      return [];
    }
  },

  /* ------------------- 20. ECHEC DMARC ------------------------------- */
  {
    id: 'dmarc_fail', title: "Echec DMARC (politique anti-usurpation)", severity: 'high', weight: 15,
    why: "DMARC combine SPF et DKIM et definit ce que le destinataire doit faire si l'authentification echoue. Un echec DMARC est un signe fort d'usurpation du domaine.",
    benign: "Des domaines sans politique DMARC publiee produisent des resultats \"none\" plutot qu'un echec. Un vrai echec reste notable.",
    detect(ctx) {
      const v = ctx.auth.dmarc;
      if (v === 'fail' || v === 'permerror') return ['Resultat DMARC : ' + v.toUpperCase()];
      return [];
    }
  },
  /* ---------------- 21. DOMAINE SOSIE D'UNE MARQUE ------------------- */
  {
    id: 'lookalike_domain', title: "Domaine sosie imitant une marque connue", severity: 'high', weight: 15,
    why: "Un domaine qui ressemble a une marque connue (lettre remplacee par un chiffre, mot ajoute) sert a faire croire que le message vient d'une organisation de confiance alors que le domaine reel est different.",
    benign: "Certains domaines partagent des mots avec des marques sans intention malveillante. Verifiez toujours le domaine exact, caractere par caractere.",
    detect(ctx) {
      const ev = [];
      for (const l of ctx.analysed) {
        const b = lookalikeBrand(l.host);
        if (b) ev.push(l.host + ' \u2192 ressemble a la marque "' + b + '"');
      }
      if (!ev.length && lookalikeBrand(ctx.fromDomain)) {
        ev.push('Domaine de l\'expediteur ' + ctx.fromDomain + ' \u2192 ressemble a "' + lookalikeBrand(ctx.fromDomain) + '"');
      }
      return uniq(ev).slice(0, 5);
    }
  },

  /* ---------- 22. SECRET ET CONTOURNEMENT DES PROCEDURES ------------- */
  {
    id: 'secrecy', title: "Demande de secret ou de contournement des procedures", severity: 'medium', weight: 15,
    why: "Demander de garder un message confidentiel, d'eviter les appels ou de passer outre la procedure habituelle vise a empecher toute verification. C'est un signal classique de fraude au president (BEC).",
    benign: "De vrais echanges sensibles existent, mais les procedures internes doivent rester appliquees, surtout pour un paiement.",
    detect(ctx) {
      const pats = [
        /\b(?:confidentiel|confidentielle|de maniere confidentielle|de fa[cç]on confidentielle|ne pas en parler|gardez cela pour vous|entre nous|discr[eé]tion absolue)\b/gi,
        /\b(?:je suis en (?:deplacement|d[eé]placement|reunion|r[eé]union)|je ne peux pas (?:prendre|recevoir) d'appel|indisponible pour un appel|r[eé]pondez uniquement par e-?mail)\b/gi,
        /\b(?:sans passer par la proc[eé]dure|sans validation|contourner la proc[eé]dure|proc[eé]dure habituelle)\b/gi
      ];
      return matchAll(ctx.text, pats, 5).map(h => snippet(ctx.text, h.index, h.length));
    }
  }
];

/* ===========================================================================
   MOTEUR : execution des regles, calcul du score, recommandations
   =========================================================================== */
function runAnalysis(rawText, options) {
  const opts = Object.assign({ headers: true, links: true, attachments: true, sensitive: true }, options || {});
  const ctx = buildContext(rawText);
  const findings = [];

  for (const rule of RULES) {
    if (['replyto_mismatch','spf_fail','dkim_fail','dmarc_fail'].includes(rule.id) && !opts.headers) continue;
    if (['suspicious_url','short_url','ip_url','misleading_link'].includes(rule.id) && !opts.links) continue;
    if (['attachment_unusual','attachment_exec'].includes(rule.id) && !opts.attachments) continue;
    if (!opts.sensitive && rule.weight <= 10) continue;

    let evidence = [];
    try { evidence = rule.detect(ctx) || []; } catch (e) { evidence = []; }
    if (evidence.length) {
      findings.push({
        id: rule.id, title: rule.title, severity: rule.severity, weight: rule.weight,
        why: rule.why, benign: rule.benign, evidence: evidence.slice(0, 8)
      });
    }
  }

  findings.sort((a, b) => b.weight - a.weight || a.title.localeCompare(b.title));
  const rawScore = findings.reduce((sum, f) => sum + f.weight, 0);
  const score = Math.min(100, rawScore);
  const klass = classify(score);

  const badLinks = ctx.analysed.filter(l => l.bad).length;
  const authCount = ['spf','dkim','dmarc'].filter(k => ctx.auth[k]).length;

  const result = {
    score: score, rawScore: rawScore, classification: klass,
    findings: findings,
    context: ctx,
    stats: {
      indicators: findings.length,
      links: ctx.links.length,
      badLinks: badLinks,
      attachments: ctx.attachments.length,
      authHeaders: authCount,
      length: rawText.length
    },
    recommendations: []
  };
  result.recommendations = buildRecommendations(result);
  return result;
}

function buildRecommendations(result) {
  const recs = [];
  const ids = new Set(result.findings.map(f => f.id));

  if (result.score >= THRESHOLDS.high) {
    recs.push("Traitez ce message comme une tentative probable de phishing : ne repondez pas, ne payez pas, ne saisissez aucun identifiant.");
    recs.push("Signalez le message au service informatique ou a votre fournisseur de messagerie, puis supprimez-le sans cliquer sur les liens.");
  } else if (result.score >= THRESHOLDS.suspect) {
    recs.push("Plusieurs signes d'alerte sont presents : verifiez l'expediteur par un canal independant avant toute action.");
  } else {
    recs.push("Peu de signes detectes, mais cela ne garantit pas que le message est sur : fiez-vous aussi au contexte.");
  }

  recs.push("Ne cliquez sur aucun lien et n'ouvrez aucune piece jointe tant que vous n'avez pas verifie par un autre moyen.");

  if (ids.has('password') || ids.has('mfa') || ids.has('credential_harvest'))
    recs.push("Si vous avez deja saisi vos identifiants, changez votre mot de passe immediatement et activez la double authentification.");
  if (ids.has('mfa'))
    recs.push("Ne communiquez jamais un code de verification : aucun service legitime ne le demande par e-mail, SMS ou telephone.");
  if (ids.has('payment') || ids.has('invoice'))
    recs.push("Pour tout sujet de paiement, contactez l'organisation via son site officiel ou un numero connu, jamais via les coordonnees du message.");
  if (ids.has('bank_change'))
    recs.push("Verifiez tout changement de coordonnees bancaires par telephone, en appelant un contact que vous connaissez deja (double verification).");
  if (ids.has('attachment_exec') || ids.has('macro'))
    recs.push("N'ouvrez pas la piece jointe et n'activez pas les macros. En cas de doute, faites analyser le fichier par un professionnel.");
  if (ids.has('spf_fail') || ids.has('dkim_fail') || ids.has('dmarc_fail'))
    recs.push("L'authentification du message a echoue : considerez l'expediteur comme non verifie.");
  if (ids.has('replyto_mismatch'))
    recs.push("Les reponses partent vers un autre domaine : n'utilisez pas le bouton Repondre, ecrivez a l'adresse que vous connaissez.");

  recs.push("En cas de doute sur un message important, verifiez via le site officiel de l'organisation, son application officielle, ou un numero connu et fiable.");
  return recs;
}

/* ===========================================================================
   EXEMPLES DE DEMONSTRATION
   Tous les domaines finissent par .test (reserve a la documentation) et les
   adresses IP appartiennent a des plages reservees (192.0.2.0/24,
   198.51.100.0/24, 203.0.113.0/24, 10.0.0.0/8). AUCUN lien n'est reel.
   =========================================================================== */
const SAMPLES = [
  {
    id: 'obvious', name: '1. Phishing evident', tag: 'Risque eleve',
    desc: "Urgence, menace de fermeture de compte, demande de mot de passe et lien vers une adresse IP.",
    text: `From: "Service Securite Banque" <securite@banque-verification.test>\nReply-To: recuperation.comptes@mail-relais.test\nSubject: URGENT - Votre compte sera suspendu dans les 24 heures\n\nCher client,\n\nNous avons detecte une activite inhabituelle sur votre compte.\nPour eviter la fermeture definitive de votre compte, vous devez confirmer\nvos informations immediatement.\n\nMerci de saisir votre identifiant et votre mot de passe sur notre page securisee :\nhttp://198.51.100.23/banque/connexion.php\n\nSans action de votre part dans les 24 heures, votre acces sera bloque\net vos fonds pourront etre geles.\n\nCordialement,\nService Securite`
  },
  {
    id: 'sophisticated', name: '2. Phishing sophistique', tag: 'Risque eleve',
    desc: "Message soigne, peu d'urgence, mais piece jointe a macros, texte de lien trompeur et echec DKIM.",
    text: `From: "Comptabilite - Groupe Exemple" <comptabilite@groupe-exemple.test>\nReply-To: facturation@groupe-exemple-portail.test\nSubject: Votre releve trimestriel est disponible\nAuthentication-Results: mx.exemple-destinataire.test; spf=pass; dkim=fail; dmarc=pass\n\nBonjour,\n\nVotre releve trimestriel est pret. Vous pouvez le consulter depuis votre espace client :\n[www.groupe-exemple.test](https://portail-securise-exemple.test/account/verify)\n\nLe detail complet se trouve dans la piece jointe : Releve_Q3_2024.docm\n\nSi le document ne s'affiche pas correctement, cliquez sur \"Activer le contenu\"\nlorsque la mise en garde de securite apparait.\n\nBonne journee,\nLe service comptabilite`
  },
  {
    id: 'm365', name: '3. Faux avertissement Microsoft 365', tag: 'Risque eleve',
    desc: "Imitation d'un message de securite Microsoft 365 : domaine sosie, echec SPF, demande de verification du compte.",
    text: `From: "Microsoft 365 Security" <no-reply@micros0ft-verification.test>\nReply-To: support@compte-microsoft-aide.test\nSubject: Activite de connexion inhabituelle detectee sur votre compte\nReceived-SPF: fail (domain of micros0ft-verification.test does not designate 203.0.113.77 as permitted sender)\nAuthentication-Results: mx.destinataire.test; spf=fail; dkim=none; dmarc=fail\n\nCher utilisateur,\n\nNous avons detecte une connexion inhabituelle depuis un appareil inconnu.\nPour securiser votre compte, vous devez verifier votre compte dans les plus brefs delais.\n\nVerifier mon compte : https://micros0ft-verification.test/account/verify?session=88213\n\nSi vous ne confirmez pas votre identite, l'acces a votre boite sera restreint.\n\nL'equipe de securite Microsoft 365`
  },
  {
    id: 'parcel', name: '4. Faux message de livraison de colis', tag: 'Suspect',
    desc: "Faux avis de passage avec frais de douane et lien raccourci.",
    text: `From: "Livraison Express" <avis@livraison-express-notification.test>\nSubject: Votre colis est en attente - frais de douane a regler\n\nBonjour,\n\nVotre colis (reference FR-88213094) est bloque a notre centre de tri.\nDes frais de douane de 2,99 EUR doivent etre regles sous 48 heures.\n\nPour payer et planifier la livraison, suivez ce lien :\nhttps://raccourci.test/3xColis\n\nSans reglement, le colis sera retourne a l'expediteur et des frais de dossier\nsupplementaires pourront s'appliquer.\n\nService client Livraison Express`
  },
  {
    id: 'bec', name: '5. Fausse facture / fraude au president (BEC)', tag: 'Risque eleve',
    desc: "Usurpation d'un dirigeant, changement de coordonnees bancaires, ton confidentiel.",
    text: `From: "Direction Generale" <direction@entreprise-exemple.test>\nReply-To: direction.generale@fournisseur-partenariat.test\nSubject: Re: Reglement fournisseur - changement de coordonnees bancaires\n\nBonjour,\n\nJe suis en deplacement, je ne peux pas prendre d'appel aujourd'hui.\n\nNotre fournisseur a change de banque. Merci de mettre a jour les coordonnees bancaires\nsur la prochaine facture et d'effectuer le virement vers le nouveau compte :\n\nIBAN: FR76 3000 4000 0300 0000 1234 567\nBIC: EXEMPFRPXXX\nBeneficiaire: Partenariat Exemple SARL\n\nMerci de traiter cela de maniere confidentielle et de me confirmer rapidement.\n\nCordialement,\nLa direction`
  },
  {
    id: 'legit', name: '6. E-mail legitime (pour comparaison)', tag: 'Faible risque',
    desc: "Newsletter d'une entreprise fictive : pas d'urgence, pas de demande sensible, lien normal en https.",
    text: `From: "Groupe Exemple - Actualites" <actualites@groupe-exemple.test>\nSubject: Les nouveautes du trimestre chez Groupe Exemple\n\nBonjour,\n\nVoici les nouveautes de ce trimestre :\n- notre nouveau catalogue est disponible ;\n- notre equipe support s'agrandit ;\n- un webinaire est prevu le mois prochain.\n\nPour consulter le catalogue en ligne : https://www.groupe-exemple.test/catalogue\n\nVous recevez ce message car vous etes inscrit a notre lettre d'information.\nVous pouvez vous desinscrire depuis votre espace personnel a tout moment.\n\nBonne journee,\nL'equipe communication`
  }
];

/* ===========================================================================
   RENDU DANS LA PAGE (DOM)
   Regle de securite : tout texte issu de l'e-mail est insere via textContent,
   jamais via innerHTML. Un e-mail ne peut donc pas executer de JavaScript.
   =========================================================================== */
function byId(id) { return document.getElementById(id); }

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

const SEV_LABEL = { high: 'Eleve', medium: 'Moyen', low: 'Faible', info: 'Informatif' };

/* ---------------- Cartes d'exemples ---------------- */
function renderSampleCards() {
  const grid = byId('sample-grid');
  if (!grid) return;
  grid.textContent = '';
  for (const s of SAMPLES) {
    const card = el('article', 'sample-card');
    card.appendChild(el('span', 'demo-badge', 'Donnees de demonstration'));
    card.appendChild(el('h3', null, s.name));
    card.appendChild(el('p', null, s.desc));
    const btn = el('button', 'btn btn-ghost', 'Charger cet exemple');
    btn.type = 'button';
    btn.addEventListener('click', () => {
      byId('email-input').value = s.text;
      updateCharCount();
      const form = byId('analyse-form');
      form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
      byId('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    card.appendChild(btn);
    grid.appendChild(card);
  }
}

/* ---------------- Compteur de caracteres ---------------- */
function updateCharCount() {
  const v = byId('email-input').value;
  byId('char-count').textContent = v.length + ' caractere' + (v.length > 1 ? 's' : '');
}

/* ---------------- Jauge de score ---------------- */
const GAUGE_LEN = 252;
function renderGauge(score, klass) {
  const fill = byId('gauge-fill');
  const offset = GAUGE_LEN - (GAUGE_LEN * score / 100);
  fill.style.strokeDashoffset = String(offset);
  const colors = { 'is-low': '#34d399', 'is-suspect': '#f5b942', 'is-high': '#ff5d6c' };
  fill.style.stroke = colors[klass.css] || '#4c8dff';
}

/* ---------------- Carte d'un signe d'alerte ---------------- */
function renderFinding(f) {
  const box = el('article', 'indicator sev-' + f.severity);
  const head = el('div', 'ind-head');
  head.appendChild(el('span', 'ind-title', f.title));
  head.appendChild(el('span', 'sev-tag ' + f.severity, SEV_LABEL[f.severity] || f.severity));
  head.appendChild(el('span', 'ind-weight', '+' + f.weight + ' pts'));
  box.appendChild(head);

  const ev = el('div', 'ind-block');
  ev.appendChild(el('h4', null, 'Ce qui a ete trouve'));
  const ul = el('ul', 'evidence');
  for (const e of f.evidence) ul.appendChild(el('li', null, e));
  ev.appendChild(ul);
  box.appendChild(ev);

  const why = el('div', 'ind-block');
  why.appendChild(el('h4', null, 'Pourquoi cela compte'));
  why.appendChild(el('p', null, f.why));
  box.appendChild(why);

  const ben = el('div', 'ind-block');
  ben.appendChild(el('h4', null, 'Explication benigne possible'));
  ben.appendChild(el('p', null, f.benign));
  box.appendChild(ben);

  return box;
}

/* ---------------- Tableau des liens ---------------- */
function renderLinks(result) {
  const card = byId('links-card');
  const body = byId('links-body');
  body.textContent = '';
  if (!result.context.analysed.length) { card.hidden = true; return; }
  card.hidden = false;
  for (const l of result.context.analysed) {
    const tr = el('tr', l.bad ? (l.issues.length >= 2 ? 'row-bad' : 'row-warn') : null);
    const tdUrl = el('td', 'url', l.url);
    const tdText = el('td', null, l.text || '\u2014');
    const tdIss = el('td');
    if (l.issues.length) {
      tdIss.appendChild(el('span', 'tag ' + (l.issues.length >= 2 ? 'bad' : 'warn'), l.issues.length + ' anomalie(s)'));
      const ul = el('ul', 'evidence');
      for (const i of l.issues) ul.appendChild(el('li', null, i));
      tdIss.appendChild(ul);
    } else {
      tdIss.appendChild(el('span', 'tag ok', 'Aucune anomalie evidente'));
    }
    tr.appendChild(tdUrl); tr.appendChild(tdText); tr.appendChild(tdIss);
    body.appendChild(tr);
  }
}

/* ---------------- Tableau des en-tetes ---------------- */
function renderHeaders(result) {
  const card = byId('headers-card');
  const body = byId('headers-body');
  body.textContent = '';
  const h = result.context.headers;
  const rows = [];
  const auth = result.context.auth;

  if (h['from']) rows.push(['Expediteur (From)', h['from'], result.context.fromDomain ? 'Domaine : ' + result.context.fromDomain : 'Domaine non identifie']);
  if (h['reply-to']) rows.push(['Repondre a (Reply-To)', h['reply-to'], result.context.replyToDomain ? 'Domaine : ' + result.context.replyToDomain : 'Domaine non identifie']);
  if (h['return-path']) rows.push(['Return-Path', h['return-path'], result.context.returnPathDomain ? 'Domaine : ' + result.context.returnPathDomain : '']);

  const verdict = { pass: ['ok', 'Reussi'], fail: ['bad', 'Echec'], softfail: ['warn', 'Echec toleré (softfail)'], none: ['warn', 'Aucune information'], neutral: ['warn', 'Neutre'], permerror: ['bad', 'Erreur de configuration'], temperror: ['warn', 'Erreur temporaire'], policy: ['bad', 'Refuse par politique'] };
  const addAuth = (key, label) => {
    const v = auth[key];
    if (!v) return;
    const info = verdict[v] || ['warn', v];
    rows.push([label, v.toUpperCase(), info[1]]);
  };
  addAuth('spf', 'Resultat SPF');
  addAuth('dkim', 'Resultat DKIM');
  addAuth('dmarc', 'Resultat DMARC');

  if (!rows.length) { card.hidden = true; return; }
  card.hidden = false;
  for (const [k, v, note] of rows) {
    const tr = el('tr');
    tr.appendChild(el('td', null, k));
    tr.appendChild(el('td', 'url', v));
    const td = el('td');
    td.appendChild(el('span', 'tag', note));
    tr.appendChild(td);
    body.appendChild(tr);
  }
}

/* ---------------- Rapport complet ---------------- */
function renderResults(result) {
  byId('results').hidden = false;
  byId('score-value').textContent = String(result.score);

  const cls = byId('classification');
  cls.className = 'classif ' + result.classification.css;
  byId('classification-label').textContent = result.classification.label;
  byId('score-note').textContent = result.classification.note;
  renderGauge(result.score, result.classification);

  byId('stat-indicators').textContent = String(result.stats.indicators);
  byId('stat-links').textContent = String(result.stats.links);
  byId('stat-links-bad').textContent = String(result.stats.badLinks);
  byId('stat-attach').textContent = String(result.stats.attachments);
  byId('stat-auth').textContent = String(result.stats.authHeaders);
  byId('stat-length').textContent = result.stats.length + ' car.';

  const recs = byId('recommendations');
  recs.textContent = '';
  for (const r of result.recommendations) recs.appendChild(el('li', null, r));

  const box = byId('indicators');
  box.textContent = '';
  for (const f of result.findings) box.appendChild(renderFinding(f));
  byId('no-indicators').hidden = result.findings.length > 0;

  renderLinks(result);
  renderHeaders(result);
}

/* ===========================================================================
   INITIALISATION (uniquement dans un navigateur)
   =========================================================================== */
function init() {
  renderSampleCards();
  updateCharCount();

  const input = byId('email-input');
  const form = byId('analyse-form');
  const errorBox = byId('form-error');

  input.addEventListener('input', updateCharCount);

  byId('btn-clear').addEventListener('click', () => {
    input.value = '';
    updateCharCount();
    input.focus();
  });

  byId('btn-reset').addEventListener('click', () => {
    setTimeout(() => {
      updateCharCount();
      errorBox.hidden = true;
      byId('results').hidden = true;
    }, 0);
  });

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const text = input.value;
    errorBox.hidden = true;

    if (!text.trim()) {
      errorBox.textContent = "Collez d'abord le contenu d'un e-mail a analyser.";
      errorBox.hidden = false;
      input.focus();
      return;
    }
    if (text.trim().length < 20) {
      errorBox.textContent = "Le texte est trop court pour une analyse utile (20 caracteres minimum).";
      errorBox.hidden = false;
      return;
    }

    const options = {
      headers: byId('opt-headers').checked,
      links: byId('opt-links').checked,
      attachments: byId('opt-attachments').checked,
      sensitive: byId('opt-sensitive').checked
    };

    const result = runAnalysis(text, options);
    renderResults(result);
    byId('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}

/* Export utilise uniquement par les tests automatises (Node.js).
   Le navigateur ignore ce bloc : module n'y existe pas. */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    RULES, SAMPLES, THRESHOLDS, runAnalysis, buildContext, classify,
    extractLinks, analyseLink, parseHeaders, authResults, extractAttachments,
    detectMisleadingLink, escapeHtml, snippet, hostOf, isIpHost
  };
}
