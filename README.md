# Outils de triage en cybersécurité — projets pédagogiques

Trois applications web **éducatives**, fonctionnant **entièrement dans le navigateur**,
sans serveur, sans base de données, sans API externe et sans tracker.

> **Aucune donnée n'est envoyée nulle part.** Tout est analysé localement.

---

## Contenu du dépôt

| Dossier | Outil | Ce qu'il fait |
|---|---|---|
| `phishing-email-analyser/` | **Phishing Email Analyser** | Analyse le texte d'un e-mail suspect : score de risque 0–100, 22 signes d'alerte expliqués, recommandations. |
| `network-traffic-triage-tool/` | **Network Traffic Triage Tool** | Analyse un export CSV Wireshark : tableau de bord réseau, 7 règles de détection, score d'investigation. |
| `windows-event-log-triage-tool/` | **Windows Security Event Log Triage Tool** | Analyse un export CSV de l'Observateur d'événements : 12 Event IDs expliqués, 5 règles de corrélation, rapport type SOC. |
| `index.html` | Page d'accueil | Point d'entrée commun vers les trois outils. |
| `standalone/` | **Versions fichier unique** | Les mêmes outils en un seul `.html` (HTML+CSS+JS inclus). |
| `tools/` | Outils de développement | Test de fumée « faux navigateur » et fabrication des versions fichier unique. |

Chaque dossier contient son propre `README.md` détaillé, ses exemples et ses tests.

---

## Démarrage rapide (Windows, sans rien installer)

### Méthode 1 — le plus simple

**Double-cliquez sur `DEMARRER-Windows.bat`** à la racine. La page d'accueil s'ouvre
dans votre navigateur.

> Si Windows affiche un avertissement, cliquez sur « Informations complémentaires »
> puis « Exécuter quand même ». Ce fichier ne contient qu'une ligne :
> `start "" "%~dp0index.html"`. Vous pouvez l'ouvrir dans le Bloc-notes pour le vérifier.

### Méthode 2 — sans fichier .bat

Ouvrez le dossier et **double-cliquez sur `index.html`**.

> ⚠️ Gardez `index.html`, `styles.css` et `script.js` **ensemble dans le même dossier**.
> Si vous ne copiez que le fichier HTML, la page s'affichera sans mise en forme.

### Méthode 3 — un seul fichier (le plus robuste)

Le dossier **`standalone/`** contient les mêmes outils en **fichier unique** :
HTML + CSS + JavaScript réunis dans un seul `.html`.

| Fichier | Outil |
|---|---|
| `standalone/index.html` | Page d'accueil |
| `standalone/Phishing-Email-Analyser.html` | Analyse d'e-mails |
| `standalone/Network-Traffic-Triage-Tool.html` | Triage réseau |
| `standalone/Windows-Event-Log-Triage-Tool.html` | Triage de journaux Windows |

Un seul fichier à double-cliquer : aucun risque d'oublier une dépendance.
Pratique pour l'envoyer par e-mail ou le mettre sur une clé USB.

### Aucun serveur n'est nécessaire

Ces pages fonctionnent directement depuis un fichier local (`file://`),
sans installation, sans compte et **sans connexion Internet**.

### Hébergement en ligne (facultatif)

Le dépôt est un **site statique** : déposez-le tel quel sur GitHub Pages, Netlify,
Cloudflare Pages ou tout autre hébergeur de fichiers statiques. C'est gratuit.

---

## Vérifications effectuées

| Vérification | Résultat |
|---|---|
| Tests unitaires (3 suites) | **98 tests, 0 échec** |
| Test de fumée « faux navigateur » | les 3 outils s'exécutent sans erreur |
| Ressources externes chargées | **0** (aucun CDN, aucune police distante) |
| Utilisation de `innerHTML` | **0** (protection contre l'injection) |
| Requêtes réseau émises | **0** |

```bash
node tools/dom-smoke-test.js      # les 3 outils s'executent-ils vraiment ?
node tools/build-standalone.js    # regenerer les versions fichier unique
```

> Le test de fumée simule un navigateur (document, éléments, URL, Blob, FileReader),
> lance l'initialisation de chaque outil et charge tous les exemples.
> Il a permis de détecter un vrai bug d'initialisation lors de sa première exécution.

---

## Philosophie commune

1. **Confidentialité par conception** — aucune donnée ne quitte le navigateur.
2. **Explicabilité** — chaque score est la somme de contributions affichées.
3. **Pas d'IA opaque** — uniquement des règles lisibles et des seuils modifiables.
4. **Honnêteté** — les outils indiquent ce qui mérite une investigation, jamais une certitude d'attaque.
5. **Pédagogie avant spectacle** — la valeur explicative passe avant l'apparence « avancée ».

---

## Technologies

- **HTML**, **CSS**, **JavaScript natif** (vanilla).
- Aucun framework (ni React, ni Next.js, ni Vue).
- Aucun backend (ni Node.js, ni Python).
- Aucune base de données, aucun service cloud, aucune clé API.
- Aucune dépendance à installer.

Node.js n'est utilisé que pour lancer les **tests** et régénérer les **exemples** —
c'est facultatif et n'a aucun impact sur le fonctionnement des applications.

---

## Tests (facultatif)

```bash
cd phishing-email-analyser && node tests/tests.js
cd ../network-traffic-triage-tool && node tests/tests.js
cd ../windows-event-log-triage-tool && node tests/tests.js
```

Les trois suites utilisent uniquement le module `assert` de Node.js (aucune dépendance).

---

## Avertissement

- Ces outils sont **éducatifs** : ils ne remplacent ni un antivirus, ni un EDR,
  ni un SIEM, ni un SOC professionnel.
- Une alerte est une **raison d'enquêter**, pas une **preuve** de compromission.
- **Analysez uniquement des systèmes, réseaux et journaux dont vous êtes
  propriétaire ou que vous êtes autorisé à examiner.**
- Ne cliquez jamais sur un lien suspect et n'ouvrez jamais une pièce jointe
  simplement pour la tester.

---

## Pistes d'amélioration (non implémentées)

- Support des fichiers `.eml`, `.pcap` et `.evtx`
- Export des rapports (PDF, texte, JSON)
- Correspondance MITRE ATT&CK
- Mode « quiz » pour s'entraîner
- Graphiques et chronologies enrichis

---

## Licence et usage

Projet pédagogique. Vous pouvez l'utiliser, l'étudier et l'adapter librement
pour apprendre, dans le respect de la loi et des systèmes que vous êtes autorisé
à analyser.
