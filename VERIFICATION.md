# VERIFICATION.md — Ce qui a été vérifié, et les bugs corrigés

Ce document liste **honnêtement** ce qui a été testé, ce qui a été trouvé,
et ce qui reste comme limite connue.

---

## 1. Résultats de la vérification

| Vérification | Résultat |
|---|---|
| Tests unitaires (3 suites) | **115 tests — 0 échec** |
| Tests adversariaux / fuzzing | **116 vérifications — 0 problème** |
| Test « faux navigateur » (exécution réelle du code) | 3 outils OK, toute l'interface remplie |
| Syntaxe JavaScript (`node --check`) | 6 fichiers OK |
| Ressources externes chargées | **0** |
| Utilisation de `innerHTML` / `eval` / `new Function` | **0** |
| `fetch` / `XMLHttpRequest` / `WebSocket` / `sendBeacon` | **0** |
| Cookies / `localStorage` / `sessionStorage` / `indexedDB` | **0** |
| Performance — 50 000 paquets réseau | ~0,3 s |
| Performance — 200 000 événements Windows | ~1,5 s |
| Performance — e-mail de 1 Mo | < 3 s |

Commandes pour tout revérifier soi-même :

```bash
node tools/dom-smoke-test.js      # les 3 outils s'executent-ils vraiment ?
node tools/fuzz-test.js           # entrees hostiles, bornes des scores, performance
node phishing-email-analyser/tests/tests.js
node network-traffic-triage-tool/tests/tests.js
node windows-event-log-triage-tool/tests/tests.js
```

---

## 2. Bugs réels trouvés puis corrigés

### Bug 1 — Gel du navigateur (grave)

**Où :** `phishing-email-analyser/script.js`, extraction des liens HTML.

**Symptôme :** un e-mail contenant beaucoup de `<a href="` sans chevron fermant
faisait **geler la page plus de 30 secondes** (analyse figée, onglet bloqué).

**Cause :** une expression régulière `<a[^>]*href...` : le `[^>]*` non borné
obligeait le moteur à reparcourir tout le texte à chaque occurrence. Coût en O(n²).

**Correction :** remplacement de la regex par un **parcours linéaire** avec `indexOf`.

**Résultat mesuré :** 180 000 caractères analysés en **1 ms** (au lieu de > 30 s).

**Test de non-régression ajouté :** « beaucoup de balises `<a` non fermées ne
gèlent pas la page » (< 500 ms).

---

### Bug 2 — Liens comptés en double

**Où :** `phishing-email-analyser/script.js`, `extractLinks()`.

**Symptôme :** un lien écrit en markdown ou en HTML était compté **deux fois**
(une fois avec son texte affiché, une fois en « lien en clair »). Le compteur
« Liens trouvés » était donc doublé, et le tableau affichait chaque lien deux fois.

**Correction :** dédoublonnage par URL, en conservant le texte affiché.

**Test de non-régression ajouté :** « un même lien n'est compté qu'une seule fois ».

---

### Bug 3 — Plantage sur les gros fichiers Windows

**Où :** `windows-event-log-triage-tool/script.js`, `timeRangeOf()`.

**Symptôme :** `Math.min.apply(null, tableau)` dépassait la limite d'arguments du
moteur JavaScript sur les fichiers volumineux → `RangeError`.

**Correction :** remplacement par une boucle explicite (et suppression de tous
les `push.apply`).

**Test de non-régression ajouté :** 200 000 événements lus et analysés sans erreur.

---

### Bug 4 — Zone de l'interface jamais remplie

**Où :** `network-traffic-triage-tool/index.html` (ligne « Colonnes reconnues »).

**Symptôme :** le champ `st-cols` existait dans la page mais n'était **jamais
alimenté** : il affichait « — » en permanence.

**Correction :** affichage du nombre de colonnes reconnues (ex. `6 / 7`).

**Test de non-régression ajouté :** le test « faux navigateur » vérifie désormais
que **chaque zone de l'interface reçoit bien du contenu**.

---

### Bug 5 — Ralentissement sur les longues en-têtes

**Où :** `phishing-email-analyser/script.js`, `emailDomain()`.

**Symptôme :** une en-tête `From:` de 100 000 caractères faisait passer l'analyse
de quelques millisecondes à près de **10 secondes** (regex en O(n²)).

**Correction :** analyse manuelle linéaire, sans expression régulière.

**Test de non-régression ajouté :** en-tête de 100 000 caractères < 300 ms.

---

### Bug 6 — Données de démonstration non conformes

**Où :** e-mails de démonstration.

**Symptôme :** deux exemples citaient des éléments réels : un vrai service de
raccourcissement (`bit.ly`) et un domaine sous une extension réelle (`.click`).
Or l'exigence était de n'utiliser **que** des domaines non existants.

**Correction :** tous les exemples utilisent désormais uniquement des domaines
**réservés** (`.test`) et des adresses IP **réservées** (192.0.2.x, 198.51.100.x,
203.0.113.x, 192.168.x.x, 10.x.x.x). Deux raccourcisseurs **fictifs**
(`raccourci.test`, `lien-court.test`) ont été ajoutés pour continuer à démontrer
la règle, sans citer de service réel.

**Test de non-régression ajouté :** vérification automatique que **toutes** les IP
et **tous** les domaines des exemples sont réservés ou fictifs.

---

## 3. Ce qui a été vérifié et jugé sain

- **Aucune référence cassée** : tous les identifiants d'éléments utilisés par les
  trois scripts existent bien dans les pages HTML correspondantes.
- **Aucun bouton mort** : chaque bouton de l'interface est relié à une action.
- **Aucun doublon d'identifiant** dans les pages HTML.
- **Scores bornés** : jamais de `NaN`, jamais négatif, jamais supérieur à 100
  (vérifié sur des milliers d'exécutions aléatoires).
- **Règles toutes atteignables** : chaque règle se déclenche au moins une fois sur
  les exemples fournis.
- **Aucun identifiant de règle en double.**
- **Aucun code dangereux** : pas d'`innerHTML`, pas d'`eval`, pas de requête
  réseau, pas de stockage, pas de cookie.
- **Robustesse** : entrées vides, caractères nuls, emoji, texte inversé (RTL), BOM,
  guillemets non fermés, séparateurs `,` `;` et tabulation, colonnes manquantes ou
  en double, fichiers mal encodés — **aucune exception levée**.
- **Aucune expression régulière à ralentissement catastrophique** restante
  (toutes les regex des trois moteurs ont été testées sur des entrées hostiles
  de 50 000 à 300 000 caractères).

---

## 4. Limites connues (assumées et documentées)

- Version 1 : **CSV uniquement** (pas de `.pcap`, `.evtx`, `.eml`).
- Les dates au format `03/04/2025` sont **ambiguës** : l'hypothèse jour/mois est
  retenue et **signalée dans l'interface**.
- La détection des ports réseau dépend du format de la colonne `Info` de Wireshark.
- Pas de fenêtres temporelles avancées, pas de baselining, pas de GeoIP,
  pas d'enrichissement externe.
- **Une absence d'alerte ne prouve pas qu'une activité est sûre.**
- Ces outils ne remplacent ni un antivirus, ni un EDR, ni un SIEM, ni un SOC.

---

## 5. Comment vérifier vous-même (sans rien installer)

1. Ouvrez un outil dans votre navigateur.
2. Appuyez sur **F12** → onglet **Réseau** (Network).
3. Utilisez l'outil (chargez un exemple, lancez l'analyse).
4. Constatez qu'**aucune requête** n'est émise.
5. Onglet **Application** → **Cookies** et **Stockage local** : rien n'est écrit.

C'est la preuve la plus directe que l'analyse reste bien sur votre machine.

---

## 6. Méthode de vérification utilisée

| Étape | Outil | Ce qu'elle apporte |
|---|---|---|
| 1 | `node --check` | Le code est-il syntaxiquement valide ? |
| 2 | Tests unitaires | Le comportement attendu est-il respecté ? |
| 3 | Fuzzing | Le code résiste-t-il à des entrées hostiles ? |
| 4 | Faux navigateur | Le code s'exécute-t-il vraiment, et remplit-il l'interface ? |
| 5 | Relecture indépendante | Un regard neuf trouve-t-il ce que les tests ignorent ? |
| 6 | Correction + test de non-régression | Le bug ne peut-il pas revenir ? |

L'étape 5 (relecture indépendante) est celle qui a trouvé le **gel du navigateur**
et le **comptage en double** : deux bugs que mes propres tests ne voyaient pas.
C'est pour cela qu'elle est indispensable.

