# Windows Security Event Log Triage Tool — Outil de triage des journaux d'événements de sécurité Windows

> **Outil éducatif de triage SOC.** Les constats indiquent une activité qui mérite une investigation et **ne prouvent pas** un comportement malveillant.
>
> **Analysez uniquement des journaux provenant de systèmes que vous possédez ou que vous êtes autorisé à investiguer.**

---

## 1. Objectif du projet

Apprendre à **enquêter sur des événements de sécurité Windows** comme le ferait un
analyste SOC, en mettant l'accent sur la **corrélation** : un événement isolé
raconte rarement toute l'histoire.

Le principe :

1. Vous collectez des événements dans l'**Observateur d'événements** Windows.
2. Vous les exportez en **CSV**.
3. Vous chargez le CSV dans l'application.
4. L'application analyse le fichier **localement dans votre navigateur**.
5. Elle identifie les **Event IDs** importants et **corrèle** les événements liés.
6. Vous obtenez un **rapport de triage de type SOC**, explicable ligne par ligne.

---

## 2. Confidentialité (important)

**Vos journaux d'événements Windows sont analysés localement dans votre navigateur et ne sont envoyés nulle part.**

- Aucun serveur, aucun backend, aucune base de données.
- Aucune API d'IA, aucun service d'analyse externe, aucune clé API.
- Aucun cookie, aucun traceur, aucune publicité, aucune télémétrie.
- Le fichier n'est jamais transmis : il est lu en mémoire par le navigateur.

> Vérification possible : F12 → onglet **Réseau** → chargez un fichier → aucune requête sortante.

---

## 3. Technologies

| Utilisé | Non utilisé |
|---|---|
| HTML, CSS, JavaScript natif | React, Next.js, Vue |
| Site statique | Backend Node.js / Python |
| — | Base de données, services cloud |
| — | API d'IA, clés API, frameworks inutiles |

---

## 4. Structure des fichiers

```
windows-event-log-triage-tool/
├── index.html                              # Interface
├── styles.css                              # Thème sombre « cybersécurité »
├── script.js                               # Moteur : lecture CSV, Event IDs, corrélation
├── README.md
├── samples/                                # Journaux fictifs de démonstration
│   ├── normal-windows-events.csv
│   ├── password-guessing.csv
│   ├── account-persistence.csv
│   └── suspicious-admin-activity.csv
├── tools/
│   └── make-samples.js                     # Génère les exemples (facultatif)
└── tests/
    └── tests.js                            # Tests automatiques (facultatif)
```

---

## 5. Lancer l'application sur Windows (rien à installer)

1. Copiez le dossier `windows-event-log-triage-tool` sur votre ordinateur.
2. **Double-cliquez sur `index.html`**.
3. Cliquez sur un exemple pour découvrir le fonctionnement immédiatement.

Aucune commande, aucun serveur, aucune installation.

---

## 6. Comment exporter vos journaux Windows

### Méthode 1 — Observateur d'événements

1. Touche Windows → tapez `eventvwr` → **Observateur d'événements**.
2. **Journaux Windows** → **Sécurité**.
3. Filtrez si nécessaire (*Filtrer le journal actuel* → Event ID 4624, 4625, 4720…).
4. Sélectionnez les événements (Ctrl+A pour tout).
5. Clic droit → **Enregistrer les événements sélectionnés sous...** → format CSV.

### Méthode 2 — PowerShell (plus fiable pour obtenir un vrai CSV)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4720,4726,4728,4732,1102,4688,7045} -MaxEvents 500 |
  Select-Object LevelDisplayName, TimeCreated, ProviderName, Id, Task, UserId, MachineName, Message |
  Export-Csv -Path "$env:USERPROFILE\Desktop\evenements-securite.csv" -NoTypeInformation -Encoding UTF8
```

> Cette commande s'exécute **localement**. Le journal Sécurité nécessite souvent
> un terminal lancé **en tant qu'administrateur**.

**Note honnête :** toutes les versions de Windows ne proposent pas directement
l'export CSV depuis l'Observateur d'événements. Si l'option n'existe pas chez
vous, utilisez la méthode PowerShell ci-dessus, ou exportez en `.txt`
(l'outil accepte aussi ce format s'il est séparé par des virgules ou des tabulations).

---

## 7. Tolérance sur les noms de colonnes

Les entêtes sont normalisés puis comparés à des variantes. Sont reconnus, par exemple :

| Champ | Variantes acceptées |
|---|---|
| Event ID | `Event ID`, `EventID`, `event_id`, `ID`, `Event Code` |
| Date | `Date and Time`, `TimeCreated`, `Date`, `Horodatage` |
| Compte | `User`, `Utilisateur`, `Account`, `Account Name`, `SubjectUserName` |
| Machine | `Computer`, `ComputerName`, `Ordinateur`, `Machine` |
| Niveau | `Level`, `LevelDisplayName`, `Niveau`, `Severity` |
| Source | `Source`, `ProviderName`, `Fournisseur` |
| Message | `Message`, `Description`, `Détails` |

Si la colonne **Event ID** est absente, l'outil ne plante pas : il affiche un
message explicite. Les colonnes facultatives manquantes sont signalées, car elles
limitent l'analyse.

---

## 8. Event IDs pris en charge

| Event ID | Nom | Sévérité par défaut | Explication simple |
|---|---|---|---|
| 4624 | Connexion réussie | Informationnel | Un compte a ouvert une session. Important surtout comme **contexte**. |
| 4625 | Échec de connexion | Faible | Un échec isolé est banal ; des échecs **répétés** deviennent intéressants. |
| 4634 | Fermeture de session | Informationnel | Utile pour reconstituer une chronologie. |
| 4672 | Privilèges spéciaux attribués | Faible | Souvent un compte administrateur. Fréquent. |
| 4720 | Compte utilisateur créé | Moyen | Peut être administratif… ou de la persistance. À vérifier. |
| 4726 | Compte utilisateur supprimé | Faible | Souvent administratif, à mettre en contexte. |
| 4728 | Ajout à un groupe global | Moyen (Élevé si privilégié) | Modifie les droits de l'utilisateur. |
| 4732 | Ajout à un groupe local | Moyen (Élevé si privilégié) | Idem. Si le groupe est « Administrateurs », priorité haute. |
| 1102 | Journal d'audit effacé | **Élevé** | Peut être une maintenance, mais aussi une suppression de traces. |
| 4688 | Processus créé | Informationnel | Contexte : nom du processus, parent, ligne de commande. |
| 4104 | Bloc de script PowerShell | Informationnel | Excellente visibilité. PowerShell n'est **pas** suspect en soi. |
| 7045 | Service installé | Moyen | Installation légitime… ou mécanisme de persistance. |

> **Une connexion réussie n'est jamais signalée comme malveillante.** Elle sert
> de contexte pour interpréter les autres événements.

---

## 9. Règles de corrélation (le cœur du projet)

| # | Règle | Déclenchement | Sévérité | Points |
|---|---|---|---|---|
| 1 | Échecs de connexion répétés | ≥ 5 événements 4625 pour un même compte | Moyen | +10 |
| 2 | Échecs suivis d'une connexion réussie | 4625 × N puis 4624 pour le même compte | Élevé | +20 |
| 3 | Compte créé puis privilèges ajoutés | 4720 puis 4728/4732 pour le même compte | Élevé | +25 |
| 4 | Journal de sécurité effacé | présence de 1102 | Élevé | +30 |
| 5 | Activité administrative / privilèges | regroupement de 4672, 4720, 4726, 4728, 4732, 7045, 1102 | Synthèse | hors score |

**Exemple de règle 2 :**

```
POSSIBLE DEVINETTE DE MOT DE PASSE SUIVIE D'UNE CONNEXION RÉUSSIE
Sévérité : Élevé
Compte : jsmith
Séquence : 4625 → 4625 → 4625 → 4625 → 4625 → 4624
Échecs : 12   |   Connexion réussie : oui
```

> Les constats de **corrélation s'ajoutent** aux constats individuels. C'est
> volontaire : une séquence est plus parlante qu'un événement isolé. Le score est
> plafonné à 100.

---

## 10. Score d'investigation

| Score | Niveau |
|---|---|
| 0 | Aucune activité notable |
| 1 – 19 | Priorité faible |
| 20 – 49 | Priorité moyenne |
| 50 – 79 | Priorité élevée |
| 80 – 100 | Priorité très élevée |

Chaque contribution est affichée, par exemple :

```
+30  Journal d'audit de sécurité effacé (corrélation)
+25  Nouveau compte ayant reçu des privilèges (corrélation)
+25  Changement d'appartenance à un groupe de sécurité
+20  Échecs répétés suivis d'une connexion réussie (corrélation)
+15  Compte utilisateur créé
+10  Échecs de connexion répétés (corrélation)
------------------------------
Score d'investigation : 100  →  Priorité très élevée
```

⚠️ Ce score est un **mécanisme pédagogique de priorisation**, pas une
probabilité mathématique de compromission.

---

## 11. Sévérités

**Informationnel** · **Faible** · **Moyen** · **Élevé**

Le niveau « Critique » est volontairement évité : la sévérité représente une
**priorité d'investigation**, pas une **certitude de compromission**.

---

## 12. Tableau de bord, filtres et chronologie

**Tableau de bord :** total d'événements, connexions réussies, échecs, comptes
créés/supprimés, changements de privilèges, effacements de journal, créations de
processus, services installés, blocs PowerShell, constats à investiguer.

**Classements :** comptes les plus actifs, comptes avec le plus d'échecs,
Event IDs les plus fréquents.

**Chronologie** des événements notables (si les horodatages sont exploitables).

**Filtres :** Event ID, compte, sévérité, adresse IP source, type d'événement,
et une recherche libre.

---

## 13. Exemples fournis

| Fichier | Contenu | Résultat attendu |
|---|---|---|
| `normal-windows-events.csv` | Activité courante + 1 échec isolé | Score faible (~15), aucun constat de corrélation |
| `password-guessing.csv` | 12 échecs (4625) puis une réussite (4624) | Échecs répétés + échecs suivis d'une réussite |
| `account-persistence.csv` | 4720 puis 4732 (Administrators) | Nouveau compte ayant reçu des privilèges |
| `suspicious-admin-activity.csv` | Échecs, réussite, 4720, 4728, 7045, 4104 encodé, 1102 | Score 100 — priorité très élevée |

Tous les comptes, machines et adresses IP sont **fictifs** (plages privées
`192.168.10.x`, `10.0.0.x`, et `203.0.113.x` réservée à la documentation).

---

## 14. Comment penser comme un analyste SOC

1. **Identifier** l'événement.
2. **Comprendre** ce qui s'est produit.
3. **Identifier** l'utilisateur ou le système concerné.
4. **Déterminer** si l'activité est attendue.
5. **Chercher** des événements liés.
6. **Corréler** authentification et privilèges.
7. **Recueillir** davantage d'éléments de preuve.
8. **Décider** si une escalade est nécessaire.

> « Un événement de sécurité isolé raconte rarement toute l'histoire. Les analystes construisent le contexte en corrélant plusieurs événements. »
>
> « Une détection est une raison d'enquêter, pas une preuve qu'un attaquant est présent. »

---

## 15. Faux positifs

Beaucoup de constats ont une explication banale :

- scripts d'administration et de déploiement ;
- maintenance planifiée et nettoyage de journaux ;
- utilisateurs qui se trompent de mot de passe ;
- services avec des identifiants périmés ;
- création de comptes de service ou de prestataires ;
- logiciels légitimes qui installent des services.

L'exercice consiste justement à **vérifier le contexte** avant de conclure.


---

## 16. Limites honnêtes

- Les **exports CSV varient** selon la version de Windows, la langue et la configuration d'audit.
- **Les horodatages peuvent être ambigus** : dans `03/04/2025`, impossible de savoir avec certitude s'il s'agit du 3 avril ou du 4 mars. L'outil retient l'hypothèse **jour/mois** et **le signale explicitement** au lieu de faire semblant d'être précis.
- Si aucun horodatage n'est exploitable, la corrélation repose sur **l'ordre des lignes** du fichier, et la fenêtre temporelle n'est pas appliquée.
- **Toutes les informations ne sont pas toujours disponibles** : la colonne `User` est souvent vide pour un échec de connexion (4625) ; l'outil tente alors de lire le nom de compte dans le message.
- **La configuration d'audit limite la visibilité** : sans audit de création de processus activé, aucun 4688 n'apparaîtra.
- **L'absence d'un événement ne prouve pas que l'activité n'a pas eu lieu.**
- Cet outil ne remplace **ni un EDR, ni un SIEM, ni un SOC professionnel**.
- Une analyse dans un navigateur ne peut pas corréler des sources de données externes (MFA, réseau, Threat Intelligence).
- Les **Event IDs seuls ne permettent pas de déterminer une intention**.

---

## 17. Tests (facultatif)

```bash
cd windows-event-log-triage-tool
node tests/tests.js
```

41 tests couvrent : variantes de colonnes, séparateurs, CSV mal formé, absence de
colonne, protection contre l'injection HTML, formats d'horodatage, extraction du
contexte (français et anglais), groupes privilégiés, détection PowerShell encodée,
les 5 règles de corrélation, les seuils configurables et la cohérence du score.

Pour régénérer les exemples :

```bash
node tools/make-samples.js
```

---

## 18. Sécurité du code

- Le contenu du CSV est traité comme une **entrée non fiable**.
- Aucune valeur issue du fichier n'est insérée via `innerHTML` : tout passe par
  `textContent`, donc **aucun script ne peut être exécuté**.
- Les fichiers malformés échouent proprement avec un message explicite.
- Aucune requête réseau n'est émise par l'application.
- Aucun fichier n'est conservé après la fermeture de l'onglet.

---

## 19. Améliorations futures (non implémentées)

- Analyse directe des fichiers `.evtx`
- Support Sysmon
- Analyse approfondie des blocs PowerShell 4104
- Visualisation de l'arbre des processus
- Correspondance MITRE ATT&CK
- Analyse de chronologie avancée
- Baselining des connexions
- Détection de création de tâches planifiées
- Analyse des journaux Windows Defender
- Export d'un rapport d'incident
- Intégration SIEM

---

## 20. Démonstration (scénario conseillé)

| Étape | Charger | Résultat attendu | Message à faire passer |
|---|---|---|---|
| 1 | Activité normale | Peu de constats | « La majorité du journal est normale. » |
| 2 | Échecs répétés | Échecs de connexion répétés | « Un échec isolé n'est rien ; 12 deviennent intéressants. » |
| 3 | Échecs + réussite | Échecs suivis d'une connexion réussie | « La séquence change l'interprétation. » |
| 4 | Compte + privilèges | Nouveau compte ayant reçu des privilèges | « Création + élévation = persistance possible. » |
| 5 | Journal effacé | Constat de sévérité Élevé | « Effacer un journal supprime les preuves. » |

> **Conclusion à partager :** « Les événements individuels comptent, mais la vraie valeur vient de la façon dont ils se rapportent les uns aux autres. »

---

## 21. Usage éducatif

Ce projet ne prétend **pas** détecter automatiquement les attaquants.
Il apprend à **lire**, **corréler** et **prioriser** des événements Windows —
et à comprendre pourquoi un analyste décide d'investiguer.

