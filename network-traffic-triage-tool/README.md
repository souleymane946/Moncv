# Network Traffic Triage Tool — Outil de triage du trafic réseau

> **Outil éducatif de triage réseau.** Les alertes indiquent une activité qui mérite une investigation mais **ne prouvent pas** un comportement malveillant.
>
> **Analysez uniquement des systèmes et réseaux dont vous êtes propriétaire ou que vous êtes autorisé à surveiller.**

---

## 1. À quoi sert ce projet ?

Ce projet est un outil **pédagogique** qui apprend à raisonner comme un analyste SOC
face à une capture de trafic réseau.

Le principe est simple :

1. Vous capturez du trafic avec **Wireshark**.
2. Vous exportez la **liste des paquets au format CSV**.
3. Vous chargez ce CSV dans l'application.
4. L'application analyse le fichier **localement dans votre navigateur**.
5. Vous obtenez un rapport de triage : qui parle à qui, avec quel protocole, et
   quels comportements méritent une investigation.

L'objectif n'est **pas** de produire un « détecteur de hackers automatique »,
mais d'apprendre à **interpréter** un trafic et à **expliquer** pourquoi une
activité sort de l'ordinaire.

---

## 2. Confidentialité (important)

**Vos données de capture réseau sont analysées localement dans votre navigateur et ne sont envoyées nulle part.**

- Aucun serveur, aucun backend.
- Aucune API d'IA, aucun service d'analyse externe.
- Aucun cookie, aucun traceur, aucune publicité, aucune télémétrie.
- Le fichier CSV n'est **jamais** transmis : il est lu par le navigateur, traité en mémoire, puis oublié.

> Vous pouvez le vérifier vous-même : ouvrez les outils de développement du navigateur (F12) → onglet **Réseau**, puis chargez un fichier. Vous ne verrez aucune requête sortante.

---

## 3. Technologies utilisées

| Utilisé | Non utilisé |
|---|---|
| HTML | React, Next.js, Vue |
| CSS | Backend Node.js / Python |
| JavaScript natif (vanilla) | Base de données |
| — | Services cloud, API d'IA, clés API |
| — | Frameworks ou dépendances inutiles |

Le projet est un **site 100 % statique** : il peut être hébergé gratuitement
(GitHub Pages, Netlify, etc.) et reste gratuit pour tous les visiteurs.

---

## 4. Structure des fichiers

```
network-traffic-triage-tool/
├── index.html                 # La page de l'application
├── styles.css                 # Le thème visuel (sombre, « cybersécurité »)
├── script.js                  # Le moteur : lecture CSV, agrégation, règles
├── README.md                  # Ce document
├── samples/                   # Captures CSV fictives (démonstration)
│   ├── normal-network.csv
│   ├── host-scan.csv
│   ├── icmp-sweep.csv
│   └── mixed-soc-sample.csv
├── tools/
│   └── make-samples.js        # Génère les fichiers d'exemple (facultatif)
└── tests/
    └── tests.js               # Tests automatiques (facultatif, Node.js)
```

---

## 5. Comment l'utiliser sur Windows (sans rien installer)

1. Copiez le dossier `network-traffic-triage-tool` sur votre ordinateur.
2. **Double-cliquez sur `index.html`** : il s'ouvre dans votre navigateur.
3. Cliquez sur un exemple dans la section « Exemples de démonstration » pour
   voir immédiatement le fonctionnement.

C'est tout. Aucun serveur, aucune installation, aucune commande.

> Pour analyser **votre** capture, exportez-la depuis Wireshark (voir §6),
> puis glissez le fichier CSV dans la zone de dépôt.

### Hébergement en ligne (facultatif)

Déposez le dossier sur GitHub Pages, Netlify ou tout hébergeur de fichiers
statiques. Aucune configuration particulière n'est nécessaire.

---

## 6. Comment exporter un CSV depuis Wireshark

1. Ouvrez Wireshark et démarrez une capture (ou ouvrez un fichier `.pcap` existant).
2. Arrêtez la capture quand vous avez assez de paquets.
3. Menu **File (Fichier) → Export Packet Dissections → As CSV…**
4. Choisissez un nom de fichier et validez.
5. Chargez ce fichier dans l'outil.

L'export contient normalement les colonnes :

```
No.,Time,Source,Destination,Protocol,Length,Info
```

L'outil tolère de nombreuses variantes de noms de colonnes.

---

## 7. Tolérance sur les noms de colonnes

Les entêtes sont normalisés (minuscules, sans espaces ni ponctuation) puis comparés
à une liste de variantes. Par exemple, tous ces noms sont reconnus comme la
**colonne source** :

`Source` · `Source IP` · `src` · `ip.src` · `IPv4 Source` · `Adresse source`

Idem pour la destination, le protocole, la longueur et la colonne `Info`.

**Si une colonne importante est absente**, l'application ne plante pas :
elle affiche un message clair, par exemple :

> « Ce fichier CSV ne semble pas contenir de colonne d'adresse source. »

Les colonnes facultatives manquantes sont également signalées, car elles
limitent l'analyse (ex. : sans colonne `Info`, la détection de ports et de
drapeaux TCP devient impossible).

---

## 8. Ce que contient le rapport

### Vue d'ensemble du réseau

- Nombre total de paquets
- Nombre d'hôtes sources uniques
- Nombre d'hôtes destinations uniques
- Hôte source le plus actif
- Destination la plus contactée
- Protocole le plus utilisé
- Taille moyenne des paquets (si la colonne `Length` est présente)
- Durée couverte par la capture (si la colonne `Time` est présente)

### Classements

- **Top 10 des sources** par nombre de paquets
- **Top 10 des destinations**
- **Répartition des protocoles** (seuls ceux présents sont affichés) :
  TCP, UDP, DNS, ICMP, ARP, HTTP, HTTPS/TLS, Autres

---

## 9. Les 7 règles de détection

Chaque règle affiche : **nom**, **niveau de sévérité**, **preuves observées**,
**pourquoi cela peut être important**, **explication bénigne possible** et
**investigation recommandée**.

| # | Règle | Seuil par défaut | Sévérité | Points |
|---|---|---|---|---|
| 1 | Hôte très actif (volume de paquets élevé) | > 50 paquets par source | Moyen | +20 |
| 2 | Scan d'hôtes possible | > 10 destinations uniques par source | Élevé | +15 |
| 3 | Scan de ports possible | > 10 ports différents vers une même destination | Élevé | +15 |
| 4 | Activité ICMP élevée | > 30 paquets ICMP par source | Moyen | +15 |
| 5 | Activité DNS élevée | > 30 paquets DNS par source | Moyen | +15 |
| 6 | Communications répétées entre deux hôtes | > 40 paquets entre deux hôtes | Faible | +10 |
| 7 | Activité TCP SYN importante | > 20 SYN sans réponse par source | Élevé | +15 |

**Tous les seuils sont modifiables** dans l'interface, puis appliqués avec le
bouton « Recalculer avec ces seuils ».

> Une règle ne se déclenche **qu'une seule fois**, même si plusieurs hôtes
> dépassent le seuil : la liste des hôtes concernés apparaît dans les preuves.
> Cela évite un score artificiellement gonflé.

---

## 10. Le score d'investigation

Le score est la **somme des points des règles déclenchées**, plafonnée à 100.
Chaque contribution est affichée :

```
+20  Hôte très actif (volume de paquets élevé)
+15  Scan d'hôtes possible
+15  Activité ICMP élevée
-----------------------
Score d'investigation : 50
Niveau : Activité élevée
```

| Score | Niveau |
|---|---|
| 0 | Aucune activité notable |
| 1 – 19 | Activité faible |
| 20 – 39 | Activité modérée |
| 40 – 69 | Activité élevée |
| 70 – 100 | Activité très élevée |

⚠️ Ce score **n'est pas** une probabilité d'attaque. C'est un **indicateur de
priorité d'investigation**, à but pédagogique.

---

## 11. Niveaux de sévérité

Quatre niveaux seulement :

**Informationnel** · **Faible** · **Moyen** · **Élevé**

Le niveau « Critique » est volontairement absent : un outil de triage ne peut
pas être certain qu'une attaque est en cours. La sévérité représente une
**priorité d'investigation**, pas une **certitude d'attaque**.

---

## 12. Exemples fournis

| Fichier | Contenu | Résultat attendu |
|---|---|---|
| `normal-network.csv` | Navigation courante (DNS, HTTPS, ARP) | Aucune alerte |
| `host-scan.csv` | 1 source → 24 destinations + nombreux ports | Scan d'hôtes, scan de ports, SYN |
| `icmp-sweep.csv` | 45 pings depuis un seul hôte | Scan d'hôtes, activité ICMP élevée |
| `mixed-soc-sample.csv` | Volume + DNS + ICMP + SYN | Score élevé, 6 règles déclenchées |

Toutes les adresses utilisées sont **réservées** (192.168.x.x, 10.x.x.x,
203.0.113.x, 198.51.100.x, 192.0.2.x). Aucune donnée réelle.

---

## 13. Comment penser comme un analyste

1. **Observer** un comportement inhabituel.
2. **Identifier** la source et la destination.
3. **Identifier** le protocole.
4. **Déterminer** si c'est attendu.
5. **Rechercher** d'autres indicateurs.
6. **Corréler** avec d'autres sources de données.
7. **Décider** si une investigation approfondie est nécessaire.

> « Une anomalie est un point de départ pour une enquête, pas une preuve de compromission. »


---

## 14. Faux positifs : pourquoi c'est normal

Un scan réseau ressemble beaucoup à… un inventaire réseau légitime.
Beaucoup de comportements « suspects » ont une explication banale :

- sauvegardes nocturnes ;
- mises à jour logicielles ;
- supervision (Zabbix, Nagios, PRTG) ;
- serveur DHCP, DNS, antivirus ;
- machines virtuelles et conteneurs ;
- scripts d'administration.

C'est justement l'exercice : apprendre à **distinguer** par le contexte,
pas seulement par le volume.

---

## 15. Limites honnêtes de la version 1

- **CSV uniquement.** Les fichiers `.pcap` et `.pcapng` ne sont pas pris en charge.
- **Pas de fenêtres temporelles** : l'outil ne mesure pas les débits par seconde.
- **Pas de baselining** : l'outil ne connaît pas « la normale » de votre réseau.
- **Pas de GeoIP, pas d'enrichissement externe, pas de Threat Intelligence.**
- **Pas d'analyse avancée des drapeaux TCP** (au-delà de SYN/ACK/RST).
- La détection de ports dépend de la colonne `Info`, dont le format varie
  selon la version de Wireshark.
- L'absence d'alerte **ne prouve pas** que le réseau est sain : cela signifie
  seulement qu'aucune règle utilisée ne s'est déclenchée.
- Un outil de triage ne remplace **jamais** un IDS/IPS, un EDR ou un SIEM.

---

## 16. Tests (facultatif)

Si Node.js est installé sur votre machine (ce n'est **pas** nécessaire pour
utiliser l'application) :

```bash
cd network-traffic-triage-tool
node tests/tests.js
```

Les tests vérifient notamment : la reconnaissance des variantes de colonnes,
le séparateur `;`, les champs entre guillemets, les CSV mal formés, l'absence
de colonnes, la protection contre l'injection HTML, les 7 règles, les seuils
et la cohérence du score.

Pour régénérer les fichiers d'exemple :

```bash
node tools/make-samples.js
```

---

## 17. Sécurité du code

- Le contenu du CSV est traité comme une **entrée non fiable**.
- Aucune valeur issue du fichier n'est insérée via `innerHTML` : tout passe par
  `textContent`, donc **aucun script ne peut être exécuté**.
- Les fichiers malformés échouent proprement, avec un message explicite.
- Aucune requête réseau n'est émise par l'application.

---

## 18. Idées d'amélioration (non implémentées en version 1)

- Support direct des fichiers `.pcap` / `.pcapng`
- Analyse avancée des drapeaux TCP
- Détections basées sur des fenêtres temporelles
- Baselining du trafic
- Graphiques réseau
- GeoIP
- Enrichissement Threat Intelligence
- Analyse des domaines DNS
- Export de rapport au format SOC
- Règles de type IDS

---

## 19. Usage éducatif

Ce projet a été conçu pour **apprendre**, pas pour impressionner.
La valeur pédagogique et l'explicabilité des détections passent avant
l'apparence « avancée » de l'application.

Bon apprentissage, et rappelez-vous : **triez, ne concluez pas**.

