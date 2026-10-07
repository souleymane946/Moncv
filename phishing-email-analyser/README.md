# Phishing Email Analyser — Analyse locale d'e-mails suspects

> **Outil pédagogique d'évaluation préliminaire (triage).** Il identifie des signes d'alerte courants dans le texte d'un e-mail et **ne peut pas déterminer avec certitude** qu'un message est malveillant.
>
> **Ne cliquez jamais** sur un lien suspect et **n'ouvrez jamais** une pièce jointe simplement « pour tester ».

---

## 1. Objectif

Aider à comprendre et à reconnaître les schémas d'**hameçonnage** (phishing) et
d'**ingénierie sociale**, en expliquant **chaque** signe d'alerte détecté.

L'utilisateur colle le contenu d'un e-mail, clique sur « Analyser l'e-mail », et
obtient :

1. un **score de risque de 0 à 100** ;
2. une **classification** : Faible risque / Suspect / Risque élevé ;
3. l'**explication de chaque signe d'alerte** ayant contribué au résultat ;
4. des **recommandations pratiques**.

---

## 2. Confidentialité (important)

**Votre e-mail est analysé uniquement dans votre navigateur.**

- Aucun serveur, aucun backend, aucune base de données.
- Aucun fournisseur d'IA, aucune API externe, aucune clé API.
- Aucun service d'analyse (analytics), aucun cookie, aucun traceur, aucune télémétrie.
- L'outil **ne visite jamais** les liens et **n'ouvre jamais** les pièces jointes.

> Vérification : F12 → onglet **Réseau** → analysez un e-mail → aucune requête sortante.

---

## 3. Technologies

HTML + CSS + JavaScript natif. Aucun framework, aucune dépendance, aucun backend.
Site **100 % statique**, hébergeable gratuitement et gratuit pour tous les visiteurs.

---

## 4. Structure

```
phishing-email-analyser/
├── index.html     # Interface
├── styles.css     # Thème sombre « cybersécurité »
├── script.js      # Moteur : 22 règles explicables + score
├── README.md
└── tests/
    └── tests.js   # 29 tests automatiques (facultatif, Node.js)
```

---

## 5. Utilisation sur Windows (rien à installer)

1. Copiez le dossier `phishing-email-analyser` sur votre ordinateur.
2. **Double-cliquez sur `index.html`**.
3. Cliquez sur un exemple pour découvrir le fonctionnement, ou collez votre e-mail.

---

## 6. Comment fonctionne le score ?

Chaque règle déclenchée a un **poids fixe et affiché**. Le score est simplement
la **somme des poids**, plafonnée à 100. Rien de caché, aucun hasard, aucune IA.

| Score | Classification |
|---|---|
| 0 – 24 | Faible risque |
| 25 – 59 | Suspect |
| 60 – 100 | Risque élevé |

Exemple de rapport :

```
+18  Demande de mot de passe
+15  Menace de suspension ou de fermeture de compte
+15  URL pointant directement vers une adresse IP
+12  Langage d'urgence ou de pression
+10  Formulations courantes d'usurpation d'identité
-----------------------------------------------
Score : 70 / 100   →   Risque élevé
```

---

## 7. Les 22 indicateurs recherchés

| # | Indicateur | Poids | Sévérité |
|---|---|---|---|
| 1 | Langage d'urgence ou de pression | +12 | Moyen |
| 2 | Menace de suspension ou de fermeture de compte | +15 | Moyen |
| 3 | Demande de mot de passe | +18 | Élevé |
| 4 | Demande de code MFA ou de vérification | +18 | Élevé |
| 5 | Demande de paiement ou de cartes-cadeaux | +18 | Élevé |
| 6 | Demande de modification des coordonnées bancaires | +20 | Élevé |
| 7 | URL suspecte (domaine imitant une marque, extension douteuse…) | +15 | Élevé |
| 8 | URL raccourcie (destination masquée) | +12 | Moyen |
| 9 | URL utilisant directement une adresse IP | +15 | Élevé |
| 10 | Texte de lien trompeur (texte ≠ destination) | +12 | Moyen |
| 11 | Formulations d'usurpation d'identité | +10 | Moyen |
| 12 | Nom de pièce jointe inhabituel | +10 | Moyen |
| 13 | Pièce jointe exécutable (.exe, .js, .vbs, .lnk, .docm…) | +20 | Élevé |
| 14 | Demande d'activation des macros | +18 | Élevé |
| 15 | Langage lié à une facture inattendue | +12 | Moyen |
| 16 | Formulations visant à voler les identifiants | +15 | Élevé |
| 17 | Incohérence expéditeur / Reply-To | +15 | Élevé |
| 18 | Échec SPF | +15 | Élevé |
| 19 | Échec DKIM | +10 | Moyen |
| 20 | Échec DMARC | +15 | Élevé |
| 21 | Domaine sosie imitant une marque connue (« micros0ft ») | +15 | Élevé |
| 22 | Demande de secret / contournement des procédures (BEC) | +15 | Moyen |

Les indicateurs 18 à 20 ne s'appliquent que si vous collez les **en-têtes** du
message (`Authentication-Results:`, `Received-SPF:`…). Ils sont optionnels mais
améliorent nettement la détection.

---

## 8. Les 6 e-mails de démonstration

Tous **entièrement fictifs** : domaines en `.test`, adresses IP réservées
(192.0.2.x, 198.51.100.x, 203.0.113.x). Aucun lien malveillant fonctionnel.

| # | Exemple | Résultat attendu |
|---|---|---|
| 1 | Phishing évident | Risque élevé (~85) |
| 2 | Phishing sophistiqué (macros, lien trompeur) | Risque élevé (100) |
| 3 | Faux avertissement Microsoft 365 | Risque élevé (100) |
| 4 | Faux message de livraison de colis | Suspect (~55) |
| 5 | Fausse facture / fraude au président (BEC) | Risque élevé (~62) |
| 6 | E-mail légitime | Faible risque (0) |

L'exemple 6 est important : il montre que l'outil **ne crie pas au loup** sur un
message normal.

---

## 9. Sécurité du code

- Le contenu de l'e-mail est traité comme une **entrée non fiable**.
- Aucune valeur n'est insérée via `innerHTML` : tout passe par `textContent`.
  Un e-mail ne peut donc **pas exécuter de JavaScript**.
- Les liens sont affichés en **texte brut** et ne sont **jamais cliquables**.
- Les fichiers/e-mails malformés échouent proprement.

---

## 10. Limites honnêtes

- L'outil analyse du **texte** : il ne peut pas vérifier si un lien est réellement
  malveillant (il ne le visite pas, volontairement).
- Un score bas **ne garantit pas** qu'un e-mail est sûr.
- Un score élevé **ne prouve pas** une attaque.
- Les techniques d'hameçonnage évoluent constamment : les règles se basent sur
  des schémas connus et peuvent manquer une attaque très ciblée.
- L'outil ne remplace **ni une passerelle de messagerie sécurisée, ni un EDR,
  ni la vigilance humaine**.

---

## 11. Tests (facultatif)

```bash
cd phishing-email-analyser
node tests/tests.js
```

29 tests couvrent : la classification des 6 exemples, l'absence de fausses
alertes sur l'e-mail légitime, les entrées vides ou malformées, la protection
contre l'injection HTML, l'analyse des liens, des pièces jointes, des en-têtes
SPF/DKIM/DMARC, des domaines sosies, les options de l'interface et la cohérence
du score.

---

## 12. Améliorations futures (non implémentées)

- Analyse de fichiers `.eml` / `.msg`
- Extraction automatique des en-têtes depuis un message transféré
- Vérification hors ligne de listes de domaines (fichier local, sans réseau)
- Comparaison visuelle de domaines sosies
- Export du rapport en PDF ou texte
- Mode « quiz » pour s'entraîner à repérer le phishing

---

## 13. Rappel important

- Ne cliquez pas sur les liens et n'ouvrez pas les pièces jointes d'un message suspect.
- Pour tout message important, vérifiez **indépendamment** : site officiel,
  application officielle, ou numéro connu et fiable.
- Signalez les messages suspects à votre service informatique.

> **Un signe d'alerte est un point de départ pour vérifier, pas une preuve de compromission.**

