# Compatibilité des écrans

Périmètre retenu le **3 octobre 2026** : une même recette InkyOS pour les trois
formats **Spectra 6** et les anciens **Impression sept couleurs**. La détection
et le rendu appartiennent à Inky Studio ; l’image intègre son payload épinglé.
**Aucun modèle n’est encore qualifié de bout en bout avec InkyOS et l’app iOS.**

## Matrice cible

Les variantes ci-dessous sont celles du catalogue Pimoroni. Elles indiquent
un choix logiciel possible, pas une identification certaine d’une dalle montée.

| Famille | Format / SKU constructeur | Résolution native | Variante EEPROM | Module Python `inky` | Version examinée |
|---|---|---|---|---|---|
| Spectra 6, six couleurs | 4″ / PIM789 | 600 × 400 | 25 | `inky_e640` | 2.3.0 et 2.4.0 |
| Spectra 6, six couleurs | 7,3″ / PIM773 | 800 × 480 | 22 ; 26 pour AC | `inky_e673` | 22 : 2.3.0/2.4.0 ; 26 : 2.4.0 |
| Spectra 6, six couleurs | 13,3″ / PIM774 | 1600 × 1200 | 21 ; 27 pour AC | `inky_el133uf1` | 21 : 2.3.0/2.4.0 ; 27 : 2.4.0 |
| Gallery Palette, sept couleurs | 5,7″ / PIM534 | 600 × 448 | 14 | `inky_uc8159` | 2.3.0 et 2.4.0 |
| Gallery Palette, sept couleurs | 7,3″ / PIM667 | 800 × 480 | 20 | `inky_ac073tc1a` | 2.3.0 et 2.4.0 |

Sources constructeur : [gamme Spectra 6](https://shop.pimoroni.com/products/inky-impression),
[ancien 5,7″](https://shop.pimoroni.com/products/inky-impression-5-7),
[référence produit 5,7″](https://shop.pimoroni.com/products/inky-impression-5-7.js),
[ancienne table 7,3″](https://shop.pimoroni.com/products/inky-impression-7-3?variant=55186435211643).
Correspondances logicielles : [auto.py 2.3.0](https://github.com/pimoroni/inky/blob/v2.3.0/inky/auto.py),
[auto.py 2.4.0](https://github.com/pimoroni/inky/blob/v2.4.0/inky/auto.py),
[variantes EEPROM 2.4.0](https://github.com/pimoroni/inky/blob/v2.4.0/inky/eeprom.py).
Les fiches marchandes évoluent ; le SKU et la diagonale ne déterminent pas
à eux seuls la révision de waveform. La matrice ne couvre pas tous les autres
panneaux que la bibliothèque upstream peut piloter.

## Identification du banc

Le PCB examiné porte **Inky Impression 7.3″, 800×480, 170×111 mm overall,
160×96 mm active**. Ces dimensions et son dessin corroborent l’ancienne
famille Gallery Palette/PIM667. C’est une inférence visuelle, cohérente avec
la variante EEPROM 20, sans référence complète de dalle confirmée.
Le [guide officiel](https://learn.pimoroni.com/article/getting-started-with-inky-impression)
distingue les modèles portant le marquage Spectra de l’ancienne génération.

L’identification initiale PIM773/Spectra 6 est retirée. Le lien produit 5,7″
concerne un écran 600×448 ; il ne reclassifie pas le PCB 7,3″ photographié.
Les deux formats sept couleurs figurent donc séparément dans la cible.
Les photographies et leurs métadonnées restent privées ; seuls ces constats
techniques sont consignés ici.

Le [retour physique v2](validation/2026-10-03-observer-detail-return.json)
reste inchangé : **800×480, couleur 4, variante 20**. Il conserve aussi la
référence initialement déclarée ; le présent suivi actualise son interprétation.
Le driver candidat upstream est AC073TC1A, mais le code couleur 4 n’a pas de
libellé dans les tables examinées. Cette absence ne démontre ni corruption
ni équivalence avec le code 5. L’erreur `eeprom_unreviewed` reste valable ;
aucune réécriture EEPROM, activation ou qualification n’en découle.

## Écart avec les sources InkyOS actuelles

- Le payload candidat utilise encore **`inky==2.3.0`**. Le diagnostic accepte
  quatre tuples exacts : les variantes 20, 21, 22 et 25 avec dimensions et
  couleur attendues. Il ne reconnaît pas encore 14, 26, 27 ni le code couleur 4.
- Le catalogue est répété dans l’observateur, le preflight et le runtime
  d’enrôlement. Leur évolution doit rester cohérente avec les validateurs,
  les tests et les hashes des diagnostics qui les chargent.
- Le preflight exige `inky-2.3.0.dist-info`. Recevoir un payload 2.4.0 demande
  aussi de revoir ce contrôle ; changer seulement le manifeste ne suffit pas.
- La version 2.4.0 est une **candidate à évaluer avec Inky Studio** pour les
  révisions AC. Elle modifie aussi des séquences de commande E673/EL133UF1 :
  elle ne constitue pas une simple extension d’identifiants. Aucun upgrade de
  dépendance ou changement de catalogue n’est livré par ce document.

Voir [observe-test-panel.py](../scripts/observe-test-panel.py),
[test-lan-preflight.py](../scripts/test-lan-preflight.py) et
[test-enrollment-firstboot.py](../scripts/test-enrollment-firstboot.py).
Les données du manifeste applicatif n’imposent pas de résolution d’écran.

## Réalisation et critères de qualification

1. **Inky Studio** : vérifier autodétection et révisions AC, palettes six/sept
   couleurs, dimensions et rotation, crop/preview iOS, écran de bienvenue et QR.
   Aucun driver ne doit être choisi sur la seule résolution 800×480, commune
   aux deux familles. Définir explicitement le traitement d’une déclaration
   EEPROM inconnue ; un fallback mock ne doit pas valider le matériel.
2. **InkyOS** : recevoir ce candidat et ses dépendances figées, aligner les
   catalogues/validateurs et leurs tests, puis reconstruire une image vierge
   avec les pins cohérents. Intégrer aussi le correctif radio déjà testé.
   Préserver les images et rapports historiques comme preuves datées.
3. **Banc par modèle et révision** : relever la classe réellement sélectionnée,
   vérifier mire et palette, orientations, refreshs consécutifs, retour d’erreur,
   redémarrage et premier appairage iOS. Mesurer latence, alimentation et mémoire
   sur Zero 2 W, en particulier pour le 13,3″ ; ne pas extrapoler le résultat
   d’un petit écran au grand format.
4. **Publication** : ne marquer une ligne « qualifiée » qu’avec son couple
   Pi/panneau, versions OS/kernel/firmware/app/driver, image et preuves de banc.
   Les modèles non essayés gardent un statut expérimental même si les tests
   logiciels passent. La release finale est ensuite épinglée dans l’image.

La qualification commence par le panneau actuellement observé. Les autres
formats suivent avec le même socle OS et une SD de test dédiée ; une nouvelle
taille ne justifie pas un fork de l’application ou du protocole.
