# État d’intégration InkyOS

État au **3 octobre 2026**. InkyOS reste un prototype : le boot système et
l’enrôlement sont observés sur le banc dédié, mais l’écran, le parcours iOS,
le Wi-Fi et la release complète ne sont pas encore qualifiés.

## Périmètre

- **InkyOS** : recette d’image, base OS, premier boot système, intégration du
  payload, qualification SD et récupération.
- **Inky Studio** : backend, iOS, BLE/HTTPS, pilote d’écran, helper réseau et
  mises à jour applicatives. Les contrats partagés sont décrits dans
  [HANDOFF.md](HANDOFF.md) ; aucun fork applicatif n’est maintenu ici.
- Les essais utilisent une SD dédiée. Les images génériques ne doivent
  contenir aucun secret, profil réseau, photo ou identité d’installation.

## Artefacts et préparation vérifiés

Le point de départ de la recette est le commit
`7b40c38768fd826d8b36e07619f40d62cdf982eb`.

Le [plan de construction](BUILD-PLAN.md) conserve la comparaison des builders
upstream et le choix d’une base ARM64 figée. Les inventaires, dépendances,
limites de reproductibilité et tests sont décrits dans
[DEVELOPMENT.md](DEVELOPMENT.md), [REPRODUCIBILITY.md](REPRODUCIBILITY.md)
et les [sources matérielles](HARDWARE-SOURCES.md).

Le candidat applicatif pour les nouveaux builds TEST est épinglé à
`758a2bf7ed099aad41ef35316e53228e797b0b2b`, manifeste
`0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551`.
Cette livraison corrige les métadonnées des panneaux sans changement de
protocole. Le candidat historique `6a697d1` reste réservé à ses audits datés.

La [variante TEST LAN](TEST-LAN.md) conserve app/helper/SSH masqués.
Sa [preuve de préparation](validation/2026-09-30-test-lan-prepared.json)
lie les images, recettes, contrôles statiques et le banc SSH/PAM **39/39**
avec runner inerte. Ce banc ne livre pas un canal d’activation applicative.

L’[image d’enrôlement](TEST-ENROLLMENT.md), construite depuis `2c54070`,
mesure 3 061 841 920 octets et porte le SHA-256
`7a1b70463e5501830f67e9c4b2ffcb69d8970a154115a8e9f8aa2e27eeb9d86e`.
Les contrôles système/app/préparation/enrôlement passent (**62+26+16+16**).
Les [preuves de construction](validation/2026-09-30-test-enrollment.json)
et le [banc de retour négatif](validation/2026-09-30-test-enrollment-return.json)
distinguent tests logiciels, relecture indépendante et observation matérielle.
Cet artefact personnalisé reste local ; il ne constitue pas une image de
redistribution.

## Observations sur le banc

Le banc actif associe un Pi Zero 2 W et une SD Qumox 16 Go, capacité mesurée
**15 938 355 200 octets**. Les essais historiques de l’image diagnostic sont
consignés dans [SD-QUALIFICATION.md](SD-QUALIFICATION.md) ; ils ne qualifient
pas automatiquement l’image d’enrôlement ni les autres modèles de carte.

Le [flash d’enrôlement](validation/2026-10-03-sd-enrollment-flash.json) termine
avec succès dans Imager 2.0.11.1, après vérification observée et éjection.
Une relecture raw indépendante au moment du flash n’est pas revendiquée.
Le démarrage et l’arrêt sont ensuite confirmés par l’opérateur du banc.

L’[acquisition complète et le retour ext4/FAT](validation/2026-10-03-sd-enrollment-return.json)
passent **10 contrôles d’infrastructure et 21/21 contrôles de cohérence**.
Profil, état `enrolled`, rapport, runtime et clé publique hôte correspondent
à l’export attendu. Le fichier de clé privée n’est pas ouvert. Les copies
complètes restent protégées et les montages/loops sont nettoyés.
La [procédure de récupération](SD-RECOVERY.md) distingue acquisition,
comparaison locale et qualification matérielle.

Le [retour physique du diagnostic des sondes](validation/2026-10-03-observer-diagnostic-return.json)
est cohérent sur ses dix contrôles, avec `state_unchanged=true`. La source,
la ligne de boot préparée et l’ancien rapport correspondent aux valeurs
attendues ; `/dev/i2c-1` et `wlan0` sont présents. La sonde écran reçoit
29 octets mais signale `eeprom_unreviewed` après passage des cinq gardes :
le tuple est hors du catalogue accepté, sans modèle de panneau établi.
La réponse firmware radio est valide, avec `country_abbrev` différent de
`FR`, puis `kernel_observation_invalid` laisse indéterminée l’observation
regulatory ou channels en échec. Aucun pays n’est appliqué.

Après ce retour v1, la ligne de boot originale est restaurée et relue en FAT readonly. Les
anciens rapports, la réservation et le script sont conservés. Ce retour
n’inclut pas de nouvelle acquisition ext4. Le complément
[diagnostic v2](../scripts/detail-enrollment-observers.py) est préparé et relu :
les suites ciblées v1/v2 passent **30 tests sur Mac et 30 sur Linux ARM64**.
Il conserve les gardes v1 et les identités, exporte quatre entiers EEPROM
et un booléen de catalogue, puis analyse indépendamment les trois observations
radio issues d’une seule collecte. La
[préparation SD v2](validation/2026-10-03-observer-detail-sd.json) est suivie d'un
boot et d'un arrêt observés, puis du
[retour physique v2](validation/2026-10-03-observer-detail-return.json) :
**10 contrôles de cohérence et cinq gardes réussis**, les deux devices présents.

L'EEPROM déclare **800×480, couleur 4, variante 20** ; le tuple reste non reconnu.
Upstream choisirait le driver AC073TC1A 7,3 pouces sur la variante, mais le code
couleur 4 n'a pas de libellé. L’identification initiale **PIM773 / Spectra 6**
est retirée après examen visuel : le PCB porte **7,3″, 800×480, 170×111 mm**,
ce qui corrobore l’ancienne famille sept couleurs et la variante 20. La référence
exacte de la dalle et le driver physique restent à établir ; le code couleur
4 n’est ni normalisé ni une preuve de corruption. Les rapports historiques
conservent la déclaration initiale ; ce suivi la remplace pour l’identification
actuelle. Voir la [matrice de compatibilité](DISPLAY-COMPATIBILITY.md).
La radio
retourne firmware `XY/XY`, révision 0, global `00` et PHY `99`, header `plain`.
Le parser regulatory réussit ; celui des channels rejette 14 tokens de fréquence
au contrôle d'entier. Aucun pays n'est appliqué ; aucune connexion n'est qualifiée.

La ligne de boot originale est restaurée et relue en FAT readonly ; sept fichiers
des essais sont préservés. La SD reste connectée en lecture seule. Aucun nouveau
contrôle exhaustif ext4 ni lecture de clé privée n'est effectué. Le correctif
de compatibilité du parser avec le suffixe officiel `.0` est livré dans les
sources, **pas installé sur la SD**. Il passe les
[595 tests sur Mac et Linux ARM64](validation/2026-10-03-iw-frequency-parser.json),
avec quatre et un tests ignorés respectivement. Les sorties brutes omises ne permettent pas
d'affirmer que les 14 tokens portaient ce suffixe. Les sources et limites figurent
dans [HARDWARE-SOURCES.md](HARDWARE-SOURCES.md) et
[OBSERVER-DIAGNOSTIC.md](OBSERVER-DIAGNOSTIC.md).

La carte est ensuite [préparée et éjectée pour la comparaison radio v3](validation/2026-10-03-radio-compare-sd.json),
depuis `88782a6` et sa CI verte. Deux nouveaux fichiers FAT permettent de
comparer les parsers sur une collecte unique ; les sondes rootfs et l’identité
ne sont pas modifiées. Les sept artefacts antérieurs restent identiques après
relecture FAT readonly. Le [banc logiciel](validation/2026-10-03-radio-compare-preparation.json)
passe 616 tests sur chacun des deux hôtes et vérifie les sources historiques
exactes avec I/O inertées.

Le [retour v3](validation/2026-10-03-radio-compare-return.json) ne contient ni
claim ni rapport de comparaison. Le script est retrouvé intact sous un nom
`FSCK`, tandis que le parser, les sept anciennes preuves et la ligne de boot
correspondent à la préparation. Le boot et l’arrêt observés ne valident donc
pas l’exécution du diagnostic. Le contrôle FAT readonly passe ; la ligne de
boot normale est restaurée en conservant dix fichiers, dont les deux fichiers
récupérés. Le candidat `INKYCMP.PY` à nom court passe les tests, mais sa
persistance doit être contrôlée après réinsertion avant un nouveau boot.
Ce [fichier est préparé et la carte éjectée](validation/2026-10-03-radio-short-sd.json)
pour une réinsertion au Mac, avec la ligne de boot normale conservée.

Le [contrôle de réinsertion puis l’armement](validation/2026-10-03-radio-short-armed.json)
sont maintenant vérifiés : douze fichiers identiques à la préparation après
retrait/réinsertion au Mac, puis modification de la seule ligne de boot.
Elle lance `INKYCMP.PY`, masque ENROLL et demande l’arrêt automatique.
La relecture FAT readonly contrôle cette ligne et les onze fichiers conservés,
avant éjection.

Le [retour du comparateur à nom court](validation/2026-10-03-radio-short-return.json)
réussit : douze fichiers préparés identiques, nouveau claim et rapport,
quatre pins conformes, dix contrôles et cinq gardes vrais. Sur la même collecte,
l’ancien parser échoue et le corrigé lit quatorze canaux, dont 1–13 annoncés
actifs et 14 désactivé. L’état reste inchangé ; aucun pays ni connexion n’est
qualifié. La ligne de boot originale est restaurée, puis relue en FAT readonly
avec treize fichiers conservés. Aucun nouveau boot de parsing n’est armé.

## Prochaines étapes

Le [runtime opérateur](TEST-ACCESS-RUNTIME.md) est maintenant livré dans les
sources : dispatcher SSH, runner preflight/stop avec activation refusée, et
contrôle TEST du pays distinct de la connexion. Le banc optionnel utilise ces
mêmes sources. Cela ne les installe pas sur la SD et ne fournit pas encore
la transition réseau privée complète.

1. Préparer hors SD un candidat TEST cohérent depuis une image propre :
   correctif radio intégré, [canal opérateur](TEST-OPERATOR.md) réel,
   application et vérification du pays, heure contrôlée et activation bornée.
   Le runtime est testé ; son configurateur privé et la transition vers la
   connexion restent à livrer. Le stop mutateur reste testé avec des fixtures.
2. Coordonner avec Inky Studio le candidat AC073TC1A, le traitement explicite
   de la couleur EEPROM inconnue, un payload épinglé et une version iOS
   Bluetooth installable. Les anciennes références TestFlight ne suffisent pas.
   La coordination du 3 octobre confirme que le candidat actuel peut encore
   basculer vers un écran simulé après une erreur de détection et qu’un timeout
   du driver ne garantit pas un échec remonté. Ces comportements doivent être
   rendus explicites avant de valider un affichage physique. Aucun nouveau
   candidat Bluetooth distribuable n’est confirmé.
3. Regrouper la préparation du prochain essai : profil réseau privé 2,4 GHz,
   confiance SSH liée à l’enrôlement, diagnostics et arrêt. Réutiliser un
   enrôlement uniquement si ses bindings restent valides avec le candidat.
   Une fois l’accès établi, garder la SD dans le Pi pour vérifier à distance
   le preflight, l’activation, l’affichage et une photo LAN, puis tester
   l’adoption QR/BLE depuis la session LAN authentifiée.
4. Éprouver la récupération avant changement Wi-Fi et rollback. Étendre
   ensuite les essais aux autres [formats d’écran](DISPLAY-COMPATIBILITY.md),
   aux modèles de SD et aux redémarrages, puis figer la release applicative.

Ce regroupement vise à réduire les manipulations physiques. Le nombre de
boots restant dépend des résultats ; la qualification de tous les formats
n’est pas un prérequis au premier essai iPhone sur ce banc.

Le bootstrap factory entièrement sans LAN reste un contrat conjoint à livrer.
Le parcours existant qui ouvre une fenêtre QR depuis une session LAN
authentifiée ne valide pas cette première adoption hors réseau.
