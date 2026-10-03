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
radio issues d’une seule collecte. **Il est installé sur la SD de test et la
carte est éjectée, après relecture FAT readonly et CI verte du commit `dcfedeb`.
Son boot et son retour restent à observer ; il n'est pas qualifié matériellement.**
La [preuve SD v2](validation/2026-10-03-observer-detail-sd.json) et les limites figurent dans
[OBSERVER-DIAGNOSTIC.md](OBSERVER-DIAGNOSTIC.md).

## Prochaines étapes

1. Observer le boot du diagnostic v2 sur le banc dédié, récupérer son rapport
   FAT et restaurer la ligne de boot, sans publier d’identifiant.
2. Identifier le panneau et vérifier la compatibilité avec le payload épinglé
   avant tout refresh d’écran.
3. Finaliser le [canal opérateur](TEST-OPERATOR.md), le pays Wi-Fi effectif et
   l’heure vérifiée avant TLS ; le banc SSH actuel utilise un runner inerte.
4. Qualifier photos LAN, adoption QR/BLE, changement Wi-Fi et rollback avec
   une version iOS compatible, puis figer la release applicative.
5. Poursuivre la matrice SD, les redémarrages et la récupération avant toute
   affirmation de qualification complète ou de distribution.

Le bootstrap factory entièrement sans LAN reste un contrat conjoint à livrer.
Le parcours existant qui ouvre une fenêtre QR depuis une session LAN
authentifiée ne valide pas cette première adoption hors réseau.
