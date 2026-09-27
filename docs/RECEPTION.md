# Réception du relais Inky Studio

Reçu le **27 septembre 2026** dans `inkyOS`.
Point de départ vérifié : `main`, commit
`7b40c38768fd826d8b36e07619f40d62cdf982eb`, arbre de travail propre à réception.

## Périmètre reçu

- **InkyOS** : recette reproductible, base OS, intégration du premier boot
  système, qualification sur SD dédiée, maintenance et récupération OS.
- **Session Inky Studio** : iOS/backend/BLE, protocole, conformité chiffrement,
  TestFlight et tests applicatifs sur le cadre. Aucun fork applicatif dans InkyOS.
- Aucune action sur le cadre personnel ou sa SD. Aucun secret, photo, identité
  personnelle ou document administratif nécessaire à cette étude.

L'accusé de réception a été envoyé à la session
`session de coordination privee` avec l'outil inter-session.
Cette session a répondu et confirmé la réception le même jour ; elle annonce
ne plus modifier ce dépôt. Préserver néanmoins les modifications concurrentes.

## Ce qui est établi, et ce qui ne l'est pas

`README.md`, `HANDOFF.md` et `HARDWARE-SOURCES.md` ont été lus. Leur distinction
entre tests effectués et qualification restante est conservée.

L'état backend `0.5.0-rc.2` / `ae61df1`, TestFlight build 3 disponible, build 4
bloqué par conformité et PR #11 draft est **transmis par Inky Studio** ; cette
session n'a ni interrogé ni requalifié le Pi ou TestFlight. Le statut applicatif
doit être reconfirmé avant de figer un payload.

Le QR initial exige encore une session LAN authentifiée. L'image ne peut donc
pas, à elle seule, rendre possible la première adoption sans réseau. L'heure
TLS, le pays Wi-Fi et la récupération physique restent des contrats conjoints.
Le modèle exact du panneau reste à confirmer.

L'historique local Inky a été consulté de façon ciblée : il confirme l'intention
local-first, mais ses anciens libellés d'écran ne remplacent pas l'identification
physique demandée dans le dossier actuel.

## Livrable de cette reprise

Le [plan de réalisation](BUILD-PLAN.md) compare les builders upstream, propose
la base et l'environnement, décrit une recette minimale et ses critères de
qualification. Il sépare les propositions des décisions déjà validées.

À réception : aucune image construite, aucun premier boot ni flash effectué.
Depuis, un prototype système a été assemblé (avancement ci-dessous).
L'intégration d'une image complète attend une release applicative qualifiée
et épinglée.

## Informations à obtenir pour l'exécution

1. Environnement Linux ARM64 : VM Debian sur le Mac maintenant vérifiée pour
   loop/montages/chroot ; qualification de l'image Pi intégrée encore à faire.
2. Inventaire du Pi/panneau de test et de deux SD dédiées, distinctes de la SD
   personnelle ; référence du panneau et EEPROM à fournir par le banc matériel.
3. Release Inky Studio qualifiée : commit complet, asset, SHA-256, lock des
   dépendances, versions app/helper compatibles et compte-rendu iPhone/Pi.
4. Accord technique avec Inky Studio sur l'API d'initialisation hors ligne,
   l'heure vérifiée, le pays Wi-Fi, la récupération physique et le packaging.

Ces points conditionnent les étapes qui en dépendent ; ils n'empêchent pas la
comparaison des outils et la préparation de la recette.

## Seconde lecture demandée par l’opérateur

Le 27 septembre, l’opérateur demande de privilégier la simplicité et de réexaminer
les décisions avant implémentation. Le remote privé `inkyOS`, branche
`main` à `7b40c38…`, a été revérifié via Git et GitHub. Depuis, l’opérateur a autorisé
la poursuite, les tests et des pushes réguliers ; le socle a été poussé dans
`853ed87`, puis premier boot/delta packages/contrats dans `324231b`.

Le plan place désormais l'image officielle Lite datée + personnalisation offline
comme première option à éprouver ; pi-gen reste le recours si les adaptations
mesurées le justifient. La VM Linux dédiée évite de présumer un achat de matériel.
Lima 2.2.0 et Colima 0.10.3 sont présents, sans preuve de build à ce stade.

l’opérateur confirme ne pas avoir de SD de test disponible actuellement ; sa carte est
déjà dans son Raspberry Pi. La conserver intacte : aucun flash, reconfiguration
ou essai de coupure InkyOS sur cette installation. La préparation et les builds
sur le Mac/VM peuvent avancer ; les essais matériels restent différés jusqu'à
disponibilité d'une SD dédiée et du banc convenu. Ne pas assimiler les contrôles
offline à une qualification physique.

## Premier avancement exécuté

À la suite du « oui avançons » de l’opérateur, création de la VM isolée `inkyos-build`,
acquisition vérifiée d'une image Lite ARM64 datée et développement de l'outillage
d'inspection. `make inspect` fonctionne de bout en bout ; les tests locaux et
les contrôles Linux sont passés. Voir [DEVELOPMENT.md](DEVELOPMENT.md).

La base contient déjà la majeure partie des dépendances système ; le delta
comprend notamment `python3-dbus` et l'adaptation du premier boot cloud-init.
Aucune intégration app, génération d'identité du cadre, modification du protocole
ou qualification matérielle n'est déduite de ce résultat.

## Prototype système assemblé

Le premier `make prototype` réussit dans la VM : package ajouté offline,
renommage du compte verrouillé, retrait des privilèges généraux, adaptation du
boot, gate statique et vérification systemd. L'image reste sans application.
Les rapports et limites sont suivis dans [DEVELOPMENT.md](DEVELOPMENT.md).

Inky Studio a relu [APPLICATION-PAYLOAD.md](APPLICATION-PAYLOAD.md) et accepté
la direction de packaging proposée ; aucun payload qualifié n'est encore livré.
La session poursuit ses travaux iOS sans changement backend/protocole prévu.
Les contrats première adoption/heure/pays et les essais SD dédiés restent ouverts.
