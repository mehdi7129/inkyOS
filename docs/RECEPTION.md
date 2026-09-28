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

Deux builds propres de `cf822c9` ont ensuite donné un contenu comparé identique,
avec hashes d'image différents. Les 75 tests passent sur Mac et Linux ARM64.
Les [preuves](validation/2026-09-27-system-prototype.json) distinguent ces
résultats de la qualification matérielle et signalent la CI GitHub non démarrée
à cause d'une limite du compte. Aucun réglage administratif consulté ou modifié.

Une seconde paire propre de `0157714` confirme l'égalité de contenu avec le
manifeste schema 2 : xattrs/ACL, liens physiques et racines sont désormais
inclus. Les images restent différentes octet pour octet ; l'audit des différences
est consigné dans [REPRODUCIBILITY.md](REPRODUCIBILITY.md), les hashes dans la
[preuve v2](validation/2026-09-27-system-prototype-v2.json). La suite compte
maintenant 115 tests, avec résultats Mac et Linux ARM64 conservés.

Le validateur d'entrée du futur payload est opérationnel sans intégration ni
exécution de l'app. Inky Studio a précisé les références des contrats : HTTP
n'a pas de version globale, BLE et helper sont v1. Les références exigent le
commit complet du payload et un chemin source canonique ; les aliases mobiles
et commits incohérents sont refusés. Aucun payload qualifié n'a été livré.

L'[audit Python ARM64](PYTHON-COMPATIBILITY.md) a identifié les wheels natives
`RPi.GPIO` et `spidev` à produire pour la release commune. Résultat transmis à
Inky Studio, sans modification du source applicatif. Les résolutions partielles
et métadonnées PyPI ne constituent pas un lock qualifié.

À la reprise suivante, un [essai natif isolé](NATIVE-WHEELS.md) compile ces deux
dépendances sans réseau pendant le build. Les artefacts rehashés ont été transmis
à Inky Studio, qui prépare le payload/lock commun sur sa propre branche.
Les wheels concordent octet pour octet entre deux builds. Aucun import applicatif,
installation dans l'image ou accès au Pi n'a été réalisé par cette sonde.

Le candidat applicatif `6a697d1` a ensuite passé l'inspection inerte des
archives puis un [banc logiciel offline](OFFLINE-QUALIFICATION.md) distinct :
40 wheels installées dans un venv neuf, editable, pip check, dix imports natifs
et trois réponses API/frontend conformes, sans état applicatif ni lifespan.
Les preuves rehashées sont transmises à Inky Studio pour sa PR #13 ; le
prototype système reste inchangé et sans backend. La suite compte maintenant
143 tests (140 exécutés sur Mac, 142 sur Linux ; skips documentés).

## Démarrage sans LAN et intégration — 28 septembre

l’opérateur demande explicitement le premier boot sans LAN, les contrats heure/pays
et l'intégration dans l'image. Coordination active avec Inky Studio : contrat
commun `4bdaf6b`, lot applicatif d'état/receipt `2c03466`, branches distinctes du
candidat de packaging. Le [suivi premier boot](FIRST-BOOT.md) distingue code
testé, interfaces internes et décisions encore ouvertes. Aucun wire format ou
droit système élargi n'est imposé unilatéralement.

L'intégration expérimentale du candidat `6a697d1` est désormais implémentée :
installation offline au chemin final, fichiers système dérivés du même source,
services masqués et Wi-Fi désactivé avant le futur contrat pays. Le modèle de
reçu OS est testé mais non installé dans l'image. Les preuves d'assemblage
complet sont suivies dans [APPLICATION-IMAGE.md](APPLICATION-IMAGE.md).

Deux builds propres de `1ee27e2` intègrent ce candidat : contenu et métadonnées
comparées identiques, images différentes octet pour octet. Les 62 contrôles
système, 26 contrôles applicatifs et 13 checks de fixture premier boot passent
pour chacun. La [preuve d'image](validation/2026-09-28-application-prototype.json)
ne vaut ni activation applicative ni qualification matérielle.

Le [banc croisé](validation/2026-09-28-factory-contract-cross.json) vérifie 11 cas
entre le reçu OS et le magasin factory applicatif exact `2c03466`, notamment
la perte de DB après consommation du reçu. Le modèle heure/pays/initialisation
reste expérimental, séparé du protocole v1 et de l'image.

Les entrées Desktop ont subi une éviction macOS (`dataless`). Le travail se
poursuit dans un clone local du même dépôt, branche `main`, sous
`~/Library/Caches/inkyos-checkout` ; le checkout Desktop est préservé. Les builds
et preuves complètes ignorés par Git sont dans ce clone. Aucun réglage iCloud
n'a été changé. Les commits continuent à être poussés vers le remote existant.

Le banc Linux `make bootstrap-probe` ajoute 46 checks avec de vrais UID kernel
et un reçu root-owned, sans mutation d'heure/radio. La suite compte 221 tests
Mac/Linux ; [méthode et limites](BOOTSTRAP-PROBE.md) sont conservées.

La dernière annotation CI vérifiée sur le run GitHub `36401860603` indique que
le job n'a pas démarré à cause de paiements récents refusés ou d'une limite de
dépense à augmenter ; sa liste d'étapes est vide. Cette formulation générique
ne permet pas de distinguer paiement, quota et budget exacts. Aucun écran ou
champ de facturation privé lu ou modifié. Les suites Mac/Linux continuent
indépendamment ; cela ne transforme pas la CI GitHub en succès.

La visibilité des dépôts explique pourquoi Inky Studio peut avoir une CI active
au même moment : `inky-studio` est public, `inkyOS` privé (métadonnées GitHub
vérifiées le 28 septembre). Les runners standard publics sont gratuits ; les
dépôts privés dépendent du quota et du budget du propriétaire, selon les
[règles GitHub](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
Aucune visibilité ni configuration de facturation n'a été changée.
