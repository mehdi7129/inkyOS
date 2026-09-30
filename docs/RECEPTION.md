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

Le [gate avant NetworkManager](WIFI-BOOT-GATE.md) est implémenté sur fixtures,
sans entrée runtime ni installation. Les 239 tests passent sur Mac/Linux, dont
un oracle du vrai parser GLib sous Linux. Inky Studio a accepté uniquement la
fonction et les fixtures inactives ; l'activation, la tolérance du backend à
l'absence du helper et la fermeture radio réelle restent à qualifier.

Le profil TLS séparé applicatif est poussé dans `a1596a2` (PR #14 draft (`inky-studio/pull/14`)).
Le lot suivant prépare identité avant RTC, réparation du certificat sous la
même clé et coordination avec un adapter OS simulé. Aucun dispatcher bootstrap,
GATT, flow iOS complet ou démarrage sans LAN utilisable n'est déduit de ces lots.
Le payload de l'image reste exactement `6a697d1`, avec services masqués.

Dernière passe : 243 tests Mac/Linux sans échec (4/1 skips), 62 checks du banc
Linux UID/root receipt après ajout de l'inspection readonly, et 20 scénarios
croisés sur les cores applicatifs corrigés `5b5ad6e`. Le reçu n'est plus consommé
si les credentials manquent dès l'entrée. Les preuves conservent séparément
l'ancienne révision et la correction. Aucun de ces lots ne modifie l'image.

Pour obtenir le parcours sans LAN utilisable, restent les raccords runtime :
création OS fiable de l'autorité initiale, IPC de production, opérations d'heure
autorisées et idempotentes, dispatcher/GATT/bootstrap iOS et reconnexion TLS
normale, pays réellement observé et gate actif. Un payload commun qualifié devra
ensuite être épinglé et reconstruit, puis testé sur une SD dédiée. Les composants
actuels sont des fondations testées ; le premier démarrage complet n'est pas
annoncé comme fonctionnel.

Le 28 septembre, à la demande explicite de l’opérateur, `inkyOS` est devenu
public (`private=false`, `visibility=public` vérifiés via l'API GitHub). Une
vérification ciblée des fichiers suivis et des 157 blobs de l'historique n'a
détecté aucun secret réel avec les motifs recherchés ; les URL contenant des
credentials correspondent à des fixtures explicites. Aucun artefact Actions
n'était présent. Cela ne publie aucune image ni release qualifiée et ne change
aucun réglage de facturation. Le prochain push permet de vérifier si les jobs
sur runner standard public démarrent ; les échecs privés précédents restent
des échecs avant exécution, et non des tests réussis.

Le premier push public `2399924` a effectivement déclenché une
CI réussie (`inkyOS/actions/runs/36409574780`) :
243 tests exécutés, aucun échec, 1 skip. Le blocage avant démarrage est donc
levé pour ce run sur runner standard public.

Relais Inky Studio du 28 septembre, fusion vérifiée via GitHub : la
PR #14 (`inky-studio/pull/14`), head testé `5b5ad6e`,
est fusionnée dans `codex/ios-demo-onboarding` au commit
`30aed843c9389f590eae9f78d41bf12423698fe7`. Ce n'est ni un merge dans `main`,
ni une release, ni un déploiement. La suite applicative est suivie dans
#15 (`inky-studio/issues/15`) pour le runtime
first-boot/iOS et #16 (`inky-studio/issues/16`)
pour la qualification physique BLE/Wi-Fi et la release. Le pin applicatif
InkyOS reste `6a697d1` ; aucun raccord runtime supplémentaire n'est annoncé
par cette fusion.

Le 30 septembre, l’opérateur a fourni une SD de test de 128 Go et confirmé le Pi Zero
2 W. Une variante autonome de diagnostic a été construite depuis le parent
applicatif inchangé : app/helper masqués, Wi-Fi désactivé pour cet essai, mises
à jour firmware/APT bloquées, rapport expurgé sur FAT puis demande de poweroff.
305 tests passent sur Mac/Linux et CI ; le vrai FAT sous sandbox systemd est
testé dans la VM. L'image et les contrôles statiques sont décrits dans
[SD-DIAGNOSTIC.md](SD-DIAGNOSTIC.md).

La SD a été écrite avec succès et éjectée par Raspberry Pi Imager 2.0.6 après
un refus macOS de l'ouverture raw en CLI avant écriture. La preuve distingue
succès affiché par Imager et absence de relecture raw indépendante. Aucun boot
du Raspberry, refresh du panneau ou scénario iPhone n'a été exécuté. Le prochain
geste matériel appartient à l’opérateur : Pi hors tension, démarrer sur cette SD de
test puis, après arrêt propre, la remettre dans le Mac pour lire le rapport.
La SD personnelle reste intacte et la VM de build est arrêtée.

Après cet essai, l’opérateur a confirmé l'arrêt du Pi et remis la SD dans le Mac.
Le [premier rapport physique](validation/2026-09-30-sd-first-boot.json) confirme
le boot du Pi Zero 2 W en ARM64, firstboot/resize/growfs réussis, identité
système cohérente et 117,60 Go décimaux disponibles sur ext4. Les tailles de
partitions ont aussi été relevées en lecture seule sur le Mac. Les services
attendus sont actifs ou masqués selon la variante ; app/helper restent inactifs.
L'arrêt est confirmé par l'utilisateur et non par ce snapshot écrit avant
poweroff. Redémarrage, comparaison A/B, écran, adoption et Wi-Fi restent ouverts.

l’opérateur a trouvé une SD plus adaptée et souhaite l'utiliser ensuite. Conserver
la preuve de cette première carte, puis préparer la nouvelle depuis l'image
vierge : ne pas cloner la carte initialisée avec son identité. La nouvelle
carte n'est pas encore identifiée ni flashée. Aucun changement du cadre
personnel ou du protocole applicatif n'a été effectué.

Relais Inky Studio confirmé ensuite le 30 septembre : la branche
`codex/ios-demo-onboarding` reste à `30aed843`, sans nouveau pin qualifié.
Coordinator non importé au démarrage, dispatcher/bootstrap GATT, credentials
durables et flow iPhone sans LAN restent à intégrer dans l'issue #15. Les
raccords OS attendus sont inspect/begin privilégiés avec reçu root durable,
rôles UID séparés et NetworkManager démarré radio fermée jusqu'au pays vérifié.
Le protocole réseau v1 actuel n'accepte pas heure/pays ; aucun élargissement
local n'est réalisé. Le comparateur de rapports SD prépare les prochains
essais d'identité en attendant ces raccords et la nouvelle carte.

l’opérateur précise ensuite la carte prévue : **Qumox 16 Go**, référence détaillée
non fournie. L'image actuelle mesure 3061841920 octets. Capacité réelle et média
cible restent à vérifier à son insertion ; aucune qualification de cette carte
n'est déduite de sa capacité nominale et elle n'est pas encore flashée.

Le comparateur de rapports est livré avec 19 tests dédiés. La suite de 324
tests passe sur Mac/Linux ARM64 ; le même rapport physique comparé à lui-même
est refusé comme attendu (boot identique), sans publier d'empreinte d'identité.
Les [sources et résultats](validation/2026-09-30-sd-report-comparison.json)
sont épinglés. Le rapport de la première carte est conservé localement ; la
SD de 128 Go a été éjectée proprement du Mac, sans réécriture, pour permettre
l'insertion ultérieure de la Qumox. Aucun média SD n'était détecté lors du
dernier relevé après cette éjection ; aucun flash de la Qumox n'a été lancé.

l’opérateur a ensuite inséré la Qumox. Le Mac détecte une seule SD physique amovible
de 15938355200 octets, inscriptible, compatible avec la taille de l'image vierge
épinglée. Imager a été lancé sur ce média. La vérification à 31 %, l'écran
« Écriture terminée » et l'éjection sont observés ; une erreur d'ouverture de
`/dev/rdisk6` est également apparue. L'UI a changé sous intervention utilisateur
avant l'action suivante de l'automatisation. La
[preuve d'observation](validation/2026-09-30-sd-qumox-flash-observation.json)
conserve cette contradiction : flash non accepté avant clarification/vérification,
aucun boot de cette carte effectué. Aucun réglage de confidentialité ou accès
complet au disque n'a été modifié.

l’opérateur confirme avoir seulement fermé l'erreur, sans relance manuelle. La
séquence est compatible avec le bug upstream Imager #1511 ; sa causalité
exacte reste non prouvée. Le correctif est présent dans la copie officielle
2.0.11.1 préparée localement, dont DMG, signature Raspberry Pi et notarization
sont vérifiés. Cette session a sélectionné le même artefact vierge ; elle
attend la réinsertion physique de la Qumox, car aucun média SD n'est détecté.
Le flash précédent reste non accepté ; aucune modification des réglages Mac
ni remplacement de l'app installée n'a été effectué.

l’opérateur a réinséré la Qumox. La nouvelle session 2.0.11.1 confirme une seule SD
physique amovible de 15938355200 octets ; une seule écriture du même artefact
vierge est lancée. Écriture à 77 %, fin sans erreur et éjection automatique
sont observées ; le device a disparu côté Mac. Le
[retry propre](validation/2026-09-30-sd-qumox-clean-flash.json) est accepté
pour l'essai suivant. La progression de vérification n'a pas été capturée :
défaut GUI activé dans la source exacte, aucune action de skip, aucune
relecture raw indépendante revendiquée. Le premier essai reste consigné
comme ambigu. La Qumox attend son premier boot réel, puis comparaison A/B et
second boot manuel pour la stabilité de l'identité. App/helper toujours masqués.

La Qumox a ensuite été démarrée : l’opérateur acquitte les étapes, et un rapport
physique est récupéré à son retour dans le Mac. Firstboot/resize/growfs sont
réussis, identité système cohérente, 11,89 Go décimaux libres sur ext4 et
services attendus observés. La
[preuve réduite](validation/2026-09-30-sd-qumox-first-boot.json) sépare snapshot,
métadonnées Mac et acquittement utilisateur ; elle ne déduit pas l'arrêt
effectif du JSON écrit avant poweroff.

Le comparateur `different-cards` passe sur les deux premiers rapports :
machine-id et hostname sont distincts, cohérents sur chaque SD, sans publier
leurs empreintes. S01/S02/S04 sont observés dans leur portée système initiale ;
persistance S05, série de reboots et qualification complète restent ouverts.
Prochain geste : un nouveau boot de la même Qumox, sans reflash, puis rapport
et comparaison `same-card`. La SD A doit aussi être redémarrée. Aucun refresh
du panneau, parcours iPhone ou transaction Wi-Fi n'a été exécuté.
