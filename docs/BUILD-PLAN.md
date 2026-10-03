# InkyOS — plan de réalisation de l'image

Étude du **27 septembre 2026**, suivie d'une inspection puis d'un assemblage
du prototype système. La base officielle et le delta `.deb` sont figés ;
**aucune image avec l'application ni test SD**. Voir les
[outils et résultats exécutés](DEVELOPMENT.md).
Les acquis applicatifs restent ceux du [HANDOFF](HANDOFF.md) ; aucune release
applicative finale n'est sélectionnée ici.

## 1. Réexamen : éprouver la solution la plus simple

Après seconde lecture du plan le 27 septembre : **le choix de
pi-gen n'est pas figé**. L'option prioritaire à éprouver est une **image officielle
Raspberry Pi OS Lite ARM64 datée et conservée avec son SHA-256, personnalisée
hors ligne sur une copie**. La cible initiale reste le Pi Zero 2 W, avec le panneau
à identifier. Une base binaire figée évite de reconstruire toute la distribution
et de conserver séparément tous ses packages avant d'avoir validé le produit.

Raspberry Pi fournit image Lite, checksum, archives et SBOM. La version courante
consultée, datée du 15 septembre 2026, annonce toutefois un kernel 6.18 ; le banc
transmis utilise 6.12.75. L'image du 15 septembre est désormais épinglée dans
`config/base-image.lock.json` et ses hashes compressé/décompressé ont été
vérifiés. Elle constitue la **base expérimentale**, sans qualification du cadre.
[Téléchargements officiels](https://www.raspberrypi.com/software/operating-systems/).

Premier essai technique proposé : inspecter une image datée sans la démarrer,
mesurer le delta packages/configuration/premier boot, puis vérifier que ce delta
est rejouable sur une copie. Conserver les `.deb` ajoutés et leurs dépendances,
ainsi que les wheels ; éviter un upgrade général qui ferait dériver la base.
Si cela exige trop d'adaptations fragiles, revenir à **pi-gen ARM64/Trixie,
stages Lite 0–2**. `rpi-image-gen` reste documenté pour un besoin d'assemblage
plus spécifique. Ne développer qu'une seule chaîne après ce premier essai.

L'environnement à éprouver en premier est une **VM Debian ARM64 dédiée sur le
Mac Apple Silicon**, avec disque Linux interne. Lima 2.2.0 est installé ; son
backend VZ et ses guests Debian sont documentés. Cette virtualisation de même
architecture est désormais testée : root, loop devices, montages FAT/ext4 et
chroot ARM64 passent. Cela ne qualifie pas une image Pi intégrée.
Ne pas réutiliser ni modifier les VM d'autres projets. Aucun achat de Pi 5 n'est
nécessaire à ce stade. Un hôte physique ARM64 reste une solution de repli.
[Lima : guests](https://lima-vm.io/docs/faq/),
[virtualisation](https://lima-vm.io/docs/config/vmtype/).

Le Mac disposait d'environ 50 Gio libres avant l'essai. La VM `inkyos-build`
a été créée avec 2 CPU, 3 Gio de RAM et un disque sparse limité à 16 Gio. Les
copies transitoires de l'image dans la VM sont supprimées après inspection.

ARM64 est un choix de travail : le Zero 2 W possède un CPU 64 bits mais seulement
512 Mo de RAM. Le kernel `rpi-v8` constaté ne prouve pas à lui seul l'architecture
du userland du banc. Mesurer la mémoire réelle et vérifier les wheels Python ;
ne pas annoncer un gain par rapport à ARM32 sans comparaison.
[Fiche officielle Zero 2 W](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/).

## 2. Comparaison des builders étudiés

Cette comparaison reste utile si l'image officielle personnalisée ne suffit
pas. Elle ne rend pas obligatoire la reconstruction complète pour v0.

Références de l'étude :

- **pi-gen ARM64** : `74d08a337bd29da289b9aedbe5b48c79fb2e5a03`, référence
  `arm64` résolue le 27 septembre. Le SHA `6a0419c1…` du dossier initial est la
  référence `master` **32 bits**, pas le pin à utiliser pour le candidat ARM64.
  [README ARM64](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/README.md).
- **rpi-image-gen** : `bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1`, référence du
  dossier initial, relue pour cette comparaison.
  [README](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/README.adoc).

| Critère | pi-gen ARM64 | rpi-image-gen |
|---|---|---|
| Assemblage | Stages de la distribution Raspberry Pi OS ; Lite jusqu'à stage2. | Suites, device layers, packages, overlays et hooks composables. |
| Hôte documenté | Debian ; chemin natif pris en charge. Docker réclame des privilèges et des loop devices. | Debian Bookworm/Trixie ARM64 natif ; QEMU/conteneurs hors chemin officiellement pris en charge. |
| Zero 2 W | Kernel `rpi-v8` dans la base, avec d'autres kernels qu'il faudra inventorier. | Device explicite `rpizero2w`, dépendant de `rpi-generic64` et `rpi-linux-v8`. |
| Réseau/BLE | Lite inclut NetworkManager, BlueZ et Avahi. | Layers dédiées à sélectionner ; le quickstart `trixie-minbase` utilise networkd/iwd. |
| Premier boot | Wizard utilisateur/cloud-init à adapter pour une appliance sans login partagé. | Contrôle plus direct, mais comptes, réseau et politique de boot restent à définir. |
| Reproductibilité | APT roulant et upgrade final : pin Git insuffisant. | Snapshots Debian possibles selon la suite ; dépôt Raspberry Pi et autres entrées à figer aussi. |
| Inventaires | `.info`, SBOM SPDX si outil présent ; compléter pour app/Python. | Artefacts d'inventaire/SBOM ; compléter aussi pour les composants ajoutés. |

Sources pi-gen : [paquets Lite](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/stage2/01-sys-tweaks/00-packages),
[kernel/firmware](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/stage0/02-firmware/01-packages),
[Docker](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/build-docker.sh),
[export final](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/export-image/05-finalise/01-run.sh).

Un fichier shell compatible avec le Bash de macOS ne prouve pas qu'un build
Docker Desktop est pris en charge. Les builders nécessitent des opérations
privilégiées Linux ; utiliser un environnement dédié, sans données personnelles.

Avec rpi-image-gen, `image-rpios` désigne un **layout de disque**, pas la garantie
d'obtenir Raspberry Pi OS Lite à l'identique. Le quickstart Pi 5 ne doit pas être
copié comme recette Zero 2 W. Une archive rootfs sans kernel/device n'est pas une
image bootable. Les layers et suites exactes sont des entrées du manifeste.

L'alternative appliance se composerait avec `rpizero2w`, `image-rpios`,
`debian-trixie-arm64-minbase-snapshot`, `network-manager`, `bluez` et une layer
InkyOS externe via `-S`. Cette composition n'a pas été exécutée. Le snapshot
Debian dépend de `SOURCE_DATE_EPOCH` ; il faut aussi verrouiller le dépôt Pi.
Le hostname aléatoire par défaut est généré **au build** : tous les clones le
partageraient. Le manifeste upstream utilise SHA-1 pour ses artefacts ; ajouter
des SHA-256 et épingler l'outil SBOM dans notre environnement.

Sources rpi-image-gen : [device Zero 2 W](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/device/zero2w/device.yaml),
[layout](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/image/mbr/simple_dual/image.yaml),
[suite minbase](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/layer/suite/debian/trixie-minbase.yaml),
[CI slim](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/config/ci/arm64-rpi-trixie-slim.yaml),
[snapshot](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/layer/debian/trixie/arm64/base-minbase-snapshot.yaml),
[NetworkManager](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/layer/net-misc/network-manager.yaml),
[BlueZ](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/layer/net-wireless/bluez.yaml),
[hostname](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/layer/base/device-base.yaml),
[manifest](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/builtin/hooks/deploy99-manifest).

## 3. Écarts à résoudre avant assemblage

### Base et services système — particularités du recours pi-gen

Pour pi-gen, le stage InkyOS seul ne suffit pas : les étapes d'export exécutées
ensuite doivent être incluses dans la recette auditée.

- Ne pas fournir de mot de passe Linux partagé. Sans `FIRST_USER_PASS`, le compte
  est verrouillé, mais l'export arme encore `rename-user`. Le simple réglage
  `DISABLE_FIRST_BOOT_USER_RENAME=1` exige un password dans `build.sh`.
  Adapter explicitement cette étape, sans mot de passe de contournement.
  [Validation de configuration](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/build.sh),
  [rename-user](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/export-image/01-user-rename/01-run.sh).
- `ENABLE_CLOUD_INIT=0` ne saute pas l'installation des packages du sous-stage
  `stage2/04-cloud-init`. Exclure réellement ce sous-stage si le premier boot
  appartient à InkyOS ; vérifier aussi l'absence d'un wizard concurrent.
  [Paquets](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/stage2/04-cloud-init/00-packages),
  [script conditionnel](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/stage2/04-cloud-init/01-run.sh).
- L'export relance `apt update` et `dist-upgrade`. Figer ses sources aussi ;
  vérifier la liste des paquets après export, pas seulement à la sortie du stage.
  [Étape APT finale](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/export-image/02-set-sources/01-run.sh).
- Le [bootstrap stage0](https://github.com/RPi-Distro/pi-gen/blob/74d08a337bd29da289b9aedbe5b48c79fb2e5a03/stage0/prerun.sh)
  pointe aussi directement vers `deb.debian.org` : le figer avant la création
  du rootfs, en plus des sources APT installées et de l'export final.
- Exclure l'export intermédiaire stage2 avec `SKIP_IMAGES` et exporter seulement
  le stage InkyOS final. Une image Lite sans payload ne doit pas être confondue
  avec le candidat InkyOS.
- Garder SSH désactivé initialement ; définir séparément le support avancé par
  clé individuelle. Auditer les droits sudo du compte app créé : les droits
  généraux d'administration ne sont pas requis. Préserver en revanche la règle
  limitée au start/stop/restart du service fournie par `install.sh`, utilisée par
  l'updater et la CLI.

### Payload applicatif commun

Lecture du dépôt `inky-studio` au commit `ae61df1c0f01408861ccb1210ec85986768d6784` :

| Constat du code | Conséquence pour la recette |
|---|---|
| `install.sh` lance apt, choisit une release mouvante, peut récupérer `main`, démarre des services et peut rebooter. | Ne pas l'exécuter dans un build d'image ; extraire un packaging offline commun ou vérifier une adaptation explicite avec Inky Studio. |
| Python laisse la plupart des dépendances et `hatchling` non figés ; seul le pin driver ne suffit pas. | Lock transitif et wheelhouse ARM64/Python correspondant, hashes inclus ; aucune résolution Internet au premier boot. |
| `client/dist` et l'updater dépendent de la disposition du source. | Conserver `server`, `client/dist`, `shared`, `scripts` et le venv avec installation editable au chemin final ; une wheel applicative seule n'est pas équivalente. |
| L'updater écrit dans le payload et le venv. | Compte app non-root propriétaire de ces chemins ; helper/polkit/unités root-owned, séparés. Un rootfs applicatif read-only demande une évolution upstream. |
| Le défaut Python des données est `server/data` ; l'unité fixe `/var/lib/inky-studio`. | Définir `INKY_STUDIO_DATA_DIR` de façon cohérente pour service, CLI et contrôles. |
| Le helper utilise Python système et D-Bus, avec NetworkManager requis. | Inclure explicitement `python3-dbus`, BlueZ, NetworkManager, rfkill et outils systemd nécessaires ; vérifier IPC/polkit. |

Sources : `inky-studio/install.sh` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`),
`inky-studio/scripts/install-bluetooth.sh` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`),
`inky-studio/server/pyproject.toml` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`),
`inky-studio/server/inky_web/services/updater.py` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`),
`inky-studio/server/inky_web/db.py` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`).

Proposition de layout : compte de service `inky`, login verrouillé,
`/home/inky/inky-studio` pour le payload/venv et `/var/lib/inky-studio` pour les
données. Le nom de compte reste propre à l'image, sans imposer ce choix à
l'installateur classique. Préserver la CLI `/usr/local/bin/inky-studio`, les noms
de services, les chemins du helper et leurs permissions du HANDOFF. Vérifier
explicitement les groupes/udev `spi`, `i2c`, `gpio` et `inky-provisioning`.

## 4. Recette minimale proposée et preuves attendues

Cette séquence est désormais exécutée jusqu'au **prototype système sans app**
avec `make prototype` ; `make inspect` reste l'inspection de la base seule.
Le delta APT est épinglé et installé offline. Payload/wheelhouse Python et
qualification matérielle restent à fournir. Les pins builder ci-dessus sont
des références d'étude ; les adaptations de stages/export ne s'appliquent que
si pi-gen devient nécessaire. Les résultats et limites de reproductibilité
sont consignés dans [DEVELOPMENT.md](DEVELOPMENT.md).

| Étape | Travail prévu | Vérification avant la suite |
|---|---|---|
| A. Préparer les entrées | Image officielle Lite datée, URL et SHA-256 vérifiés, archive/inventaire conservés ; recette InkyOS et environnement versionnés. | Base générique authentifiée par la source officielle ; aucun fichier de SD personnelle. |
| B. Figer les composants ajoutés | Delta `.deb` avec dépendances et origine vérifiée ; asset app qualifié et wheelhouse hashés. | Pas de résolution mouvante ; le delta ne remplace pas implicitement kernel/Python ou une grande partie de la base. |
| C. Préparer une copie Lite | Monter et personnaliser une copie de l'image dans Linux ; inspecter et adapter wizard/cloud-init/premier boot de cette image exacte. | Inventaire packages, ARM64, kernel/firmware/overlays ; conservation des partitions et aucune activation runtime au build. |
| D. Intégrer InkyOS | Comptes, permissions, NetworkManager/BlueZ/Avahi, SPI/I²C, payload complet et venv avec installation editable à son chemin final, dépendances issues du wheelhouse. | Équivalence aux unités/CLI/helper de la release épinglée ; propriétaire unique de SPI. |
| E. Préparer le boot | Installer et activer les unités sans les démarrer ; pas de création d'identité applicative au build. | Ordre des unités, reprise après erreur, absence d'attente réseau pour l'onboarding. |
| F. Exporter et inspecter | Finalisation, nettoyage des identités et des états, démontage propre ; image puis compression. | Inspection après la dernière modification, scan des fichiers interdits, hashes image/archive. |
| G. Rejouer | Deux builds propres des mêmes entrées ; cache conservé seulement s'il est identifié par contenu. | Comparaison packages, fichiers, modes/owners, services, image ; chaque divergence expliquée. |
| H. Qualifier | Seulement ensuite, SD dédiées et release app compatible avec l'adoption initiale. | Matrice de la section 7, aucune action sur la SD personnelle. |

Le build cible ne doit lancer ni le backend, ni un test ASGI avec lifespan, ni
un refresh. Les smoke tests qui créent DB/credentials/identités se font sur une
copie jetable. Précompiler l'UI avant intégration ; aucun Node/npm au premier boot.
Ne pas reprendre l'auto-réglage du swap depuis la RAM de l'hôte de build : la
cible est le Zero 2 W, quelle que soit la puissance du builder.

Si l'essai impose pi-gen, remplacer A–C par checkout ARM64 épinglé, sources de
bootstrap/APT conservées et stages 0–2 + InkyOS ; appliquer les adaptations
d'export de la section 3. Les contrôles D–H restent communs.

Une extension OS minimale pourra être étudiée avant la release app, mais elle
restera un prototype système sans statut d'installateur autonome Inky Studio.

## 5. Ce que « reproductible » doit signifier ici

Une même suite Debian et un SHA Git ne figent ni APT, ni pip, ni le firmware.
Avec l'option image officielle, la promesse est d'abord **un assemblage rejouable
depuis une base binaire conservée**, pas la reconstruction de cette base depuis
ses sources. Son SHA-256 et son inventaire font partie des entrées. On conserve
séparément tous les composants ajoutés ou remplacés.

Si on reconstruit la base avec un builder, il faut figer l'ensemble des paquets.
Le [service officiel Debian Snapshot](https://snapshot.debian.org/) permet de
retrouver des états datés de Debian ; il ne fournit pas automatiquement un
snapshot du dépôt Raspberry Pi. Conserver les deux ensembles de paquets et leurs
preuves d'origine. Un proxy/cache APT seul n'est pas un lock.

Le manifeste devra contenir :

- version/commit de la recette et environnement ; image source, URL, SHA-256
  et inventaire, ou builder/patches si reconstruction ;
- suites, architectures, inventaire complet et versions ; sources/index APT
  et SHA-256 des `.deb` ajoutés, ou de tous les paquets si reconstruction ;
- kernel, modules, firmware, DTB, overlays et configuration boot ;
- app : release, commit, URL exacte et SHA-256 de l'asset ; helper et ABI/versions
  compatibles ; Python, outil de build et dépendances transitives hashées ;
- versions des outils filesystem/compression, paramètres et date de référence ;
- SHA-256 de l'image et de l'archive, inventaire des fichiers et permissions,
  SBOM, notices/licences et références aux preuves de qualification.

Vérifier réellement la disponibilité des sources et notices nécessaires à la
redistribution ; un SBOM ne suffit pas à valider les licences.

Premier critère : entrées conservées et même contenu logiciel/configuration
reconstruit. Deuxième critère distinct : identité binaire des images. Les dates,
UUID de filesystem, allocation ext4 et métadonnées d'archive peuvent différer.
Les comparer puis documenter ou normaliser les écarts ; **ne pas promettre un
SHA-256 identique avant de l'avoir mesuré**. Un checksum d'artefact permet sa
vérification, pas la démonstration de sa reproductibilité.

## 6. Premier boot système et extensions conjointes

InkyOS prépare les permissions, le stockage et l'identité **système**. Inky Studio
reste propriétaire des credentials, UUID/clé du cadre, certificats, ownership,
fenêtres QR et rendu de l'écran. Un script OS ne doit pas synthétiser ces bases
privées ni ouvrir une fenêtre d'adoption à chaque boot.

Proposition de séquence :

1. Le système prépare le stockage, génère son identité et assure la disponibilité
   de l'aléa kernel avant les secrets. Il crée seulement les répertoires et droits
   attendus par l'app/helper. Une interruption doit permettre une reprise
   idempotente ; le marqueur de succès vient après les écritures durables.
2. NetworkManager, BlueZ, Avahi et le helper deviennent disponibles, sans attendre
   de réseau commun ni exposer de compte support partagé. Aucun profil Wi-Fi
   personnel préchargé. Le hostname individuel est indépendant d'une identité
   matérielle personnelle ; tester les collisions de découverte.
3. L'app applique un **contrat de bootstrap à développer**, gère l'heure et son
   état neuf/adopté/récupération, puis son écran de bienvenue/QR. L'app seule
   utilise le display. L'absence de réseau n'implique jamais « cadre neuf ».
4. Après adoption, reboot et update conservent identité et ownership. Une erreur
   ou une identité partiellement écrite exige un état de réparation explicite,
   jamais une réinitialisation silencieuse des droits.

L'image générique ne contient ni `/etc/machine-id` valide, ni copie D-Bus de cet
ID, ni host keys SSH, random seed clonée, état BlueZ/NM, credentials app,
certificats/clé du cadre, ownership, photos ou historiques. Vérifier aussi logs,
homes, caches, `server/data`, fichiers de provisioning et fichiers supprimés dans
l'artefact final ; partir vierge évite de devoir assainir une SD personnelle.

Attention : pour systemd, un `machine-id` **vide** n'active pas
`ConditionFirstBoot=yes`, alors qu'un fichier absent ou `uninitialized` le fait.
Ne pas confondre ce signal système avec l'état d'adoption durable. La procédure
doit survivre aux coupures même lorsque le « premier boot » systemd est terminé.
[Référence systemd v257](https://github.com/systemd/systemd/blob/v257/man/machine-id.xml),
[random seed](https://github.com/systemd/systemd/blob/v257/man/systemd-random-seed.service.xml).

| Contrat à convenir avec Inky Studio | Blocage actuel / preuve exigée |
|---|---|
| Bootstrap de l'heure, identité et TLS | Avec BLE actif, `main.py` initialise TLS avant le lifespan ; une date antérieure à 2026 empêche même le welcome/API. Certificat de 396 jours : la date de build ne couvre pas un stockage prolongé. Définir le mécanisme authentifié et tester date erronée/expiration sans désactiver TLS. |
| Première adoption sans LAN | L'ouverture QR est authentifiée en HTTP/HTTPS aujourd'hui. Définir preuve physique, état durable jamais adopté, expiration/réarmement et anti-réouverture après reboot. |
| Pays Wi-Fi | Aucun réglage pays dans les opérations BLE actuelles. Définir UI iOS, validation du pays, action helper restreinte, persistance et ordre d'activation radio. Ne pas imposer le pays du développeur à tous. |
| Écran et découverte | Welcome/QR par le même display owner ; Avahi et hostname individuel côté OS. Tester `.local` sur réseau local et hotspot iPhone, ainsi que deux cadres. |
| Packaging offline et compatibilité | Payload sans installation mouvante ; unité, wrapper, helper/polkit et lock de dépendances versionnés. Définir quelles mises à jour app sont compatibles avec chaque image/helper. |
| Recovery physique et restauration | Moyen utilisable sur le panneau réellement identifié, sans supposer la présence d'un bouton. Reset explicite, preuve physique et sort des photos/identités documentés. |

Sources du blocage : `inky-studio/server/inky_web/main.py` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`),
`inky-studio/server/inky_web/provisioning/identity.py` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`),
`inky-studio/server/inky_web/provisioning/api.py` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`),
`inky-studio/server/inky_web/provisioning/runtime.py` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`).

Ces lignes définissent des besoins, **pas un nouveau protocole décidé par InkyOS**.
Le choix du mécanisme de temps exige une conception conjointe avant tout code OS
qui en dépend. Attendre NTP sans réseau ou accepter tous les certificats ne
résout pas ce contrat.

## 7. Qualification sur SD dédiée

Matrice initiale : Zero 2 W + panneau identifié + versions matérielles/logicielles
exactes. Les deux SD proviennent du même artefact vierge ; elles peuvent être
testées successivement sur un banc dédié. Les comptes, réseaux et photos de test
sont fictifs. Les seuils ci-dessous sont des critères proposés, pas des mesures.

Mise à jour du 30 septembre : la cible produit est **microSD de 16 Go nominales,
marque non fixée**, choisie selon disponibilité/prix puis qualifiée. L'image
diagnostic actuelle mesure 3061841920 octets et tient sur la Qumox observée à
15938355200 octets ; chaque flash vérifie la capacité réelle. L'ancienne SD
de 128 Go est retirée des essais pour cette campagne. La campagne active
reste sur Qumox seule ; les résultats A/B initiaux sont conservés, sans
exiger un nouveau boot de A ni déclarer ses essais manquants réussis.
La matrice étendue reste une condition de qualification/distribution,
pas un préalable à un premier essai applicatif explicitement expérimental.

| Essai | Critère / preuve à conserver |
|---|---|
| Inspection avant boot | Hashs, partitions, services/permissions, aucun état privé ; SSH inactif et aucun password Linux partagé. |
| Deux installations | Identités système/app différentes entre cartes ; identité stable après 10 reboots par carte ; comptes/permissions conformes. Ne conserver que les empreintes utiles aux preuves. |
| Démarrage sans réseau | Welcome et QR fonctionnent sans LAN préalable après livraison du contrat app ; heure correcte, mauvaise date et expiration testées. |
| Adoption et Wi-Fi | iPhone physique, QR correct/erroné/expiré, mauvais password, confirmation HTTPS, timeout 180 s et rollback ; hotspot 2,4 GHz. Coordination du banc avec Inky Studio. |
| Perte de BLE/réseau | Reprise déterministe ; aucun contournement TLS ni perte d'ownership ; un cadre adopté n'ouvre pas de nouveau droit. |
| Écran | EEPROM/référence et classe driver concordantes, `is_mock=false` ; au moins 5 refreshs consécutifs sans conflit GPIO ; durée mesurée. |
| Charge et alimentation | Temps de boot prêt/QR, RAM/swap, espace disque, durée refresh, OOM et état de throttling/undervoltage relevés. Ne pas déduire une consommation de la valeur nominale du bloc. |
| Coupures contrôlées | Durant initialisation, adoption, transaction Wi-Fi et update ; reprise/rollback documentés pour chaque phase, uniquement sur banc et SD de test. |
| Update app | Combinaison app/helper/OS compatible, identité/photos persistantes ; échec testé avec limites du rollback venv explicites. |
| Récupération | Reflash d'une autre SD et restauration vérifiée ; politique d'identité évitant deux cadres actifs avec la même clé ; nouvelle adoption explicite si identité perdue. |
| Seconde personne | Flash avec Imager, installation et récupération depuis le guide sans assistance du développeur. |

Chaque rapport précise image SHA-256, versions, matériel, scénario, résultat et
mesures. Un test synthétique ou en VM ne valide pas radio, SPI, display ou coupure
réelle. Ne publier aucune matrice de compatibilité supplémentaire par déduction.

## 8. Maintenance et ordre de réalisation

Pour v0, proposer le layout simple boot FAT + root ext4, avec code et données
séparés par chemins. Une partition de données dédiée peut faciliter certaines
migrations, mais ne remplace pas une sauvegarde ; elle reste à décider sur mesures.

| Stratégie OS | Intérêt | Coût et limite |
|---|---|---|
| Reconstruction + reflash sur carte de secours — proposée pour v0 | Recette courte et testable ; ancienne carte conservée ; pas de nouveau boot manager. | Sauvegarde/restauration privées à concevoir et tester ; intervention physique. |
| A/B OS | Retour à l'ancien système envisageable après échec de boot. | Deux slots, sélection de boot, validation santé, migrations et données communes à concevoir ; ne règle pas le rollback du venv de l'updater actuel. |

L'updater app reste celui d'Inky Studio. Son suivi de `latest`, ses dépendances
pip résolues à l'update et son rollback sans venv limitent la qualification durable
d'une image. Coordonner une politique de versions compatibles avant distribution ;
ne pas changer son dépôt cible ni présenter cet updater comme un update OS.
Toute mise à jour kernel/firmware/packages doit produire une nouvelle combinaison
inventoriée et qualifiée, avec une politique de correctifs de sécurité documentée.

Ordre de travail proposé :

1. **Maintenant** : vérifier l'environnement Linux, éprouver l'image officielle
   avec un delta système minimal, préparer le packaging/manifeste et concevoir
   le bootstrap conjoint. Un prototype système sans app finale peut avancer.
2. **Après release app et identification matérielle** : entrées figées, stage et
   finalisation offline, contrôle de l'image, deux builds comparés.
3. **Sur banc dédié** : premier boot, adoption iPhone et matrice SD complète.
4. **Après preuves** : image compressée, SHA-256/provenance/licences, guide Imager,
   procédure de restauration et décision de distribution.

L'hôte de build Linux ARM64 est maintenant éprouvé. Restent ouverts : identification
du panneau/banc, release app définitive et contrats listés en section 6. Aucun de ces éléments n'est
implicitement remplacé par un matériel hors banc ou par une valeur arbitraire.

**Disponibilité au 30 septembre : Qumox 16 Go de test fournie**, premier boot
et un redémarrage avec identité conservée observés. L'ancienne SD de test
128 Go sort du périmètre actif pour cette campagne. La campagne complète et
les essais applicatifs restent ouverts.

Pour v0, conserver une seule cible, boot FAT + root ext4 et récupération par
reflash de secours. A/B, partitionnement spécial, service cloud et mécanisme
d'update OS sur mesure sont différés. Les campagnes de 10 reboots, coupures et
seconde personne servent la qualification/distribution ; elles ne bloquent pas
un premier prototype système inspectable.
