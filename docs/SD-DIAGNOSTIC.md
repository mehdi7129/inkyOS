# SD de diagnostic expérimentale

Cette variante sert au premier essai d'une SD dédiée sur un Raspberry Pi Zero 2 W.
Elle dérive d'un export applicatif local déjà vérifié. L'app et son helper restent
masked ; le parcours QR/BLE/iPhone sans LAN n'est pas disponible dans cette image.
Elle ne constitue pas une release, ni une qualification du panneau ou du Wi-Fi.

## Construction

La VM ARM64 `inkyos-build` doit déjà être démarrée et marquée comme builder. Depuis
le checkout de travail :

```sh
PYTHON=python3.13 bash scripts/build-sd-diagnostic.sh build/prototype.TLQXKxT6
```

Le script vérifie le parent, copie l'image dans un nouveau dossier de build,
snapshotte une whitelist de sources et ajoute uniquement le diagnostic statique.
Il n'installe aucun package, ne lance aucun service cible et ne flashe aucune SD.
Dans la VM, les opérations sur la copie utilisent des namespaces mount/net/UTS
privés. Les dix fichiers kernel/initramfs/cmdline/fstab/resize/grow sont conservés.
Seul `config.txt` reçoit le delta firmware/radio prévu : `bootloader_update=0` et
`dtoverlay=disable-wifi`. Les services/timers EEPROM et APT sont masked.

Les nouveaux exports restent sous `build/sd-diagnostic.XXXXXXXX/`, ignorés par
Git. Ils comprennent l'image, le manifeste de dérivation, le parent manifeste,
les hashes du snapshot de sources, les gates système/app, l'inventaire complet
des métadonnées, l'inspection de l'image, les résultats systemd et fsck.

```sh
python3.13 scripts/verify-sd-diagnostic.py build/sd-diagnostic.XXXXXXXX
```

Ce verifier accepte le type `sd-diagnostic` exclusivement. Le verifier des
prototypes ne doit pas être utilisé sur cette variante. Les hashes établissent
la cohérence d'un export local non signé ; ils ne prouvent pas son authenticité,
son démarrage ni le fonctionnement du matériel.

## Écriture sur le Mac

`scripts/flash-sd-macos.py` accepte uniquement une carte Secure Digital physique,
amovible et inscriptible, y compris dans le lecteur interne du Mac. Le disque,
sa capacité et son objet IORegistry doivent correspondre aux valeurs relevées
pour la carte autorisée. Son remplacement ou sa réinsertion invalide ce relevé.
Sans `--write`, la commande ne fait qu'un contrôle préalable.

Une écriture nécessite les droits administrateur macOS. Le raw device est
verrouillé exclusivement, l'image est vérifiée contre son SHA-256, puis écrite,
synchronisée par `DKIOCSYNCHRONIZECACHE` et relue sur toute sa longueur avant
éjection. Une primitive de synchronisation refusée est un échec explicite.
Les octets au-delà de l'image ne sont ni inspectés ni effacés ; cette opération
n'est pas un effacement sécurisé de toute la carte. La relecture et le flush
accepté par le driver ne qualifient pas les coupures d'alimentation du contrôleur SD.

```sh
python3.13 scripts/flash-sd-macos.py \
  --image build/sd-diagnostic.XXXXXXXX/inkyos-sd-diagnostic.img \
  --sha256 SHA256_IMAGE \
  --device diskN --capacity-bytes CAPACITE --registry-id OBJET_IOREGISTRY
```

L'ajout explicite de `--write` déclenche l'écrasement de la carte sélectionnée.

## Premier et second démarrage

Après la resize initiale prévue par Raspberry Pi OS, un timer lance une collecte
bornée après 45 secondes. Une exportation réussie sur la partition boot déclenche
un arrêt automatique. Aucun reboot automatique n'est demandé par le diagnostic.
Le rapport minimal est sous
`inkyos-diagnostics/boot-<SHA256boot_id>.json` sur la partition FAT ; il exclut les
identités personnelles et les données applicatives. Le fichier
`INKYOS-DIAGNOSTIC.txt` rappelle le mode expérimental sur la SD.

Attendre l'arrêt réel du Pi avant de couper son alimentation ou retirer la SD.
En cas d'échec de collecte, l'arrêt automatique n'est pas garanti : un écran ou
une console de diagnostic reste nécessaire pour déterminer l'état. La présence
du timer dans l'image ne prouve pas que le boot l'a atteint.

Le deuxième démarrage est déclenché manuellement par l'utilisateur. Il produit
un autre rapport pour vérifier la stabilité de l'identité système et la resize,
sans activer l'app. Les rapports bruts restent locaux ; seuls des résultats
réduits et relus doivent être versionnés pour la qualification.

## Comparer les observations localement

Copier uniquement les rapports du répertoire `inkyos-diagnostics` dans un
répertoire local ignoré sous `build/`, en conservant séparément carte et phase
du test. Comparer les deux démarrages d'une même carte :

```sh
python3.13 scripts/compare-sd-reports.py --mode same-card \
  build/sd-A/first.json build/sd-A/restart.json
```

Comparer les premières observations de deux cartes flashées depuis le même
artefact vierge :

```sh
python3.13 scripts/compare-sd-reports.py --mode different-cards \
  build/sd-A/first.json build/sd-B/first.json
```

Le mode est une déclaration de l'opérateur : le JSON ne peut pas identifier
matériellement la carte. Le comparateur vérifie les observations nécessaires
à l'identité et le succès firstboot, puis exige deux boot IDs distincts.
Deux copies du même rapport ne valident donc pas un redémarrage. Sur une même
carte, machine-id et hostname doivent rester identiques ; entre cartes vierges,
les deux doivent différer. Les assertions de cohérence sont également
recoupées avec les empreintes locales.

Les fichiers sont lus sans écriture, avec taille bornée et refus des liens,
fichiers spéciaux et JSON ambigus. La sortie contient des contrôles booléens et
les SHA-256 des artefacts lus ; aucune empreinte machine/hostname/boot ou chemin
local n'est publié. Codes de sortie : 0 comparaison réussie, 1 critère refusé,
2 entrée invalide. Le rapport n'est pas une attestation signée et ne contient
pas le pin de l'image : conserver séparément la preuve du flash. Une comparaison
réussie ne qualifie ni l'app, ni la radio, ni toute la campagne SD.

Validation du 30 septembre : 19 tests dédiés, dans une suite de 324 tests sans
échec sur Mac et Linux ARM64 (4 et 1 skips). Le vrai rapport physique comparé
à lui-même est correctement refusé, code 1 : identité/cohérence/firstboot
acceptés, mais boot identique. La
[preuve logicielle](validation/2026-09-30-sd-report-comparison.json) épingle
les sources exécutées et conserve ce résultat négatif attendu. Aucun reboot
physique ou comparaison A/B supplémentaire n'est déduit de ces tests.

## Premier artefact et SD préparés le 30 septembre

La recette propre `196733a` a produit une image de 3061841920 octets :
SHA-256 `6a5821c1a0adca679a611b8aa97d20ac7dba2e0694d0b6a1a871eee9b273e248`.
16 contrôles diagnostic, 62 gates système et 26 gates applicatifs passent,
ainsi que systemd, fsck FAT/ext4 et la préservation des dix fichiers boot/grow.
Les 305 fixtures passent sur Mac/Linux et dans la CI publique. Un test avec
un vrai montage FAT et le sandbox systemd a exporté deux fois avec succès
sur le même boot de VM, sans déclencher de poweroff.

La tentative CLI macOS a été refusée à l'ouverture du raw device, même root,
avant toute écriture. Raspberry Pi Imager 2.0.6 a ensuite écrit l'image locale
sur la SD fournie de 128 Go, sans personnalisation. Son écran final a confirmé
la réussite et l'éjection automatique ; le disque n'était plus présent dans
`diskutil`. Aucune relecture raw indépendante n'est revendiquée. La
[preuve réduite](validation/2026-09-30-sd-diagnostic-flash.json) conserve cette
distinction. À la fin de cette préparation, la VM était arrêtée et le premier
boot physique restait NON TESTÉ.

## Rapport du premier boot récupéré le 30 septembre

L’opérateur a démarré le Pi Zero 2 W sur cette carte puis confirmé son arrêt avant
de la remettre dans le Mac. Un rapport a été récupéré et conservé localement ;
seule la [preuve réduite](validation/2026-09-30-sd-first-boot.json) est publiée,
sans empreintes d'identités ni identifiant de boot.

Firstboot, resize et growfs réussissent ; l'identité système est cohérente.
Le rootfs ext4 dispose de 117598322688 octets libres (117,60 Go décimaux).
Les états des services correspondent à la variante de diagnostic. Le snapshot
indique 40,242 °C et aucun flag de throttling ; ses 46 secondes d'uptime ne
constituent pas une mesure de durée de boot. L'arrêt est une observation
distincte de l'utilisateur, puisque le rapport précède poweroff.

Le redémarrage manuel, la comparaison de deux installations vierges et la
campagne applicative restent à faire. Le remplacement de cette carte
est prévu : repartir du même artefact vierge évite de recopier
une identité déjà générée. À la fin de cette première observation, aucun
changement de carte ni nouveau flash n'avait encore été effectué.

## Remplacement par la Qumox 16 Go — 30 septembre

L’inventaire de cette seconde carte relève 15938355200 octets,
média SD physique amovible inscriptible. Le premier flash avec Imager 2.0.6
a présenté une vérification à 31 %, une fin avec éjection et une erreur
d'ouverture raw simultanée. Il reste **non accepté** ; la
[preuve d'observation](validation/2026-09-30-sd-qumox-flash-observation.json)
conserve cette ambiguïté. L’opérateur a seulement fermé l'erreur, sans relancer
manuellement l'écriture.

Cette séquence est compatible avec le [bug upstream #1511](https://github.com/raspberrypi/rpi-imager/issues/1511),
sans en prouver la cause sur cette carte. Le
[correctif](https://github.com/raspberrypi/rpi-imager/commit/f1e5335314937aa1d35f4cfeb7df3c3e4d2277a9)
empêche une seconde écriture pendant la première et corrige le watchdog.
Le conseil de confidentialité affiché par l'ancienne version couvre tout échec
d'ouverture ; il ne démontre pas un besoin d'accès complet au disque.

Une copie officielle d'[Imager 2.0.11.1](https://github.com/raspberrypi/rpi-imager/releases/tag/v2.0.11.1)
est préparée localement : DMG hashé selon la release, signature Apple vérifiée,
Team ID Raspberry Pi `8RDZTRXE62` identique à l'app existante et Gatekeeper
accepté avec notarization. L'app installée existante et les réglages de
confidentialité restent inchangés. La nouvelle session a sélectionné le même
artefact vierge ; aucun média SD n'y est encore détecté. Réinsérer la carte,
identifier à nouveau son device/capacité, puis effectuer une seule écriture
avec vérification avant le boot. Ne pas réutiliser un numéro de disque par
hypothèse après éjection.

Après réinsertion, la carte de 15938355200 octets est identifiée à nouveau
comme seule SD physique amovible inscriptible. Une seule écriture est lancée
avec Imager 2.0.11.1 ; 77 % d'écriture puis « Écriture terminée » sont observés,
sans erreur, avec éjection automatique et disparition du device côté Mac.
La [preuve du retry propre](validation/2026-09-30-sd-qumox-clean-flash.json)
accepte ce résultat UI pour le prochain boot. Elle conserve séparément le
premier essai ambigu, qui n'est pas accepté rétroactivement.

La progression de vérification n'a pas été capturée. Le
[code GUI exact](https://github.com/raspberrypi/rpi-imager/blob/f259e1c99007b8a84b4e0049f03f0c34050f38e0/src/imagewriter.cpp#L137)
active cette passe par défaut ; aucune action de skip n'a été faite. Cela ne
constitue pas une relecture raw indépendante ni un 100 % observé. À l'issue
de ce flash, aucun boot de la Qumox, comparaison A/B ou test de persistance
n'était encore conclu.

Suite prévue à ce stade : Pi hors tension, premier démarrage de la Qumox puis arrêt
automatique confirmé par l’opérateur ; remettre la SD dans le Mac pour récupérer le
rapport local. Comparer les premières observations 128 Go/Qumox avec
`different-cards`. Faire ensuite un second démarrage manuel de la Qumox,
récupérer son autre rapport et utiliser `same-card`. Le flash n'active pas
l'app/helper et ne valide aucun parcours iPhone, radio ou écran.

## Premier boot Qumox récupéré et identités A/B comparées — 30 septembre

Après l'acquittement des étapes par l’opérateur, la carte est détectée dans le Mac.
Un rapport régulier est copié depuis le répertoire diagnostic FAT, sans lire
les autres contenus de la SD. Le
[résultat réduit](validation/2026-09-30-sd-qumox-first-boot.json) confirme
firstboot/resize/growfs réussis, identité cohérente et 11,89 Go décimaux libres
sur ext4. Les services attendus correspondent à la variante masquée.

La comparaison `different-cards` entre les premiers rapports 128 Go/Qumox
passe, code 0 : boot IDs distincts et machine-id/hostname différents. Les
empreintes d'identité ne sont pas publiées. L'association aux deux cartes et
au même artefact vierge vient du workflow de préparation ; les rapports locaux
ne sont pas des attestations signées.

Les 56 secondes d'uptime et la température de 37,014 °C sont un snapshot,
sans mesure de durée de boot, charge ou consommation. L'acquittement utilisateur
n'est pas une confirmation séparée explicite de l'arrêt ; le rapport est écrit
avant poweroff. La qualification complète reste ouverte.

Prochain essai prévu à ce stade : **redémarrer manuellement la Qumox sans la reflasher**,
attendre l'arrêt, la remettre dans le Mac et conserver le nouveau rapport
avec celui-ci. Exécuter `same-card`, puis vérifier aussi services et capacité
du FS. Un contrôle sur la SD de 128 Go était également prévu à ce stade,
avant son retrait ultérieur du périmètre actif.

## Second boot Qumox et persistance — 30 septembre

Après ce nouveau démarrage sans reflash, deux rapports sont retrouvés sur la
FAT ; le premier est inchangé. La comparaison `same-card` passe, code 0 :
boots distincts, machine-id et hostname conservés, état version 1 cohérent.
Firstboot réussit à nouveau ; services actifs et masques restent conformes
aux snapshots attendus. Resize/growfs sont inactifs sans échec rapporté,
état normal après leur travail initial ; la capacité ext4 est conservée.

La [preuve réduite](validation/2026-09-30-sd-qumox-second-boot.json) sépare
comparaison d'identité et observations des services/FS. Elle corrige aussi
le nom du champ historique pour le volume FAT : `diskutil info` donne
528593408 octets de volume, tandis que `diskutil list` mesure une partition
de 536870912 octets. Les valeurs historiques ne sont pas remplacées.

S05 est documenté sur B dans ce périmètre. A est ensuite retirée de la campagne :
son redémarrage prévu n'est pas exécuté. B compte un seul
redémarrage manuel pour S06. Aucune série de
dix, erreur transitoire exhaustive, coupure, adoption ou transaction réseau
n'est déduite des deux snapshots. Conserver la Qumox pour les essais suivants,
sans reflash pendant la série de persistance. La cible produit est 16 Go
nominaux, marque non fixée ; une autre référence n'hérite pas des résultats
Qumox par sa seule capacité annoncée.
