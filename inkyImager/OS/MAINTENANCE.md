# Mise à jour du backend sur la carte actuelle

État au 23 octobre 2026 : outils préparés et vérifiés sur fixtures, aucun outil
d’écriture armé et aucune modification du Pi ou de la SD. Le flash inkyImager, le démarrage,
le QR puis le parcours iPhone de la build 16 sont confirmés par Mehdi.

## Périmètre

La demande est le partage d’un accès PHOTOS par QR depuis chaque iPhone déjà
autorisé. Studio possède les changements iOS/backend ; InkyOS possède leur
installation sur la carte actuelle. Un accès PHOTO reste PHOTO : la mise à jour
n’ajoute ni propriétaire, ni administration, ni configuration Wi-Fi.

Baseline livré : backend `b75bf1e7d0ab0a50d14f01527994fc17a3f62e42`, image RAW
générique `395985cc8b483a054f50c5a51219ee8644c323debf85374e92cbdbfcca9f87aa`.
Cette image identifie le code livré ; **elle ne doit pas servir de base à la
mise à jour de la carte déjà utilisée**, qui contient désormais ses propres
identités, accès et photos.

## Transport retenu

Une maintenance hors ligne de la SD actuelle conserve les données. Elle part
d’une nouvelle sauvegarde privée de cette carte, prépare une copie de sa
partition ext4, puis remplace seulement cette partition après vérification.
La table des partitions et la partition FAT sont conservées.

Il n’existe pas de voie en ligne utilisable dans le profil livré :

- SSH est masqué ; le compte `inky` UID1000 est verrouillé, shell nologin.
- `/api/system/update` existe dans le backend mais refuse les accès PHOTO.
  Son implémentation attend un checkout, `INKY_STUDIO_REPO_SLUG`, pip et sudo,
  absents ou incompatibles avec cette installation par wheel.
- Le service tourne comme `inky`, avec `ProtectSystem=strict` et
  `NoNewPrivileges=yes`. Son seul chemin de données inscriptible est
  `/var/lib/inky-studio`.

Ne pas activer SSH ni élargir l’accès PHOTO pour contourner ces limites.
Le bouton **Flasher la carte** d’inkyImager installe une image neuve ; il ne
constitue pas un outil de maintenance conservant les données.

## Lot attendu de Studio

Avant de préparer une écriture, fournir un lot fermé comprenant :

1. Commit parent exact `b75bf1e7…`, commit final et diff complet des sources.
2. Nouveau wheel applicatif, SHA-256 et inventaire des fichiers installés.
   Les dépendances et les sources de composition restent identiques ; toute
   différence doit être explicitement incluse dans la revue du lot.
3. Pour chaque fichier remplacé, chemin relatif, taille, hash ancien et nouveau,
   UID/GID et mode attendus. Inclure les métadonnées `.dist-info` et `RECORD`.
4. Résultats des tests : état existant b75 réutilisé sans migration, anciens
   accès/photos/reconnexion conservés, invitation/révocation PHOTO déléguées
   seulement en mode LAN, anciens clients iOS compatibles avec `can_invite`.
5. Compatibilité de retour au code b75 précisée pour les états créés par le
   nouveau backend. Une absence de migration SQL ne prouve pas à elle seule
   que tous les fichiers persistants sont rétrocompatibles.

Le seul périmètre de code permis par défaut est le package applicatif sous
`/usr/lib/inky-studio/server/.venv/lib/python3.13/site-packages/inky_web/`
et ses métadonnées de distribution applicative. Un besoin hors de ce périmètre
doit être identifié avant d’établir le plan, pas découvert pendant l’écriture.

## Données et configuration à préserver

Conserver tous les fichiers, contenus, modes et UID/GID de :

- `/var/lib/inky-studio/**` : photos, base principale, accès PHOTO et sessions,
  credentials, identité du cadre et TLS ;
- `/etc/inky-studio/**`, unité `inky-studio.service` et dépendances systemd ;
- `/etc/hostname`, `/etc/machine-id` et l’identité réseau existante ;
- configuration et état NetworkManager, profil Wi-Fi et reçu réseau Imager ;
- boot/FAT, MBR, kernel, firmware, pilotes et configuration de l’écran.

La comparaison est locale et privée. Aucun token, mot de passe, contenu de clé
ou dump de credentials ne doit apparaître dans les messages entre sessions.

## Préparation et validation avant retour sur la SD

1. Une fois le lot Studio validé et les outils prêts, demander l’arrêt du Pi
   puis le retour de sa SD dans le Mac. Relever à nouveau son identité IOKit,
   sa capacité et sa table de partitions ; aucun ancien numéro de disque ou
   offset ne fait autorité. Vérifier l’espace de sauvegarde avant acquisition.
2. Acquérir toute la SD en lecture seule avec l’accès `authopen` corrigé,
   comparer le hash du flux avec une relecture locale, conserver l’original.
   Cette relecture locale ne prétend pas être une seconde lecture de la SD.
3. Extraire ext4 et travailler seulement sur une copie régulière privée.
   Si le journal nécessite une récupération, la faire sur cette copie, jamais
   sur la SD ou la sauvegarde originale. Établir le baseline de préservation
   après cette récupération.
4. Vérifier tous les anciens fichiers et tous les nouveaux payloads avant la
   première modification de la copie. Appliquer le plan borné du package.
   Comparer ensuite les fichiers persistants et la configuration protégée au
   baseline récupéré ; aucune nouvelle identité ni capsule Wi-Fi.
5. Valider les hashes/métadonnées du package, les imports ARM64 dans un banc
   isolé sans réseau ni GPIO, et le filesystem. Geler et hasher le candidat.
6. Revalider la SD et ses octets depuis l’acquisition. Un nouvel outil natif
   utilisant `authopen` doit limiter l’écriture à la plage ext4 constatée.
   Il doit vérifier MBR/FAT avant/après, synchroniser, relire toute la plage
   écrite, conserver le reçu puis traiter l’éjection séparément.
7. Conserver la sauvegarde pour retour arrière. Une écriture de partition
   n’est pas atomique face à une coupure ; seule une relecture correspondante
   établit le succès de l’écriture.
8. Rebrancher le Pi et vérifier : même accès iPhone, photos conservées,
   reconnexion, puis invitation QR iPhone→iPhone et révocation attendue.

## Réemploi historique et travail restant

L’ancien `ext4-copy-editor.py` du lot privé
`offline-migration-writer-20261016.2969338a` démontre l’édition bornée d’une copie
ext4 avec debugfs sur Mac. Les outils
`root-partition-flash-tools-20261016.u6l0lh3g` ont déjà écrit puis relu une seule
partition root, avec vérification du MBR et éjection. Ce sont des références de
code et de méthode, **pas des commandes à relancer** : leurs pins, nonce,
identités média et contraintes appartiennent à l’ancien profil TEST.

Le matérialiseur `install-factory-studio-bundle-rootfs.py` vérifie et crée un
bundle neuf ; il refuse une destination existante et n’est pas un updater.
`build-image.py` refuse également les données personnelles ; il ne doit pas
être appliqué à la carte existante.

Le lot Studio final `716104b130d34d1973001e78f15e25989d4c2e76` est reçu et ses
68 fichiers vérifiés indépendamment. Sa fermeture `SHA256SUMS` a pour SHA-256
`c927902c1cc3ffb751be16ed6958171a5b62988c9732a7b4b7198c9f07b00f2b`.

L’outil natif `inkyMaintenance` fournit `list`, `acquire`, `write-root` et
`eject`. Ses 14 tests passent. L’éditeur
[`prepare-backend-update.py`](../maintenance/prepare-backend-update.py) passe
12 tests, dont de vraies copies ext4 et la comparaison des valeurs complètes
d’attributs étendus ; une revue indépendante a vérifié le correctif des valeurs
longues que `debugfs ea_list` masque. Les tests n’utilisent pas la SD réelle.
Le [guide de l’éditeur](../maintenance/README.md) décrit les preuves et le
contrat avec le writer.

Un coffre APFS chiffré AES-256 séparé est préparé sur le Western Digital,
permissions activées, environ 107 Go libres avant acquisition. Les anciennes
sauvegardes restent à leur emplacement. Le reçu privé
`~/Library/Caches/inkyImager-os-20261023/MAINTENANCE-TOOLS.json` identifie les
outils signés/hachés et leur espace externe ; la clé du nouveau coffre et ses
métadonnées de récupération sont conservées dans Application Support.

Restent l’insertion de la carte, sa sauvegarde intégrale, la préparation du
candidat depuis cette sauvegarde puis la revue de ses preuves avant écriture.
Le lanceur de lecture est produit pour la carte effectivement détectée par
[`prepare-read-session.py`](../maintenance/prepare-read-session.py). Il ne
prépare et ne lance aucune mise à jour. Aucun résultat sur fixtures ne doit
être présenté comme une acquisition ou une écriture déjà effectuée sur la SD.
