# Premier boot privé d'enrôlement

Préparation du 30 septembre 2026 pour la Qumox 16 Go et le Pi Zero 2 W.
Cette phase se construit depuis l'[image TEST LAN préparée](TEST-LAN.md),
sans démarrer l'app, le helper ou SSH. **Export privé construit et vérifié ;
contrôleur de retour livré et relu, refus natif sur l'image non bootée confirmé.
Aucun flash ni exécution sur le Pi à ce stade.**

Le premier boot doit identifier l'écran, observer la radio et produire la
clé hôte SSH du Pi. Il ne configure aucun réseau. Le pays demandé `FR`, confirmé
par l’opérateur, figure dans le profil privé pour nommer la cible des observations ;
aucun `iw reg set`, scan, association ou déblocage radio n'est exécuté.

L'écran décrit comme « Inky Spectra, format carte postale » ne reçoit toujours
aucun modèle présumé. L'EEPROM doit fournir le tuple effectivement reconnu.
Une lecture bloquée ne devient pas un résultat positif ; l'app reste arrêtée.

## Séparation des artefacts

Le parent générique, rehashé et relu, est
`build/test-lan-prepared.wIV9Vjtj`, SHA-256
`4cd9d6fa8183dfb8a7a04c350ab3d3366900264fab2fa0dff90192a7e4cc9a04`.
Il reste inchangé. Le nouveau candidat privé contient une clé publique
opérateur créée pour cet essai et un challenge aléatoire. Il n'utilise aucune
clé personnelle existante, aucun nom de compte personnel, photo, SSID ou PSK.
Sa clé privée opérateur reste sur le Mac et n'est jamais lue ou copiée dans
la VM ou l'image. Aucun fingerprint, challenge ou clé ne va dans Git/logs publics.

La sortie `private/test-enrollment.XXXXXXXX` est ignorée par Git, dossier 0700,
fichiers privés 0600. L'image générique PREPARED ne contient pas cette
personnalisation. L'export enfant porte `kind=test-lan-enrollment`,
`private_artifact=true`, `bootstrap_action=enroll-and-stop`,
`no_active_application=true`, `ready_for_activation=false` et aucune
qualification matérielle/release. Il n'est pas une image de distribution.

```sh
make test-enrollment PYTHON=python3.13 \
  PARENT_EXPORT=build/test-lan-prepared.wIV9Vjtj TEST_COUNTRY=FR
```

Cette commande crée une clé opérateur neuve dans le dossier privé et
assemble une copie ; elle ne touche aucune SD et ne lance aucun runtime du Pi.

L'export local `private/test-enrollment.23b4736c` est construit depuis les
sources propres `2c540701fb222dde0437edd47002f6a49945da5b` (CI verte).
L'image fait 3 061 841 920 octets, SHA-256
`7a1b70463e5501830f67e9c4b2ffcb69d8970a154115a8e9f8aa2e27eeb9d86e`.
Ses 62 contrôles système, 26 applicatifs, 16 hérités PREPARED et 16 propres
à l'enrôlement passent. Le manifeste et les inventaires sont contrôlés,
les dix fichiers boot/grow et tout le bootfs restent identiques au parent ;
systemd verify et les deux fsck passent. La copie d'image VM a été retirée
après réception vérifiée ; le contrôle externe ne trouve aucun loop/montage
de staging. La [preuve publique réduite](validation/2026-09-30-test-enrollment.json)
omet toute personnalisation. L'image et ses preuves complètes restent privées.

Le build installe le runtime, les deux sondes readonly et une seule unité
root d'enrôlement après firstboot. Les comptes applicatifs, masques SSH,
mises à jour, permissions privées et fichiers boot/grow restent inchangés.
Le marqueur PREPARED conservé décrit ses contraintes héritées ; le profil privé
et le manifest enfant déclarent l'unique action de boot supplémentaire.
Les seize contraintes statiques héritées sont distinguées du contrôle propre
de cette unité, plutôt que de prétendre que l'enfant n'a aucun hook de boot.

La relecture a corrigé la garde live : elle impose le couple final
`758a2bf7` / `0d587792`, puis recoupe le marqueur avec le manifeste et la
déclaration applicative installés. Le couple historique reste admissible pour
les audits historiques uniquement, jamais pour cet enrôlement.
Les **501 fixtures** passent sur Mac (4 skips) et Linux ARM64 (1 skip), sans
échec. Le banc natif des six
helpers filesystem passe **17/17** sur ext4 32 MiB et FAT32 64 MiB : fsync,
publication sans remplacement, refus des fichiers préexistants et
conservation des fichiers partiels. Le contrôle externe confirme zéro loop
device et aucun montage de staging restant. Ce banc ne démarre pas le runtime,
ne génère aucune clé hôte et ne simule pas une coupure électrique.

## Exécution prévue sur la carte de test

1. Contrôler la recette, l'export privé, les masques et la méthode de reprise
   offline avec Inky Studio, puis identifier précisément la carte cible.
2. Au boot, exiger Linux ARM64/root, le modèle Zero 2 W, le profil root-owned
   exact et firstboot réussi. App/helper doivent rester arrêtés et masqués.
3. Générer une nouvelle clé hôte Ed25519 à un chemin fixe privé sur le Pi.
   La clé privée n'est jamais lue pour le rapport. Toute clé/état/rapport
   préexistant bloque la progression ; aucune suppression ni régénération.
4. Lire les observations EEPROM et radio avec commandes fixes et délais bornés.
   La radio peut rester bloquée tant que Wi-Fi est désactivé. Ni son tuple
   firmware ni le panneau/driver/affichage ne sont qualifiés par ces seules lectures.
5. Écrire un rapport fermé sur FAT avec challenge/pins, clé hôte publique et
   observations réduites. Synchroniser puis demander l'arrêt propre. Le rapport
   précède le poweroff ; l’opérateur devra constater l'arrêt avant de retirer la SD.
6. Au retour sur le Mac, contrôler offline le binding carte/image/rapport et
   préparer `known_hosts` depuis cette preuve physique. La découverte LAN ne
   remplace jamais ce contrôle. Une erreur impose une reprise explicite,
   avec conservation des données de cet essai.

Le contrôle de retour doit lire aussi l'état privé ext4 `state.json` : il doit
être `enrolled` et référencer exactement le hash du profil attendu. FAT et
ext4 ne forment pas une transaction atomique commune. Un rapport FAT présent
avec un état `pending`, `review-required`, absent ou différent ne permet donc
pas de préparer la confiance SSH. Le challenge, les pins, le hash du runtime
et la clé publique hôte doivent également correspondre aux artefacts locaux
et au fichier `.pub` de la carte, sans ouvrir sa clé privée. Le contrôleur de
retour readonly est livré ; son usage réel attend le retour de la SD.

### Contrôle readonly sous Linux

`scripts/verify-test-enrollment-return.py` lit uniquement un export attendu et
des systèmes ext4/FAT **déjà montés en lecture seule**. Il ne monte pas la SD,
ne flashe rien et n'ouvre aucune clé privée. La seule lecture des métadonnées
de l'image attendue ne rehash pas son contenu : l'intégrité complète de
l'export doit avoir été vérifiée séparément comme pour l'export construit ici.

```sh
sudo python3 -I sources/verify-test-enrollment-return.py \
  --rootfs /mnt/inkyos-return/returned-root \
  --bootfs /mnt/inkyos-return/returned-boot \
  --expected-export /mnt/inkyos-return/expected
```

Ces chemins illustrent le layout, sans exécuter une acquisition. Tous leurs
ancêtres doivent être root-owned et non writable par groupe/autres ;
`/mnt/inkyos-return` et `expected` doivent être protégés, l'export attendu en
0700 et ses preuves privées en 0600. `/var/tmp` est refusé malgré un sous-dossier
en 0700. Les deux racines retournées doivent être les montages complets ext4
et vfat RO identifiés par leurs FD/mount IDs, vérifiés avant et après lecture.
Pour une copie locale de la SD, le loop device devra être readonly, ext4
monté `ro,noload` et FAT `ro` ; aucun rejeu du journal ne doit écrire dans la copie.

Le Mac ne monte pas nativement ext4. L'acquisition de la Qumox identifiée devra
donc produire une **copie privée locale** pour cette lecture Linux, ou employer
un lecteur Linux. Cette acquisition reste une étape matérielle distincte,
avec contrôle de la carte choisie et du nombre d'octets. Une copie après boot
peut contenir la clé hôte privée : conserver le conteneur en 0700 et le fichier
en 0600, ne jamais le publier ni en extraire la clé. Le contrôleur ne lit pas
le fichier de clé privée, uniquement son type, ses permissions et sa taille.

La sortie JSON est fermée, sans identité, clé, fingerprint, challenge ou log
brut. Exit 0 signifie cohérence locale ; exit 1 signifie retour incomplet ou
incohérent ; exit 2 signifie entrée invalide. Aucun de ces résultats n'autorise
SSH, l'app ou une association. Les 24 fixtures ciblées, les six tests du banc
négatif et leurs relectures passent ; la suite complète atteint 531 tests
Mac/Linux sans échec.
Elles ne remplacent pas une acquisition ni un retour matériel réels.

Le [banc négatif natif](validation/2026-09-30-test-enrollment-return.json)
est maintenant exécuté sur une copie exacte de l'image privée non bootée.
Ses neuf contrôles passent : le contrôleur vérifie les deux montages RO et
l'export attendu, puis retourne explicitement `FAIL / return_incomplete`
(exit 1), avec uniquement ses quatre premiers contrôles positifs. Il manque
encore la clé hôte et le rapport, comme attendu avant tout boot. Aucun
enrôlement réussi n'est simulé. L'image est rehashée avant/après, identique ;
loops et montages sont retirés puis contrôlés extérieurement. La copie VM est
retirée après ce contrôle ; l'export privé original est conservé sur le Mac.
Ce banc et les 99 sources exécutées de la suite sont liés à `b697bfc` (CI verte).
Inky Studio a ensuite terminé sa revue indépendante du contrôleur, des
artefacts du banc et de cette méthode RO : aucun défaut confirmé, revue statique
et 650 assertions synthétiques PASS. Le reçu final est lié par hash dans la
preuve réduite. Cette revue ne qualifie ni l'acquisition SD, ni un retour
positif, ni l'arrêt physique, et ne déclenche aucune action matérielle.

Le rapport FAT contient la clé hôte publique nécessaire à la confiance SSH.
Il reste local et n'est pas publié brut. Il ne contient aucun secret réseau,
clé privée, photo, MAC, serial de Pi, identité applicative ou UTC présumée.
Les preuves Git doivent être réduites à hashes d'artefacts et résultats non
identifiants. Les hashes locaux ne sont pas une attestation matérielle indépendante.

## Après le retour physique

La phase réseau et le [canal opérateur](TEST-OPERATOR.md) restent distincts :
profil Wi-Fi fourni localement, pays firmware réellement vérifié avant
connexion, accès SSH lié à la clé hôte observée, puis heure réelle avant TLS.
Le runtime d'activation applicative et son permis volatil restent à implémenter
et relire. Le banc SSH réussi utilise seulement un runner inerte.

Les photos LAN avec build 3 pourront être testées après la réception effective
de l'app et du panneau. Le claim QR/BLE attend TestFlight build 5 disponible
sur l'iPhone. Cette phase ne livre pas le bootstrap factory sans LAN ni les
transactions Wi-Fi/rollback ; leur qualification reste au banc commun.
