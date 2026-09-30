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
