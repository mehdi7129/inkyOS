# Profil InkyOS pour inkyImager

Ce profil démarre directement sur le Wi-Fi préparé dans l’app Mac. Il est
distinct de l’image factory14 : aucun propriétaire, journal d’adoption ou état
factory n’est fabriqué pour contourner ses contrôles.

## Contrat Mac → premier démarrage

Fichier FAT : `/boot/firmware/inky-imager.json`, UTF-8, 4 096 octets maximum :

```json
{"schema_version":1,"wifi":{"ssid":"nom du Wi-Fi","password":"mot de passe","country":"FR"}}
```

Le SSID conserve ses octets UTF-8, espaces compris : de 1 à 32 octets, sans NUL.
La version initiale accepte la France, un Wi-Fi WPA2 sur 2,4 GHz et une
passphrase ASCII imprimable de 8 à 63 caractères ou une PSK de 64 chiffres
hexadécimaux. Le [format keyfile de NetworkManager](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-keyfile.html)
accepte les SSID sous forme de liste d’octets décimaux ; la
[propriété WPA-PSK](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-dbus.html)
accepte une clé hexadécimale de 64 caractères.

L’importeur écrit un profil autoconnect privé avec une PSK dérivée en hexadécimal,
le pays réglementaire persistant, puis un petit reçu privé contenant seulement
des hashes. Tous sont synchronisés avant suppression du JSON FAT. Une coupure
après publication du profil ou du reçu est reprise sans réécriture du profil ni
nouvelle identité. Le pays et l’activation WLAN sont réappliqués chaque boot.

## Assemblage Linux minimal réutilisable

1. Conserver la base officielle pristine vérifiée : RAW de 3 061 841 920 octets,
   SHA-256 `49fafba626ec00e0f9800349b9edae6caf8cfc223f673b875b72ac2797ed9576`.
   Créer une seule copie privée dans un nouveau workspace, par exemple
   `/var/lib/inkyos-build/factory-image.imager20261023/` (nom requis par le
   materializer existant, sans signification factory au runtime).
2. Réutiliser l’isolation mount/net/UTS et le montage loop de
   `scripts/build-factory-active-linux.py::MountedImage`, ou l’équivalent court
   du builder système. Ne monter que les partitions de ce fichier privé.
   Préserver cmdline/resize/fstab/kernel comme les builders existants.
3. Réutiliser uniquement la préparation commune du système : dpkg offline des
   paquets déjà verrouillés, les deux paquets I²C via
   `scripts/install-test-access-packages.py::install`, puis les trois commandes
   account de `build-factory-active-linux.py::mutate_system` : `pi` devient
   `inky`, UID/GID1000 conservés, shell nologin, groupes spi/i2c/gpio.
   Ne pas appeler le reste de `mutate_system`.
4. Appeler
   `scripts/configure-rootfs.py::configure(root, boot, recipe, factory=None)`.
   Cela conserve le resize officiel, installe le hostname persistant unique,
   masque SSH et prépare GPIO/I²C/SPI. WirelessEnabled doit être vrai.
5. Appeler directement
   `scripts/install-factory-studio-bundle-rootfs.py::install_bundle(rootfs,
   input_manifest, input_sha256, sources_dir, wheels_dir,
   receipt_output=...)`, puis `verify_bundle(...)`, avec le nouveau lot Studio
   LAN et ses dépendances/wheels déjà fermées. Cette primitive matérialise
   `/usr/lib/inky-studio` sans démarrer de code cible. Elle n’exige pas les
   writers ou le runtime factory ; ne pas appeler `factory-assembly-profile`.
6. Après fixation du contrat LAN Studio, appeler :

   ```python
   configure_imager.configure(
       rootfs, bootfs, recipe, source_directory,
       backend_exec_start=reviewed_command,
       backend_environment=reviewed_environment,
   )
   ```

   `reviewed_command` doit être la commande Python du module LAN revue, dans la
   venv intégrée. Le template `.in` n’est jamais installé sans remplacement.
   Le profil installe l’importeur avant NetworkManager, l’unité applicative
   normale, la configuration d’environnement et le fichier FAT
   `.metadata_never_index`. Il masque la restauration rfkill et Bluetooth pour
   ce parcours Wi-Fi. Le nom de l’API ne constitue pas une preuve de lancement
   réel du backend : vérifier ensuite l’unité rendue et ses chemins d’écriture.
7. Vérifier offline : paquet/application matérialisés, unités et dépendances
   systemd, hostname encore non initialisé, aucun profil Wi-Fi/capsule/secret
   personnel embarqué, aucun marker `/etc/inky-studio/factory-v1.json`,
   `/etc/inkyos/factory-runtime-v1.json` ou `/run/inkyos-factory`, ni unité de
   fermeture WLAN. Vérifier aussi les imports du module LAN sous le Python
   ARM64 cible, les fsck, puis exporter XZ et relire intégralement.

Les sources fonctionnelles à préparer sont celles du checkout courant ; les
paquets et wheels fermés du dernier lot peuvent être réutilisés s’ils sont
inchangés. Le lot Studio LAN doit remplacer le seul wheel/source applicatif
modifié. Les outils de montage et d’installation restent ceux déjà présents,
sans nouvelle dépendance réseau pendant l’assemblage.

## Builder unique

`build-image.py` réalise ces étapes, sans exécution du backend :

```sh
/usr/bin/python3 -I -B -S WORK/imager-os/build-image.py \
  --work /var/lib/inkyos-build/factory-image.imager20261023 \
  --inputs-sha256 SHA256_IMAGER_INPUTS
```

`WORK/imager-inputs.json` contient exactement ces champs :

```json
{
  "schema_version": 1,
  "kind": "inky-imager-image-inputs",
  "os_commit": "COMMIT_OS_40_HEX",
  "studio_commit": "COMMIT_STUDIO_40_HEX",
  "files": {"base.img": {"sha256": "49fafba626ec00e0f9800349b9edae6caf8cfc223f673b875b72ac2797ed9576", "size_bytes": 3061841920}},
  "backend": {"inputs": "backend/inputs.json", "sources": "backend/sources", "wheels": "backend/wheels"},
  "backend_exec_start": "/usr/lib/inky-studio/server/.venv/bin/python3 -I -B -m inky_web.imager_lan",
  "backend_environment": {
    "INKY_STUDIO_DISPLAY_MODE": "hardware",
    "INKY_STUDIO_DISPLAY_PROFILE": "ac073-800x480-timed-wait",
    "INKY_STUDIO_DATA_DIR": "/var/lib/inky-studio"
  }
}
```

L’exemple doit être complété par les hashes/tailles de **tous** les fichiers de
`recipe/`, `backend/`, `imager-os/` et `packages/`. Les namespaces sont fermés.
Les deux archives I²C doivent être présentes dans `recipe/packages/`, comme le
demande leur installateur existant ; le paquet système `python3-dbus` est dans
`packages/`. Le fichier `base.img` est une unique base vérifiée, éventuellement
déplacée depuis un ancien workspace ; un `base-reuse.json` à la racine est
autorisé sans duplication du RAW. Le builder crée une seule `candidate.img`.

Il attend udev après `losetup --partscan`, reprend uniquement le contrôleur de
montage existant, vérifie les unités, préserve les fichiers officiels de
boot/resize, produit l’inventaire/fsck puis `imager-candidate.json`. Aucun nouvel
exporter ou cycle d’approbation factory n’est ajouté. Ne pas rejouer une
composition partielle : ses fichiers et journaux doivent d’abord être inspectés.

## Vérification effectuée

`python3 -I -B -m unittest discover -s inkyImager/Tests/OS -p 'test_*.py'`

14 tests sur fixtures : vecteur WPA connu, UTF-8/espaces/caractères INI,
validation, permissions, reprise après chaque publication durable, échec radio,
changement de capsule, refus des liens, refus d’anciens markers factory et rendu
normal des unités. Aucun réseau réel, VM, SD, backend ou écran n’a été utilisé
par ces tests. Le démarrage du Pi et l’envoi d’une photo restent à qualifier.
