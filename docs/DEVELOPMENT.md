# Développer InkyOS sans carte SD

Le premier outil livré télécharge une base officielle figée et l'inspecte dans
une VM Linux isolée. **Il ne construit pas encore une image InkyOS avec l'app.**
Aucun accès au Raspberry Pi, à une SD ou à un autre disque physique n'est requis.

## Utilisation

Sur le Mac Apple Silicon, avec Python 3.9+ et Lima 2.0+ :

```sh
make test
make inspect
make vm-stop
```

`make inspect` crée ou démarre `inkyos-build`, télécharge la base si nécessaire,
vérifie les hashes puis inspecte une copie dans Linux. Les rapports sont écrits
dans un nouveau dossier `build/inspection.XXXXXXXX/` à chaque exécution :

- `builder.json` : versions des outils et contrôles loop/FAT/ext4/chroot ARM64 ;
- `base.json` : OS, packages, unités, comptes verrouillés et état générique.

Pour télécharger seulement : `make fetch`. Pour démarrer/arrêter uniquement la
VM : `make vm-start` / `make vm-stop`. Aucun de ces targets ne flashe une carte.

Le premier passage télécharge environ 516 Mio pour l'image Pi compressée, plus
la base Debian et les packages de la VM. L'image Pi décompressée fait environ
2,85 Gio ; une copie transitoire supplémentaire existe dans la VM pendant
l'inspection. Son disque sparse a une capacité maximale configurée de 16 Gio,
avec 3 Gio de RAM et 2 CPU. `cache/` et `build/` sont exclus de Git.

## Entrées et séparation des systèmes

| Composant | Source versionnée | Rôle |
|---|---|---|
| Base Pi | [base-image.lock.json](../config/base-image.lock.json) | Image Raspberry Pi OS Lite du 15/09/2026, hashes/tailles compressés et décompressés ; références `.info`/SBOM. |
| Hôte Linux | [lima.yaml](../infra/lima.yaml) | Debian 13 ARM64 du 12/07/2026, digest SHA-512, ressources et outils. |
| Acquisition | [fetch-base.py](../scripts/fetch-base.py) | Téléchargement temporaire, bornes, contrôle puis publication ; cache rehashé avant utilisation. |
| Contrôle hôte | [check-builder.sh](../scripts/check-builder.sh) | Montages et chroot sur de petits fichiers temporaires fabriqués dans la VM. |
| Inspection | [inspect-image.sh](../scripts/inspect-image.sh) et [inspect-rootfs.py](../scripts/inspect-rootfs.py) | Lecture statique, sans chroot ni exécution de l'image Pi. |

La VM possède son propre OS et ses propres identités de développement. Son
rootfs n'est jamais copié dans l'image Pi. Aucun home du Mac n'est monté ; seuls
scripts, lock et image officielle sont transférés explicitement. Containerd,
Rosetta et forwarding de services sont désactivés ; la connexion locale de
contrôle SSH de Lima reste nécessaire.

Les packages des outils de la VM sont installés depuis Debian au provisionnement,
puis inventoriés dans le rapport : leur résolution initiale n'est pas encore
figée. Cette limite concerne l'environnement de développement ; aucun `apt
upgrade` n'est lancé sur l'image cible. La modification de `infra/lima.yaml` ne
réécrit pas automatiquement la configuration d'une VM déjà créée.

## Contrôles effectivement réalisés le 27 septembre 2026

- VM Debian ARM64 démarrée sur le Mac ; loop read-only, montages FAT/ext4 et
  chroot ARM64 natif passent avec des fixtures temporaires.
- Archive officielle et image décompressée téléchargées ; tailles et SHA-256
  correspondent au lock, y compris après copie dans la VM.
- Base montée en lecture seule, ext4 avec `noload` ; aucune unit de l'image
  démarrée. Démontage et libération des loop devices vérifiés après inspection.
- 633 packages installés, userland ARM64, kernel Pi `6.18.50` et firmware
  `1:1.20260907-1` inventoriés. Cette combinaison diffère du banc personnel.
- NetworkManager `1.52.1-1+rpt4`, BlueZ `5.82-1.1+rpt2`, Avahi `0.8-16`, Python
  et venv `3.13.5-1` présents. `python3-dbus`, requis par le helper, absent.
- `machine-id` à `uninitialized`, aucune host key SSH présente, comptes recensés
  verrouillés et répertoire des profils Wi-Fi vide ; aucune random seed dans
  les deux emplacements vérifiés.

Ces observations valident la faisabilité de l'inspection sur le Mac et l'intérêt
d'une personnalisation limitée de Lite. Elles ne prouvent ni le premier boot Pi,
ni l'unicité après clonage, ni le driver écran, ni le Bluetooth réel.

## Adaptations à réaliser ensuite

La base contient cloud-init, `userconf-pi` et des fichiers de provisioning
génériques dans la partition boot. Le rapport signale leur présence, sans
supposer qu'ils contiennent des données personnelles. Un fichier d'état existe
aussi sous `/var/lib/NetworkManager` ; il doit être identifié avant de choisir
ce qui est conservé ou réinitialisé.

Le prochain stage offline devra :

1. Figer le petit delta de packages, notamment `python3-dbus`, en vérifiant ses
   dépendances contre l'inventaire cible.
2. Adapter explicitement le premier boot de cette image exacte, créer le compte
   applicatif verrouillé et ses permissions, puis configurer SPI/I²C. Conserver
   un seul responsable du provisioning et du display.
3. Intégrer le payload Inky Studio commun lorsque la release et son packaging
   offline sont qualifiés. Le contrat heure/adoption sans LAN reste côté app.
4. Produire une image de test et ses contrôles avant toute qualification sur
   SD dédiée. La SD personnelle reste intacte.

## Limites des rapports

L'inspecteur ne sérialise pas de password, clé, ID machine, SSID ou contenu de
données applicatives. Il refuse de suivre les symlinks de l'image ; certains
faits sont donc marqués absents ou non inspectables. Les modes/owners affichés
sur la partition FAT proviennent du montage, pas de permissions Unix stockées.

Une unit présente ou liée dans un target n'est pas nécessairement fonctionnelle,
et ce relevé ne couvre pas tous les masks, presets et dépendances. Le contrôle
des chemins sensibles est ciblé, pas un certificat d'absence exhaustive de
secrets. Une base inspectée reste **non qualifiée matériellement**.
