# Développer InkyOS sans carte SD

Un **prototype système sans Inky Studio** est assemblé depuis une base officielle
Lite ARM64 figée. Aucun accès au Pi, à sa SD personnelle ou à un disque physique.
Le premier assemblage a réussi le 27 septembre 2026 ; aucune qualification SD.

## Utilisation sur Mac Apple Silicon

Prérequis : Python 3.9+ côté Mac, Lima 2.0+ et Git. Le Python Linux du builder
est 3.13. Les tests locaux ne nécessitent aucune dépendance Python externe.

```sh
make test
make inspect       # facultatif : base seule en lecture seule
make prototype     # tests, VM, entrées vérifiées, assemblage, export
make vm-stop
```

Chaque build crée `build/prototype.XXXXXXXX/inkyos-system-prototype.img` et ses
rapports. Aucun target ne flashe ni ne publie l'image. `cache/` et `build/` sont
exclus de Git. Le premier passage télécharge environ 516 Mio pour la base Pi,
plus Debian et les outils du builder. Chaque image décompressée fait 2,85 Gio.
Prévoir la source, les exports conservés et une copie transitoire dans la VM.
La VM utilise 2 CPU, 3 Gio RAM et un disque sparse de 16 Gio maximum. Sa copie
est retirée après export réussi ; les runs échoués restent pour diagnostic.

## Entrées et isolation

| Entrée | Référence |
|---|---|
| Base Pi | [base-image.lock.json](../config/base-image.lock.json) : image du 15/09/2026, hashes/tailles archive/image, inventaire officiel et SBOM. |
| Delta OS | [system-packages.lock.json](../config/system-packages.lock.json) : python3-dbus 1.4.0-1 ARM64, 96064 octets. Hash authentifié par InRelease Debian signé puis Packages.xz ; dépendances déjà présentes. |
| Builder | [lima.yaml](../infra/lima.yaml) : Debian 13 ARM64 du 12/07/2026, SHA-512, ressources limitées. |
| Recette | Liste explicite de scripts/overlay/locks, hashes, commit Git et indicateur d'arbre modifié dans recipe-inputs.json. |

Aucun home partagé, transfert d'agent SSH, containerd ou Rosetta. Seul le SSH
local de contrôle Lima reste forwardé. Les identités VM ne sont pas recopiées.
Le build vérifie le marqueur builder, accepte seulement une image régulière
dans son dossier dédié et rehash la base avant toute mutation. Aucun archivage
récursif du dépôt ou du home ; les entrées sont explicitement listées.

L'installation dpkg est privée de réseau, dans des namespaces mount/network/UTS.
Le chroot reçoit un /dev temporaire limité à null/zero/random/urandom et un
policy-rc.d qui bloque les démarrages. Aucun backend ni service cible lancé.
Les caches sont rehashés ; un fichier corrompu est refusé, jamais écrasé.
Les preuves Debian brutes restent dans cache/packages/provenance/.

Les packages **du builder** sont résolus au provisionnement et inventoriés,
pas tous figés : limite reconnue de l'environnement. Aucun apt upgrade de
l'image cible. Modifier lima.yaml ne réécrit pas une VM déjà créée.

## Delta système

- pi devient inky, mêmes UID/GID 1000, home déplacé, login/password verrouillés,
  groupes supplémentaires limités à spi/i2c/gpio, sans sudo/netdev/subuid/subgid.
- Cloud-init, les wizards userconfig/systemd-firstboot, SSH, génération de clés,
  interrupteur FAT SSH et attente NetworkManager-wait-online neutralisés.
- Aucun profil Wi-Fi ni pays préchargé. WirelessEnabled activé, états rfkill
  Bluetooth génériques de la base conservés. Cela ne valide pas les radios ni
  le futur ordre pays/scan/connexion, qui reste un contrat applicatif.
- SPI/I²C, i2c-dev et spi0-0cs configurés selon l'installation actuelle ;
  fonctionnement à qualifier sur le panneau physique.
- Premier boot : hostname individuel tiré de getrandom bloquant, état atomique
  avant fichiers hostname/hosts et hostname kernel. Reboot stable ; corruption
  bloquante. NM/Avahi/Bluetooth exigent le succès de cette initialisation.
- machine-id=uninitialized, initramfs, resize, fstab et unités de croissance
  upstream conservés ; hashes avant/après contrôlés. Voir
  [BASE-CUSTOMIZATION.md](BASE-CUSTOMIZATION.md).

Le hostname avant boot reste générique. Aucune identité app, clé, QR, photo,
base de données ou association créée au build. Payload, venv, helper/polkit/CLI
viendront de la release commune [APPLICATION-PAYLOAD.md](APPLICATION-PAYLOAD.md).

## Rapports par build

| Rapport | Portée |
|---|---|
| builder.json | Versions et capacité loop/FAT/ext4/chroot ARM64 sur fixtures. |
| firstboot-smoke.json | Vraies API getrandom/sethostname dans une UTS séparée, deux racines jetables, stabilité et hostname builder inchangé. |
| qualification-static.json | Comptes, fichiers, identités absentes, packages, masks et configuration. |
| systemd-verify.txt | Syntaxe/graphe des units, sans démarrage. |
| boot-preserved.sha256 | Kernel/initramfs/cmdline/fstab/grow identiques avant/après. |
| fsck-ext4.txt, fsck-fat.txt | Contrôle sans réparation des filesystems démontés. |
| filesystem-manifest.json | Tous fichiers hashés, modes/owners/liens, sans timestamps. |
| image-inspection.json | Inspection finale readonly, packages et hash image. |
| manifest.json, SHA256SUMS | Recette, hashes des rapports/image et transfert au Mac vérifié. |

Le manifeste intégral est réservé à ces images génériques, jamais à une SD
personnelle. Les gates de secrets ciblent les chemins connus : ils ne sont pas
un certificat exhaustif d'absence de secrets.

## Résultats et reproductibilité

Premier prototype : 61 gates statiques réussis, import dbus dans Python cible,
dpkg --audit vide, systemd-analyze verify sans erreur ni avertissement, export
hashé. **634 packages**, contre 633 dans la base. Kernel 6.18.50, firmware
1:1.20260907-1, NM 1.52.1-1+rpt4, BlueZ 5.82-1.1+rpt2 et Python 3.13.5-1
restent ceux de la base. Le smoke Linux séparé passe ses 13 contrôles.

Les tests couvrent cache corrompu, chemins dangereux, absence de données
sensibles dans les rapports, état firstboot invalide et dix points de coupure
simulée. Une exception ne reproduit pas une panne électrique de SD. **75 tests
passent sur macOS et Linux ARM64/Python 3.13**, après correction des permissions
explicites des fixtures qui dépendaient initialement du umask de l'hôte.

La CI GitHub est configurée pour ces fixtures et la syntaxe shell, sans build
privilégié ni matériel, avec actions officielles épinglées et permissions de
lecture seules. Son premier job (`inkyOS/actions/runs/36336690630`)
n'a toutefois pas démarré : GitHub signale un blocage de facturation/plafond
du compte. Aucun réglage administratif lu ou modifié ; ne pas présenter cette
CI comme verte.

Pour deux builds du même commit propre :

```sh
python3 scripts/compare-builds.py build/prototype.PREMIER build/prototype.SECOND --output build/comparison.json
```

La comparaison exige mêmes entrées et même contenu complet, modes/owners/liens
inclus, sans exceptions de chemins. L'égalité des hashes d'image est rapportée
séparément. Timestamps, xattrs/ACL, topologie des hardlinks, allocations et
journal ext4/FAT ne sont pas représentés par le manifeste : son égalité ne
signifie pas bit-for-bit.

Rejeu effectivement exécuté depuis **cf822c9, arbre propre** :
`prototype.nFixei9f` et `prototype.Vb8fnc8L`. Mêmes entrées, mêmes **74 018
entrées rootfs et 433 entrées boot**, aucune différence parmi les champs
comparés. Les SHA-256 des images diffèrent : aucune reproductibilité binaire
revendiquée. Chaque build passe 61 gates statiques, 13 contrôles smoke Linux,
systemd sans sortie, conservation des dix fichiers boot/grow et fsck ext4/FAT
sans réparation. Les exports ont été rehashés après transfert ; aucun loop
device n'est resté attaché. Les preuves compactes sont versionnées dans
[le relevé de validation](validation/2026-09-27-system-prototype.json).

## Ce qui manque pour l'image finale

1. Release Inky Studio qualifiée, payload/lock transitif/wheelhouse ARM64 épinglés
   et intégration commune des units/CLI/helper.
2. Contrats première adoption sans LAN, heure/TLS hors réseau, pays Wi-Fi,
   récupération physique. Aucun contournement implémenté ici.
3. SD dédiée, Pi/panneau identifié et vrais essais boot/resize/radios/GPIO,
   mémoire, coupures, adoption et rollback selon [SD-QUALIFICATION.md](SD-QUALIFICATION.md).

Aucun boot du kernel Pi, service en fonctionnement, écran, Wi-Fi ou Bluetooth
physique n'est qualifié par ces contrôles. La SD personnelle reste intacte.
