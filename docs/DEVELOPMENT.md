# Développer InkyOS sans carte SD

Un **prototype système sans Inky Studio** est assemblé depuis une base officielle
Lite ARM64 figée. Une [cible applicative expérimentale](APPLICATION-IMAGE.md)
installe maintenant un candidat épinglé avec services masqués. Aucun accès au
Pi ni à un disque physique lors de la construction. Le premier assemblage système
a réussi le 27 septembre 2026 ; aucune qualification SD.

## Utilisation sur Mac Apple Silicon

Prérequis : Python 3.11+ côté Mac, Lima 2.0+ et Git. Le Python Linux du builder
est 3.13. Les tests locaux ne nécessitent aucune dépendance Python externe.

```sh
make test
make test-linux     # fixtures Linux ARM64 + syntaxe shell, sans montage de l'image
make inspect       # facultatif : base seule en lecture seule
make prototype     # tests Mac/Linux, entrées vérifiées, assemblage, export contrôlé
make vm-stop
```

Chaque build crée `build/prototype.XXXXXXXX/inkyos-system-prototype.img` et ses
rapports. Aucun target ne flashe ni ne publie l'image. `cache/` et `build/` sont
exclus de Git. Le premier passage télécharge environ 516 Mio pour la base Pi,
plus Debian et les outils du builder. Chaque image décompressée fait 2,85 Gio.
Prévoir la source, les exports conservés et une copie transitoire dans la VM.
La VM utilise 2 CPU, 3 Gio RAM et un disque sparse de 16 Gio maximum. Sa copie
est retirée après export réussi ; les runs échoués restent pour diagnostic.

`make test-linux` copie uniquement les scripts, tests, locks et l'overlay
explicitement sélectionnés dans un dossier VM distinct. Il vérifie les hashes
puis exécute les fixtures sans privilèges. Le dossier `build/linux-tests.*`
conserve `inputs.json` (octets testés), `results.json` (Python + syntaxe shell)
et `tests.txt` hashé. La CI GitHub reste un contrôle séparé.

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
base de données ou association créée au build. Le prototype applicatif ajoute
payload/venv/helper/polkit/CLI du candidat commun, un compte helper non-root et
son groupe restreint ; son Wi-Fi reste désactivé et ses services masqués.
Voir [APPLICATION-IMAGE.md](APPLICATION-IMAGE.md).

## Rapports par build

| Rapport | Portée |
|---|---|
| builder.json | Versions et capacité loop/FAT/ext4/chroot ARM64 sur fixtures. |
| firstboot-smoke.json | Vraies API getrandom/sethostname dans une UTS séparée, deux racines jetables, stabilité et hostname builder inchangé. |
| qualification-static.json | Comptes, fichiers, identités absentes, packages, masks et configuration. |
| systemd-verify.txt | Syntaxe/graphe des units, sans démarrage. |
| boot-preserved.sha256 | Kernel/initramfs/cmdline/fstab/grow identiques avant/après. |
| fsck-ext4.txt, fsck-fat.txt | Contrôle sans réparation des filesystems démontés. |
| filesystem-manifest.json | Schema 2 : fichiers, modes/owners, racines, liens physiques, types spéciaux et xattrs/ACL/capabilities hashés ; sans timestamps. |
| image-inspection.json | Inspection finale readonly, packages et hash image. |
| manifest.json, SHA256SUMS | Recette, hashes des rapports/image et transfert au Mac vérifié. |

Le manifeste intégral est réservé à ces images génériques, jamais à une SD
personnelle. Les gates de secrets ciblent les chemins connus : ils ne sont pas
un certificat exhaustif d'absence de secrets.

La recette monte les partitions avec `noatime`, puis les remonte en lecture
seule avant l'inventaire complet. Les lectures de contrôle ne doivent pas
modifier les dates d'accès de la base. Le schema 2 distingue attributs inspectés
(éventuellement liste vide), API/filesystem non pris en charge et erreur de
permission (échec). Il n'assimile pas une ACL macOS à une ACL Linux.

## Revalider un export déjà produit

```sh
python3 scripts/verify-artifacts.py build/prototype.EXEMPLE --output build/export-verification.json
```

Ce contrôle relit intégralement l'image et tous les rapports déclarés, vérifie
tailles/hashes, recette, structure du manifeste et cohérence des gates PASS.
Il ne monte rien et n'exécute aucun code de l'image. Le build l'appelle après
l'export ; son rapport est écrit à côté du dossier, sous `build/prototype.*.integrity.json`.
Un manifeste local non signé n'est pas une preuve d'authenticité : ces hashes
détectent les incohérences, pas une falsification cohérente de tout le bundle.

## Résultats et reproductibilité

Premier prototype : 61 gates statiques réussis, import dbus dans Python cible,
dpkg --audit vide, systemd-analyze verify sans erreur ni avertissement, export
hashé. **634 packages**, contre 633 dans la base. Kernel 6.18.50, firmware
1:1.20260907-1, NM 1.52.1-1+rpt4, BlueZ 5.82-1.1+rpt2 et Python 3.13.5-1
restent ceux de la base. Le smoke Linux séparé passe ses 13 contrôles.

Les tests couvrent cache corrompu, chemins dangereux, absence de données
sensibles dans les rapports, état firstboot invalide et dix points de coupure
simulée. Une exception ne reproduit pas une panne électrique de SD. La suite
actuelle comprend **143 tests** : 140 exécutés et 3 skips sur macOS, 142 exécutés
et 1 skip sur Linux ARM64/Python 3.13. Les skips concernent les API Linux et
les privilèges de création de fichiers spéciaux. Les **14 fixtures du manifeste**
ont aussi été exécutées avec privilèges dans Linux : toutes passent, sans skip,
y compris les vrais xattrs/ACL et nœuds spéciaux jetables. Aucun accès matériel.

La CI GitHub est configurée pour ces fixtures et la syntaxe shell, sans build
privilégié ni matériel, avec actions officielles épinglées et permissions de
lecture seules. La CI n° `36336690630`
n'a toutefois pas démarré ; les validations locales sont consignées séparément.
Ce résultat historique ne doit pas être présenté comme une CI réussie.

Pour deux builds du même commit propre :

```sh
python3 scripts/compare-builds.py build/prototype.PREMIER build/prototype.SECOND --verify-images --output build/comparison.json
```

La comparaison exige mêmes entrées et mêmes enregistrements, sans exceptions
de chemins. Elle revalide les rapports avant de les comparer. `--verify-images`
relit aussi les deux images ; sans cette option, l'égalité binaire reste
inconnue (`image_byte_identical: null`), même si les hashes enregistrés sont
égaux. Le schema 1 historique reste accepté avec ses limites ; mélanger schema
1 et 2 est refusé, car leurs périmètres diffèrent. Les timestamps, allocations,
flags internes et journal ext4/FAT restent hors du manifeste : son égalité ne
signifie pas bit-for-bit. L'[analyse des octets](REPRODUCIBILITY.md) précise
les causes mesurées sur les deux paires de builds.

Rejeu effectivement exécuté depuis **cf822c9, arbre propre** :
`prototype.nFixei9f` et `prototype.Vb8fnc8L`. Mêmes entrées, mêmes **74 018
entrées rootfs et 433 entrées boot**, aucune différence parmi les champs
comparés. Les SHA-256 des images diffèrent : aucune reproductibilité binaire
revendiquée. Chaque build passe 61 gates statiques, 13 contrôles smoke Linux,
systemd sans sortie, conservation des dix fichiers boot/grow et fsck ext4/FAT
sans réparation. Les exports ont été rehashés après transfert ; aucun loop
device n'est resté attaché. Les preuves compactes sont versionnées dans
[le relevé de validation](validation/2026-09-27-system-prototype.json).

Deuxième paire depuis **0157714, arbre propre**, avec manifeste schema 2 :
`prototype.DT7ciqAq` et `prototype.Pe2cY9Za`. Mêmes entrées, mêmes **74 019
entrées rootfs et 434 entrées boot**, dont 628 entrées liées physiquement et
une entrée portant des ACL. Les racines sont maintenant incluses. Tous les
xattrs ont été inspectés ; aucune différence du contenu attesté. Les mêmes
61 gates, 13 contrôles smoke, systemd, conservation boot/grow et fsck passent.
L'export est revalidé et les deux images rehashées par le comparateur.

La lecture `noatime` et l'inventaire readonly suppriment les 73 469 écarts
limités aux dates d'accès de la première paire. Il reste 888 blocs ext4
différents, contre 10 327 auparavant : timestamps, journal et allocations
varient encore. **Aucune identité binaire revendiquée.** La nouvelle
[preuve compacte](validation/2026-09-27-system-prototype-v2.json) conserve les
hashes et distingue le commit des images de la correction suivante du
validateur applicatif. Les 115 tests incluent cette correction ; elle ne change
aucun fichier de la recette système.

## Ce qui manque pour l'image finale

L'[audit Python](PYTHON-COMPATIBILITY.md) vérifie les métadonnées des dépendances
du source applicatif transmis, sans installer ni exécuter l'app. Le runtime
générique et Hatchling se résolvent en wheels compatibles ; l'extra Pi complet
ne se résout pas exclusivement depuis PyPI pour `RPi.GPIO` et `spidev`.
Un [essai natif séparé](NATIVE-WHEELS.md) a depuis produit ces deux wheels
ARM64/cp313 ; leurs octets concordent entre deux builds. Le candidat applicatif
`6a697d1` fournit maintenant un lock de 40 wheels, dont `editables`. Son
[installation et smoke d'import/API offline](OFFLINE-QUALIFICATION.md) passent
dans un venv neuf de la VM, après contrôle des archives. Aucun de ces résultats
n'est une qualification du rootfs exact de l'image ou du matériel.

L'[intégration dans le rootfs](APPLICATION-IMAGE.md) a ensuite été exécutée deux
fois au commit `1ee27e2` : installation offline et contrôles statiques réussis,
contenu et métadonnées comparées identiques, services applicatifs masqués. Les
modèles premier boot sans LAN avancent séparément ; la suite atteint 216 tests
sur Mac/Linux, sans preuve de démarrage matériel.

1. Release Inky Studio qualifiée, payload/lock transitif/wheelhouse ARM64 épinglés
   et intégration commune des units/CLI/helper.
2. Contrats première adoption sans LAN, heure/TLS hors réseau, pays Wi-Fi,
   récupération physique. Aucun contournement implémenté ici.
3. SD dédiée, Pi/panneau identifié et vrais essais boot/resize/radios/GPIO,
   mémoire, coupures, adoption et rollback selon [SD-QUALIFICATION.md](SD-QUALIFICATION.md).

Aucun boot du kernel Pi, service en fonctionnement, écran, Wi-Fi ou Bluetooth
physique n'est qualifié par ces contrôles. Les installations hors banc restent intactes.
