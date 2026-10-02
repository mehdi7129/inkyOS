# Récupération privée de la SD d'enrôlement

La SD bootée contient une identité neuve et peut contenir une clé hôte privée.
Sa copie complète reste locale, dans un dossier `private/` ignoré par Git ;
aucune extraction, publication ou lecture directe du fichier de clé privée.
Une copie brute peut également contenir des octets non alloués du filesystem.

## Acquisition sur le Mac

Identifier à chaque insertion le disque entier, sa capacité et son objet
IORegistry. `scripts/acquire-sd-macos.py` reprend la garde du flasheur, mais
ouvre le raw device **en lecture seule**. Cette garde exige actuellement un
média SD inscriptible, même pour l'acquisition. La destination doit être un
nouveau dossier enfant direct de `private/` (0700), sans symlink ni ancêtre
modifiable par groupe/autres.

```sh
python3.13 -I scripts/acquire-sd-macos.py \
  --device DISQUE_IDENTIFIE --capacity-bytes CAPACITE_OBSERVEE \
  --registry-id IDENTIFIANT_IOREGISTRY_OBSERVE \
  --output-dir CHEMIN_ABSOLU/private/sd-acquisition.NOUVEL_ESSAI \
  --owner-uid UID_OPERATEUR --owner-gid GID_OPERATEUR --progress
```

Sans `--acquire`, cette commande est un dry-run sans démontage ni copie.
Après validation, la même commande avec `sudo` et `--acquire` nécessite
l'authentification macOS de l'opérateur ; le mot de passe se saisit directement
dans Terminal. UID/GID doivent alors correspondre à `SUDO_UID`/`SUDO_GID`.
Le script ne crée aucun accès administrateur permanent.
`--progress` affiche les phases `copy` et `local_readback`, le pourcentage et
les compteurs sur stderr ; stdout reste exclusivement le résultat JSON.

L'acquisition démonte seulement le disque identifié et lit sa capacité entière,
sans écrire sur le raw device. Les blocs entièrement nuls deviennent des trous
dans le fichier local : aucun octet lu n'est omis du hash ou de l'image logique.
La taille finale est imposée, puis la copie locale est relue et son SHA-256
comparé au flux d'acquisition. Cela ne constitue pas une seconde lecture de
la SD. L'espace libre initial doit néanmoins couvrir sa capacité complète.

`returned.img` et `acquisition.json` sont privés (0600). Une erreur conserve
les fichiers partiels ; ni écrasement ni reprise implicite. N'utiliser la copie
que si le reçu indique `status=complete`, `copy_complete=true` et
`local_readback_verified=true`, après recoupement de taille/hash. Le script
n'éjecte pas la SD automatiquement. Un démontage peut synchroniser des écritures
déjà en attente dans macOS ; il ne transforme pas le passage précédent par un
montage FAT writable en acquisition forensique depuis l'insertion.

## Contrôle Linux sur la copie

Le Mac ne monte pas ext4 nativement. Utiliser le builder dédié sans partager
le dossier privé entier. Transférer uniquement l'image acquise et les fichiers
explicitement admis par le runner ; jamais la clé client opérateur.

La configuration initiale de la VM est de 16 GiB. Pour la copie Qumox complète
et l'export attendu, elle a été portée localement à 32 GiB puis son filesystem
vérifié. L'[extension de disque Lima](https://lima-vm.io/docs/config/disk/)
se fait, VM arrêtée, avec `limactl edit --tty=false --disk 32 inkyos-build`.
Vérifier aussi l'espace physique libre du Mac ; conserver les trous lors du
transfert d'une image sparse, sans supposer que les secteurs libres sont nuls.

Le runner `scripts/check-test-enrollment-return-linux.sh` attend un staging
root-owned 0700, sous `/var/lib/inkyos-build/enrollment-return.<8hex>` ou
`/mnt/inkyos-return.<8hex>`. Son `--help` décrit les 30 fichiers admis et leurs
permissions : runner, neuf sources, dix-neuf fichiers de l'export attendu et
`returned.img`, tous liés par `inputs.json` et son hash explicite. Les images
attendue et retournée sont rehashées avant les montages.

```sh
sudo bash STAGING/check-test-enrollment-return-linux.sh \
  STAGING INPUTS_SHA256 TAILLE_COMPLETE_RETOUR SHA256_RETOUR
```

Le loop est readonly ; ext4 est monté `ro,noload,noatime,nosuid,nodev,noexec`,
FAT `ro,noatime,nosuid,nodev,noexec`, dans des namespaces privés sans réseau.
Le contrôleur existant compare l'état ext4 et le rapport FAT à l'export attendu.
Le runner conserve son résultat fermé et ses codes 0/1/2, sauf erreur
d'infrastructure ou de cleanup (code 2). Un PASS ne déclenche aucune activation.
Les fichiers de rapport du runner restent privés, notamment le hash de la
copie retournée. Après exécution, contrôler extérieurement l'absence de loops
et montages avant toute suppression d'une copie temporaire.

Le banc `probe-test-enrollment-return-linux.sh` reste réservé au refus attendu
sur l'image non bootée ; il n'est pas une procédure de retour positif.

Les [preuves des outils](validation/2026-10-03-sd-recovery-tools.json) lient
64 fixtures ciblées Mac, la CI et un essai natif du nouveau runner sur une copie
de l'image non bootée. Les dix contrôles d'infrastructure passent ; le contrôleur
retourne bien `FAIL / return_incomplete`, code 1. Un contrôle externe confirme
l'absence de montages/loops et le hash inchangé des deux copies avant leur
suppression dans la VM. L'export privé original reste conservé sur le Mac.

## Retour physique du 3 octobre 2026

l’opérateur confirme avoir démarré le Pi avec la SD écrite, constaté son arrêt puis
remis la carte dans le Mac. Le rapport FAT est récupéré dans une copie privée.
Son schéma passe ; le challenge, le profil, les pins et le runtime correspondent
à l'export local. Il déclare `enrolled`, mais **la lecture FAT seule ne vérifie
pas l'état ext4**. Les deux observations panneau/radio sont `blocked`, sans
donnée exploitable. Le runtime réduit actuellement les causes de refus à cet
état commun : une EEPROM inconnue, un accès impossible ou un timeout ne peuvent
pas être distingués depuis ce seul rapport.

La [preuve préliminaire](validation/2026-10-03-sd-enrollment-return-preliminary.json)
conserve cette limite ; l'écran, la radio et l'app ne sont pas qualifiés.

L'acquisition complète est ensuite terminée : 15938355200 octets lus avec un
descripteur raw readonly, puis relus dans la copie locale avec le même SHA-256.
Le premier essai interrompu à 2185232384 octets reste conservé. La relance dans
ce même dossier a été refusée avant ouverture raw ; le nouvel essai utilise
une autre destination et affiche sa progression.

Les secteurs libres ne sont presque pas nuls : la copie sparse consomme
15925772288 octets. Une compression locale gzip niveau 1 produit une archive
privée de 970146017 octets. Le flux source est rehashé, puis l'archive entière
est décompressée pour vérifier taille et hash contre le reçu d'acquisition.
Archive, répertoire et preuves sont synchronisés avant de retirer la copie
raw générée sur le Mac. Cette opération ponctuelle conserve les octets exacts,
ne touche pas la SD et ne supprime pas le premier essai interrompu ; ce n'est
pas encore une commande de compression packagée dans le dépôt.

La copie est reconstruite dans la VM dédiée et rehashée. Le runner termine
avec dix contrôles d'infrastructure réussis et **21/21 contrôles du retour
réel**, exit 0, PASS. État ext4 `enrolled`, profil, rapport FAT, runtime et clé
publique hôte sont liés à l'export attendu. Le fichier de clé privée n'est pas
lu directement ; il reste inclus dans le conteneur privé copié et hashé.

Une inspection complémentaire readonly confirme les scripts/unité installés,
leurs permissions, la configuration I²C/SPI, `i2c-dev` et la présence de `iw`.
Aucun journal persistant n'est disponible et aucune cause des sondes bloquées
n'est confirmée. Les contrôles externes constatent zéro loop/montage restant.
La [preuve réduite du retour](validation/2026-10-03-sd-enrollment-return.json)
ne contient ni identité, challenge, clé, ni hash de la SD retournée. Ce PASS
vérifie la cohérence des fichiers ; il ne qualifie pas l'écran, la radio,
l'app ou la release. Un prochain boot de diagnostic doit conserver les erreurs
fermées des sondes plutôt que leurs seules observations réduites.
