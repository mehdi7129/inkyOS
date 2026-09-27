# Reproductibilité : mesure des deux prototypes système

Audit du 27 septembre 2026 : **les entrées et le contenu inventorié sont
identiques ; les images disque ne sont pas identiques octet pour octet**.
Pour cette étape, viser une recette figée, des attestations de contenu complètes
et le SHA-256 de chaque image livrée est le niveau utile. La qualification SD
reste distincte ; ces images ne contiennent encore aucune application.

## Périmètre et preuves

Deux builds du commit propre `cf822c943bebce02db246f0554503514e2aa671d`, même
recette et mêmes entrées épinglées, de **3 061 841 920 octets chacun** :

| Build | SHA-256 de l'image, recalculé intégralement |
|---|---|
| `prototype.nFixei9f` | `b14eff0eecf6f5543f5a8d1d566c17d24af89a5ca9eb22423772658dfa92a743` |
| `prototype.Vb8fnc8L` | `d7b204c12fea649d5c014aa726162d2088f9137eca8e6022b537c64dcb7fa597` |

Les deux `filesystem-manifest.json` sont strictement identiques, SHA-256
`215665deafa7fa96697081f3c0366d6671f3f295d2a0e4d7d59f42b3074c082e` :
74 018 entrées rootfs et 433 entrées bootfs. Leur schema 1 couvre les chemins,
types, modes, UID/GID, tailles/hashes des fichiers, cibles des symlinks et
numéros de devices. Il ne couvre pas les timestamps, les xattrs/ACL/capabilities,
les relations de hardlinks ni les allocations disque : ne pas lui attribuer
une preuve sur ces champs absents. L'attestation doit annoncer son périmètre.

Analyse sur Mac uniquement : sources ouvertes `rb`, mappings `ACCESS_READ`,
aucun montage, chroot, service ou accès Pi. Les octets ont été comparés sur
toute la taille des deux images ; les blocs différents ont ensuite été
interprétés suivant leur structure FAT/ext4. Aucune image n'a été réécrite.
Les rapports locaux non versionnés sont dans `build/repro-audit/` :
`byte-comparison.json`, `ext4-classification-v2.json`, `summary.json` ; les
scripts d'analyse ponctuelle sont `scan-bytes.py` et `classify-ext4.py`.
Ils ne font pas partie de la recette de production.

## Où diffèrent les octets

| Région | Début en octets | Taille | Octets différents | Blocs de 4 KiB différents |
|---|---:|---:|---:|---:|
| MBR et espace avant partitions | 0 | 8 388 608 | 0 | 0 |
| FAT32, partition 1 | 8 388 608 | 536 870 912 | 4 | 2 |
| ext4, partition 2 | 545 259 520 | 2 516 582 400 | 3 663 559 | 10 327 |

Il n'y a pas d'espace après la partition 2. La table de partitions et
l'identifiant MBR sont donc identiques. Tous les écarts FAT sont des champs
temporels de deux entrées de répertoire : trois octets pour la création et
dernière écriture de `INKYOS.TXT`, un octet pour la dernière écriture de
`CONFIG.TXT`. Leurs offsets d'entrée dans la partition sont respectivement
8 276 352 et 9 339 232. Les autres octets FAT, y compris tables d'allocation,
boot sector et fichiers, sont égaux. Les champs ont été identifiés avec
[`struct msdos_dir_entry` du noyau Linux](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/msdos_fs.h#L157-L168).

Répartition exhaustive des **10 327 blocs ext4 différents**, catégories
mutuellement exclusives :

| Catégorie | Blocs | Octets différents |
|---|---:|---:|
| Superblock principal | 1 | 15 |
| Descripteurs de groupes | 1 | 4 |
| Bitmap d'allocation de blocs | 1 | 18 |
| Tables d'inodes | 4 624 | 661 297 |
| Blocs de répertoires | 10 | 39 |
| Journal, inode 8 | 5 499 | 2 392 055 |
| Blocs alloués dans une image et libres dans l'autre | 98 | 282 249 |
| Blocs de fichiers alloués dans les deux images | 79 | 270 800 |
| Blocs libres dans les deux images | 14 | 57 082 |

Les 15 octets du superblock concernent ses heures de montage/écriture, le
suffixe du chemin de montage temporaire, le compteur de KiB écrits et son
checksum. Les derniers montages sont à 17:24:11 et 17:27:15 UTC. Le chemin
`/var/tmp/inkyos-work/prototype.<suffixe>/root` est conservé dans ce champ,
pas un chemin personnel du Mac. La structure est documentée dans le
[superblock ext4 officiel](https://www.kernel.org/doc/html/latest/filesystems/ext4/super.html).

**73 593 slots d'inodes** diffèrent : 73 588 sont alloués des deux côtés,
5 libres des deux côtés. Tous présentent des différences d'atime, de sa
fraction de seconde et de checksum ; **73 469 ne diffèrent que sur ces
champs**. Parmi l'ensemble, 124 ont aussi des ctime différents, 89 des mtime,
92 des dates de création et numéros de génération différents, et 61 des
adresses de blocs différentes. Les bitmaps d'inodes restent identiques.
Ces champs sont décrits dans la
[structure officielle des inodes](https://www.kernel.org/doc/html/latest/filesystems/ext4/inodes.html).

Les **61 fichiers déplacés** ont été relus logiquement à travers leurs
extents : leurs octets sont identiques entre images et leurs tailles/hashes
correspondent aux deux manifestes. Comparer le même offset disque compare
donc parfois deux fichiers différents. Les dix blocs de répertoires ne
diffèrent qu'à leurs quatre derniers octets, le checksum : celui-ci dépend
notamment du numéro de génération de l'inode, même lorsque les entrées sont
égales. Voir [extents](https://www.kernel.org/doc/html/latest/filesystems/ext4/ifork.html)
et [checksums de répertoires](https://www.kernel.org/doc/html/latest/filesystems/ext4/directory.html).

Les écarts de journal sont localisés dans les extents de l'inode 8 ; ils ne
constituent pas des différences de fichiers visibles. Les 14 blocs libres
sont libres selon les deux bitmaps, mais conservent des octets différents.
Leur provenance exacte après suppressions n'a pas été attribuée ; aucun
contenu résiduel n'est publié. Le journal est une structure transactionnelle
distincte des fichiers courants :
[documentation jbd2](https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html).
Le décodeur ponctuel ne remplace pas `e2fsck` ; il n'interprète pas le mapping
indirect de l'inode réservé 7, sans laisser de bloc différent non classé ici.

## Correction simple et limite à conserver

La recette mesurée monte ext4/FAT en écriture sans `noatime`, puis lit les
arbres, notamment tous les fichiers pour le manifeste. Les atime anciens
de la base sont donc susceptibles d'être actualisés. C'est une explication
fortement étayée du grand nombre d'écarts atime seuls, pas une mesure avant/
après d'une correction. `SOURCE_DATE_EPOCH` transmis à `dpkg` ne fige pas
l'horloge des montages ni toutes les métadonnées du filesystem.

**Recommandation transmise au responsable de la recette : ajouter `noatime`
aux deux montages de personnalisation, avant toute lecture.** Coût faible :
deux options de montage ; pas de changement du format, de `fstab`, du
premier boot ni du protocole applicatif. Cela empêche les lectures d'audit
de mettre à jour les dates d'accès, répertoires compris. Le comportement est
défini dans le [manuel officiel de mount](https://github.com/util-linux/util-linux/blob/v2.41.2/sys-utils/mount.8.adoc).
Deux nouveaux builds seront nécessaires pour chiffrer le gain : les mesures
ci-dessus concernent exclusivement les deux images antérieures à ce changement.

Cette option ne normalise ni les créations/écritures, ni les générations
d'inodes, ni l'allocation, ni le journal, ni les champs du superblock. Elle
ne suffit donc pas à annoncer une image reproductible octet pour octet.
Forcer ces données après coup serait un chantier plus coûteux et risqué :
les checksums ext4 couvrent plusieurs structures liées, et les données
libres/journalisées resteraient à traiter. Éviter les patches binaires
d'inodes ou de journal ; leur cohérence est décrite dans les
[règles de checksum ext4](https://www.kernel.org/doc/html/latest/filesystems/ext4/checksums.html).

Pour v0, conserver le niveau explicite **mêmes entrées + même contenu attesté**,
avec vérifications de filesystem et qualification SD, puis publier le digest
exact de l'artefact choisi. La croissance Raspberry Pi, les identités créées
au premier boot et la récupération doivent rester qualifiées séparément.
Une exigence future d'égalité binaire demanderait un objectif et un budget
propres ; elle ne justifie pas de recomposer la distribution à ce stade.

## Annexe : deuxième paire après `noatime` et inventaire en lecture seule

Nouvelle mesure du 27 septembre 2026, après export complet des deux builds du
commit propre **`01577141b0a4e7e177ccb73a7060a16d30475d33`**. Les premières
mesures ci-dessus restent historiques. La nouvelle recette utilise `noatime`
dès les montages de personnalisation, puis remonte les filesystems en lecture
seule avant l'inventaire. Elle produit aussi le manifeste filesystem schema 2.

| Build | SHA-256 recalculé intégralement, conforme au manifeste |
|---|---|
| `prototype.DT7ciqAq` | `5dbf220f12c9cd9fcde449aa3288358566e9b4f5e450e3dda9d803b30ef75371` |
| `prototype.Pe2cY9Za` | `2b2d0f6300db2a4ff924aa2310205400cb54f27af438ced292d75fcf703c29a1` |

Les images font encore 3 061 841 920 octets. Les deux recettes sont identiques
et les deux attestations filesystem schema 2 sont strictement égales :
SHA-256 `7d1b82aec9d8dbe94f7a40314a470e68d80bfc3b129d9d8e3951744c2274766d`,
**74 019 entrées rootfs et 434 bootfs**, racines incluses. Le périmètre est
désormais `content-and-metadata-without-timestamps`, avec xattrs et relations
de hardlinks représentés. Les rapports locaux `prototype.<suffixe>.integrity.json`
indiquent PASS et vérification SHA des images ; ils ne constituent toujours
ni une signature d'origine ni une qualification matérielle.

| Mesure | Première paire, sans `noatime` | Nouvelle paire |
|---|---:|---:|
| Octets différents MBR/espace initial | 0 | 0 |
| Octets différents FAT | 4 | 4 |
| Blocs ext4 différents, 4 KiB | 10 327 | **888** |
| Octets différents ext4 | 3 663 559 | **1 737 660** |
| Slots d'inodes différents | 73 593 | **124** |
| Inodes avec différences limitées à atime/checksums | 73 469 | **0** |
| Blocs différents dans les tables d'inodes | 4 624 | **45** |
| Octets différents dans les tables d'inodes | 661 297 | **2 817** |
| Blocs différents dans le journal | 5 499 | **552** |

Le nombre de blocs ext4 différents baisse de **91,4 %**, celui des octets
différents de **52,6 %** entre ces deux paires. L'absence d'écarts atime seuls
confirme l'effet attendu de la protection des lectures. Ce n'est cependant
pas une expérience isolant chaque option : le remount readonly et l'inventaire
schema 2 ont également changé, et les allocations varient entre exécutions.
Ne pas attribuer tout le gain du journal ou des blocs de données à `noatime` seul.

Décomposition exhaustive de la nouvelle partition ext4 :

| Catégorie | Blocs différents | Octets différents |
|---|---:|---:|
| Superblock principal | 1 | 14 |
| Descripteurs de groupes | 1 | 4 |
| Bitmap de blocs | 1 | 34 |
| Tables d'inodes | 45 | 2 817 |
| Répertoires, checksum seul | 10 | 38 |
| Journal | 552 | 833 142 |
| Alloués dans une image, libres dans l'autre | 244 | 800 265 |
| Fichiers alloués dans les deux images | 4 | 11 316 |
| Libres dans les deux images | 30 | 90 030 |

Les 124 slots différents comprennent 119 inodes alloués et 5 libres des deux
côtés. Les 92 atime encore différents concernent aussi des créations ou
modifications d'inodes ; aucun ne diffère seulement par une lecture.
Les 59 fichiers dont le mapping de blocs diffère ont été reconstruits via
leurs extents et hashés : **contenus logiques identiques et conformes aux
manifestes**. Les dix blocs de répertoires ne diffèrent toujours que par
checksum. Les quatre octets FAT restent les mêmes catégories temporelles de
`INKYOS.TXT` et `CONFIG.TXT`, sans différence de leurs données.

Méthode et restrictions identiques à l'audit initial : lecture directe sur
Mac, aucune VM, aucun montage ou fichier image modifié. Les résultats sont
conservés sous `build/repro-audit/byte-comparison-noatime.json`,
`ext4-classification-noatime.json` et `summary-noatime.json` ; les sommes de
catégories ont été vérifiées contre la comparaison brute intégrale.
**Le contenu attesté est reproductible pour cette paire ; les images restent
différentes octet pour octet.** La recommandation v0 et les limites de
qualification restent donc inchangées.
