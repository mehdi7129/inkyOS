# Préparation hors ligne du partage PHOTO

`prepare-backend-update.py` prépare une **copie de la partition ext4 de la carte
actuelle**. Il ne sait pas ouvrir un périphérique, monter un filesystem,
exécuter le backend ou écrire sur la SD. Le bouton « Flasher » d’inkyImager ne
sert pas à cette opération conservatrice.

Le lot ciblé est fermé : backend `b75bf1e7…` vers `716104b1…`, Python 3.13,
trois modules Python et le `RECORD` observé. Les données utilisateur, la
configuration réseau, les identités et les fichiers installés supplémentaires
sont conservés. Aucun changement de schéma SQL n’est effectué.

## Entrées

- Workspace existant, privé `0700`, appartenant à l’utilisateur courant.
- `acquisition.json` et son SHA-256, produits par `inkyMaintenance acquire`.
  Le reçu doit attester une acquisition complète en lecture seule, un hash
  du flux et une relecture locale correspondante. Le backup est un fichier
  privé `0600` ou figé `0400`, dans ce même workspace.
- Delta Studio, wheel et manifeste de référence b75, avec leurs SHA-256
  explicitement fournis. Les artefacts publics `0644` sont acceptés ; les
  reçus et images privés restent limités à `0400/0600`.
- Outils locaux e2fsprogs 1.47.4 déjà installés. Les deux exécutables réellement
  utilisés (`debugfs` et `e2fsck`) sont vérifiés contre les hashes revus dans
  le script avant toute opération sur la copie.

Le script refuse les liens hôtes, fichiers à plusieurs hardlinks, objets
non réguliers, paths `/dev`, baselines modifiés et une préparation déjà
existante. Il exige la place de p2 plus une réserve de 1 GiB avant extraction.

## Étapes effectuées

1. Vérifier les pins, la fermeture du wheel et son `RECORD`, les trois modules
   autorisés, et l’absence de changement d’un autre membre du wheel par
   comparaison avec le manifeste b75. Aucun code livré n’est exécuté.
2. Relire le backup complet et comparer ses hashes au reçu : MBR, ensemble
   précédent p2 (FAT et gaps compris), p2, suffixe et contenu total. La
   géométrie est dérivée du MBR observé ; aucun numéro de disque ou offset
   historique n’est réutilisé.
3. Extraire p2 vers le nouveau `root-candidate.img`, privé `0600`. Une éventuelle
   récupération du journal s’effectue **sur cette copie uniquement**, via
   `e2fsck -p`. Une erreur nécessitant une réparation non automatique fait
   refuser la préparation ; le backup original reste intact.
4. Contrôler le profil LAN livré et l’absence d’état factory/TEST. Construire
   un inventaire logique du filesystem récupéré, contenant permissions,
   propriétaire, groupes, liens, attributs et hashes du contenu. Les fichiers
   privés sont hashés en flux, sans dump de contenu dans les logs ou stdout.
   Chaque valeur complète d’attribut étendu est lue dans un fichier temporaire
   `0600`, hashée avec son nom et sa taille, puis supprimée ; la liste abrégée
   de debugfs ne sert jamais de preuve du contenu. Les liens symboliques et
   les devices ext4 ne sont jamais suivis ou ouverts.
5. Vérifier tous les fichiers du manifeste b75, sauf le hash global du
   `RECORD` installé qui peut contenir des extras locaux. Vérifier les trois
   anciens modules et les trois anciennes lignes `RECORD` observées avant
   toute modification du package.
6. Remplacer les trois modules puis changer **uniquement leurs trois lignes**
   dans le `RECORD` installé. Les autres lignes sont conservées octet pour
   octet, même si elles décrivent des extras locaux (`INSTALLER`, caches,
   `direct_url.json`, etc.). Les quatre fichiers restent root:root `0644`.
7. Refaire l’inventaire complet et le comparer : mêmes noms et mêmes contenus,
   modes, UID/GID, liens et attributs pour tous les autres fichiers. Les
   répertoires gardent leur identité et leurs permissions ; leurs timestamps
   ou allocations internes ne constituent pas des données utilisateur.
8. Exécuter un fsck en lecture seule, hasher le candidat, le figer en `0400`,
   puis publier le reçu candidat et la requête destinée au writer natif.

Une préparation refusée ne publie pas de reçu `complete`. Les fichiers de
travail partiels sont conservés pour diagnostic ; ne pas relancer aveuglément
dans le même workspace et ne pas les confondre avec le backup vérifié.

## Invocation de préparation

Cet exemple n’écrit **aucun octet de la SD**. Les chemins privés et le hash du
reçu sont renseignés après l’acquisition réelle, pas avant.

```sh
python3 -I -B inkyImager/maintenance/prepare-backend-update.py \
  --workspace /chemin/prive700 \
  --receipt /chemin/prive700/acquisition.json \
  --receipt-sha256 SHA256_DU_RECU_REEL \
  --manifest /chemin/lot/package/installed-file-delta.json \
  --manifest-sha256 222a999014e8052cd63f19392d0c8a892cf42b2e066ccbfe250f5e92603d138c \
  --wheel /chemin/lot/package/wheel/inky_studio_server-0.5.0rc2-py3-none-any.whl \
  --wheel-sha256 c39afae429b6bc9e8cf387a191c714bfbc96bb6c92d29ce13884bc079a06bdfc \
  --reference-manifest /chemin/lot/package/reference/base-factory-bundle-manifest.json \
  --reference-sha256 6eda8438b7fe4a226ec77fef2d9b98c8521a030c52314f6956005b2054738d2a
```

## Sorties et contrat natif

Toutes les sorties restent dans le workspace privé :

- `root-candidate.img` : p2 uniquement, taille identique à p2 acquise, mode0400 ;
- `preparation/` : fsck et inventaires privés avant/après, payloads publics
  appliqués. Les logs ne contiennent pas de valeurs de credentials ;
- `candidate-approval.json` : version1, kind
  `inkyos-maintenance-candidate`, statut `complete`, pins du reçu, du backup et
  du candidat, backend parent/final, résultats des comparaisons et du fsck ;
- `write-root-request.json` : version1, UID courant, cible IOKit reprise du reçu,
  noms de fichiers du backup/candidat/reçu candidat et leurs pins.

Le reçu candidat rapporte les contrôles sur une copie. Il ne constitue ni un
flash effectué ni une qualification du boot/photo/partage sur matériel.
Le writer natif doit revalider les fichiers et la SD, écrire seulement p2,
relire cette plage intégralement, vérifier MBR/FAT/suffixe inchangés et traiter
l’éjection sans réécrire une partition déjà vérifiée.

## Tests

```sh
python3 -I -B -m unittest discover -s inkyImager/maintenance/tests -p 'test_*.py' -v
```

Les tests utilisent des images ext4 régulières de 32 MiB, des contenus de
credentials factices et des deltas/wheels synthétiques. Ils couvrent le
parcours complet, la récupération sur copie uniquement, les extras `RECORD`,
la conservation de fichiers/permissions/liens/devices, les attributs étendus
longs de 64/128 octets et leurs falsifications de même longueur, les mauvais hashes,
les chemins hors périmètre et la détection d’une corruption volontaire d’un
fichier protégé. Aucun Pi, SD, Bluetooth, Wi-Fi ou backend cible n’est utilisé.
