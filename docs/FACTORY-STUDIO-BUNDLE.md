# Expected Studio bundle — planner statique

`scripts/plan-factory-studio-bundle.py` calcule les records attendus d'un bundle
à installer sous `/usr/lib/inky-studio`. Il ne crée pas de venv, ne lance aucun
enfant, pip, build backend ou code candidat, et ne touche aucune image. Les
records sont dérivés des octets épinglés **avant** tout futur build ; les hashes
d'une sortie pip ou d'un arbre observé ne sont jamais promus en expected.

La validation de ce lot porte uniquement sur des fixtures ZIP synthétiques.
Aucune wheel app réelle ni aucun candidat factory n'est fourni ou qualifié par
ce changement. Les pins TEST, le support exporter `096a…`, le contrat runtime et
Studio restent inchangés.

## Entrées fermées

Le manifest d'entrée a exactement ces champs :

```json
{
  "schema_version": 1,
  "kind": "factory-studio-bundle-inputs",
  "studio_commit": "<40 caractères hexadécimaux minuscules>",
  "python_version": "3.13.5",
  "app_wheel": "inky_studio_server-1.0.0-py3-none-any.whl",
  "source_sha256": {
    "scripts/inky-network-helper.py": "<SHA-256>"
  },
  "wheel_sha256": {
    "inky_studio_server-1.0.0-py3-none-any.whl": "<SHA-256>"
  }
}
```

Cet exemple est descriptif, pas un input utilisable. La sérialisation exigée est
JSON ASCII, clés triées, séparateurs `(',', ':')`, suivie d'un LF. Le SHA-256
obligatoire porte sur ces octets exacts. Les clés inconnues ou dupliquées,
booléens à la place d'entiers, valeurs non finies et encodages non canoniques sont
refusés. La version Python est `3.13.<entier sans zéro initial>`.

Les fichiers sources sont relatifs au bundle ; seuls
`scripts/inky-network-helper.py` (obligatoire) et `client/dist/<fichiers>` sont
acceptés. Il n'y a pas de copie de checkout ou de configuration de build.
Le répertoire sources contient exactement les fichiers épinglés et leurs
parents nécessaires, sans répertoire vide supplémentaire. Le wheelhouse contient
exactement les fichiers `.whl` épinglés, à plat. Les sources, le wheelhouse et
le manifest d'entrée ne peuvent se recouvrir.

`app_wheel` désigne un fichier wheel préconstruit réellement fourni, pas une
instruction pour le construire ni un substitut editable. Il doit contenir
`inky_web/__init__.py`, `inky_web/main.py` et un METADATA dont Name/Version
correspondent au nom de wheel. Une autre wheel ne peut fournir ni `inky_web/`
ni un module `inky_web.*`. Les dépendances restent une liste explicite de wheels :
le planner ne résout ni ne vérifie la satisfaction de `Requires-Dist`.

Les contrôles wheel réutilisent ceux du verifier exporter : RECORD exact, SHA-256
et longueurs internes, métadonnées WHEEL/tags, noms canoniques, absence de membre
spécial ou de bits privilégiés et limite de 64 MiB par archive/payload wheel.
Le parser commun accepte un argument keyword-only `allowed_filename_tags` :
sa valeur par défaut `None` conserve exactement les deux familles de l'exporter,
`py3-none-any` et `cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64`.
La politique Studio est une constante fermée de neuf triplets filename :

```text
py3-none-any
py2.py3-none-any
cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64
cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64
cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64
cp313-cp313-manylinux_2_27_aarch64.manylinux_2_28_aarch64
cp313-cp313-linux_aarch64
cp311-abi3-manylinux_2_34_aarch64
cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64
```

Ces noms correspondent aux familles des wheels inventoriées pour CPython 3.13.5
avec GIL, Linux ARM64/glibc 2.41. Leur admission ne sélectionne pas de nouvelle
version ni ne prouve la compatibilité des octets. Aucun tag n'est renommé ; les
tags développés du fichier WHEEL doivent toujours correspondre exactement au
produit cartésien des composants filename. La CLI et le manifest d'entrée ne
peuvent modifier cette politique. Le planner et le second passage de l'installer
utilisent le même adapter Studio ; aucun état global du parser exporter n'est
modifié.

Cet adapter ajoute un **préflight statique des headers natifs**, absent du parser
exporter. Tout basename `.so` ou contenant `.so.` et tout payload portant la
signature ELF doivent fournir au moins les 64 octets d'un header ELF64,
little-endian, version 1, machine AArch64 (183), avec version du header 1 et
taille de header 64. Les shared objects `.so`/`.so.*` doivent annoncer ET_DYN (3).
La politique Studio refuse ces objets dans une wheel portant la plateforme
`any`, même avec un RECORD valide. Les autres payloads restent des octets opaques.
Ce contrôle ne charge aucun objet et ne valide ni symboles ABI3, ni dépendances
du loader, ni instructions CPU, ni imports, ni drivers ou matériel. Les limites
existantes restent inchangées. La fermeture `Requires-Dist`/`Requires-Python`
reste une validation séparée ; aucun reçu de ce lot ne l'atteste.

Les chemins de hooks `.pth`, `.egg-link`, sitecustomize/usercustomize, code généré
`.pyc`/`__pycache__`, `.data`, fichiers editable, `.egg-info`, répertoires VCS et
configurations de build connues sont refusés. Aucun script console n'est généré
depuis `entry_points.txt`. Les collisions entre wheels, fichiers et répertoires,
les symlinks, hardlinks et fichiers spéciaux des inputs sont refusés. Les limites
globales sont 128 wheels, 20 000 fichiers sources/délivrés, 256 MiB de payload,
100 000 records et 32 MiB de manifest produit ; le manifest d'entrée est borné
à 1 MiB.

Cette whitelist ne constitue pas un audit de privacy. Un fichier JS ou METADATA
peut contenir des données privées ; sa publication requiert une revue séparée.
Un SHA fourni par le caller n'atteste pas non plus l'origine de la wheel, son lien
au commit déclaré, son processus de build ou son comportement. Ces obligations
restent à établir pour le futur candidat réel.

## Sorties et API

```python
manifest_bytes, receipt = plan(input_manifest, input_sha256, sources_dir, wheels_dir)
receipt = publish_plan(input_manifest, input_sha256, sources_dir, wheels_dir,
                       output=output_path, receipt_output=receipt_path)
```

L'API reçoit des `Path` absolus et canoniques. Le module charge uniquement les
helpers OS du dépôt : `verify-factory-exporter-rootfs.py`, `manifest-rootfs.py`,
`install-application-rootfs.py` et, transitivement, `inspect-application-archives.py`.
Aucun module des inputs n'est importé. Les erreurs exposent `Refused.reason`.

La CLI exige `--input-manifest`, `--input-sha256`, `--sources-dir`, `--wheels-dir`,
`--output` et `--receipt`. Les répertoires de sortie doivent déjà exister dans un
workspace de confiance. Tous les inputs et les deux destinations sont validés
avant la première écriture. Les sorties sont créées exclusivement, sans
écrasement, en mode `0644` sous l'identité du planner. Une erreur I/O après la
première création peut laisser une sortie partielle : aucune réparation,
suppression ou transaction multi-fichiers n'est revendiquée. Une sortie
préexistante impose un refus au prochain essai.

Le manifest a exactement le schéma runtime déjà fixé :

```json
{"schema_version":1,"kind":"factory-studio-bundle-manifest","studio_commit":"<commit>","records":{}}
```

`records` est relatif à `/usr/lib/inky-studio`, inclut `.` et exclut uniquement
son propre `manifest.json`. Le venv attendu est fixé à `server/.venv`, sans
editable, avec les symlinks Python/lib64 et la configuration sans system site
de l'exporter. Son interpréteur final est `/usr/bin/python3.13`. Toutes les
directories attendues sont root:root `0755`, les fichiers `0644`, sauf le helper
`0555`, et les symlinks `0777`.

Les records `xattrs: {status: inspected, entries: {}}` expriment **l'état attendu
du futur arbre installé** selon le format d'inventaire. Ils n'affirment pas une
inspection des xattrs des inputs locaux. Le receipt distingue cette sémantique
avec `record_metadata: expected-root-owned-no-xattrs` ; le planner ne change
aucun owner local et ne qualifie aucune métadonnée d'image.

Le receipt `scope: factory-studio-bundle-plan-only` contient les SHA des octets
d'entrée et du manifest produit, le commit déclaré et les comptes de fichiers,
wheels et records. Il déclare `image_code_executed: false` et
`application_candidate_qualified: false`. Aucun manifest runtime, boot context,
Ready, autorité ou credentials n'est produit.

## Limites d'intégration

Le mapping actuel `CLIENT_DIST` de Studio fondé sur `parents[2]/client/dist`
ne désigne pas le frontend externe attendu après installation non editable.
Ce planner conserve les chemins livrables et ne corrige ni ne prouve le frontend.
Les imports, dependencies, resource paths et le fonctionnement réel de l'app
nécessitent leur propre revue et validation.

Le support système factory renouvelé, les sources guardées Studio, la revue
ELF/loader/OpenSSL, les identités, le build sous UID1000, la vérification postbuild,
le graphe d'activation et le hardware sont hors de ce lot. Un futur installer
devra revérifier les mêmes inputs et comparer l'arbre obtenu aux records attendus
avant freeze ; ce plan n'est ni un snapshot des inputs ni une preuve de closure.

## Installation offline du bundle planifié

Le [banc ciblé](validation/2026-10-11-factory-studio-bundle-install-tests.json)
passe 54 tests Linux ARM64 root sans skip, avec des inputs synthétiques et
`_production_environment` remplacé par un workspace de fixture explicite. Les
owners, xattrs et syscalls Linux sont réels ; l'admission CLI production reste
à qualifier. La suite locale complète passe 1 585 tests avec 15 skips.

`scripts/install-factory-studio-bundle-rootfs.py` matérialise désormais ce plan
dans un rootfs de build privé. Il n'exécute ni interpréteur cible, code Studio,
helper, pip, console script ou backend de build. Il ne lance aucun enfant, ne
consulte pas NSS, ne crée aucun compte et n'utilise ni mount, chroot, service ou
réseau. Les wheels doivent donc être déjà construites et épinglées ; ce lot ne
prouve pas leur origine ni leur construction sous UID1000.

```python
receipt = install_bundle(rootfs, input_manifest, input_sha256, sources_dir,
                         wheels_dir, receipt_output=receipt_path)
receipt = verify_bundle(rootfs, input_manifest, input_sha256, sources_dir, wheels_dir)
```

La CLI n'expose que `--rootfs`, `--input-manifest`, `--input-sha256`,
`--sources-dir`, `--wheels-dir` et `--receipt`. Elle exige Linux root avec GID
primaire 0 et le rootfs canonique
`/var/lib/inkyos-build/factory-studio.<token alnum>/root`. Le workspace parent
doit être root:root `0700`, et le marker root-owned
`/var/lib/inkyos-build/owner` doit contenir exactement `inkyos-builder-v1` suivi
d'un LF. Aucun prérequis ARM64 n'est nécessaire pour cette copie statique.

Tous les chemins doivent être absolus sans traversal ni symlink. Chaque parent
est ouvert par FD avec `O_NOFOLLOW`, gardé ouvert et revérifié par identité avant
publication. Les parents, inputs et fichiers lus doivent être root:root, sans
write groupe/other, bits privilégiés ou xattrs. Les inputs et le reçu restent
dans le workspace, hors rootfs et sans recouvrement entre eux. Sources et
wheelhouse conservent les inventaires exacts et les limites du planner.

L'installateur admet un sous-ensemble matérialisable des plans du planner, sans
modifier ce dernier : chaque chemin final, préfixe site-packages compris, et
`manifest.json` doivent avoir au plus 64 composants et 4096 octets UTF-8. Chaque
composant doit aussi respecter en octets encodés le `PC_NAME_MAX` obtenu par
`fpathconf` sur le FD parent de la destination. Le nom du reçu est contrôlé sur
son propre parent. Une limite indéterminée/non positive est refusée. Ce contrôle
complet précède toute création générique ou de bundle ; un membre wheel accepté
par le planner mais dépassant ces limites ne provoque aucune écriture.

`/usr/lib/inky-studio` doit être entièrement absent, qu'il s'agisse d'un fichier,
d'un répertoire ou d'un lien. Les parents `usr` et `usr/lib` préexistants doivent
être sûrs et leurs droits restent inchangés. Si l'un manque, seules ces deux
directories génériques planifiées sont créées, root:root `0755`. Un reçu
préexistant est refusé avant toute création dans le rootfs.

Le planner dérive les records avant la première écriture. Un second passage
borné ouvre les octets sources et wheels par FD, valide leurs pins et RECORD,
puis compare chaque taille/hash et l'ensemble des fichiers aux records attendus.
Il revérifie le plan et les inputs avant les créations exclusives. Les bytes
sont ensuite livrés directement dans les chemins planifiés, avec les
directories, `pyvenv.cfg` et les quatre symlinks du scaffold. Aucun `extractall`,
editable, activate ou script console généré n'est utilisé.

L'inventaire réel comprend bytes, types, modes, owners et xattrs Linux ; il doit
être exactement égal au plan **avant** `manifest.json`. Les inputs sont relus et
revérifiés à cette frontière. Seuls les bytes du manifest précédemment dérivé
sont alors publiés exclusivement en `0644`, puis l'arbre et ces bytes sont
revérifiés. Le reçu neuf `0600` est écrit et relu en dernier. `verify_bundle`
refait ces vérifications sans écriture et sans réparer une divergence.

Une erreur I/O peut laisser des directories, fichiers ou un manifest/reçu
partiel. Ces sorties sont conservées ; aucune suppression, reprise, réparation,
écrasement, rollback ou transaction multi-fichiers n'est revendiqué. Une nouvelle
installation sur ce même bundle ou reçu refuse. Un reçu n'est accepté qu'après
le retour réussi et sa vérification ; sa présence seule après une erreur ne
constitue pas une preuve.

Le receipt porte `scope: offline-factory-studio-bundle-install`,
`operation: install` ou `verify`, les pins et comptes du plan,
`record_metadata: inspected-root-owned-no-xattrs` et `bundle_verified: true`.
Il déclare explicitement `support_verified`, `image_code_executed`,
`application_code_executed`, `runtime_qualified` et `hardware_qualified` à false.
Les comptes hérités du plan excluent son propre `manifest.json`. Aucun chemin
local, identité, secret, runtime manifest, autorité, Ready ou credentials n'est
produit par ce receipt.

Le caller doit posséder un workspace exclusif sans writer concurrent, y compris
sous root. Les FDs et rechecks protègent le chemin sélectionné ; ils ne créent ni
verrou d'exclusion de build ni réservation runtime. Les tests Mac utilisent
uniquement un root synthétique différent de `/`, des owners locaux, une
observation xattrs Linux simulée et des symlinks Darwin ajustés par `lchmod` à
`0777`. La CLI ne propose aucun bypass fixture. La qualification Linux doit
exercer les syscalls et xattrs réels ; ces fixtures n'établissent pas le support
système, les imports, dependencies, provenance, privacy, frontend, guards,
graphe installé, premier boot ou matériel.

La [validation des tags et headers ELF](validation/2026-10-11-factory-studio-wheel-policy-tests.json)
exécute 144 cas synthétiques sur Linux ARM64 root sans skip, puis la suite Mac
complète (1 603 tests, 15 skips). Elle conserve le premier échec de pin adjacent
et sa correction relue. Elle ne qualifie ni les dépendances réelles, le loader,
le support système, une image ni le matériel.

Le [validator de dépendances offline](../vendor/build-tooling/README.md)
vérifie séparément la closure runtime de la wheel applicative avec l’extra `pi`,
en réutilisant ce preflight et le tooling épinglé hors bundle/rootfs. Ses
[33 tests synthétiques](validation/2026-10-11-factory-studio-dependency-tests.json)
passent sur Mac et Linux ARM64, sans qualifier par eux-mêmes un payload réel.
