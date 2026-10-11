# Expected Studio bundle — planner statique

`scripts/plan-factory-studio-bundle.py` calcule les records attendus d'un bundle
à installer sous `/usr/lib/inky-studio`. Il ne crée pas de venv, ne lance aucun
enfant, pip, build backend ou code candidat, et ne touche aucune image. Les
records sont dérivés des octets épinglés **avant** tout futur build ; les hashes
d'une sortie pip ou d'un arbre observé ne sont jamais promus en expected.

Les premiers lots ont été validés avec des fixtures ZIP synthétiques. Une
[validation statique d'inputs réels](validation/2026-10-11-factory-studio-real-input-plan.json)
est désormais consignée pour le commit Studio déclaré `a071f19`, avec les outils
OS `8102d08`. Elle vérifie les métadonnées de dépendances et calcule les records
attendus, sans installer ni qualifier le candidat. Les pins TEST, le support
exporter `096a…`, le contrat runtime et Studio restent inchangés.

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

Une exception fermée admet uniquement trois fichiers réguliers de la wheel
`numpy-2.5.3-cp313-cp313-manylinux_2_27_aarch64.manylinux_2_28_aarch64.whl`,
dont le SHA-256 complet est
`c76d5dde9f445058f83d0c02af00557a4db91de9a9a57c0df87d1535001d654b` :

- `numpy/_core/tests/examples/cython/setup.py` ;
- `numpy/_core/tests/examples/limited_api/setup.py` ;
- `numpy/f2py/setup.cfg`.

L'adapter commun au planner et au second passage de l'installer conserve leurs
octets, leurs hashes et le RECORD original. Il les traite comme des données
pendant le build statique : cela ne signifie pas que ces scripts seraient
inexécutables dans un autre contexte. L'exception exige les trois fichiers,
ne permet aucun namespace `inky_web`, et ne s'étend ni aux sources, ni aux
autres chemins, ni à une autre wheel ou un autre digest. Les contrôles de type,
hooks, RECORD et collisions restent appliqués ; aucun flag CLI ou champ du
manifest ne peut élargir cette exception. Sa validation ici utilise des
fixtures synthétiques avec substitution explicite du pin ; elle ne qualifie
pas le candidat réel ni le comportement de NumPy. Le
[banc de cette exception](validation/2026-10-11-factory-studio-numpy-data-tests.json)
passe 152 cas sur Linux ARM64 root sans skip, puis la suite Mac complète
(1 644 tests, 15 skips), avec vérification des sources inchangées.

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

## Validation statique d'inputs réels

Le [rapport associé aux outils `8102d08`](validation/2026-10-11-factory-studio-real-input-plan.json)
consigne deux sorties réussies : les 34 distributions fournies sont atteintes
depuis la wheel app avec l'extra `pi`, puis le planner dérive 2 405 records
attendus pour 2 093 fichiers de payload, à partir de 34 wheels et 8 sources.
Le manifest attendu porte le SHA-256
`db58d3badc5921139dede5f0197a96c317745e68d2da5ab947de24f2a0f50673`.
Les 58 fichiers d'entrée gelés et les 10 fichiers d'outillage ont été rehashés
avant et après ; leurs octets sont inchangés. Seuls les hashes, commits et
compteurs sont projetés publiquement, sans publier les inputs ou le manifest.

Ce run s'exécute sur l'hôte macOS. Le tooling `packaging` épinglé est exécuté,
mais aucun code candidat n'est importé ou exécuté. La cible des métadonnées est
CPython 3.13.5 sur Linux ARM64 ; les champs livrés marqués `Dynamic` sont contrôlés
comme les autres champs. Cela ne constitue ni une exécution sur cette cible,
ni une installation, ni une preuve d'ABI ou de dépendances non déclarées.
Les owners, modes et xattrs du plan restent des valeurs **attendues**.

Le même rapport distingue la régression locale de 1 650 tests macOS, avec
15 skips, et les 39 fixtures Linux du validator mis à jour, encore **non
observées**. Les anciens rapports restent associés à leurs sources : les
33 fixtures de dépendances à `619e4a0`, et les 152 fixtures NumPy à `6d47776`.
Ces preuves historiques ne sont pas réattribuées à `8102d08`.

## Limites d'intégration

Le défaut de mapping `CLIENT_DIST` signalé sur les premiers candidats ne vaut
pas constat sur les nouveaux octets `a071f19`. Ce run conserve les chemins
livrables mais ne vérifie pas leur utilisation par le frontend. Les imports,
dépendances non déclarées, resource paths et le fonctionnement réel de l'app
nécessitent leur propre validation.

Le support système factory renouvelé, le fonctionnement des guards Studio, la
revue ELF/loader/OpenSSL, les identités, la provenance et la reproductibilité
du build des wheels, le graphe d'activation et le hardware restent hors de ce
run. L'installer devra revérifier les mêmes inputs et comparer l'arbre obtenu
aux records attendus avant freeze ; le plan seul ne prouve pas cette installation
ni la fermeture du runtime.

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
[33 tests synthétiques à `619e4a0`](validation/2026-10-11-factory-studio-dependency-tests.json)
passent sur Mac et Linux ARM64, sans qualifier par eux-mêmes un payload réel.
La [validation réelle de métadonnées et du plan à `8102d08`](validation/2026-10-11-factory-studio-real-input-plan.json)
est une observation séparée ; elle ne qualifie pas les imports ou le runtime.
