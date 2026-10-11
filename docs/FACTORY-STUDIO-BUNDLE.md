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
Les deux familles de tags actuellement admises sont `py3-none-any` et
`cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64`. Un candidat nécessitant
un autre tag est refusé ; cette contrainte n'est pas élargie ici.

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
