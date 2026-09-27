# Compatibilité Python de la candidate applicative

Audit du 27 septembre 2026. **Le runtime sans extra Pi se résout en wheels ; l'ensemble runtime + Pi ne se résout pas exclusivement depuis les wheels publiées sur PyPI.** Les blocages sont `RPi.GPIO` et `spidev`. Ce sont des constats de disponibilité des distributions, pas des incompatibilités d'exécution démontrées.

Statut : recherche expérimentale, sans installation, import du backend, compilation depuis les sources, exécution Linux cible ou qualification matérielle. Aucun lock applicatif final n'est produit. Aucun changement de base OS, d'architecture ou de dépendance applicative n'est décidé ici.

## Périmètre et cible

Source lue par `git show`, sans utiliser les changements du working tree : `inky-studio-ios`, commit `ae61df1c0f01408861ccb1210ec85986768d6784`, fichier `server/pyproject.toml`, projet `inky-studio-server` version `0.5.0rc2`. SHA256 du fichier : `ab31c8b9a7cbdc80c7d754dc586b38c10db3a10da334fbc7bc6b966c71dcee25`.

La contrainte applicative est `requires-python = ">=3.11"`. L'audit couvre les dix dépendances runtime, l'extra `pi` (`inky==2.3.0`, `gpiod>=2.2`, `RPi.GPIO>=0.7`) et `build-system.requires = ["hatchling"]`, avec leurs dépendances transitives. L'extra `dev` est hors périmètre.

La cible est CPython **3.13.5**, ABI ordinaire **cp313** avec GIL, **Linux aarch64 / ARM64**, glibc **2.41**. Les wheels `cp313t`, ARM 32 bits, macOS et musllinux ne représentent pas cette cible.

Outil observé : `uv 0.9.18 (0cee76417 2025-12-16)`, déjà installé sur le Mac. Son aide propose `aarch64-manylinux_2_40`, mais pas `aarch64-manylinux_2_41`. La résolution utilise donc le plafond glibc 2.40. C'est une vérification conservatrice : les tags manylinux sélectionnés demandent tous glibc 2.34 ou moins, admissibles en principe sur 2.41 selon la [spécification des tags](https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/). Cela ne vérifie ni le chargement des bibliothèques natives ni leur comportement sur le Pi.

L'absence de wheels appropriées pour les deux blocages a aussi été vérifiée dans l'inventaire des fichiers PyPI, indépendamment du plafond du résolveur. Une wheel réservée à glibc 2.41 n'y est donc pas simplement passée inaperçue.

## Méthode reproductible

Les tableaux de dépendances du TOML épinglé sont copiés dans `build/python-research/runtime.in`, `runtime-pi.in` et `build-backend.in`. Ces fichiers contiennent uniquement des exigences de registre, aucun chemin local, URL de source ou editable. `uv pip compile` résout ces entrées sans construire l'application. Voir la [documentation uv 0.9.18](https://github.com/astral-sh/uv/blob/0.9.18/docs/pip/compile.md).

Les derniers runs sont exécutés avec environnement vidé, configuration désactivée, index public explicite, cache dédié et authentification isolée. `HOME` n'est pas redéfini. Exemple depuis la racine du dépôt, avec les entrées déjà extraites :

```sh
research_dir="$PWD/build/python-research"
research_uv="$(command -v uv)"
env -i \
  PATH="$(dirname "$research_uv"):/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  NETRC=/dev/null \
  UV_CREDENTIALS_DIR="$research_dir/empty-credentials" \
  "$research_uv" \
  --no-config --cache-dir "$research_dir/cache" \
  --no-python-downloads --no-managed-python --color never --no-progress \
  pip compile --upgrade \
  --default-index https://pypi.org/simple --keyring-provider disabled \
  --only-binary :all: \
  --python-version 3.13.5 --python-platform aarch64-manylinux_2_40 \
  --generate-hashes --no-header --emit-index-annotation --verbose \
  "$research_dir/runtime.in" \
  --output-file "$research_dir/runtime.requirements.txt"
```

`empty-credentials` est un répertoire de recherche vide, vérifié avant et après les runs. `--no-config` désactive la découverte des configurations persistantes ([documentation versionnée](https://github.com/astral-sh/uv/blob/0.9.18/docs/concepts/configuration-files.md)). `NETRC` désigne explicitement `/dev/null` et le stockage d'identifiants uv est isolé ([authentification uv 0.9.18](https://github.com/astral-sh/uv/blob/0.9.18/docs/concepts/authentication/http.md), [UV_CREDENTIALS_DIR, disponible depuis 0.8.15](https://docs.astral.sh/uv/reference/environment/#uv-credentials-dir)).

`--only-binary :all:` interdit les builds des distributions sources du registre ([documentation officielle](https://docs.astral.sh/uv/pip/compatibility/#only-binary-enforcement)). Ne pas ajouter `--no-build` simultanément : cette version de la CLI rejette cette combinaison. `--generate-hashes` produit des hashes de distributions dans les sorties de recherche ; il ne signifie pas que chaque archive a été téléchargée et rehashée par cet audit.

Les logs signalent que Python 3.13.5 n'est pas installé sur le Mac et découvrent Python 3.13.3 macOS. Ils confirment aussi la résolution pour la cible `>=3.13.5` et sélectionnent des wheels Linux ARM64. Le message générique annonçant l'interpréteur « for builds » n'autorise aucun build avec cette commande. Aucun interpréteur cible n'a été téléchargé ou exécuté.

`--upgrade` évite de transformer implicitement une ancienne sortie de recherche en contrainte. Les versions ci-dessous sont une observation datée du registre public ; une nouvelle résolution ultérieure peut choisir d'autres versions.

## Résultats observés

| Entrée | Résultat | Portée |
| --- | --- | --- |
| Runtime | exit 0, 26 paquets | Wheels compatibles sélectionnées selon métadonnées et tags |
| Runtime + extra Pi, contraintes intactes | exit 1 | `RPi.GPIO>=0.7` sans wheel utilisable |
| Hatchling et dépendances | exit 0, 6 paquets | Outils de build disponibles en wheels ; application non construite |
| Diagnostic sans la seule exigence `RPi.GPIO` | exit 1 | `spidev`, dépendance obligatoire d'Inky 2.3.0, sans wheel utilisable |
| Runtime + `gpiod`, `gpiodevice`, `numpy`, `smbus2` | exit 0, 30 paquets | Diagnostic partiel des autres transitives ; ni installation candidate ni graphe Pi complet |

La wheel `inky-2.3.0-py3-none-any.whl` est disponible. Ses dépendances observées sont `gpiodevice>=0.0.3`, `numpy`, `pillow`, `smbus2`, `spidev`. `gpiodevice` dépend de `gpiod`. Source : [métadonnées de la release Inky 2.3.0](https://pypi.org/pypi/inky/2.3.0/json), corroborées par le log du résolveur. L'audit ne valide pas les commentaires historiques du pyproject sur les versions du driver.

Versions runtime sélectionnées :

```text
annotated-doc 0.0.5       annotated-types 0.8.0    anyio 4.15.1
cffi 2.1.1               click 8.5.0              cryptography 50.0.1
dbus-fast 5.0.22         fastapi 0.141.1          h11 0.16.0
httptools 0.8.0          idna 3.20                pillow 12.3.0
pycparser 3.0            pydantic 2.13.5          pydantic-core 2.46.5
python-dotenv 1.2.3      python-multipart 0.0.32  pyyaml 6.0.3
qrcode 8.2               starlette 1.7.0          typing-extensions 4.16.0
typing-inspection 0.4.4  uvicorn 0.54.0           uvloop 0.22.1
watchfiles 1.3.0         websockets 17.1
```

Autres wheels du diagnostic Pi : `gpiod 2.5.0`, `gpiodevice 0.1.0`, `numpy 2.5.3`, `smbus2 0.6.1`. Build backend : `hatchling 1.32.4`, `packaging 26.3`, `pathspec 1.1.1`, `pluggy 1.6.0`, `tomlkit 0.15.1`, `trove-classifiers 2026.9.21.13`, tous `py3-none-any`.

Les bornes larges du pyproject autorisent ces versions. La réussite de résolution n'établit pas leur compatibilité avec le code applicatif, ni leur équivalence avec l'environnement déjà déployé.

## Tags des wheels natives sélectionnées

Chaque ligne correspond au fichier exact inventorié. Les plateformes séparées par des points sont plusieurs tags portés par la même wheel.

| Paquet | Python / ABI | Plateforme(s) |
| --- | --- | --- |
| cffi 2.1.1 | cp313 / cp313 | manylinux2014_aarch64.manylinux_2_17_aarch64 |
| cryptography 50.0.1 | cp311 / abi3 | manylinux_2_34_aarch64 |
| dbus-fast 5.0.22 | cp313 / cp313 | manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64 |
| gpiod 2.5.0 | cp313 / cp313 | manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64 |
| httptools 0.8.0 | cp313 / cp313 | manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64 |
| numpy 2.5.3 | cp313 / cp313 | manylinux_2_27_aarch64.manylinux_2_28_aarch64 |
| pillow 12.3.0 | cp313 / cp313 | manylinux_2_27_aarch64.manylinux_2_28_aarch64 |
| pydantic-core 2.46.5 | cp313 / cp313 | manylinux_2_17_aarch64.manylinux2014_aarch64 |
| pyyaml 6.0.3 | cp313 / cp313 | manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64 |
| uvloop 0.22.1 | cp313 / cp313 | manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64 |
| watchfiles 1.3.0 | cp310 / abi3 | manylinux_2_17_aarch64.manylinux2014_aarch64 |
| websockets 17.1 | cp313 / cp313 | manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64 |

Les autres fichiers sélectionnés sont universels `py3-none-any`, sauf `smbus2`, `py2.py3-none-any`. Les noms complets, URLs, tailles, SHA256 annoncés, `Requires-Python` et dépendances figurent dans l'[inventaire expérimental](validation/2026-09-27-python-wheels.json). Les fichiers wheel n'ont pas fait l'objet d'un téléchargement complet et d'une vérification indépendante de leurs octets par cet audit.

## Les deux distributions à produire ou fournir

Selon les inventaires officiels [RPi.GPIO](https://pypi.org/pypi/RPi.GPIO/json) et [spidev](https://pypi.org/pypi/spidev/json), consultés le 27 septembre :

| Paquet | Wheels publiées observées | Conséquence pour la cible |
| --- | --- | --- |
| RPi.GPIO, dernière stable 0.7.1 | Stable : `cp27-cp27mu`, `cp37-cp37m`, `cp38-cp38`, `cp39-cp39`, `cp310-cp310`, toutes `linux_armv6l`. Les prereleases inventoriées ne fournissent pas davantage de wheel cible. | Ni architecture aarch64, ni ABI cp313/abi3 |
| spidev, dernière stable 3.8 | Releases 3.6, 3.7, 3.8 : `cp39-cp39-linux_armv7l` | Ni architecture aarch64, ni ABI cp313/abi3 |

Les sources suivantes sont **inventoriées seulement** ; elles n'ont pas été téléchargées, importées ou compilées :

| Source | Taille annoncée | SHA256 annoncé par PyPI |
| --- | ---: | --- |
| [RPi.GPIO-0.7.1.tar.gz](https://files.pythonhosted.org/packages/c4/0f/10b524a12b3445af1c607c27b2f5ed122ef55756e29942900e5c950735f2/RPi.GPIO-0.7.1.tar.gz) | 29 090 octets | `cd61c4b03c37b62bba4a5acfea9862749c33c618e0295e7e90aa4713fb373b70` |
| [spidev-3.8.tar.gz](https://files.pythonhosted.org/packages/67/87/039b6eeea781598015b538691bc174cc0bf77df9d4d2d3b8bf9245c0de8c/spidev-3.8.tar.gz) | 13 893 octets | `2bc02fb8c6312d519ebf1f4331067427c0921d3f77b8bcaf05189a2e8b8382c0` |

L'[API JSON PyPI](https://docs.pypi.org/api/json/) fournit les fichiers, hashes et métadonnées déclarées lors de la publication. Ces éléments n'attestent pas la réussite d'un build, l'authenticité de son auteur ou l'absence de vulnérabilités.

L'inventaire préexistant des 633 paquets de la base officielle (`build/inspection.U23iyshp/base.json`) contient déjà **`python3-spidev 3.6-1+b6 arm64`**. Il ne contient aucun paquet nommé `rpi.gpio`/`rpi-gpio` ou portant ces chaînes. Cette présence système n'établit pas la satisfaction de la distribution PyPI dans le futur venv isolé. Aucun recours à `system-site-packages` n'est retenu ici.

## Suite à coordonner avec l'application

La piste simple à qualifier est de produire les wheels natives manquantes dans le pipeline commun de release, puis de fournir un wheelhouse fermé pour la cible ARM64/Python 3.13.5. Cet audit n'exécute pas ces builds et ne garantit pas leur réussite. Les versions, sources et éventuels correctifs doivent être décidés et épinglés côté release ; ne pas substituer une bibliothèque ou retirer une dépendance silencieusement.

Le livrable applicatif attendu doit réunir :

1. Un graphe complet runtime + Pi figé, compatible avec la candidate réellement testée ; le payload source/UI issu d'un commit immuable, installé editable au chemin final avec Hatchling épinglé, selon [APPLICATION-PAYLOAD.md](APPLICATION-PAYLOAD.md).
2. Les wheels exactes avec provenance, tags, tailles et SHA256 vérifiés sur les octets, y compris les deux productions natives ; leurs dépendances de build et bibliothèques système identifiées.
3. Une preuve d'installation offline dans un venv isolé de la cible, puis des tests d'import/API sous Linux ARM64/Python 3.13.5. Les tests GPIO/SPI, rendu et qualification du cadre restent distincts et nécessaires.

Aucun résultat de ce document ne qualifie une release applicative, un premier boot ou une SD.

## Preuves conservées

L'[inventaire JSON versionné](validation/2026-09-27-python-wheels.json) contient 37 fichiers wheel sélectionnés, les deux inventaires bloquants, les sources officielles et les résultats des cinq runs pertinents. Son statut est `experimental-metadata-audit-not-application-lock`.

Les entrées, sorties du résolveur, aide/version uv et reçus détaillés sont dans `build/python-research/`, hors configuration de production. Le JSON versionné consigne leurs hashes et les heures de vérification. Les essais intermédiaires de CLI restent des traces de recherche et ne sont pas des preuves de compatibilité supplémentaires.
