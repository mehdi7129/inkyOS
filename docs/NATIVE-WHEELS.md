# Essai de compilation native ARM64

Le 27 septembre 2026, **RPi.GPIO 0.7.1 et spidev 3.8 compilent sous
CPython 3.13.5 / Debian 13 ARM64**. Deux exécutions dans des répertoires distincts
produisent des wheels identiques octet pour octet. Leurs exports sur le Mac ont
été rehashés. Ce résultat lève l'inconnue de compilation de l'[audit précédent](PYTHON-COMPATIBILITY.md),
sans qualifier leur exécution sur Raspberry Pi.

| Wheel expérimentale | Taille | SHA-256 vérifié |
|---|---:|---|
| `rpi_gpio-0.7.1-cp313-cp313-linux_aarch64.whl` | 28 671 | `52d86fc78338beee32603f161211100a91d85d7f19a0bc3f60cf40f7b437f010` |
| `spidev-3.8-cp313-cp313-linux_aarch64.whl` | 19 403 | `d9ebf9037db18279373f34839c4db19f6222d7bc976ba7d27d859c66e61e4cdc` |

Les fichiers sont conservés dans `build/native-wheels-research/run-3/` et
`run-4/`, exclus de Git. Les premiers runs 1/2 restent présents : après revue,
les contrôles des wheels ont été renforcés et les compilations répétées.
Les quatre exécutions produisent les mêmes octets. Les [preuves versionnées](validation/2026-09-27-native-wheels.json)
contiennent URL/hash des sources, recette, inventaire exact des packages du
builder, outils, hashes des rapports et résultats des deux exécutions.
Ces artefacts ont été transmis à Inky Studio pour son candidat offline ; aucun
asset n'est publié dans une release et aucune image système ne les intègre.

## Méthode exécutée

La sonde [probe-native-wheels-linux.py](../scripts/probe-native-wheels-linux.py)
n'accepte que les deux sdists exactes déjà inventoriées sur PyPI. Leurs octets
ont été téléchargés puis vérifiés par taille et SHA-256 avant transfert ; la
sonde les revalide dans la VM. Elle copie leurs entrées ordinaires bornées dans
des répertoires neufs, sans utiliser `extractall`.

L'orchestrateur exige Linux ARM64, Python 3.13.5 et le marqueur du builder dédié.
Les backends setuptools et le compilateur tournent sous UID/GID 65534, sans
groupes supplémentaires ni élévation de privilèges, dans des namespaces réseau,
UTS et IPC distincts. Le réseau est absent pendant les builds. Aucun home du
Mac, source applicatif, volume physique ou périphérique du Pi n'est partagé.
La VM reste la frontière d'isolation ; ce n'est pas un sandbox de filesystem
complet contre du code arbitraire.

Les outils de compilation ont été installés uniquement dans cette VM par APT
(`build-essential`, `python3-dev`, `python3-pip`, `python3-setuptools`,
`python3-wheel`, `python3-venv`). Les versions effectivement utilisées sont
GCC 14.2.0, pip 25.1.1, setuptools 78.1.1 et wheel 0.46.1. Les headers CPython
proviennent de `python3.13-dev 3.13.5-2+deb13u5` ; aucune modification des
packages de l'image Pi n'a été effectuée.

Les deux runs partagent ce toolchain provisionné. Son inventaire est figé dans
la preuve, mais les `.deb` de tout le toolchain ne sont pas archivés : aucune
reconstruction indépendante du builder n'est démontrée.

Réglages conservés : `SOURCE_DATE_EPOCH=1789430400`, `TZ=UTC`,
`LANG=C.UTF-8`, `PYTHONHASHSEED=0`, umask 022, `CFLAGS`/`CXXFLAGS` avec
`-g0 -ffile-prefix-map=<job>=/build/native-wheel`. Aucun `-march=native` ou
`-mcpu=native`. Configuration pip désactivée, environnement vidé, cache désactivé.

Le frontend utilise `pip wheel --use-pep517 --no-index --no-deps
--no-build-isolation --no-cache-dir`. Les dépendances du backend sont déjà
installées ; ce réglage interdit de les résoudre implicitement sur Internet.
Il suit l'[interface officielle de pip wheel](https://pip.pypa.io/en/stable/cli/pip_wheel/).
Chaque build est limité à 180 secondes et le groupe de processus est arrêté
en cas de dépassement. Les sorties précédentes ne sont jamais écrasées.

Pour rejouer, après préparation des sources vérifiées et des outils dans la
VM, copier la sonde puis utiliser deux noms de sortie encore inexistants :

```sh
limactl shell --workdir=/tmp inkyos-build sudo python3 \
  /var/tmp/inkyos-native-wheels/ESSAI/probe-native-wheels-linux.py \
  --inputs /var/tmp/inkyos-native-wheels/ESSAI/inputs \
  --output /var/tmp/inkyos-native-wheels/ESSAI/run-1
```

Cette sonde expérimentale n'est pas appelée par `make prototype` et n'installe
pas les wheels produites. Le contrat de release commune reste celui de
[APPLICATION-PAYLOAD.md](APPLICATION-PAYLOAD.md).

## Vérifications et limites

- Les deux compilations, puis leur répétition, retournent exit 0.
- Les wheels sont des fichiers réguliers et passent les contrôles ZIP/CRC,
  nom/tag, manifeste `RECORD` complet et tailles décompressées bornées. Leurs
  extensions portent des headers ELF64 little-endian AArch64.
- Les octets des deux wheels sont identiques entre les runs, malgré des chemins
  de travail différents. Aucun renommage en `manylinux` ou `abi3` n'est effectué.
- Les gardes ont été éprouvées : orchestration non-root et source corrompue
  refusées avant création du dossier de sortie.
- Cinq tests de fixtures refusent notamment un FIFO, une expansion excessive,
  une wheel pure/mal étiquetée, un objet x86_64 et un `RECORD` incohérent.

Aucune bibliothèque produite n'a été importée par cette sonde et aucun service
applicatif n'a été lancé. Un [banc logiciel ultérieur](OFFLINE-QUALIFICATION.md)
teste séparément les imports compatibles avec la VM. `RPi.GPIO` vérifie le
matériel dès son import et refuse un hôte
non Raspberry Pi dans le [source 0.7.1](https://pypi.org/project/RPi.GPIO/0.7.1/).
Un tel échec dans une VM ne suffirait pas à diagnostiquer une incompatibilité ABI.

L'installation offline du graphe complet, les imports adaptés, la compatibilité
de l'application et les essais GPIO/SPI restent à exécuter séparément. Les droits
sur `/dev/gpiomem`, la carte, le panneau et le comportement sous charge ne sont
pas déduits de cette compilation. La SD personnelle reste hors des essais.
