# Qualification logicielle offline du candidat applicatif

Le candidat Inky Studio **`6a697d134290ced0214fc74b903f4b3c336d70fa`**
(`0.5.0-rc.2`, PR applicative #13) passe son installation offline et son smoke
test d'import/API dans la VM Debian 13 ARM64/Python 3.13.5. Le 27 septembre 2026,
les cinq étapes retournent exit 0. **Ce résultat ne qualifie ni la release
finale, ni le boot du Pi, ni l'image complète.**

SHA-256 du manifeste reçu et contrôlé :
`2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f`.
Les [preuves versionnées](validation/2026-09-27-application-offline.json)
incluent l'environnement, les scripts exacts, les étapes et hashes des logs.

## Résultats exécutés

| Contrôle | Résultat |
|---|---|
| Archives épinglées | 84 fichiers applicatifs, 40 wheels ; hashes, CRC, structure et déclaration du commit conformes. |
| Nouveau venv | Créé dans un workspace jetable ; un `.venv` fourni par le payload est refusé. |
| Dépendances | Installation sans réseau, versions/hashes exacts du lock, wheels uniquement. |
| Projet editable | Installation de `server[pi]` sans dépendances implicites ni build isolation réseau ; Hatchling et `editables` fournis. |
| `pip check` | Aucune dépendance cassée. |
| Imports natifs | spidev, gpiod, numpy, dbus_fast, pydantic_core, Pillow, cryptography, uvloop, httptools et watchfiles réussissent. |
| Opérations locales | Signature/vérification Ed25519 en mémoire et encodage/décodage d'un PNG synthétique. |
| API ASGI | `/api/health` : 200 et version attendue ; `/api/state` sans authentification : 401 ; `/` : frontend HTML, 200. |
| État applicatif | Aucun état écrit dans le dossier de données temporaire ; lifespan non exécuté. |

`RPi.GPIO 0.7.1` est installé, mais n'est pas importé : son contrôle de matériel
refuse normalement un hôte non-Pi. Aucun test GPIO/SPI, écran, Bluetooth, Wi-Fi,
TLS réseau ou adoption n'est déduit de cette installation.

## Banc séparé de l'image

[qualify-application-linux.py](../scripts/qualify-application-linux.py) est un
banc expérimental réservé à `inkyos-build`. Il ne fait pas partie de
`make prototype`. Le script de smoke appartient au candidat applicatif,
`scripts/qualify_offline_runtime.py`, SHA-256 :
`d2a927a9c061b2252890c9e89588bf99195306309094e21cc491b2fd6065bba0`.
Il a été relu avant exécution. InkyOS ne maintient pas de fork de ces tests.

Le banc vérifie les assets, en crée un snapshot root-only puis répète
l'[inspection inerte](ARCHIVE-CONTRACT.md) avant toute extraction. Il ne copie
que des fichiers ordinaires dans un dossier nouveau et applique sa propre
vérification de chemins. Le lock accepte uniquement des versions exactes et
des SHA-256, sans URL, chemin local ou directive pip supplémentaire.

Seuls les sources/editable/venv deviennent accessibles en écriture à UID 65534.
Le wheelhouse, le lock et une copie du programme de qualification restent
root-owned. Le hash de ce programme est contrôlé avant et après chaque étape.
L'orchestrateur root lance pip et le candidat sans privilèges, sans groupes
supplémentaires et sans élévation possible, dans un namespace réseau isolé.

Le smoke vérifie que `socket.if_nameindex()` ne renvoie que l'interface `lo`
et n'utilise que les requêtes ASGI en mémoire. `/sys/class/net` n'est pas une
preuve adaptée ici : son montage existant continue à décrire le namespace
hôte. Ce faux rejet a été reproduit dans la VM et corrigé côté application.

Pip est lancé avec `--isolated`, `--no-cache-dir` et `--no-index`. Les
dépendances utilisent aussi `--only-binary=:all:` et `--require-hashes` ;
l'editable utilise `--no-deps --no-build-isolation`. Chaque étape possède un
timeout de 300 s avec arrêt du process group ; un dépassement produit un
résultat d'échec. Les fichiers écrits par les processus sont bornés à 64 Mio,
et le JSON de smoke à 1 Mio. La VM dédiée reste la frontière d'isolation :
ce banc est destiné à du source relu, pas à exécuter du code hostile arbitraire.

## Rejouer avec les mêmes entrées

Après transfert des quatre assets et des trois scripts InkyOS
(`qualify-application-linux.py`, `inspect-application-archives.py`,
`verify-application.py`) dans un dossier dédié de la VM :

```sh
limactl shell --workdir=/tmp inkyos-build sudo python3 \
  /var/tmp/inkyos-application-tests/ESSAI/tools/qualify-application-linux.py \
  --manifest /var/tmp/inkyos-application-tests/ESSAI/assets/inky-studio-manifest-v1.json \
  --sha256 2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f \
  --assets-dir /var/tmp/inkyos-application-tests/ESSAI/assets \
  --output /var/tmp/inkyos-application-tests/ESSAI/run-neuf
```

Les entrées proviennent du candidat exact, pas d'une release `latest`. Le dossier
de sortie doit être inexistant. Le résultat final de cette campagne est conservé
dans `build/application-qualification-6a697d1/run-3/` sur le Mac ; ses cinq logs
ont été rehashés après export. Les premiers runs ont aussi passé le smoke avant
les renforcements du banc ; la preuve versionnée porte sur la recette finale.

## Ce qui reste à qualifier

La VM utilise la même architecture et version Python que la cible, mais son
inventaire de packages diffère et elle ne boote pas le kernel Pi. Ce test ne
prouve pas encore le fonctionnement dans le rootfs exact de l'image, sous
systemd, avec helper/polkit, display, radios ou ressources du Zero 2 W.

Le packaging ne règle pas les contrats de premier démarrage : horloge/TLS,
premier QR sans LAN, pays Wi-Fi, authentification après adoption et reprise
après coupure. Aucun de ces protocoles n'a été modifié ici. L'intégration de
l'image et les essais physiques attendent leur conception/qualification
commune et une SD dédiée ; la SD personnelle reste intacte.
