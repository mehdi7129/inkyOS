# Diagnostic du boot réseau TEST

État au **10 octobre 2026**. La connexion au banc reste non confirmée.
Cette lecture du retour SD précise l'étape atteinte ; elle ne qualifie pas
le réseau, l'écran ou l'appairage iPhone.

## Observations vérifiées

- Copie complète de la SD acquise en lecture seule, relue localement et
  vérifiée par hash. L'original et tous les paramètres restent privés.
- Analyse dans la VM Linux dédiée, avec loop en lecture seule, ext4
  `ro,noload` et FAT `ro`, sans exécuter le code de la SD. Démontages et
  détachement du loop vérifiés après lecture.
- État d'enrôlement `enrolled`, profil cohérent ; cache d'accès `imported`
  complet avec exactement les quatre fichiers attendus.
- Hashes du profil, de la clé publique au format wire SSH, du manifeste
  runtime, de la capsule, de sa signature et du profil réseau cohérents.
  Capsule et signature en cache identiques aux fichiers installés sur FAT.
- Configuration opérateur absente ; état NetworkManager enregistré avec
  `WirelessEnabled=false` ; aucun profil de connexion persistant.
- Répertoire des journaux persistants vide et absence de `syslog`.

L'import a donc abouti au moins une fois. Le cache n'est ni incomplet ni
bloqué dans l'état `importing`. L'absence de configuration opérateur ne prouve
pas à elle seule qu'aucune association Wi-Fi n'a jamais eu lieu. L'état radio
sauvegardé peut provenir du verrou initial ou du nettoyage après échec.

## Limites

Le système de fichiers demande une récupération de journal après la coupure
d'alimentation ; aucun replay ni réparation n'a été effectué. Les fichiers
persistants peuvent être antérieurs au dernier boot. Les fichiers sous `/run`
et les journaux volatils ne survivent pas à l'arrêt.

Pour limiter la duplication, l'analyse utilise une dérivée contenant les
blocs ext4 utilisés, y compris les données de fichiers, et le préfixe MBR/FAT
original. Ses hashes ont été vérifiés au transfert et à la lecture dans la VM.
La copie complète est conservée ; les blocs ext4 libres ne font pas partie de
cette dérivée. L'acquisition n'était pas protégée contre toutes les écritures
automatiques de macOS dès l'insertion.

## Rapports persistants de la variante diagnostique

Le runtime conserve deux petits fichiers sous
`/var/lib/inkyos-test-diagnostics`, répertoire root `0700` créé par systemd :

- `last-wifi-gate.json` : résultat du verrou WLAN précédant NetworkManager,
  après validation de ses sources.
- `last-boot.json` : marqueur initial incomplet, puis résultat final après
  nettoyage, avec l'étape atteinte et les observations d'import, de connexion
  et du contrôle pays lorsqu'elles sont disponibles.

Chaque fichier est root `0600`, borné à 8 Kio et remplacé atomiquement avec
fsync et relecture. Le schéma ne conserve que des erreurs énumérées et des
booléens, jamais de SSID, mot de passe, clé ou sortie brute de commande.
Un identifiant aléatoire de boot du kernel permet uniquement de rapprocher
les deux reçus privés ; ce n'est pas une identité de cadre et il n'est pas
destiné à un export public.

Ces observations ne sont jamais une autorisation de connexion ou d'activation.
L'`ExecCondition` SSH n'écrit aucun diagnostic. Une erreur de stockage est
ignorée après les opérations métier ; elle ne relâche aucun contrôle radio.
La persistance possède son propre budget de deux secondes dans un enfant :
au dépassement, le parent demande sa fin et poursuit sans attente bloquante.
Une attente kernel non interruptible peut retarder la fin effective de
l'enfant, qui reste dans le cgroup du service.

Un temporaire laissé par une écriture interrompue est conservé pour analyse,
sans réparation automatique. Il peut empêcher les écritures suivantes. Un
reçu ancien peut aussi subsister si les sources ne passent pas les contrôles
initiaux, si le disque est plein ou si le service est tué. Même un identifiant
de boot commun ne prouve donc pas que les reçus représentent le dernier essai.
`complete=true` signifie que la procédure s'est terminée, pas qu'elle a réussi.
Un marqueur incomplet ne localise pas précisément une interruption ultérieure.

Le banc `scripts/probe-test-diagnostic-storage.py`, exécuté comme root dans
la VM Linux ARM64 marquée, crée un service systemd temporaire et inerte avec
`ProtectSystem=strict`, `PrivateNetwork=yes`, `StateDirectory` privé et les
mêmes primitives d'écriture. Il vérifie création, remplacement, permissions,
persistance après sortie et refus d'écriture hors du répertoire autorisé.
Il ne lance ni NetworkManager, ni radio, ni application.

La SD du retour analysé ne contient pas encore cette instrumentation.

Deux fragilités ont été reproduites sur fixtures : le périphérique rfkill
peut manquer au premier relevé, et le readback du pays peut arriver après
la première observation. Aucune n'est encore identifiée comme la cause
matérielle de cet échec. Ne pas les transformer en diagnostic confirmé.

Modifier le runtime change son manifeste, lié au profil d'enrôlement et à la
capsule. Un remplacement isolé des scripts sur la carte invaliderait ces
bindings. Préparer une nouvelle variante cohérente et testée avant le prochain
essai, sans modifier le protocole Studio ni affaiblir les contrôles existants.

Le [relevé réduit](validation/2026-10-10-test-access-boot-return.json) ne contient
aucun identifiant de carte, clé, hash de copie privée ou paramètre réseau.
