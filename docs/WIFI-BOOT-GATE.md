# Gate Wi-Fi au démarrage de NetworkManager

**Prototype inactif, 28 septembre 2026.** La
[fonction de préparation](../scripts/wifi-boot-gate.py) est testée sur des
répertoires de fixture. Elle n'est ni installée ni appelée par l'image. Une
exécution directe du fichier échoue explicitement ; il ne possède pas encore
d'entrée runtime approuvée.

## Décision commune

Pour la future image usine uniquement, remettre `WirelessEnabled=false` avant
chaque démarrage de NetworkManager, puis laisser le daemon et D-Bus démarrer.
Le helper peut ensuite appliquer et vérifier le pays avant activation du Wi-Fi.
Un restart de NetworkManager refermera donc le Wi-Fi jusqu'à revalidation.
Cette politique ne doit pas être appliquée à un cadre existant par une simple
mise à jour de l'application.

NM 1.52.1 [lit son état au démarrage et utilise true par défaut](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/nm-config.c),
puis [applique cet état aux radios](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/nm-manager.c).
Écrire le fichier pendant que le daemon tourne ne remplace pas son état mémoire.
La fonction exige donc que NM soit arrêté ; son verrou de répertoire ne verrouille
que nos writers, pas NetworkManager.

Un futur `ExecStartPre` dédié sur
[NetworkManager.service](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/data/NetworkManager.service.in)
est la direction retenue. Son échec doit empêcher `ExecStart`, suivant
[systemd 257](https://github.com/systemd/systemd/blob/v257.13/man/systemd.service.xml).
Ne pas coupler cette opération au firstboot hostname : Bluetooth dépend aussi
de ce dernier. Aucun choix de pays ou appel D-Bus ne précède le démarrage NM.

## Ce que fait le prototype

La fonction accepte une racine de fixture explicite et ne crée aucun répertoire.
Elle ouvre les parents par descripteurs, refuse liens, hardlinks, propriétaires
ou permissions dangereux et borne la lecture à 64 KiB. Un fichier absent peut
être créé fermé ; un état ambigu ou corrompu est refusé sans réinterprétation.

Le parser conserve les lignes étrangères et les autres booléens NM. Il traite
uniquement LF comme séparateur de ligne, avec trim ASCII, pour éviter qu'un
séparateur Unicode caché dans une valeur devienne une fausse clé. La seule clé
modifiée est `main/WirelessEnabled`. L'écriture utilise un temporaire exclusif
0600, fsync fichier, rename puis fsync répertoire, même lors d'une répétition
identique. Une erreur de persistance ne renvoie jamais de succès durable.

Toute clé `Encoding` est refusée : GLib traite spécialement celle du premier
groupe et une valeur incompatible peut invalider tout le fichier. La suite Linux
vérifie les sorties avec le vrai parser
[GKeyFile](https://docs.gtk.org/glib/method.KeyFile.load_from_data.html), puis exige
un booléen false sans `GError` ; une clé absente renverrait aussi false, avec une
[erreur distincte](https://docs.gtk.org/glib/method.KeyFile.get_boolean.html).

Les fixtures couvrent restart, absence, corruption, doublons, CRLF, syntaxe
Unicode ambiguë, taille, chemins dangereux et échecs aux frontières d'écriture.
Les sentinelles Bluetooth, pays, bootfs et identité restent intactes. Ces tests
ne prouvent pas une coupure électrique sur SD.

Résultat : 18 tests dédiés inclus dans une suite de 239 tests, sans échec sur Mac
et Linux ARM64 (4 skips Mac, 1 Linux). L'oracle GLib 2.84.4 s'exécute réellement
sous Linux ; il est ignoré sur Mac. Les
[sources et résultats hashés](validation/2026-09-28-wifi-boot-gate.json) sont conservés.

## Avant toute activation

- Revoir l'entrée runtime à racine fixe, le drop-in, les permissions effectives
  de l'unité NM exacte de la base et la politique usine/legacy.
- Raccorder la revalidation du pays et la sérialisation avec scan/connexion ;
  un ancien record `confirmed` n'autorise pas seul le redémarrage radio.
- Tester l'échec du gate : helper indisponible, mais bootstrap BLE encore
  accessible. Dans le candidat `6a697d1`, le helper `Requires` NM, tandis que
  le backend `Wants` seulement le helper. Cela ne prouve pas la tolérance du
  runtime applicatif à son absence.
- Qualifier la radio avant NM : [systemd-rfkill restaure l'état au boot](https://github.com/systemd/systemd/blob/v257.13/man/systemd-rfkill.service.xml),
  et un supplicant autonome ou le firmware peuvent conserver un état actif.
  Le fichier NM seul n'est pas une preuve d'absence d'émission ou de scan.
  Aucun `rfkill unblock all` ni coupure Bluetooth ne fait partie de cette solution.

Cette brique reste distincte du [modèle de pays observé](FIRST-BOOT.md) et du
[banc SO_PEERCRED](BOOTSTRAP-PROBE.md). Aucun pays par défaut, nouveau privilège
helper ou changement de bootfs n'a été ajouté.
