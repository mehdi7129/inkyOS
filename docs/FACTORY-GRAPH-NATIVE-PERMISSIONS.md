# Permissions natives du graph : mesure du 12 octobre 2026

Une fixture Linux ARM64 a observé les primitives natives utilisées par le
[graph Phase A](FACTORY-GRAPH-ADMISSION.md), sous UID 1000 sans capabilities.
Son résultat est `OBSERVED` : certaines permissions sont établies dans ce
banc, sans admission du graph installé ni qualification de l'image.

## Source et environnement mesurés

La fixture a importé les définitions de
[`staging/bootstrap/writer-graph.py`](../staging/bootstrap/writer-graph.py)
depuis la source InkyOS `656c19b3838289ee5e3debb88d3b9f9d7d36a871`, avec
SHA-256 `cec2369dc4e46048a05e817369592ccde1c52d1e60342ee9872d46c7a9e3e408`.
Elle n'a ouvert ni `Graph`, ni les sources installées, ni une admission.
Ce relevé ne décrit pas un runtime déployé depuis le commit `276a0b9`.

Le banc utilisait Debian 13 ARM64, kernel `6.12.111+deb13-cloud-arm64`,
systemd `257.13-1~deb13u1` et Python `3.13.5`. Les définitions ont été
importées par le parent root ; tous les FDs et appels mesurés ont été obtenus
après passage à UID/GID 1000, sans groupes supplémentaires. Les ensembles
effective, permitted, inheritable et ambient de capabilities étaient nuls.

## Observations

| Opération réelle | Résultat et portée |
| --- | --- |
| `pidfd_open` de PID1 et du MainPID de `dbus.service` | FDs vivants et non héritables, ouverts après le changement d'identité. |
| `GetUnitByPIDFD` avec passage du vrai FD | PID1 mappé à `init.scope` ; MainPID D-Bus mappé à son unité et invocation. Mappings stables avant/après. |
| Propriétés Unit/Service typées de `dbus.service` | Décodage réel réussi ; identité, état et MainPID stables avant/après. Les champs comptables de `ExecStart` ne sont pas une preuve d'exécutable courant. |
| Socket déjà connecté au bus système | `SO_PEERPIDFD` et `SO_PEERCRED` accessibles ; pidfd vivant, non héritable et credentials root acceptés par le decoder du candidat. |
| Comparaison des pidfds du peer | Identique à PID1, différent du MainPID de `dbus.service`. |

Le dernier résultat est compatible avec un listener créé par socket activation
puis transmis au serveur. Il interdit de traiter le peer du socket comme une
preuve du processus qui sert la connexion ou écrit chaque message. Le graph
actuel ancre le manager par `pidfd_open(1)` et son mapping `init.scope` ; il
n'exige pas que le peer du bus soit le MainPID de `dbus.service`.

Pour l'IPC InkyOS, le guard exige toujours un peer identique à l'ancre MainPID
IPC. Cette mesure du bus système ne teste pas ce socket. Un listener créé par
PID1 ferait refuser ce guard ; un listener créé par le MainPID puis hérité peut
conserver son identité sans attester l'émetteur de chaque message.

## Nettoyage et limites

Un compte NSS anonyme temporaire, explicitement verrouillé, sans home ni
credential de connexion, a été créé puis sa suppression a été confirmée.
Les enfants possédés ont été réapés exactement et la quiescence des commandes
a été confirmée. Les 25 artefacts privés ont été relus et leurs pins vérifiés ;
les sources et pins du runtime sont restés identiques. Aucun service n'a été
créé, redémarré ou contrôlé, aucun cache NSS n'a été purgé. Des métadonnées,
backups ou journaux des outils NSS peuvent subsister : le banc n'est pas
déclaré globalement inchangé.

Restent non qualifiés : sandbox exact des units, vue PID sous ce sandbox,
graph installé et ses writers, IPC réel parent/enfant, sender par message,
autorité owner/Phase B, closure import/ABI du bundle et budgets du Pi.
Aucun `/proc/*/exe` étranger n'a été lu et cette mesure ne prouve pas
l'exécutable courant. Le premier boot, BLE, Wi-Fi, affichage, reboot et
matériel restent à qualifier séparément. Aucune image, SD ni application du
Pi n'a été activée par ce banc ; la source TEST actuellement installée reste
inchangée. Aucune gate d'activation complète n'est fermée par ce seul relevé.
