# Déclencheur factory explicite, encore inactif

Le template `staging/bootstrap/inkyos-factory-start.service` constitue une entrée
de boot distincte des cinq unités fermées du contrat factory. Ce lot ne l'installe
ni ne l'active. Il ne fournit aucun compte, permission, manifeste, pin, reçu
d'initialisation ou image SD et n'autorise pas le parcours `system_setup`.

Son `Requires` avec `After` attend le succès de `inkyos-firstboot.service`, puis
ses deux `ExecStart` oneshot demandent dans cet ordre le démarrage du superviseur
et celui de `inky-studio.service`. Le premier `systemctl start` reste bloquant
jusqu'au résultat du superviseur ; un code non nul empêche l'appel suivant. Le
superviseur conserve son `Wants`/`After` existant sur admission-prepare et ses
preuves natives : un échec de préparation fait refuser son exécution. Aucune
unité épinglée n'est modifiée, aucun arrêt n'est propagé entre ces unités, et il
n'existe ni restart automatique ni nettoyage de l'admission.

Avant ces appels, deux `test` refusent toute entrée `Ready` existante, y compris
un lien pendant. C'est seulement un veto de nouvelle entrée, jamais une preuve
d'admission. Il empêche de traiter le `start` sans effet d'un superviseur déjà
`active (exited)` comme une exécution factory nouvelle. Le vrai CLI superviseur
renvoie également 78 pour `already_ready` ; aucune condition systemd ou liste
`SuccessExitStatus` ne transforme ce refus en succès. Ce déclencheur n'est pas
une entrée de reprise normale d'un cadre adopté. Son lancement sur un second
boot factory éventuel reste soumis à la vraie réinspection `consumed` du
superviseur ; il ne doit pas être activé dans un profil normal par défaut.

Une future recette peut installer ce fichier sous
`/usr/lib/systemd/system/inkyos-factory-start.service` et activer uniquement ce
nom vers `multi-user.target`, après intégration revue de l'ensemble du profil.
Le vérificateur actuel accepte ce nom distinct et son lien d'activation, tout en
refusant encore les liens vers chacune des cinq unités fermées. Cela ne prouve
pas la complétude du support : le vrai packager doit inventorier les octets de
cette unité et les exécutables/deps qu'elle utilise, sans inventer leurs pins.

Les sept tests ciblés exercent le vrai vérificateur de fichiers d'unités et le
vrai refus superviseur `already_ready`, avec admission temporaire. Leur adapter
inerte représente seulement les dépendances et la propagation des codes des
commandes séquentielles, et les gardes `test` s'exécutent sur des fichiers
temporaires (`/bin/test` sur Mac ; le profil Linux doit inventorier son vrai
`/usr/bin/test`). Ces seuls tests synthétiques ne qualifient aucun
PID1/service/graphe natif, reboot, Bluetooth, Wi-Fi ou écran. Le banc complémentaire
ci-dessous vérifie la syntaxe et l'ordonnancement sur des services inertes.

## Banc PID1 inerte du 16 octobre 2026

Le probe explicite `staging/bootstrap/probe-factory-boot-trigger-linux.py` refuse
toute cible autre qu'un builder Linux ARM64 root avec le marqueur
`/var/lib/inkyos-build/owner = inkyos-builder-v1` et un vrai PID1 systemd. Son
appel est `sudo python3 -I -B PROBE --run TEMPLATE REPORT TEMPLATE_SHA256`.
Il n'exécute jamais de code produit : seuls les noms des unités et le chemin
`Ready` du trigger sont remplacés, vers des noms aléatoires
`inkyos-trigger-probe-<UUID>-...` et un répertoire privé sous `/run`. Le reste des
octets du trigger est conservé ; les trois services dépendants sont des Python
inertes qui consignent leur rôle et sortent avec le code demandé.

Dans la VM dédiée `inkyos-build` (Debian ARM64, systemd 257.13, noyau
6.12.111+deb13-cloud-arm64), les six cas ont passé leur `systemd-analyze verify`
avant le premier démarrage et leur démarrage réel via PID1 :

| Cas | Événements réellement observés | Résultat du trigger |
| --- | --- | --- |
| Succès | firstboot, supervisor, main | Succès |
| Superviseur sortant 78 | firstboot, supervisor | Échec, main non lancé |
| Firstboot sortant 1 | firstboot | Échec, superviseur/main non lancés |
| Ready fichier existant | firstboot | Échec, superviseur/main non lancés |
| Ready lien pendant | firstboot | Échec, superviseur/main non lancés |
| Main sortant 79 | firstboot, supervisor, main | Échec remonté |

Chaque cas a arrêté uniquement ses propres noms, réinitialisé seulement les
états `failed` observés, retiré ses fichiers sous `/run/systemd/system`, puis
vérifié les quatre `LoadState=not-found` après rechargement PID1. Aucun nom réel
InkyOS n'a été lancé, arrêté ou modifié. La VM reste disponible pour les autres
travaux. Le premier essai avait signalé un défaut de cleanup du probe :
`reset-failed` sur des unités déjà garbage-collected échoue. Les fichiers avaient
été retirés ; le probe corrigé a passé les six nettoyages avec de nouveaux noms.
Ce premier rapport d'échec est conservé et ne compte pas comme validation.

Les preuves locales sont dans `build/native-factory-trigger.raqxsahj/` :
`inputs.json`, les deux sources exactes transférées, `execution.json`, stdout,
stderr et `report.json`. SHA-256 :

- Template : `4c920afd1c81c3983624cb9cc5826a184eb6d15c5775346e450518fdde674381`.
- Probe : `86773b2fc1c7e9aa1177b2a58c16835d335af5ffc67de40a3ce1fdf1590b9aed`.
- Rapport : `8ff93e015921b0d99f4a35e51c22b487fd8b6d1da09f6a698ebed83f1dcc058a`.

Le rapport conserve également les hashes des exécutables natifs et de chaque
unité fixture, les états systemd et les événements. Ce banc qualifie le
déclenchement et ses refus dans cette VM. Il ne qualifie pas le vrai superviseur,
le support/manifeste factory installé, l'autorité, le graphe des writers,
l'appairage, un reboot, les radios ou l'écran physique.
