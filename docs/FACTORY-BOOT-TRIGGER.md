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
`/usr/bin/test`). Aucun PID1/service/graphe natif, reboot, Bluetooth, Wi-Fi ou écran
n'est qualifié. La syntaxe et l'ordonnancement restent à vérifier par
`systemd-analyze verify` et un banc Linux isolé avant toute installation réelle.
