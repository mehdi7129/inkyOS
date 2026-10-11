# Supervision du publisher factory — banc staging

Le [probe Linux](../staging/bootstrap/probe-factory-service-linux.py) vérifie un
[modèle d’unité](../staging/bootstrap/inkyos-factory-fixture.service) avec des
producteurs inertes. Le modèle contient `ExecStart=/usr/bin/false`, sans section
`Install` : il ne lance aucun service applicatif et aucune recette ne l’installe.

Le [résultat natif du 11 octobre 2026](validation/2026-10-11-factory-service-native.json)
passe dix cas dans la VM Linux ARM64 dédiée. Chaque unité temporaire est arrêtée
et son cgroup doit être absent ou vide avant de conclure le test.

| Cas | Résultat observé |
|---|---|
| Producteur simple | Producteur sous UID/GID 1000, groupes supplémentaires vides et capacités abandonnées ; fichier publié par le parent avec propriétaire 1000 |
| Tentative de fork ou de thread supplémentaire | Refus du contrôleur pids avec `TasksMax=2` |
| Producteur bloqué | Timeout du publisher et récupération de l’enfant |
| Timeout de l’unité | Arrêt du cgroup, y compris un enfant ignorant SIGTERM |
| Retrait successif de CHOWN, DAC_OVERRIDE, SETUID, SETGID et KILL | Refus attendu de l’opération nécessitant la capacité retirée |

Le parent reste root avec ces cinq capacités seulement ; l’enfant abandonne
ses privilèges avant l’exécution. Le banc observe `NoNewPrivileges`, les espaces
réseau et périphériques privés, un refus d’écriture `EROFS` sur un témoin hors
des exceptions `ReadWritePaths` limitées aux deux dossiers de fixture, et la
limite de tâches réelle. Les sorties standard et
erreur des unités sont désactivées. Les fichiers du banc restent privés.

L’unité système utilise root par défaut et vérifie UID et capacités avant tout
travail. Avec systemd 257.13, déclarer `User=root` explicitement en présence des
filtres seccomp emprunte une branche qui retire `CAP_SETUID` si elle n’est pas
ambient ; ce comportement a été reproduit avant toute génération et correspond
au [code officiel](https://github.com/systemd/systemd/blob/v257.13/src/core/exec-invoke.c#L4820).
Le modèle conserve les protections et une liste de capacités ambient vide.

Ce banc ne qualifie ni le candidat Studio complet, ni ses chemins installés,
ni l’exclusion des autres processus applicatifs. La barrière entre l’app,
le helper et la génération factory reste à développer. Le contrôle du cgroup
ne remplace pas les pins du candidat ni l’ordre durable du
[hook factory](FACTORY-AUTHORITY.md). Aucune image ou SD n’est modifiée par ce banc.
