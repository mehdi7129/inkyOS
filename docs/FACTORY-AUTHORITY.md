# Permission factory — staging

Le [hook](../scripts/factory-authority.py) consomme une permission positive,
appelle le [publisher credentials](FACTORY-CREDENTIALS.md), puis crée l’autorité
OS à usage unique. Ce raccord reste **STAGING** : il n’est installé ni exécuté
par une recette ; aucun service, image TEST, compte ou premier boot existant ne
change. Il ne crée jamais une permission manquante. La reprise examine seulement
les metadata des credentials courants, sans lire leur contenu.

Les conditions doivent toutes être explicites :

- `INKY_STUDIO_FACTORY_REQUIRED=1` et `INKY_STUDIO_DATA_DIR=/var/lib/inky-studio`.
- `/etc/inky-studio/factory-v1.json`, fichier ordinaire à lien unique, `root:root`
  `0644`, parents root non modifiables par les autres utilisateurs, sans symlink.
  JSON fermé : `{"version":1,"app_uid":1000,"data_dir":"/var/lib/inky-studio"}`.
- `/var/lib/inkyos/factory-permission/`, `root:root` `0700`, préparé par un futur
  profil opt-in distinct. Il contient uniquement `lock`, vide, et `pending.json`,
  tous deux ordinaires, à lien unique et `root:root` `0600`.

Le contenu de `pending.json` est générique, sans identité ni secret :

```json
{"version":1,"operation":"create-initialization-authority"}
```

Le hook vérifie les octets épinglés des deux modules OS avant de les charger :
`/usr/local/lib/inkyos/initialization-receipt.py` et
`/usr/local/lib/inkyos/factory-credentials-publisher.py`, fichiers ordinaires à
lien unique, `root:root` `0555`, avec parents fiables. Il revérifie leurs pins et
metadata au cours de l’opération. Les types JSON sont exacts ; champs en trop,
doublons et mauvaises permissions provoquent un refus.

Sous le verrou stable exclusif non bloquant, le hook renomme `pending.json` en
`consumed.json`, puis appelle `fsync` sur le dossier. **Il appelle le publisher
une seule fois, uniquement après le retour réussi de ce `fsync`.** Ce dernier
exige un dossier applicatif vide, collecte le sérialiseur sous UID/GID 1000,
récupère l’enfant avec EOF et exit 0, publie exclusivement les credentials,
synchronise et relit les octets. Le hook revérifie permission, modules et
metadata credentials avant d’appeler `create_authorization`. Le verrou reste
détenu pendant toute la séquence. Une erreur de publication ne crée aucune
autorité et ne restaure pas la permission.
L’autorité cible est fixée à `/var/lib/inkyos/initialization`. Une entrée déjà
présente à cet endroit alors que la permission est encore pending est ambiguë
et refusée, même s’il s’agit d’un lien cassé. Le verrou, le dossier et les
bindings du marqueur et des modules sont revérifiés avant la création.

| État observé | Résultat du hook |
| --- | --- |
| Pending valide, aucune autorité et publication réussie | Consomme la permission, publie les credentials, puis crée l’autorité |
| Consumed valide, autorité valide, metadata credentials valides et stables | Inspection seulement, sans publication ni nouvelle autorité |
| Consumed, autorité absente, partielle ou corrompue | Récupération explicite requise |
| Consumed, credentials absents ou metadata invalides | Récupération explicite requise, jamais de régénération |
| Permission absente, deux marqueurs, fichier inattendu ou contrôle invalide | Refus, aucune création |
| Autre processus tenant le verrou | `busy`, sans attente sur ce verrou |

Une réponse de succès contient seulement `status: created|existing` et
`authority_status: authorized|consumed`. Le succès du hook ne donne pas de droit
de création à l’app : celle-ci doit encore obtenir le reçu courant
`newly_consumed` via [IPC-A](INITIALIZATION-IPC.md). Les erreurs restent fermées :
`configuration_invalid`, `permission_unavailable`, `recovery_required`, `busy`.

La reprise exige un dossier `/var/lib/inky-studio` sans symlink, UID/GID 1000,
mode `0700`, sous des parents root fiables. `credentials.json` doit être un
fichier ordinaire non vide, de 8192 octets maximum, à lien unique, UID/GID 1000,
mode `0600`. Le hook
compare ses metadata avant et après inspection du reçu, sans ouvrir le fichier.
Les autres données applicatives peuvent exister. Une rotation terminée avant
cet appel est acceptée : aucune empreinte initiale du payload n’est conservée
ou comparée. La validation du format courant reste à Studio ; le résultat
`existing` du hook ne qualifie pas la sémantique des credentials.

Une interruption avant consommation peut reprendre. Après renommage et avant
création durable de l’autorité, la reprise exige une récupération explicite,
même si les credentials ont déjà été publiés entièrement.
Si la création durable a terminé mais sa réponse a été perdue, la reprise
inspecte cette même autorité et les metadata actuelles. Aucun rollback ni
nettoyage automatique ne remet
la permission en pending. La restauration complète d’un ancien filesystem reste
hors de cette protection.

Les [fixtures](../tests/test_factory_authority.py) utilisent seulement des racines
synthétiques privées et des producteurs inertes avec les vrais modules OS
épinglés : types et permissions, concurrence entre processus, ordre durable,
interruptions entre consommation, publication et création d’autorité,
reprise, rotation, metadata et erreurs de `fsync`. Elles ne lancent pas le vrai
sérialiseur Studio. Les coupures de processus ne simulent pas la perte
physique des caches d’une SD. `flock` du hook est non bloquant ; les I/O kernel
et le verrou interne de lecture du reçu ne sont pas rendus annulables par ce
module. Les injections de fixture sont refusées sur la racine système, y
compris l’alias `//`, avant tout accès aux bindings.

Ce raccord ne prouve ni les pins du candidat Studio installé, ni l’exclusion
réelle de l’app et du helper, ni la quiescence du cgroup après un enfant non
récupéré. Ces conditions appartiennent à la future unité et à sa barrière de
démarrage : le verrou du hook seul n’arrête pas les autres processus UID 1000.
Aucun booléen d’entrée ne tient lieu de cette preuve. Le superviseur devra
conserver la barrière en cas d’échec ou de `producer_unreaped` ; aucune erreur
du publisher n’est une autorisation de poursuivre. L’unité, son budget global,
la recette, le parcours avant IPC/app et les essais physiques restent à
concevoir et qualifier.

```sh
python3 -I -B -m unittest discover -s tests -p test_factory_authority.py -v
```
