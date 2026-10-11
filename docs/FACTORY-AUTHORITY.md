# Permission factory — staging

Le [hook](../scripts/factory-authority.py) crée l’autorité OS à usage unique à
partir d’une permission positive. Il n’est installé ni exécuté par une recette ;
aucun service, image TEST, compte ou premier boot existant ne change. Il ne lit
pas les données applicatives et ne crée jamais une permission manquante.

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

Le hook vérifie aussi les octets épinglés du module de reçu avant de le charger,
avec fichier installé `root:root` `0555`. Les types JSON sont exacts ; champs en
trop, doublons et mauvaises permissions provoquent un refus.

Sous le verrou stable exclusif non bloquant, le hook renomme `pending.json` en
`consumed.json`, puis appelle `fsync` sur le dossier. **Il appelle
`create_authorization` uniquement après le retour réussi de ce `fsync`.**
L’autorité cible est fixée à `/var/lib/inkyos/initialization`. Une entrée déjà
présente à cet endroit alors que la permission est encore pending est ambiguë
et refusée, même s’il s’agit d’un lien cassé. Le verrou, le dossier et les
bindings du marqueur et du module sont revérifiés avant la création.

| État observé | Résultat du hook |
| --- | --- |
| Pending valide, aucune autorité | Consomme la permission, puis crée l’autorité |
| Consumed valide, autorité valide | Inspection seulement, sans nouvelle autorité |
| Consumed, autorité absente, partielle ou corrompue | Récupération explicite requise |
| Permission absente, deux marqueurs, fichier inattendu ou contrôle invalide | Refus, aucune création |
| Autre processus tenant le verrou | `busy`, sans attente sur ce verrou |

Une réponse de succès contient seulement `status: created|existing` et
`authority_status: authorized|consumed`. Le succès du hook ne donne pas de droit
de création à l’app : celle-ci doit encore obtenir le reçu courant
`newly_consumed` via [IPC-A](INITIALIZATION-IPC.md). Les erreurs restent fermées :
`configuration_invalid`, `permission_unavailable`, `recovery_required`, `busy`.

Une interruption avant consommation peut reprendre. Après renommage et avant
création durable de l’autorité, la reprise exige une récupération explicite.
Si la création durable a terminé mais sa réponse a été perdue, la reprise
inspecte cette même autorité. Aucun rollback ni nettoyage automatique ne remet
la permission en pending. La restauration complète d’un ancien filesystem reste
hors de cette protection.

Les [fixtures](../tests/test_factory_authority.py) utilisent seulement des racines
synthétiques privées : types et permissions, concurrence entre processus,
interruptions avant/après renommage et synchronisation, création partielle,
reprise et erreur de `fsync`. Les coupures de processus ne simulent pas la perte
physique des caches d’une SD. `flock` du hook est non bloquant ; les I/O kernel
et le verrou interne de lecture du reçu ne sont pas rendus annulables par ce
module. L’unité et son budget, la recette, l’ordre avant IPC/app et les essais
physiques restent à concevoir et qualifier.

```sh
python3 -I -B -m unittest discover -s tests -p test_factory_authority.py -v
```
