# Admission coopérative factory — primitive de staging

La [primitive staging](../staging/bootstrap/writer-admission.py) fournit une
exclusion locale avec `flock`.
Il n'installe aucune unité, ne lance aucun worker, ne signale aucun processus et
ne modifie ni Studio, ni les pins, ni la recette image. Il n'a pas de CLI et ne
choisit jamais `/` ou `/run` par défaut. Les seuls objets créés sont génériques :
aucune autorité, clé, credential ou identité.

## API et état

Le chemin `root` est obligatoire. Le répertoire `root/run` doit déjà exister,
root:root 0755. La racine doit être root:root et non modifiable par groupe/autres.
Les composants sont parcourus avec `O_NOFOLLOW`. Les overrides d'ownership sont
des seams de tests ; des valeurs différentes de 0:0 sont refusées pour `/`.

| Appel | Contrat |
| --- | --- |
| `prepare(root)` | Propriétaire seulement. Crée une fois `run/inkyos-admission` 0755 et `lock` vide 0644. Tout répertoire admission préexistant est refusé, sans adoption ni réparation. |
| `with factory(root) as lease:` | Propriétaire seulement. Prend EX non bloquant avant de vérifier l'état. Crée et fsync `attempted` avant de rendre la main au caller. |
| `lease.publish_ready()` | Propriétaire, processus créateur et même lease EX seulement. Publie explicitement `Ready`, après les vérifications externes du superviseur. |
| `with writer(root) as lease:` | Prend SH non bloquant, puis contrôle le layout et les octets exacts de `attempted` et `Ready` sous SH. Un writer UID1000 peut lire les fichiers root0644. |
| `lease.close()` / sortie de contexte | Ferme les FD, sans `LOCK_UN`. Le verrou reste détenu par les copies obtenues via dup/fork jusqu'à leur fermeture. |

Le layout préparé contient exactement `lock`, puis `attempted`, puis éventuellement
`Ready`. Les deux marqueurs sont root:root 0644, single-link et de contenu fixe :

```json
{"schema_version":1,"state":"attempted"}
{"schema_version":1,"state":"factory-complete"}
```

Chaque fichier comprend un LF final. Modes, UID **et** GID, tailles exactes,
types, liens, xattrs/ACL et identité fd/path du lock sont contrôlés. Fichiers
supplémentaires, hardlinks, symlinks et fichiers spéciaux sont refusés. Une API
xattrs indisponible échoue fermé. Aucune entrée existante n'est écrasée/remplacée.

`Refused.reason` distingue `busy`, `already_ready`, `recovery_required`,
`not_ready`, `invalid_state`, `not_owner` et `publication_uncertain`.
Factory busy ne touche à aucun état : un `Ready` valide reste valide et les
writers existants ne reçoivent aucun signal. Sous EX, `Ready` déjà présent donne
`already_ready` ; `attempted` seul donne `recovery_required`, sans retry ni spawn.
Un layout préparé sans `Ready` donne `not_ready` au writer ; un layout absent ou
malformé donne `invalid_state`.

## Tentative persistante et publication

Une exception ou un crash après création de `attempted` ne l'efface **jamais**.
Même un échec avant le premier spawn peut donc imposer un nouveau boot. Une
erreur I/O peut laisser un layout incomplet qui est refusé. Aucun rollback,
reset, retry automatique, kill ou nettoyage d'état n'est fourni. Un crash avant
la création de `attempted` ne consomme pas la tentative, puisque aucun travail
n'a encore été rendu au caller.

Le superviseur extérieur doit avoir vérifié succès du hook, pins et cgroup vide
**avant** `publish_ready()`. Le module ne fait et ne prouve aucune de ces
vérifications. Il conserve EX pendant la publication ; les writers contrôlent
l'état après acquisition de SH. Pour une tentative fraîche sans `Ready`, un
refus avant sa création laisse l'admission fermée. Dès que la création commence,
une erreur d'écriture, fsync
ou readback peut donner `publication_uncertain` : un fichier complet peut déjà
exister et être accepté sous SH après libération de EX. Une exception tardive
ne révoque donc pas un `Ready` conforme. Le caller doit traiter cette réponse
comme incertaine, sans rejouer factory. Un crash dans cette fenêtre a la même
limite. `Ready` veut seulement dire « factory terminée », jamais IPC prêt,
produit prêt, identité de boot ou preuve d'un candidat.

## Obligations d'intégration encore absentes

Le provisionnement au boot doit garantir un `/run` réellement neuf et un lock
stable pendant toute sa durée. Ne **jamais** supprimer/recréer ces objets via
`RuntimeDirectory=` ou un stop/restart pour réinitialiser `attempted` : des
processus pourraient garder un verrou sur l'ancien inode. La préparation au
boot est une opération distincte, non intégrée ici. Un root hostile capable de
remplacer tout le layout avant ouverture n'est pas couvert.

La lease writer doit couvrir les enfants et leur drain réel, pas seulement la
vie du main. Les FD Python sont non inheritable à travers exec ; `Popen` ferme
normalement les FD. Le caller doit organiser explicitement `pass_fds` ou garder
un superviseur vivant jusqu'à la fin de tous les enfants. Un fork retient le
verrou ; un exec n'en hérite pas implicitement. Chaque `ExecStart` devra acquérir
sa propre lease : PID1 n'hérite pas de celle d'un client `systemctl`. Le
superviseur EX devra rester hors du cgroup worker arrêté/inspecté.

Le graphe futur proposé est `Wants` + `After`, avec admission explicite. Les
dépendances qui propagent stop/restart peuvent arrêter l'app avant son garde ;
elles ne sont pas installées par ce lot. Références officielles systemd v257.13 :
[relations et ordre](https://github.com/systemd/systemd/blob/v257.13/man/systemd.unit.xml#L587-L765),
[attributs des relations inverses](https://github.com/systemd/systemd/blob/v257.13/src/core/unit-dependency-atom.c#L33-L70),
[propagation des jobs](https://github.com/systemd/systemd/blob/v257.13/src/core/transaction.c#L983-L999).
La couverture des writers, des voies CLI/ASGI/updater et des effets PID1 reste
à intégrer et qualifier ; voir [le projet d'intégration](FACTORY-IMAGE-INTEGRATION.md).

Un verrou coopératif n'empêche pas une app compromise ou un writer manuel de
l'ignorer. EX libre ne prouve ni quiescence NetworkManager, ni fin physique
d'une opération e-ink après crash. Les tests synthétiques prouvent les transitions,
les refus et la rétention des FD dans leur environnement ; ils ne qualifient
ni renouvellement `/run`, ni graphe systemd, ni superviseur, ni application,
image, boot ou matériel. Mac utilise des substitutions explicites d'ownership
et xattrs. Le cas Linux root descend réellement à UID/GID1000 ; il est skipped
avec raison sur les autres environnements et sa preuve reste séparée.

Le [banc synthétique du 11 octobre 2026](validation/2026-10-11-writer-admission-tests.json)
passe 31 tests sous Linux ARM64 root, sans skip, dont les accès du writer
UID/GID 1000. Sur macOS, 28 tests passent et les trois cas Linux root sont
explicitement ignorés. Ces résultats ne changent aucune des limites ci-dessus.

Le lot suivant fournit un [contrat et des lanceurs fermés](FACTORY-WRITER-LAUNCHER.md)
et un [superviseur exécutable](FACTORY-SUPERVISOR.md). Il passe
[81 tests Linux ARM64](validation/2026-10-11-factory-runtime-tests.json), dont
un exec Python inerte conservant SH. Ce raccord n'est pas installé dans l'image ;
ses tests PID1/cgroup et payloads restent des fixtures déclarées.
