# Banc Linux du bootstrap

Le banc utilise de vrais processus Linux, un socket AF_UNIX et un reçu root-owned
dans la VM dédiée `inkyos-build`. Les adapters d'heure et de pays sont des fakes
tracés. Aucun daemon, endpoint applicatif ou composant n'est installé dans l'image.

```sh
make bootstrap-probe
make vm-stop
```

Le wrapper refuse les arguments, vérifie le marqueur du builder et copie les
trois sources dans un snapshot root-owned inaccessible aux clients. Chaque SHA-256
est vérifié avant l'exécution isolée Python. Le script Linux refuse tout hôte
autre que Linux root portant le marqueur du builder. Il crée son seul workspace
sous `/var/lib/inkyos-build`, puis le supprime ; le wrapper supprime ses snapshots.
Les sources, `inputs.json`, `report.json` et `SHA256SUMS` restent dans un nouveau
`build/bootstrap-probe.*` local. Ces artefacts sont ignorés par Git.

## Résultat vérifié le 28 septembre 2026

46 checks passent dans Linux ARM64. La
[preuve compacte](validation/2026-09-28-bootstrap-peercred.json) contient les
hashes exacts et le résultat. Les UID sont des identités de fixture, pas une
allocation de comptes de production.
La suite complète compte 221 tests, sans échec sur Mac et Linux ARM64 ; cinq
tests ciblent le framing, les gardes d'environnement et l'expiration du serveur.

| Contrôle | Résultat observé |
| --- | --- |
| App UID 1000 / helper UID 65534 | Groupes supplémentaires vidés et UID/GID changés avant `connect()` ; credentials relus par `SO_PEERCRED`, PID compris |
| Accès au reçu | App/helper/UID étranger ne peuvent ni lire, ni écrire, ni remplacer le répertoire root 0700 et ses fichiers 0600 |
| Rôles | App autorisée à initialiser seulement ; helper autorisé aux fakes heure/pays seulement ; UID 0 et étranger refusés |
| Transport | JSON invalide/dupliqué, UID injecté dans le message, EOF vide/tronqué, dépassement et client lent refusés sans effet ; fragmentation valide acceptée |
| Pays | Trace fermée → pending → apply → observation → confirmed ; aucun appel réel de radio |
| Concurrence | Deux clients : exactement un `newly_consumed` et un `already_consumed` |
| Reprise | Même intent après restart : `already_consumed` ; intent incompatible ou reçu perdu/corrompu : recovery |
| Réponse perdue | Sortie immédiate du processus serveur après consommation durable, avant réponse ; retry identique : `already_consumed` |
| Nettoyage | Fixtures supprimées, sources inchangées |

L'authentification numérique vérifie ici une frontière locale. Elle ne prouve
pas qu'un téléphone a été authentifié par l'app. Le framing EOF, ses limites et
les messages de ce banc sont internes ; ils ne définissent aucun protocole v1.
Le verrou du modèle ne sérialise que ses threads. Le reçu utilise son vrai
verrou fichier et ses écritures fsync ; les écritures temps/pays restent simulées.
Les clients sont forkés depuis le parent de fixture : les refus filesystem et
les credentials kernel ne prouvent pas une isolation de mémoire. Le serveur
expire sans signal du parent après 30 secondes, avec 2 secondes de drainage
global. Un SIGKILL du parent peut laisser son répertoire synthétique ; le
nettoyage vérifié couvre les sorties normales et les erreurs gérées.

## Avant activation

Il reste à raccorder l'autorisation owner/epoch, les limites et receipts des
mutations d'heure, l'identité et le renouvellement du certificat, puis le gate
réglementaire réel. Après reboot ou échec de vérification, un record pays
`confirmed` ancien ne suffit jamais à rouvrir le Wi-Fi. NetworkManager doit
pouvoir démarrer radio fermée pour que le helper puisse effectuer la suite.

`Refused` pour heure/pays peut suivre une application réussie mais non vérifiée :
ce n'est pas toujours une preuve d'absence d'effet. Pour l'initialisation,
`InitializationUncertain` impose une consultation avec le même intent, jamais
une nouvelle création déduite d'une DB absente ou d'une réponse perdue.

Le banc croisé [app/reçu](validation/2026-09-28-factory-contract-cross.json)
couvre séparément le magasin applicatif perdu et les bindings incohérents.
Ni ces fixtures ni une sortie de processus ne qualifient une coupure électrique,
le boot Raspberry Pi, BLE, le QR physique, l'iPhone ou une SD.
