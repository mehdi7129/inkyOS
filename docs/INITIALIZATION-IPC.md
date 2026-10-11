# Initialization IPC-A — staging

Le [serveur](../scripts/initialization-server.py) expose uniquement `initialization.inspect`
et `initialization.begin`. Son [unité](../staging/bootstrap/inkyos-initialization.service)
n’est installée ni activée par une recette. Ce travail ne démarre aucune app,
radio ou procédure d’appairage.

Le bootstrap public root/pins du serveur charge le module
`/usr/lib/inkyos/factory-runtime-contract.py`, puis délègue l'admission à son
API commune `writer_guard('ipc')`. Cette extraction ne change ni le wire, ni le
drain, ni l'unité. Les [conditions et limites du guard commun](FACTORY-WRITER-LAUNCHER.md#guard-commun-pour-les-entrées-directes)
restent distinctes du lifecycle IPC décrit ici.

L'entrée installée refuse désormais avec le code **78** avant le chargement du
reçu, le socket, `.server.lock` ou `READY=1` si la garde writer échoue. Elle lit le
contrat public fixe `/etc/inkyos/factory-runtime-v1.json`, contrôle les sources OS
root:root épinglées et prend une **nouvelle SH indépendante** sur l'admission
factory. Ready, le contexte du boot/candidat et `verify_role(..., 'ipc')` doivent
être valides. Un lancement direct au chemin installé est permis sans FD hérité ;
il passe exactement cette même garde. Aucun argument CLI ou variable
d'environnement ne permet d'exempter ce contrôle.

Le [banc du garde et de l'arrêt](validation/2026-10-11-initialization-writer-tests.json)
passe **60 tests Linux ARM64 root sans skip**, dont 16 nouveaux cas. Les leases,
forks et attentes de processus sont réels ; contrat, rôle et contexte sont des
adapters de fixture explicites. La suite locale complète passe 1 512 tests,
avec 13 skips. Cette preuve ne qualifie ni le candidat installé ni son graphe
systemd, et ne réexécute pas les anciens probes de wire/readiness.

Si une des variables `INKYOS_WRITER_LEASE_FD`, `INKYOS_WRITER_ROLE` ou
`INKYOS_WRITER_CONTEXT_SHA256` est présente, les trois sont obligatoires. Le rôle
doit être `ipc`, le SHA doit correspondre au contexte courant, et le FD doit être
un descripteur readonly du même verrou stable, avec les mêmes métadonnées. La
garde n'adopte ni ne convertit ce FD : après obtention de sa propre SH et toutes
les vérifications, elle ferme le FD initial sans `LOCK_UN`, puis retire le
triplet. Une description ouverte dupliquée ou héritée ailleurs conserve ainsi
sa lease. Les seams Python sont réservés aux racines synthétiques différentes
de `/` ; ils ne sont exposés ni par CLI ni par environnement.

Les fixtures de lifecycle IPC passent désormais par le guard commun, avec un
`FakeRuntime` déclaré pour les checks contrat/contexte/rôle et la vraie primitive
admission pour les FD et verrous. Les nouveaux tests du core utilisent le
contrat synthétique réel et ses pins. Aucun de ces tests n'installe un candidat ;
les preuves IPC antérieures restent celles des sources qu'elles épinglent.

Le socket AF_UNIX `/run/inkyos-bootstrap/control.sock` appartient à
`root:inky-provisioning` : répertoire `0750`, socket `0660`. Le serveur vérifie
`SO_PEERCRED` et admet uniquement l’UID applicatif `1000`. Le client doit vérifier
l’UID serveur `0` avant d’envoyer. Root et les autres UID sont refusés ; une trame
valide refusée est lue sous la même borne, sans appeler le reçu, afin de terminer
la réponse par EOF sur Linux. Si la lecture des credentials échoue, ce même
traitement borné renvoie `unavailable` avec `id: null`, sans opération sur le reçu.

Une connexion transporte une requête JSON UTF-8 terminée par LF, puis une réponse
et EOF. Limites, LF inclus : **1024 octets entrants, 2048 sortants, 3 secondes**
pour le traitement de la connexion. Les champs, types primitifs et UUID canoniques
sont stricts ; doublons, valeurs non finies et opérations inconnues sont refusés.

```json
{"v":1,"id":"11111111-1111-4111-8111-111111111111","op":"initialization.inspect"}
{"v":1,"id":"44444444-4444-4444-8444-444444444444","op":"initialization.begin","intent":"22222222-2222-4222-8222-222222222222"}
```

Ces UUID sont synthétiques. Chaque opération réelle reçoit un nouvel `id` ;
l’`intent` déjà persisté reste le même lors d’une reprise. Le succès est
`{v,id,ok:true,result}` avec le résultat exact du [modèle de reçu](../scripts/initialization-receipt.py).
L’échec est `{v,id,ok:false,error}` ; codes fermés : `invalid_request`, `forbidden`,
`unavailable`, `intent_conflict`, `initialization_uncertain`. Un ID indécodable
devient `null`. Aucune exception brute, identité réseau ou donnée supplémentaire
n’est renvoyée.

L’autorité doit déjà exister dans `/var/lib/inkyos/initialization`, en `root:root`
et `0700`. Le serveur ne la crée jamais et n’infère rien d’un état applicatif absent.
Seul le retour courant `newly_consumed` peut autoriser une création applicative ;
`already_consumed` permet seulement la reprise d’un stockage existant cohérent.
Timeout ou réponse perdue après `begin` restent incertains, sans annulation ni
nouvel intent automatique. Une interruption entre consommation et création de
la base exige une récupération explicite.

Un enfant effectue l’appel au reçu ; pendant une requête, le parent conserve le
délai, réserve 50 ms pour répondre et surveille l’enfant sans `waitpid` bloquant.
Un enfant non réapé interdit toute nouvelle invocation. L'enfant conserve les
FD de la SH writer et de `.server.lock` hérités au fork : la mort du parent ne
suffit pas à admettre factory ou un serveur remplaçant tant que cet enfant vit.
Le verrou stable du reçu continue de sérialiser les opérations du reçu.

Les handlers SIGTERM/SIGINT positionnent seulement un flag. Une fois ce flag
observé, aucune nouvelle invocation n'est admise ; un enfant déjà admis peut
encore être dans une opération de reçu. L'arrêt ferme le listener puis demande
SIGKILL à l'enfant et attend son **reaping terminal réel, sans délai maximal**,
avant de fermer `.server.lock` et la SH writer. Une I/O kernel non interruptible
ne devient pas annulable. ECHILD ou une autre observation ambiguë ne prouvent pas
la fin : les verrous restent détenus et l'observation continue, sans répéter de
signal vers un PID dont l'identité serait devenue incertaine. Même une erreur
de fermeture du listener ou du pipe n'autorise pas à sauter ce drain.
Une terminaison forcée de tout le cgroup et sa vérification restent une
responsabilité externe ; ce lot ne modifie pas la politique systemd. Le modèle
ne détecte pas la restauration complète d'un ancien système de fichiers.

L’unité garde les capabilities vides, `NoNewPrivileges`, `PrivateDevices`,
`PrivateNetwork`, `ProtectSystem=strict` et `RestrictAddressFamilies=AF_UNIX`.
Les exceptions `ReadWritePaths` se limitent à l’état existant et au runtime. Son groupe principal est
`inky-provisioning`, avec `root` comme groupe supplémentaire pour les fichiers
du reçu ; aucun `StateDirectory` ne crée implicitement une autorité.

L'unité utilise désormais `Type=notify`, `NotifyAccess=main` et
`TimeoutStartSec=10s`. Le processus principal envoie une seule notification
`READY=1` après la vérification du module de reçu épinglé, l'ouverture du listener
et la création de l'objet worker, avant d'accepter les requêtes. `NOTIFY_SOCKET` est
retiré de son environnement avant un éventuel fork ; un échec de notification
arrête le démarrage sans consommer l'autorité.

La [preuve de readiness native](validation/2026-10-11-ipc-notify-readiness-native.json)
consigne **57 tests serveur/reçu PASS sous Linux ARM64, sans skip**, puis deux
bancs distincts de **10 contrôles PASS** : client de fixture et client Studio
épinglé. Chacun vérifie le manager `notify/main`, `active/running` au retour de
start et de restart, puis les échanges IPC. Les unités sont arrêtées et les
cgroups liés au manager sont vides ou absents après l'arrêt. Ces observations
ne qualifient ni la readiness de l'app ni la barrière factory.

Le premier passage Linux avait révélé un défaut de la fixture de saturation :
le sender de remplissage bloquait après 278 datagrammes, alors que la limite du
récepteur était de 512 et qu'un nouveau sender pouvait encore envoyer `READY=1`.
Le test confondait donc le blocage du sender avec une queue manager pleine.
La correction `c369431` conserve plusieurs senders jusqu'au blocage du premier
envoi d'un nouveau socket, avec des bornes de 32 senders et 4096 datagrammes.
Seul le test a changé ; le serveur, l'unité et les réglages de queue du système
sont restés inchangés. Le passage corrigé est celui des 57 tests PASS ci-dessus.

## Banc natif reproductible

Dans la VM Linux de build marquée, depuis une copie des sources correspondantes :

```sh
sudo /usr/bin/python3 -I -B staging/bootstrap/probe-initialization-linux.py --run
```

Le [probe](../staging/bootstrap/probe-initialization-linux.py) vérifie les sources
épinglées, crée un état synthétique neuf et une unité transient, sans modifier de
compte. Il transpose les chemins et utilise le groupe numérique existant `65534`.
Il substitue explicitement la garde writer par un context manager inerte,
annoncé par `writer_guard: explicit-fixture-substitution` et
`installed_writer_guard_qualified: false`. Ce banc exerce le wire IPC/readiness,
pas le contrat installé, Ready ou la garde factory. Les tests dédiés de la garde
utilisent des verrous et processus réels dans des racines synthétiques ; leurs
vérifications de rôle/contrat simulées ne constituent pas une image installée.
Les clients exécutent réellement `setuid` : UID `1000` admis, `0` et `1001` refusés.
Ce dernier représente un auxiliaire synthétique, pas un compte installé.
Le probe arrête uniquement son unité et conserve son état de fixture pour revue.

La [preuve initiale du 11 octobre](validation/2026-10-11-initialization-ipc-native.json)
consigne **8 contrôles natifs PASS**, dont les permissions, capabilities vides,
consommation durable, même reçu après redémarrage et délai avec verrou bloqué.
Les tests portables de ce premier relevé comptent **46 tests, zéro échec et un ignoré
sur Mac** pour les credentials kernel Linux. Trois tests socket rejoués indépendamment sous Linux
confirment aussi le refus après échec des credentials, son EOF et sa borne de temps.
Ses sources et résultats historiques sont conservés ; le probe courant ajoute
les deux contrôles manager consignés dans la preuve de readiness ci-dessus.
Le banc ne qualifie ni les chemins/groupe de production,
ni une image, le premier boot, le cadre ou l’app iOS. Le
[hook de création initiale](FACTORY-AUTHORITY.md) est développé séparément ;
son installation, le raccord applicatif et leur qualification restent à intégrer.

## Banc croisé avec le client Studio

Le [probe croisé](../staging/bootstrap/probe-initialization-studio-linux.py)
réutilise le même banc et ses dix contrôles courants, avec le vrai `InitializationIPCClient`
Studio issu de `da966c6`. Ses huit fichiers Python sont vérifiés par SHA-256 avant
import. Les clients s'exécutent après le changement réel d'UID : leur vérification
`SO_PEERCRED`, leurs IDs, leur parser et leur contrôle d'EOF ne sont pas remplacés.
Le harness normalise ensuite uniquement le résultat Python pour ses assertions ;
il ne constitue pas une capture du wire.

Son pin du probe natif est raccordé à la fixture de garde explicitement
substituée. Ce raccord ne réexécute ni ne promeut le banc croisé ; les résultats
historiques ci-dessus restent associés à leurs anciennes sources.

Pour reproduire dans la VM marquée, copier les huit sources Studio listées dans
`STUDIO_PINS`, depuis `server/` du commit exact, sous
`staging/bootstrap/studio-client/`, en conservant leurs chemins relatifs.
Le staging et ses parents doivent appartenir à root et ne pas être modifiables
par les autres utilisateurs. Python doit disposer de `cryptography` (version
`43.0.0` lors du banc).

```sh
sudo /usr/bin/python3 -I -B staging/bootstrap/probe-initialization-studio-linux.py --run
```

La [preuve croisée initiale](validation/2026-10-11-initialization-studio-native.json)
conserve huit contrôles PASS et l'arrêt de l'unité transitoire sur ses sources
épinglées. Le nouveau passage à dix contrôles figure dans la preuve de readiness.
Aucun démarrage de l'app, BLE, perte de réponse injectée, boot d'image ou essai matériel n'est
revendiqué par ce banc.
