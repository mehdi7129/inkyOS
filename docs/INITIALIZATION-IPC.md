# Initialization IPC-A — staging

Le [serveur](../scripts/initialization-server.py) expose uniquement `initialization.inspect`
et `initialization.begin`. Son [unité](../staging/bootstrap/inkyos-initialization.service)
n’est installée ni activée par une recette. Ce travail ne démarre aucune app,
radio ou procédure d’appairage.

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

Un enfant effectue l’appel au reçu ; le parent conserve le délai, réserve 50 ms
pour répondre et surveille l’enfant sans `waitpid` bloquant. Un enfant non réapé
interdit toute nouvelle invocation. Le verrou stable du reçu sérialise aussi les
processus après redémarrage ; une I/O kernel non interruptible ne devient pas
pour autant annulable. Le modèle ne détecte pas la restauration complète d’un
ancien système de fichiers.

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
