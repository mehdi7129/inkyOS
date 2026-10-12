# Heure bootstrap — proposition minimale phase B

Politique de prototype coordonnée avec Studio. Seul le lot de calculs purs
ci-dessous est développé ; l'admission et le protocole restent à concevoir
ensemble. Aucun endpoint, service ou setter n’est installé. IPC-A, le reçu
d’initialisation et le [hook factory](FACTORY-AUTHORITY.md) restent inchangés.

La référence historique côté Studio est
`docs/inkyos/SYSTEM-BOOTSTRAP-PHASE-B.md` au commit
`3fd786f0ad6e1334d9bfe2c0a7ddd03bcafe8e49`. Ce document est absent du
candidat Studio `5671ba4ab35bdec5e63c892d35b9108a025e6d82` ; il ne constitue
pas une référence commune actuelle ni un ABI figé. La politique de prototype
consignée ici retient un worker dédié utilisant `clock_settime_ns`,
des **secondes UTC entières**, sans `timedated`, `SetNTP`, timezone ni mode relatif.
Il remplace pour ce prototype l’ancienne piste microsecondes/restauration NTP de
ce brouillon. Le latch initial ouvert/fermé et l’admission owner/epoch restent
à spécifier ensemble ; leur absence interdit toute intégration active.

## Règles numériques convenues

| Élément | Règle |
| --- | --- |
| Assertion | `utc_seconds`, entier exact, booléens et floats refusés |
| Plage | `1767225600 <= utc_seconds < 4102444800`, soit `[2026-01-01, 2100-01-01)` |
| Conversion | `requested_ns = utc_seconds * 1_000_000_000`, arithmétique entière contrôlée |
| Challenge | Usage unique, expire 30 secondes après sa **création serveur**, pas après sa réception |
| Fraîcheur | Timestamp produit au moment de répondre au challenge ; expiration vérifiée sur monotonic juste avant admission et juste avant effet |
| Valeur appliquée | Exactement `requested_ns`, sans ajouter le temps de transport ou d’attente |
| Readback | Écart maximal de ±2 secondes par rapport à la valeur demandée augmentée du temps monotonic effet→lecture |

Un challenge expire dès `now_ns >= created_ns + 30_000_000_000`. Il est lié au
serveur vivant, au boot et au contexte admis ; un redémarrage l’invalide. Son TTL
n’est pas renouvelé par un retry. Une réponse retardée exige un nouveau challenge
et un timestamp frais, jamais le réemploi d’une ancienne assertion.
`created_ns` est l’instant de création conservé par le serveur émetteur,
jamais l’arrivée de la réponse ni une valeur déclarée par le client.
Choix Linux proposé : `CLOCK_BOOTTIME` pour le TTL et les quatre bornes ci-dessous,
afin d’inclure la suspension système ; aucun fallback silencieux sur
`CLOCK_MONOTONIC`, qui l’exclut. Cette base monotonic doit être partagée par
l’émetteur et le vérificateur du challenge. [Source Python](https://docs.python.org/3.13/library/time.html#time.CLOCK_BOOTTIME)
Le TTL borne le parcours de la demande, pas l’âge réel d’une mesure fournie par
un client : produire la valeur à la réponse est une obligation du code Studio/iOS
à tester, pas une authenticité UTC que le service OS pourrait déduire du nonce.

Encadrer l’unique syscall par `e0`/`e1` monotonic, puis le readback
`CLOCK_REALTIME` par `r0`/`r1`. Exiger `e0 <= e1 <= r0 <= r1` : l’instant interne
exact de chaque effet est inconnu. Le temps écoulé appartient à
`[r0 - e1, r1 - e0]`. Pour la mesure entière `R`, l’erreur possible appartient à
`[R - requested_ns - (r1 - e0), R - requested_ns - (r0 - e1)]`.
Proposition conservatrice : **tout cet intervalle** doit être inclus dans
`[-2_000_000_000, +2_000_000_000]` ; un simple chevauchement ne suffit pas.
Une interruption de scheduling trop longue ou une correction NTP peut rendre
la mesure inconclusive : résultat incertain, jamais second setter pour compenser.
Le résultat conserve séparément assertion, mesure et quatre bornes ; il ne
substitue pas le readback à l’assertion Studio.
Les API Python fournissent les variantes entières et une horloge monotonic
indépendante des sauts de l’horloge civile. [Source Python 3.13](https://docs.python.org/3.13/library/time.html#time.clock_settime_ns)

Une correction avant ou arrière dans cette plage reste possible **uniquement**
sous admission initiale encore ouverte. Ni la mauvaise date actuelle du Pi ni
un maximum historique ne deviennent une nouvelle autorité. Cette observation
ne prouve pas UTC indépendante, synchronisation NTP, validité TLS ou heure
actuelle lors d’une lecture ultérieure du reçu.

## Calculs purs développés

Le module interne inactif [`time-policy.py`](../staging/bootstrap/time-policy.py)
implémente uniquement la conversion UTC entière, la fraîcheur numérique du
challenge et le calcul de l'intervalle de readback, avec inclusion entière dans
la tolérance. Ses [24 fixtures macOS](validation/2026-10-12-bootstrap-time-policy.json)
passent sans skip ; une seconde revue des sources a vérifié ces règles.

Le module reçoit des nombres. Il ne lit ni ne règle une horloge et ne fournit
aucune admission. Un résultat numérique vrai ne prouve ni l'origine BOOTTIME,
ni l'usage unique du challenge, ni l'owner ou le latch, ni une UTC indépendante
ou actuelle. Aucun journal, worker, transport, ABI installé ou service
privilégié n'est livré par ce lot.

## Admission : préalable indépendant du payload

L'orientation convenue avec Studio utilise un canal direct entre son coordinateur
et le futur exécuteur UTC ; le helper conserve sa mission réseau. Cela remplace
explicitement la proposition initiale qui n'admettait que le helper comme client.
L'exécuteur doit vérifier l'UID kernel attendu **et** le MainPID/InvocationID
courant du coordinateur sur le socket réellement connecté ; le coordinateur
vérifie symétriquement le serveur privilégié attendu. UID seul, root arbitraire,
helper ou enfant de la même unité ne donnent aucune admission UTC.

Cette nouvelle politique de clients n'est ni implémentée ni installée. Les guards
IPC-A existants ne sont pas réutilisables tels quels pour UTC. PIDFD et propriétés
d'unité ne prouvent pas seuls le code courant après execve. Le coordinateur doit
posséder son endpoint de contrôle sans le transmettre ; les enfants ferment
explicitement ces FDs, car CLOEXEC ne couvre pas l'héritage au fork.
SO_PEERPIDFD identifie le peer connecté, pas l'auteur de chaque message si le FD
est hérité ou passé. Sandboxes, endpoints et discipline des processus restent
à qualifier. Un ID, un hash, un challenge ou
`authorized: true` fourni par l’appelant ne constitue jamais une permission.

Studio reste seul responsable de l'owner et de l'epoch. Il doit vérifier le claim
factory gagnant durable **et** son authentification actuelle, l'absence de
révocation, l'epoch courant, l’intent/frame/SPKI et le latch initial
explicitement ouvert. La même barrière doit exclure clôture, révocation, rotation
d’epoch, admission pays/Wi-Fi/photo et autre correction pendant l’effet. Le
refresh d’accueil/QR doit avoir terminé sans interruption ni second propriétaire
SPI. Un mutex BLE seul ou l’absence d’UI ne satisfait pas cette exigence.

L’OS doit pouvoir vérifier que cette admission a été obtenue du coordinateur
authentifié et demeure réservée sous la barrière commune jusqu’à la fin réelle
du worker. Il ne relit pas arbitrairement une DB de l’app et ne fait pas confiance
à une copie de champs fournie par celle-ci. Une réservation durable conserve
l'exclusion, sans devenir une permission de tenter le setter. Une décision finale
unique ordonne refus ou engagement d'une tentative : une révocation pending qui
la précède impose le refus ; après engagement, elle ferme les nouvelles admissions
et attend le résultat conservateur et la quiescence avant la révocation effective.
Un engagement ne prouve ni le syscall ni sa réussite. Le worker revalide fraîcheur,
peer et réservation après les attentes/fsync, immédiatement avant l'effet.

La lease et le registre de lifecycle survivent à l'annulation de la coroutine
cliente ; aucune transaction SQLite ne reste ouverte pendant l'attente OS.
Décès du parent ou perte du canal ne libèrent pas un ancien exécutant non prouvé
terminé. Le gagnant révoqué ne transfère pas son scope initial à un autre owner.
**L'ordre précis entre engagement et journal, les interfaces et l'admission native
restent à développer et revoir ensemble avant effet actif.**
Le prototype pur peut injecter un vérificateur de fixture ; en production,
aucune preuve disponible ou vérification incertaine signifie refus. Aucun
nom de méthode supplémentaire ni format de jeton d’admission n’est figé ici.

## Schéma local proposé, distinct du wire

Journal privé root sous un emplacement proposé `/var/lib/inkyos/bootstrap-time/`,
dossier `0700`, fichiers ordinaires à lien unique `0600`, parents sûrs et sans
symlink. Son provisionnement initial et sa génération OS doivent être explicites :
le service ne recrée pas un journal absent ou corrompu. Aucun timestamp personnel,
scope réel ou contenu de ce journal n’est destiné à une preuve publique.

Proposition étroite : un verrou stable global et, par UUID canonique d’opération,
trois petits enregistrements fermés, sans remplacement d’un ancien ID :

| Enregistrement | Champs proposés |
| --- | --- |
| `prepared` | `version=1`, `operation_id`, `os_generation`, `request_sha256`, `utc_seconds`, `scope`, `challenge_sha256`, `challenge_created_boottime_ns`, `boot_binding` |
| `effect_attempted` | `version=1`, `operation_id`, `prepared_sha256` |
| `result` | `version=1`, `operation_id`, `prepared_sha256`, `state`, `reason`, `readback` |

`scope` conserve uniquement les liaisons vérifiées intent/frame/SPKI/owner/epoch
et génération du latch, jamais credentials ou preuve privée du téléphone. Les
types exacts de ces liaisons attendent le schéma Studio ; aucune valeur de scope
n’autorise une opération par elle-même. Les champs monotonic sont des entiers
locaux au boot ; `boot_binding` n’est pas une identité matérielle. `readback` est
`null` si non établi, sinon un objet fermé `{realtime_ns, e0, e1, r0, r1}` contenant
uniquement des entiers. Dans `result`, `state` est exclusivement
`verified`, `uncertain` ou `rejected`, et `reason` appartient à une liste fermée
à figer avec les fixtures. Aucune exception brute n’y entre.

Le hash canonique lie tous les paramètres admis, leur version et leur scope.
Même ID/autre contenu : refus. Même ID/même contenu : lecture du résultat ou de
l’incertitude, jamais nouvelle exécution. Proposition v0 : au plus 64 opérations,
aucune éviction ni compaction ; journal plein = refus de nouvelle mutation.
Un fichier partiel/inattendu, un manque d’espace ou un échec de synchronisation
ferme l’admission. Le format disque exact reste à valider ; réutiliser les
primitives fichier temporaire exclusif, fsync, publication atomique et fsync
répertoire déjà éprouvées, sans modifier le reçu IPC-A.

## Effet et reprise

Un parent sérialise les admissions ; un seul enfant réalise au plus un
`clock_settime_ns(CLOCK_REALTIME, requested_ns)`, puis le readback. `prepared`
et `effect_attempted` sont chacun durables **avant** ce syscall. Le parent
attend la fin effective du worker, valide son résultat et la barrière, puis
persiste `result` avant l’ACK. Un syscall réussi sans cette chaîne ne produit
pas de succès global. Un rejet avant effet ne déclenche aucun setter.

| Coupure observée | Reprise |
| --- | --- |
| Avant `prepared` durable | Nouvelle admission fraîche possible si tous les prérequis sont encore vérifiés |
| `prepared` seulement | Aucun rejeu ; après quiescence prouvée, terminer sans effet comme `rejected` ; nouvelle assertion sous nouvel ID seulement si la phase reste ouverte |
| `effect_attempted`, résultat absent | `uncertain`, lecture/réconciliation uniquement, jamais le setter sous cet ID |
| Résultat durable, ACK perdu | Même résultat historique sous authentification courante, sans effet |
| Reboot ou parent redémarré | Challenges invalidés, journal conservé, ancien effet jamais rejoué |

La fermeture du socket, l’expiration du client, l’envoi d’un signal et le retour
d’une commande d’arrêt ne prouvent pas seuls la terminaison. Tant qu’un worker
n’est pas réellement terminé/réapé, aucune nouvelle admission, rotation ou
clôture ne peut franchir la barrière. Après crash du parent, la reprise exige
aussi la preuve que son ancien groupe d’exécution ne contient plus d’exécutant ;
sinon récupération explicite. Une opération incertaine doit être résolue avant
toute nouvelle correction ; un nouvel ID n’efface pas ce blocage.

Le choix v0 coordonné conserve une récupération explicite sur `uncertain`, sans
retry du setter. Une bonne heure observée plus tard ne vérifie pas l'ancien effet
et ne débloque pas un certificat ou la clôture. Une éventuelle continuation sans
setter exigerait une preuve actuelle et un adapter certificat distincts ; elle
n'est pas livrée par cette politique. La réparation owner-only après clôture reste
également un contrat séparé.

Le composant ne demande aucune mutation NTP et ne prétend donc pas avoir
« restauré NTP ». Le service NTP peut rester actif et corriger l’heure lui-même.
Son absence/activité/synchronisation sont des observations distinctes ; un
readback hors tolérance reste incertain, sans arrêt NTP ni retry automatique.
Une politique NTP active/enabled inchangée ne prouve pas une synchronisation
conservée après l’effet.

## Unité future et fixtures minimales

Une unité privilégiée séparée d’IPC-A aura une bounding set limitée à
`CAP_SYS_TIME`, aucune capability accordée à Studio ou au helper, `NoNewPrivileges`,
`PrivateDevices`, `PrivateNetwork`, `ProtectSystem=strict`, exceptions `ReadWritePaths`
limitées au journal/runtime, AF_UNIX uniquement et `KillMode=control-group`. Elle devra
permettre le syscall d’horloge : `ProtectClock=yes` le bloquerait et retirerait
`CAP_SYS_TIME`. IPC-A conserve sa protection actuelle. Les commandes/chemins/clock
IDs restent fixes dans le code ; aucune interface système générique.
[Source systemd v257.13](https://github.com/systemd/systemd/blob/v257.13/man/systemd.exec.xml)

Le budget global et le contrôle du groupe après restart sont à éprouver avant
installation. Le TTL de challenge ne borne pas une I/O kernel. Les premiers
tests utilisent exclusivement un setter injecté et des horloges simulées :

- Bornes UTC exactes, bool/float/overflow/duplication refusés ; conversion entière
  et payload appliqué inchangé malgré un transport retardé.
- Expiration à 30 s depuis création, timestamp pris à la réponse, origine de la
  date de création, challenge utilisé, suspension, reboot et saut d’horloge civile ;
  aucun renouvellement implicite du TTL ni substitution de base de temps.
- Latch absent/fermé/incertain, owner révoqué, epoch changé, refresh actif,
  preuve booléenne/ID seul : refus sans appel du setter.
- Coupure et échec fsync à chaque frontière, même ID autre payload, journal plein
  ou corrompu, ACK perdu : aucun second effet ni réouverture automatique.
- Worker bloqué, parent mort, résultat tardif, révocation/clôture concurrentes :
  aucune admission avant terminaison prouvée et résolution de l’incertitude.
- Readback à ±2 s et juste au-delà, quatre bornes monotonic incohérentes,
  intervalles trop larges ou simplement chevauchants, correction NTP concurrente :
  résultat conservateur, assertion et mesure distinctes.

Ces fixtures ne qualifieront ni une mutation réelle de l’horloge, ni la preuve
d’admission, le latch Studio, le certificat, la radio ou le matériel. Aucune
mutation de l’horloge du Mac ou de la VM partagée n’est nécessaire à cette phase.
