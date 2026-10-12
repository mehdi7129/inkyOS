# Admission du graph Phase A — candidat inactif

Les sources de ce candidat inactif relient un observer OS et la composition
fixe de la Phase A au launcher, qui cible `factory-main.py`. L'installation
inactive des fichiers a son [lot séparé](FACTORY-WRITER-INSTALLATION.md) ;
la recette active et son intégration dans une image restent à qualifier.
Ce raccord ne modifie aucun protocole, caller Studio, service, compte, radio ou SD.

Le pin applicatif courant est Studio
`eb117903cb647a14e9722d7387a41058ea8807b3` (PR #35). Cet alignement source
ne qualifie pas le graph installé, le sandbox, le Pi ou les parcours iPhone.
Les preuves historiques R33 portent sur
`0a0d4bd6456b3fcd1fcdbcaf0b5269c317e3ea91` et restent distinctes. Le payload
TEST `c31b13a`, le bundle historique `a071f19`, son driver `inky==2.3.0` et
TestFlight build 9 ne sont pas remplacés par ce patch. Aucune compatibilité
matérielle n'est transférée par l'alignement ou les tests de ces hooks.

## Composition fixe

- [writer-graph.py](../staging/bootstrap/writer-graph.py) expose `open_main()`,
  `check()`, `initialization_guard(socket)`, `start_monitor(loop, event)` et
  `close()`. Ses roles sont exactement main, helper et IPC.
- [factory-main.py](../staging/bootstrap/factory-main.py) est destiné au Python
  de la venv applicative, avec argv fixe `python -I -B factory-main.py`.
  Il n'accepte ni option CLI ni choix de chemin en production.
- Après la preuve OS, le wrapper importe seulement `factory_phase_a`,
  `bootstrap_runtime` et `inky.display`. Aucun import de `inky_web.main`,
  aucune app ASGI globale, aucun normal-mode fallback.
- `serve_factory_phase_a()` reçoit DATA fixe, stop event, factory Display
  hardware, les deux callbacks obligatoires et
  `BootstrapRuntime(result, verify_epoch, display, DATA)`. Le runner choisit
  lui-même son `FactoryRuntimeConfig` et détient sa SH indépendante.
- Aucun `NetworkClient` n'est créé ou injecté. L'API peer guard du helper
  reste un raccord futur explicitement inutilisé par cette Phase A.

## Preuves et états

`BINDING` attend en lecture seule que les jobs initiaux soient terminés, avec
un budget unique. Un main/helper `Type=exec` peut être exécutable avant la fin
du job main ; il ne garantit pas la readiness produit ou du socket helper.
L'IPC `Type=notify` termine son job READY avant les unités ordonnées après lui.
La composition ne commence qu'après des observations stables du graph.

La vue PID proposée utilise `pidfd_open(1)` et le mapping trusted PID1
`GetUnitByPIDFD` attendu pour `init.scope`. Cette ancre est conservée vivante.
Un PID1 visible mappé à une autre unité, ou une primitive indisponible, refuse.
Cette méthode évite de demander la lecture d'un `/proc/1/ns/pid` étranger ;
sa valeur comme preuve de namespace et ses permissions UID 1000 restent
à qualifier nativement. Le probe NSS séparé ne mesure pas cette ancre.

Chaque writer est lié à son object path fixe, son MainPID, son invocation et
son pidfd vivant. Le main doit aussi être exactement le processus du caller.
Les propriétés D-Bus ont des types fermés, dont le vrai tableau `ExecStart`.
Les units chargées doivent conserver le fichier vendor attendu, sans alias,
drop-in, transient unit, reload requis ou propagation d'arrêt ajoutée.
Leurs identités, lancement, politiques et dependencies observées sont liés
au snapshot initial. Les champs de comptabilité ExecStart ne constituent pas
une identité de l'executable courant.

Après `ACTIVE`, toute observation impossible, timeout, décès, changement de
PID, invocation ou configuration latch `INVALID` définitivement. Aucune
réassociation ni réadmission d'une nouvelle invocation. Chaque callback fait
des observations fraîches ; aucun bool positif mis en cache ne donne admission.
L'observer permanent relaie l'invalidation à `stop_requested` via
`loop.call_soon_threadsafe`. Il n'arrête et ne signale jamais IPC/helper.

## Peer IPC et arrêt

Le guard reçoit le socket déjà connecté fourni par Studio. Il obtient le
`SO_PEERPIDFD` réel, contrôle les credentials root, l'identité avec l'ancre
MainPID IPC, son mapping PID1 et son invocation avant le premier envoi.
Un enfant de la même unité est refusé. Le pidfd reste détenu pendant la réponse,
sa validation, la fermeture du socket et son drain ; la sortie du guard ne
consulte pas le socket que Studio a déjà fermé.

Le listener IPC appartient au parent MainPID et peut être hérité par son
worker enfant. La preuve porte donc uniquement sur le **connected peer** ;
elle n'atteste pas le processus qui écrit chaque message. Aucun SCM_PIDFD
par message, broker, autorité owner/B ou nouveau protocole n'est fourni.

Sur arrêt ou cancellation, le wrapper ferme l'admission et attend les drains
Studio. Il conserve sa SH jusqu'au drain de ses scopes peer et observations.
Les handlers SIGTERM/SIGINT sont possédés avant la création de la preuve et
sa première acquisition/query, puis conservés jusqu'au cleanup confirmé.
Pendant un binding synchrone, asyncio peut différer le callback d'arrêt ; le
handler enregistré supprime déjà le comportement fatal par défaut, sans
prétendre interrompre immédiatement l'appel bloqué ou raccourcir son budget.
Les seules signalisations émises par l'observer ciblent, via leur pidfd détenu,
ses propres enfants busctl lors d'un timeout ; aucun writer n'est ciblé.
Une récolte de query inconnue ne devient pas une quiescence : le wrapper
reste fermé et réessaie seulement le cleanup des observations déjà détenues,
sans nouvelle query, rebind, import produit ou restart. Les cancellations
répétées ne libèrent pas cette preuve avant cleanup confirmé.

## Source pins et refus installé

La production bootstrap uniquement depuis les chemins root fixes et les
octets du runtime vérifiés avant compilation. Elle prend une nouvelle SH
avec `writer_guard('main')`, sans substituer un contrat réel `/` ni convertir
le lease hérité en preuve propre.

Les modules graph et wrapper doivent être des fichiers root:root `0555` présents
dans `support.paths` avec pins exacts. `busctl` doit aussi être épinglé avec
ses parents, sa résolution et sa closure ELF revue. Le schéma fermé des trois
`os_module_pins` n'est pas élargi. Le launcher épinglé doit cibler exactement
ce wrapper. La source courante satisfait cet argv ; l'ancien lancement
`-m inky_web.main` reste explicitement refusé avec `inactive_launch_contract`.
Les nouveaux pins graph/launcher et la closure des commandes doivent encore
être assemblés dans un support, un exporter et un manifest runtime revus.
Ce raccord source ne donne aucune admission au système actuel.

L'entrée vérifie intégralement le bundle main ; la capture fait une nouvelle
vérification initiale entre les observations de métadonnées, afin de ne pas
accepter comme baseline un changement survenu après l'admission. Les sources
fixes supplémentaires et la closure déclarée sont hashées à la capture.
Les callbacks relisent les
petits fichiers candidat/contexte, boot, `/run` tmpfs et Ready/attempted, et
les bindings/métadonnées/xattrs des records retenus. Ils contrôlent fresh les
identités numériques ; le mapping NSS n'est pas prétendu revérifié en continu.
Pas de hash complet du bundle à chaque check, ni lecture d'identités privées,
contenu applicatif, photo, clé ou credential.

Les listings contexte/admission sont plafonnés avant matérialisation.
Les dépendances injectables sont réservées aux contrats/tests synthétiques
dans un chemin canonique existant différent de `/`. Aucun injected argv,
unit name ou config path ne sélectionne une commande production.

## Budgets et gates encore ouvertes

Les constantes proposées sont : sources initiales 90 s, stabilisation graph
20 s, callback/peer entry 2 s, monitor 1 s, récolte query 2 s. Elles ne sont
pas des mesures du Pi. Les budgets absolus incluent la sérialisation et toutes
les queries ; le guard partage un budget pour son check et sa preuve peer.
Les délais helper Studio de 15/20 s incluent ces callbacks, pas un délai
supplémentaire gratuit. Un dépassement constaté ne donne jamais admission.
Les appels filesystem/NSS/initiaux ne sont pas des garanties temps réel ;
une opération bloquée garde son ownership jusqu'au retour/drain.

Avant une image active, qualifier séparément :

1. UID 1000, NSS, accès au bus système, propriétés et vrai pass_fds PID1.
2. Ancre PID1 visible/init.scope et vue PID sous le sandbox exact.
3. SO_PEERPIDFD, identité des pidfds et connected peer parent/enfant.
4. Types/valeurs des propriétés stock systemd 257 et graph chargé réel.
5. Attente initiale Type=exec, budgets et disponibilité du socket requis.
6. Thread/cancellation/timeout et drains conservant les SH et preuves.
7. Closure import/ABI du nouveau bundle Studio épinglé, après preuve OS.
8. Assemblage/install des nouveaux support pins et target launcher, sans
   transférer les preuves root aux permissions UID 1000.
9. Premier boot réel, BLE, appairage, Wi-Fi, affichage et reboot sur SD de test.

Les tests Mac de ce lot n'utilisent que des observations/handles synthétiques,
des threads et des tâches locales. Ils ne qualifient pas les primitives Linux,
un graph installé, PID1, le matériel, le radio ou les parcours applicatifs.
Les sources épinglées et l'ExecStart chargé prouvent un lancement attendu ;
ils ne prouvent pas l'executable/cmdline courant d'un processus étranger.
L'execve d'un même processus peut conserver PID, pidfd et invocation. Aucune
lecture étrangère inaccessible ne reçoit une validation de substitution.
Les checks ne sont pas une barrière atomique contre changement entre
observation et effet ni contre une modification root non observée.

## Validation logicielle consignée

Le [rapport historique](validation/2026-10-12-factory-graph.json) épingle les octets
des six entrées : 63 fixtures Linux ARM64 sans skip, 63 fixtures Mac ciblées et
1 822 tests de la suite Mac globale avec 16 skips de plateforme. La syntaxe
des 23 scripts Bash est vérifiée. Le défaut d’ordre des handlers d’arrêt
a été corrigé puis couvert par les tests d'entrée et de drain. Ce rapport
précède le pin et l'argv R35 ; ses hashes et résultats ne sont pas réépinglés
et ne qualifient pas ces nouvelles sources.

Ces résultats ne ferment aucune des neuf gates d’activation : le banc Linux
n’observe pas un graph PID1 installé et utilise des tokens PIDFD/peers
synthétiques. Aucune image, radio, SD ou application du Pi n’est activée.
