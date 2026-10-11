# Superviseur factory à entrée fixe

Le script [factory-supervisor.py](../scripts/factory-supervisor.py) fournit un
entry point runtime exécutable. Les deux unités sous `staging/bootstrap` sont
des templates inactifs. Ce lot n'installe aucun fichier, ne démarre aucun service
et ne transforme pas le profil TEST en image factory. Le candidat Studio complet,
le support factory final, les wrappers writer et la recette restent requis.

## Entrées installées

L'installation future place le script root:root `0555` à
`/usr/lib/inkyos/factory-supervisor.py`, le module commun au même endroit sous
`factory-runtime-contract.py`, la primitive sous `writer-admission.py`, et les
unités root-owned sous `/usr/lib/systemd/system`. Le support factory épinglé
couvre explicitement le script et les deux unités. Le module commun est chargé
depuis un fichier régulier root-owned, single-link, sans xattrs/ACL ni parent
modifiable ; son pin est vérifié par le contrat. Aucun hash du module commun
n'est dupliqué en constante dans le superviseur.

Le CLI fermé accepte seulement `--prepare-boot`, `--run` ou
`--worker-preflight BOOT_UNIT SHA256`. Ce SHA est le pin candidat retenu par le
parent sous EX ; le Pre exige son égalité avec son contrat avant le hook.
Il n'accepte ni rootfs, ni commande exporter,
ni overlay candidat, ni mode d'ignorance des pins. L'unité worker est dérivée
uniquement du SHA256 du boot ID validé par le contrat. Le hook fixe est
`/usr/local/lib/inkyos/factory-authority.py`, sans arguments, exécuté avec
Python 3.13 `-I -B -S` et l'environnement factory fermé.

`--prepare-boot` exige son cgroup PID1 dédié et appelle le module commun :
`load_contract()`, `prepare_boot_context()`, puis `import_admission()` et
`prepare('/')`. Le module commun vérifie la provenance `/run` tmpfs et lie le
boot ID et le SHA du manifeste candidat dans le contexte root:root `0644`.
Le répertoire `/run/inkyos-factory` contient exactement `context.json`.
La préparation ne remplace/adopte aucune entrée existante. Une erreur partielle
est conservée et refuse une nouvelle préparation. La preuve du renouvellement
de `/run` appartient au boot réel et à la confiance root/PID1 ; un boot ID lu
ne constitue pas à lui seul une preuve indépendante de redémarrage physique.

## Exécution et conservation d'EX

Le superviseur exige son propre cgroup, séparé du worker. Il valide le contexte
avant admission puis prend la primitive EX non bloquante. La primitive crée
et fsync `attempted` avant que le superviseur puisse lancer un worker. Le candidat
complet est vérifié sous EX avant toute création de sortie ou lancement.
Busy, Ready déjà publié, tentative déjà consommée ou worker préexistant refusent
sans stop, signal, création de sortie ou relance du hook. Aucun service app ou
helper n'est nommé par les commandes de contrôle.

La sortie opaque du hook est un fichier nouveau root:root `0600` dans un nouveau
`/run/inkyos-factory-output` `0700`, créé après EX/latch/pins. Il ne modifie pas
le répertoire de contexte fermé et n'est jamais réutilisé/nettoyé par ce script.
Le worker transient a `Restart=no`, `Delegate=no`, `TasksMax=2`,
`KillMode=control-group`, réseau/devices privés et système en lecture seule,
avec seulement les deux répertoires de données persistantes en écriture.
Les capacités permettent chown et drop UID/GID 1000 au publisher ; elles ne
permettent pas l'administration réseau ou l'heure système. Aucun SPI n'est
présent. Son ExecStartPre vérifie le candidat dans sa namespace et les gardes
de capacité/cgroup avant le hook. Il reste une observation du Pre ; ce lot ne
prétend pas observer directement toutes les instructions du hook.

Le résultat doit être exactement l'un des trois succès : created/authorized,
existing/authorized ou existing/consumed. Le dernier permet la réinspection
après adoption ; il n'autorise aucune régénération ni reprise de ledger implicite.
Les états de refus, champs supplémentaires, doublons et sorties trop grandes
échouent fermés. L'état systemd doit aussi confirmer l'exit 0 et les propriétés.
Le worker dispose d'un budget fixe de 120 secondes, le parent de 150 secondes
pour attendre son résultat. Ces budgets incluent la vérification complète des
pins dans le Pre et doivent être mesurés sur Pi Zero 2 W ; un banc M1 ne les
qualifie pas. Leur expiration conserve le latch, sans relance ni Ready.

Le superviseur demande ensuite l'arrêt de son seul worker admis. Il garde EX
jusqu'à l'observation conjointe d'une unité terminale et d'un cgroup vide. Une
commande stop perdue, un descendant ou un défaut d'observation peut donc laisser
le superviseur en attente sans deadline de libération. SIGTERM/SIGINT demandent
ce drain et, s'ils sont observés au dernier garde avant publication, refusent
Ready ; les unités du superviseur n'imposent aucun kill
par timeout. Un crash non interceptable conserve `attempted`, ce qui ferme
les writers et toute nouvelle tentative pendant ce boot, même si EX devient libre.

Après le drain, la sortie est relue identique, les pins et le contexte sont
recontrôlés sous EX, puis unité terminale/cgroup vide sont relus immédiatement
avant `publish_ready()`. Une publication incertaine
peut laisser Ready conforme ; les préconditions ont donc toutes été satisfaites
avant l'appel. Aucun retry ni révocation implicite ne suit cette réponse.
Un signal reçu après le dernier garde ou pendant la publication commencée
n'est pas une révocation atomique du fichier ; la même limite s'applique à la
fenêtre de publication de la primitive.
Ready signifie seulement factory terminée ; IPC READY, appairage, heure/pays/
Wi-Fi et produit prêt gardent leurs admissions et qualifications séparées.

## Preuves et limites

Les tests de ce lot utilisent de vraies leases de la primitive sur une racine
synthétique, avec adapters PID1/cgroup/candidat inertes. Ils couvrent busy sans
effet, tentative durable, résultat consumed, interruptions, replies de contrôle
perdues, descendants, timeout, changement de pins/contexte/sortie et interface
fermée. Linux utilise les vrais UID/GID et xattrs du processus de test. macOS
substitue explicitement l'API xattrs fd ; aucun test ne prétend alors qualifier
les ACL Linux. Les tests ne démarrent pas d'unité, n'exercent pas de payload
Studio, et ne prouvent ni graphe PID1, renouvellement `/run`, reboot ou matériel.

Avant activation, vérifier sur Linux la composition installée avec les vrais
pins : app/helper vivants et en drain rendent EX busy sans interruption ; worker
et descendants interdisent Ready jusqu'à leur vraie fin ; les chemins directs
refusent avant effets ; un nouveau boot réinspecte consumed sans régénération.
L'exclusion reste coopérative et ne prouve ni quiescence NetworkManager ni fin
physique e-ink après crash. Les deux templates utilisent `Wants`/`After`, sans
dépendance propagant l'arrêt de factory aux writers, sans `RuntimeDirectory`,
sans enablement ni restart automatique. Leur installation et le support final
demeurent des étapes à livrer dans la recette commune.
