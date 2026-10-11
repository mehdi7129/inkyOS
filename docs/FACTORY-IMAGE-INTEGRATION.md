# Intégration du profil factory dans l’image

État du 11 octobre 2026. Ce document définit le prochain lot de recette ; il
ne décrit pas une image factory livrée. Le profil TEST et son couple
backend `c31b13a` / iOS build 9 restent distincts.

## Entrées et installation

Le profil opt-in doit réunir un candidat Studio complet, l’exporter dédié,
les modules OS et leurs unités dans une même liste d’entrées épinglées.
Le lock exporter courant couvre quatre sources Studio et dix wheels ; il
ne qualifie pas à lui seul le backend complet.

Le configurateur factory doit préparer :

- `/var/lib/inky-studio`, vide, UID/GID 1000, mode `0700` ;
- le marqueur root générique et la permission consommable décrits dans
  [FACTORY-AUTHORITY.md](FACTORY-AUTHORITY.md) ;
- le hook, le publisher, le module de reçu et le serveur IPC, root-owned ;
- l’exporter dédié et son support vérifié, sans exécuter le backend ;
- les unités et leurs dépendances, sans créer d’identité, de credentials
  ni de répertoire d’autorité dans l’image distribuée.

Deux adaptations de recette sont nécessaires avant cet assemblage :

1. Le build courant utilise `/var/tmp/inkyos-work/prototype.<token>/root`,
   tandis que l’installer exporter exige un workspace root-owned sous
   `/var/lib/inkyos-build/factory-exporter.<token>/root`. Le build doit adopter
   un workspace conforme, avec une règle explicite et testée pour le profil.
2. Le support exporter actuel ferme tout `/usr/local/lib`, avec les scripts
   du profil TEST. L’ajout des modules factory et IPC exige un nouveau
   manifeste attendu propre au profil complet. Le pin TEST ne peut pas être
   réutilisé en ignorant les nouvelles entrées.

Le configurateur applicatif TEST crée actuellement un dossier `0755` et
`photos/`. Un configurateur factory séparé doit préserver ces exigences TEST
et préparer les données vierges attendues par le publisher.

## Préparation offline du layout passif

Les outils [configure-factory-rootfs.py](../scripts/configure-factory-rootfs.py)
et [verify-factory-rootfs.py](../scripts/verify-factory-rootfs.py) préparent et
vérifient ce layout séparément. Le CLI vise un workspace Linux privé, sous root,
sans writer concurrent. Les sources épinglées et toutes les préconditions sont
contrôlées avant la première écriture. Les fichiers sont créés exclusivement ;
les fichiers et droits des répertoires préexistants ne sont pas remplacés.

Le résultat contient les données vides `1000:1000/0700`, le marqueur générique,
la permission non consommée et quatre modules OS root-owned `0555`. Les services
Studio, helper et ancien cadre restent masqués. Les identités, états réseau,
pays préconfigurés et voies systemd connus sont contrôlés sans afficher leurs
valeurs. Le rapport reste limité à `offline-factory-layout` : il ne valide pas
l’ensemble de l’image ni tous les emplacements possibles de données privées.

Une erreur I/O peut laisser une préparation partielle. Un fichier réservé déjà
créé fera refuser une nouvelle préparation ; les seuls répertoires génériques
encore vides peuvent être acceptés. Aucun rollback ni nettoyage implicite n’est
effectué. L’exporter, son support complet, les unités actives et le raccord au
build restent des étapes séparées. Ces outils ne produisent pas une image
flashable et ne constituent pas la barrière runtime des writers.
Les [30 tests de layout](validation/2026-10-11-factory-passive-layout-tests.json)
passent sur macOS et Linux ARM64. Seul le banc Linux root exerce les UID/GID
0 et 1000 et l’API xattrs réels ; les fixtures macOS les substituent explicitement.

## Ordre de démarrage et admission des writers

L’ordre à réaliser et à vérifier est :

```text
identité système et stockage prêts
  → admission applicative fermée ; support exporter vérifié
  → consommation durable de la permission factory
  → génération, publication des credentials et autorité durables
  → unité factory terminée et cgroup vide
  → service IPC prêt (READY=1)
  → helper et runtime Studio admis
```

La barrière doit couvrir toutes les voies de lancement des writers. Le verrou
de permission ne sérialise que les hooks factory. Un socket fermé ne prouve
pas que le helper est inactif : celui-ci écrit déjà son état avant de créer
son socket. Les dépendances systemd doivent être complétées par une politique
explicite pour les lancements manuels, mises à jour et installateurs.

Une relance factory alors que l’app travaille doit refuser. Elle ne doit pas
arrêter l’app ou interrompre le drain SPI pour obtenir l’exclusivité. Un échec
du travail factory, une reprise non validée ou un enfant encore vivant interdit
de publier l’admission.

Le v0 retient une réservation exclusive non bloquante pour le superviseur
factory, et une réservation partagée conservée par chaque writer avant sa
première écriture et jusqu’à la fin de ses enfants et de son drain. Un latch
`attempted`, créé avant le worker, interdit une seconde tentative pendant le
même boot. La mort du superviseur ne doit donc pas permettre un nouveau hook
pendant qu’un enfant subsiste. Un échec avant publication de `Ready` reste
fermé ; même un échec bénin peut imposer un reboot. Après ce reboot, le hook
réinspecte l’état persistant sans régénérer une permission consommée.
Cette admission est coopérative : elle couvre les chemins raccordés aux wrappers
et ne constitue pas, seule, une interdiction des writers qui les contournent.

La [primitive d’admission staging](FACTORY-WRITER-ADMISSION.md) ne remplace pas
le superviseur, les wrappers ni le provisionnement du prochain boot. Ses
marqueurs génériques ne prouvent pas le boot ou le candidat : le raccord doit
vérifier un `/run` neuf, les pins et la fin réelle du cgroup avant publication.
Une réponse de publication perdue ou incertaine peut laisser `Ready` complet ;
les préconditions externes doivent déjà être satisfaites avant cette opération.
Le lock et le latch ne doivent jamais être supprimés/recréés par le cycle de
vie `RuntimeDirectory` d’un service. Les effets PID1 sur les dossiers avant
`ExecStart` restent aussi à contrôler.

Le [contrat installé et les lanceurs](FACTORY-WRITER-LAUNCHER.md) ainsi que le
[superviseur exécutable](FACTORY-SUPERVISOR.md) sont maintenant développés.
Le [banc de 81 tests Linux ARM64](validation/2026-10-11-factory-runtime-tests.json)
couvre les transitions avec de vraies leases et un exec Python inerte ; PID1,
cgroups et payloads sont des fixtures. Aucun de ces fichiers n'est installé
dans l'image TEST. L'app factory exigera un bundle root immuable à son chemin
final, un support renouvelé et les guards Studio avant toute activation.

Le graphe proposé utilise `Wants` et `After`, avec admission explicite. Une
dépendance `Requires`, `Requisite`, `PartOf` ou `BindsTo` peut propager l’arrêt
ou le restart de factory à l’app avant que le garde factory refuse. Les options
de drain ne suppriment pas ce premier SIGTERM. Ce choix est fondé sur les
[sources systemd 257.13](https://github.com/systemd/systemd/blob/v257.13/src/core/transaction.c#L983-L999)
et sa [table de dépendances](https://github.com/systemd/systemd/blob/v257.13/src/core/unit-dependency-atom.c#L33-L70),
pas sur un essai du graphe installé.

## État coordonné du candidat Studio

Le [candidat bootstrap suivant, PR draft 29](https://github.com/mehdi7129/inky-studio/pull/29),
développe les interfaces backend/iOS du parcours initial. Elles restent
injectables et ne sont pas raccordées au démarrage installé. Le contrat OS
exécutable peut servir à développer les guards en parallèle ; leur source
complète est ensuite un input du bundle factory. La qualification d'une image
ne constitue pas un préalable circulaire à l'écriture de ces guards.

La revue du candidat `cf17a0514989023143798570a8ae47739b829301`
confirme les points suivants. Ils décrivent le code candidat, pas les services
effectivement installés sur un Pi :

| Voie | Point d’intégration restant |
| --- | --- |
| `install.sh` / `inky-studio.service` | Unités encore identiques à c31 ; installation legacy à refuser avant apt, lancement OS à garder avant l’interpréteur. |
| `scripts/install-bluetooth.sh` / `inky-network.service` | Installation legacy à refuser avant comptes/groupes ; helper à garder avant `.helper.lock`, journal, clé et rollback. |
| `scripts/inky-studio-cli` | Refuser les mutations legacy, dont `start`, `stop`, `restart`, welcome/password/reset ; les lectures peuvent rester disponibles. |
| Updater | Refuser entièrement les voies API, CLI et modules pour le v0 factory. Son thread, pip et ses enfants ne sont pas couverts par la durée d’une simple coroutine. |
| `inky-studio-server` / `python -m inky_web.main` | Réserver avant `_select_startup_runtime()` ; garder aussi les entrées autorisées et refuser l’ASGI direct non couvert. Le parcours produit reste à raccorder. |
| `uninstall.sh` et installateur du launcher | Refuser avant le premier stop ou la première copie ; conserver l’ancien `inky-photo-frame.service` masqué. |

Aucun timer, socket unit ou cron installé n’a été trouvé dans cette revue.
Le socket de contrôle réseau est créé par le helper lui-même. Son démarrage
peut créer une clé et un journal, puis reprendre un rollback NetworkManager.
Ces refus et wrappers sont des changements à réaliser avec Studio, pas des
protections déjà présentes dans le candidat. Le FD de `systemctl` ne devient
pas celui des processus lancés par PID1 : chaque véritable `ExecStart` doit
prendre sa propre réservation. Pour un enfant, la transmission du FD et sa
conservation doivent être explicites. La sortie d’un helper ne prouve pas la
quiescence de NetworkManager ; la sortie de l’app ne prouve pas la fin physique
d’un rafraîchissement e-paper après un crash. Ces propriétés gardent leurs
contrôles séparés.

Le guard `initialize_factory` de ce candidat termine encore avec le code 78
après la préparation. La politique actuelle `Restart=on-failure` provoquerait
des reprises sans fournir un parcours utilisateur. **Ni la fin du hook ni
IPC READY ne suffisent à autoriser ce candidat comme runtime factory livré.**
Le lifecycle QR/claim et l’[admission d’heure](BOOTSTRAP-TIME-POLICY.md) doivent
être raccordés dans le candidat commun avant son activation.

La [proposition wire Studio du lot A](https://github.com/mehdi7129/inky-studio/blob/dee6e0b320aa202dd192877505836bbb0103fa4d/docs/inkyos/BOOTSTRAP-WIRE-PROPOSAL.md)
est maintenant relue des deux côtés. Elle distingue le QR et le profil Bluetooth
bootstrap du parcours normal, et limite le premier claim à une association
durable suivie d’une préparation encore nécessaire. Après adoption, seuls le
replay exact du claim et le status authentifié sont prévus ; aucun nouveau QR
d’adoption ni droit implicite sur l’heure, le pays ou le Wi-Fi n’est accordé.
Cette proposition reste documentaire et inactive, dans une PR draft non
fusionnée. Elle ne remplace ni le candidat runtime ci-dessus ni le couple TEST.

## Prochain lot et preuves attendues

Le [test du hook avec l’exporter installé](validation/2026-10-11-factory-installed-composition-native.json)
passe désormais ses quatre cas et la validation Studio. Le layout passif est
développé et testé séparément. La primitive coopérative passe
[31 tests Linux avec des processus synthétiques](validation/2026-10-11-writer-admission-tests.json).
Le prochain lot doit raccorder le superviseur, les wrappers et le graphe de
services. Vérifier alors l’admission fermée en cas d’échec, l’absence
d’interruption d’un travail actif, la reprise sans régénération et le graphe
sans cycle avec les vrais chemins de lancement.

Brancher ensuite ce profil au build avec le candidat Studio complet et son
support réépinglé. La validation offline doit contrôler les données vierges,
les pins, la permission générique, les unités et le Wi-Fi fermé. La validation
matérielle doit encore prouver le premier allumage sans réseau préconfiguré,
l’adoption iPhone et l’affichage. Ces preuves restent distinctes du
[banc exporter](FACTORY-EXPORTER-PROPOSAL.md).
