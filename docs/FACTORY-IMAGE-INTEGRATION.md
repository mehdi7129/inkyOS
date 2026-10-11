# Intégration du profil factory dans l’image

État du 12 octobre 2026. La recette dispose maintenant d'un profil intermédiaire
`factory-passive`. Une image privée a été assemblée et ses contrôles offline
passent sur la source `111aea3`, avec le bundle Studio inactif `a071f19`.
Ce profil n'a été ni flashé ni démarré sur un Pi. Le profil TEST et son couple
backend `c31b13a` / iOS build 9 restent distincts.

Le [rapport d'assemblage offline](validation/2026-10-12-factory-passive-image.json)
conserve le premier échec et sa résolution. Le premier build refusait la sentinelle
`machine-id` amont `0444` ; la lecture privée en RO a confirmé ses 14 bytes
`uninitialized\n`, owner root, lien unique et métadonnées stables. Le contrôle
accepte maintenant exactement `0444` ou `0644`, sans changer le fichier.
Le build suivant utilise un workspace neuf ; l'image du premier échec est préservée.

L'assemblage corrigé passe 64 contrôles système et les quatre contrôles du layout
factory. Le bundle contient huit sources, 34 wheels et 2 405 entrées attendues ;
son installation, sa relecture, l'inventaire final, les fsck et l'intégrité de
l'export passent. Le même HEAD passe 1 697 tests macOS, avec 15 skips explicites,
ainsi que la syntaxe de 23 scripts Bash. Ces résultats qualifient leurs couches
offline ; ils ne prouvent pas le runtime de l'app ou le premier appairage.

Les observations ciblées de fin de build ne trouvent plus l'image de travail ni
loop, montage ou process lié. L'inventaire `/proc` exhaustif reste non confirmé :
`mountinfo` d'un process zombie retourne `EINVAL`. Ce constat est conservé comme
limite, sans le convertir en contrôle global de cleanup réussi.

## Recette intermédiaire inactive

Le même [build-prototype.sh](../scripts/build-prototype.sh) conserve ses voies
system et application. Le profil factory passif exige une sélection explicite
et quatre entrées Studio : manifeste, SHA-256 revu, sources et wheels.
Les options application legacy sont incompatibles avec cette sélection.

```sh
PYTHON=python3.13 bash scripts/build-prototype.sh \
  --profile factory-passive \
  --studio-input-manifest /absolute/reviewed/inputs.json \
  --studio-input-sha256 REVIEWED_SHA256 \
  --studio-sources-dir /absolute/reviewed/sources \
  --studio-wheels-dir /absolute/reviewed/wheels
```

Cette commande est un exemple à préparer avec des entrées revues, pas une
instruction de flash. Les métadonnées et la fermeture des dépendances runtime
`[pi]` sont vérifiées avant le snapshot. Le staging copie exclusivement les
fichiers épinglés, au plus 64 MiB par fichier et 128 MiB cumulés, puis applique
les limites de payload du planner. Il transfère la whitelist des outils,
leurs imports transitifs et le wheel `packaging` revu ; aucune archive récursive
du checkout ou du home n'est produite. Les sources et wheels Studio servent à
inspecter des bytes : leur code n'est jamais importé ou exécuté.

Le guest workspace `/var/lib/inkyos-build/factory-image.<token>` est créé
exclusivement par root, mode `0700` ; son rootfs est monté sous `root`.
Les entrées et rapports
restent dans ce workspace protégé. Le build Linux relit les hashes de la
recette, de la base, des packages et des inputs Studio, puis recalcule les
métadonnées et le plan avant le premier montage et la première écriture rootfs.

Le raccord réutilise cet ordre : base et packages système épinglés, préparation
du compte et de la base avec Wi-Fi fermé, layout factory vierge, matérialisation
du bundle Studio dans `/usr/lib/inky-studio`, relecture complète du bundle,
contrôle précis du layout, gates système, freeze RO, inventaire et fsck existants.
Le venv et ses symlinks d'interpréteur sont présents dans le bundle final ; aucun
interpréteur applicatif, helper ou service n'est lancé.

La sentinelle `etc/machine-id` conserve les bytes exacts `uninitialized\n` et son
mode amont : le contrôle factory admet uniquement `0444` ou `0644` pour ce fichier.
Il épingle le mode observé pour la lecture, avec les contrôles existants du type,
owner, lien unique, xattrs, taille et stabilité des métadonnées. Aucun chmod ni
normalisation n'est réalisé ; une identité existante ou un changement de mode
pendant la lecture reste refusé. Les modes des autres fichiers restent inchangés.

Le layout conserve DATA vide `1000:1000/0700`, la permission générique non
consommée et les quatre modules OS épinglés. Studio, helper et ancien cadre sont
masqués ; les unités factory, supervisor et IPC sont absentes. L'image ne contient
ni exporter, ni manifeste de support/runtime, ni autorité `Ready`, credentials,
pays ou profil Wi-Fi. Les masks ne bloquent pas une exécution manuelle par root.

Le kind exporté est `factory-passive`, avec `application=null`, `startup=masked`,
`runtime_qualified=false` et `hardware_qualified=false`. La gate système utilise
le scope séparé `offline-factory-passive-contract`. Son contrôle
`EMPTY_VAR_LIB_INKYOS` exige la permission générique exacte via le vérificateur
factory ; il n'ignore pas ce dossier. Le vérificateur d'artefacts exige les pins
Studio, métadonnées, plan, installation, relecture et layout, puis compare tout
le bundle attendu à son inventaire final. Il refuse une qualification runtime,
un mélange legacy/factory ou un renommage du profil.

Les tests de recette couvrent les refus de profil, pins, source non épinglée,
dépendance manquante, target Python, données non vierges, permission modifiée,
radio ouverte, pays préconfiguré, unité non masquée et inventaire divergent.
Ils utilisent des payloads inertes ; ils ne prouvent pas un build Linux réel,
le boot, l'admission helper/IPC ou le premier appairage. Le profil complet reste
à intégrer et qualifier après le raccord runtime commun avec Studio.

## Entrées et installation

Le futur profil factory actif doit réunir un candidat Studio complet, l’exporter dédié,
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

Deux points distinguent ce raccord passif de l'assemblage actif :

1. Le build courant utilise `/var/tmp/inkyos-work/prototype.<token>/root`,
   tandis que les deux installers acceptent désormais le chemin commun exact
   `/var/lib/inkyos-build/factory-image.<token>/root`. Le profil passif sélectionne
   maintenant ce workspace ; son chemin n'autorise aucun runtime actif.
2. Le support exporter actuel ferme tout `/usr/local/lib`, avec les scripts
   du profil TEST. L’ajout des modules factory et IPC exige un nouveau
   manifeste attendu propre au profil complet. Le pin TEST ne peut pas être
   réutilisé en ignorant les nouvelles entrées.

Le token commun est non vide et ne contient que des lettres ASCII ou chiffres
(`[A-Za-z0-9]+`). Le workspace `factory-image.<token>` doit déjà être root:root
`0700`, avec des parents root:root non modifiables par groupe/autres, sans
symlinks ni xattrs/ACL. Le marker builder fixe reste obligatoire. Les installers
ne créent, ne déplacent et ne changent les droits d'aucun workspace préexistant.
Les gardes propres aux inputs, au rootfs et aux reçus exclusifs restent inchangées.

L'exporter conserve aussi son chemin dédié `factory-exporter.<token>/root` ; son
`check_workspace` et son `HOST_LAUNCHER` appliquent la même sélection fermée.
Le matérialiseur Studio conserve `factory-studio.<token>/root`. Aucun autre
préfixe factory ou chemin `/var/tmp` n'est admis par ces installers. Ce raccord
permet de viser le même rootfs ; il ne déplace pas les venv ni leurs chemins finaux.

`build-prototype.sh` et `build-image-linux.sh` raccordent seulement le profil
`factory-passive` décrit plus haut. L'exporter, son support complet, l'admission
et les services actifs ne font pas partie de cette option. Le seul raccord de
workspace ne constitue pas leur installation ou leur enablement.

Le configurateur applicatif TEST crée actuellement un dossier `0755` et
`photos/`. Le configurateur factory séparé préserve ces exigences TEST
et prépare les données vierges attendues par le publisher.

Le [banc du workspace commun](validation/2026-10-11-factory-image-workspace-tests.json)
passe 102 tests Linux ARM64 root sans skip (43 exporter, 59 installer Studio),
ainsi que 1 590 tests macOS avec 15 skips. Les inputs et les seams d'admission
sont des fixtures explicites ; le launcher host ne réalise pas de drop UID,
chroot ou exec cible réel dans ce banc. Le support factory actif et l'image
complète restent à construire et qualifier.

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
effectué. L’exporter, son support complet et les unités actives restent des
étapes séparées. Ces deux outils seuls ne produisent pas une image flashable
et ne constituent pas la barrière runtime des writers ; leur raccord passif au
build est maintenant décrit ci-dessus.
Les [30 tests de layout](validation/2026-10-11-factory-passive-layout-tests.json)
passent sur macOS et Linux ARM64. Seul le banc Linux root exerce les UID/GID
0 et 1000 et l’API xattrs réels ; les fixtures macOS les substituent explicitement.

## Contenu applicatif attendu avant installation

Le [planner du bundle Studio](FACTORY-STUDIO-BUNDLE.md) calcule le manifeste
attendu depuis les octets de sources et wheels épinglés. Il exige une wheel
app préconstruite, une seule origine pour `inky_web` et des inputs sans hooks
editable ni collisions. Le venv attendu est fixé à son chemin final sous
`/usr/lib/inky-studio/server/.venv` ; aucun fichier de sortie pip n'est promu
en référence attendue.

Le lot initial du planner utilisait des fixtures inertes. La recette passive
compare maintenant le bundle installé à son manifeste attendu avant freeze,
puis son inventaire final ; elle ne fournit pas de support factory actif ni
de candidat activable. La provenance de la wheel, ses ressources frontend,
sa confidentialité et sa closure système native restent à qualifier pour
le candidat complet.

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
La PR draft 29 exerce désormais ces échanges dans des bancs backend/iOS avec
interfaces injectables. Leur raccord au démarrage installé reste fermé, sans
fusion ni activation sur la SD TEST. Les preuves wire ne qualifient pas ce
premier boot installé et ne remplacent pas le couple TEST.

## Prochain lot et preuves attendues

Le [test du hook avec l’exporter installé](validation/2026-10-11-factory-installed-composition-native.json)
passe désormais ses quatre cas et la validation Studio. Le layout passif est
développé et testé séparément. La primitive coopérative passe
[31 tests Linux avec des processus synthétiques](validation/2026-10-11-writer-admission-tests.json).
Le superviseur et les wrappers sont développés ; leur installation et le
graphe des services restent à raccorder. Vérifier alors l’admission fermée
en cas d’échec, l’absence
d’interruption d’un travail actif, la reprise sans régénération et le graphe
sans cycle avec les vrais chemins de lancement.

Brancher ensuite ce profil au build avec le candidat Studio complet et son
support réépinglé. La validation offline doit contrôler les données vierges,
les pins, la permission générique, les unités et le Wi-Fi fermé. La validation
matérielle doit encore prouver le premier allumage sans réseau préconfiguré,
l’adoption iPhone et l’affichage. Ces preuves restent distinctes du
[banc exporter](FACTORY-EXPORTER-PROPOSAL.md).
