# Factory writer launcher — contrat installé, non activé

Ce lot fournit un module OS de vérification et un launcher exécutable à trois
rôles fermés. Il n'installe aucun fichier, n'active aucune unité et ne qualifie
aucune image. Le candidat installé exigé ci-dessous n'existe pas encore dans la
recette : sans ce contrat, le launcher refuse avec le code **78** et un motif
fermé `writer_launch_refused:<reason>` sur stderr. Aucun contenu de credentials
n'est lu ou affiché par ces deux modules.

## Fichiers et formats

Les trois modules publics `writer-admission.py`, `factory-runtime-contract.py`
et `writer-launcher.py` doivent être root:root `0555`, sous `/usr/lib/inkyos`
root:root `0755`. La primitive admission conserve son SHA-256
`915d2a5c0d5d8dd0367dbbb351e70f884a4e4647ef22e6422b1c54032df27884`.

`/etc/inkyos/factory-runtime-v1.json`, root:root `0644`, a exactement ces champs :

```json
{
  "version": 1,
  "studio_commit": "<40 caractères hexadécimaux minuscules>",
  "bundle_manifest_sha256": "<SHA-256>",
  "exporter_manifest_sha256": "<SHA-256>",
  "support_manifest_sha256": "<SHA-256>",
  "helper_uid": 998,
  "provisioning_gid": 997,
  "os_module_pins": {
    "writer-admission.py": "<SHA-256>",
    "factory-runtime-contract.py": "<SHA-256>",
    "writer-launcher.py": "<SHA-256>"
  }
}
```

Les deux IDs sont des entiers de 1 à 999, choisis par la future recette. Les
valeurs ci-dessus sont illustratives. Les pins portent sur les octets exacts,
sans normalisation. Les clés inconnues, doublons JSON et types ambigus sont
refusés. Le SHA-256 du fichier runtime entier est l'identité du candidat.

Les trois manifests publics root:root `0644` sont à des chemins fixes :

| Manifest | Format fermé |
| --- | --- |
| `/usr/lib/inky-studio/manifest.json` | Nouveau kind `factory-studio-bundle-manifest`, champs `schema_version:1`, `kind`, `studio_commit`, `records` |
| `/usr/lib/inkyos/factory-exporter/manifest.json` | Kind existant `factory-exporter-bundle-manifest`, champs `schema_version:1`, `kind`, `support_manifest_sha256`, `records` |
| `/etc/inkyos/factory-system-support.json` | Kind existant `factory-exporter-system-support` et ses champs de provenance, `python_version`, `paths`, `trees`, `absent`, `elf_closure_review` |

Les records reprennent le format d'inventaire : `type`, `uid`, `gid`, `mode`,
`xattrs`, plus `size_bytes` et `sha256` pour un fichier, ou `target` pour un
symlink. Les champs sont exacts, les owners `0:0`, les xattrs inspectés et vides.
Les modes non-symlink ne peuvent avoir de bits spéciaux ou d'écriture
groupe/autres. Les hardlinks et fichiers spéciaux sont refusés. Les inventaires
des bundles sont relatifs à leur racine, contiennent `.` et excluent seulement
leur propre `manifest.json` ; tout fichier supplémentaire observé est refusé.
Les `.pth` et `.egg-link` sont refusés dans ces bundles. Les cibles des symlinks
doivent être fermées dans l'inventaire combiné.

Le support conserve tous ses champs existants, y compris
`test_access_packages_lock_sha256` : ce SHA décrit une provenance de paquets,
pas une autorisation TEST. Le profil factory exige l'absence épinglée et observée
des chemins TEST connus énumérés dans le module, et refuse les scripts
`test-access-*` et unités `inkyos-test-*` inventoriés. Ce contrôle est borné à ces
points connus, sans prétendre reconnaître toute identité ou tout script possible.

Le support factory doit inventorier intégralement les arbres stdlib Python,
`/usr/lib/python3/dist-packages`, bibliothèques aarch64, `/usr/local/lib` et
`/etc/ld.so.conf.d`, les interpréteurs, la configuration du loader et leurs
parents. L'arbre `dist-packages` est nécessaire aux enfants Python système
`-I -B`. Les racines de revue ELF doivent couvrir l'interpréteur et les `.so`
de la stdlib, de `dist-packages` et des deux bundles. Le module vérifie les pins
et la présence de cette revue ; il ne refait pas l'analyse ELF et n'assimile pas
`DT_NEEDED` à une preuve des chargements `dlopen` ou de la configuration OpenSSL.

Les quatre modules OS authority, publisher, receipt et initialization-server
doivent être inventoriés root:root `0555`. Le support `paths` public épingle
aussi `/usr/lib/inkyos/factory-supervisor.py` et
`/usr/lib/inkyos/writer-parents.py` `0555`, et les cinq unités `0644`
`/usr/lib/systemd/system/inkyos-admission-prepare.service` et
`/usr/lib/systemd/system/inkyos-factory-supervisor.service`, ainsi que
`/usr/lib/systemd/system/inkyos-initialization.service`,
`/usr/lib/systemd/system/inky-network.service` et
`/usr/lib/systemd/system/inky-studio.service`.
Le manifest runtime et le manifest support restent hors inventaire support pour
éviter un cycle de hashes. Les manifests app/exporter sont épinglés séparément.

Les deux venv doivent déjà être installés à leur chemin final, sans editable,
avec interpréteur résolu vers `/usr/bin/python3.13` et `pyvenv.cfg` fermé. L'app
doit notamment contenir `inky_web/main.py` dans son site-packages. L'ancienne
installation editable TEST et son support ne satisfont pas ce contrat ; aucun
relocating ou conversion n'est effectué ici. Un nouvel inventaire factory et sa
revue de support restent nécessaires.

## Templates writers et fermeture statique

Les trois templates sous `staging/bootstrap` restent **inactifs**, sans
installation dans la recette, section `[Install]` ou lien d'activation. Ils
utilisent exclusivement ces commandes déjà prises en charge :

```text
/usr/bin/python3.13 -I -B -S /usr/lib/inkyos/writer-launcher.py main
/usr/bin/python3.13 -I -B -S /usr/lib/inkyos/writer-launcher.py helper
/usr/bin/python3.13 -I -B -S /usr/lib/inkyos/writer-launcher.py ipc
```

| Unité | Identité et groupes | Ordre et démarrage |
| --- | --- | --- |
| `inky-studio.service` | `inky:inky`, groupes supplémentaires `spi i2c gpio inky-provisioning` | `Type=exec`, après IPC et helper |
| `inky-network.service` | `inky-network:inky-provisioning`, aucun groupe supplémentaire | `Type=exec`, après IPC et NetworkManager |
| `inkyos-initialization.service` | `root:inky-provisioning`, groupe supplémentaire `root` | `Type=notify`, `NotifyAccess=main`, après préparation et superviseur |

Les relations sont `Wants` et `After`. Elles ne propagent pas un arrêt du
superviseur vers les writers. La SH et les guards existants restent la barrière
avant effets : l'ordre systemd seul ne constitue pas une admission. Le launcher
transmet le triplet existant et fournit l'environnement factory fermé ; les
templates ne créent ni nouveau rôle, ni variable d'override, ni wire IPC.

Après la fin du worker factory et l'observation du cgroup vide, le superviseur
publie Ready. L'IPC prend ensuite sa propre SH, charge le receipt, ouvre son
listener et crée son worker avant d'envoyer `READY=1`. Ce notify termine son
job de démarrage avant les jobs helper/app ordonnés après lui. `Type=exec`
pour ces deux derniers ne prouve pas que leur socket ou leur parcours produit
soit prêt ; aucun notify helper/app n'existe dans les interfaces actuelles.

Chaque template writer garde `Restart=no`, `KillMode=mixed`,
`KillSignal=SIGTERM`, `TimeoutStopSec=infinity` et `SendSIGKILL=no`. Le main
conserve sa lease jusqu'au drain SPI, le helper jusqu'à la fin observée de ses
effets/rollback NetworkManager et l'IPC jusqu'à la récolte effective de son
enfant. Aucun `ExecStop`, `ExecStopPost`, `RuntimeDirectory` ou `StateDirectory`
ne recrée leurs dossiers/verrous ou libère admission par un timeout PID1.

`verify_candidate()` impose maintenant les **bytes exacts** des cinq templates,
via une politique de SHA-256 dans le module runtime lui-même, même si les
records support sont réépinglés. Les cinq fichiers vendor doivent être des
fichiers simples root:root `0644`, inventoriés dans `support.paths`. Le schéma
support ne change pas ; sa liste `absent` doit aussi contenir les **535 chemins
d'influence** du module : les 55 fragments concurrents et les 480 directories
de drop-ins/dépendances applicables aux cinq noms, leurs préfixes avec tiret et
au type `service`. Une directory vide, un symlink ou un mask à un de ces chemins
ne satisfait pas l'absence.

La politique couvre les douze lookup roots systemd standard : `.control`,
transient, generators early/normal/late, system, attached, `/usr/local/lib` et
le vendor `/usr/lib`. Elle refuse `.d`, `.wants`, `.requires` et `.upholds`
applicables. Un parcours borné, sans suivre les symlinks, refuse également les
aliases et les liens d'activation entrants visant ces cinq noms. Les autres
unités du système peuvent rester présentes ; les symlinks de directories
`*.d`, `*.wants`, `*.requires` et `*.upholds` sont cependant refusés pour ne
pas suivre un parent non contrôlé qui cacherait ces liens. Les deux collectes
de chaque directory sous FD sont incrémentales et refusent dès dépassement du
budget, avant toute allocation de listing non bornée. L'absence de ces liens ne prouve
pas l'inactivité : d'autres unités peuvent contenir des `Wants`/`Requires`
textuels ou un caller peut demander un démarrage explicite. La fermeture porte
sur les influences statiques de ces cinq fragments, sans recenser tous les
exécutables ou tous les demandeurs de lancement. Le profil usine épinglé est
usr-merged : `/lib` peut être absent ou être le symlink root immuable exact
`usr/lib` ou `/usr/lib`, qui désigne le même vendor contrôlé. Un arbre split
`/lib` ou un alias différent refuse au lieu d'ajouter silencieusement un root.

Ces règles suivent les sources officielles **systemd 257.13** :
[lookup roots](https://github.com/systemd/systemd/blob/v257.13/src/libsystemd/sd-path/path-lookup.c#L443),
[préfixes/type et extensions](https://github.com/systemd/systemd/blob/v257.13/src/shared/dropin.c#L140),
[dépendances ajoutées](https://github.com/systemd/systemd/blob/v257.13/src/core/load-dropin.c#L80)
et [aliases](https://github.com/systemd/systemd/blob/v257.13/src/shared/unit-file.c#L325).

Ce contrôle décrit **les fichiers du candidat**, pas le graphe chargé par PID1.
Un `SYSTEMD_UNIT_PATH` du manager ou des paths compilés différents peuvent
changer les lookup roots ; l'environnement du caller ne les prouve pas
([règle officielle](https://github.com/systemd/systemd/blob/v257.13/man/systemd.unit.xml#L324)).
Les générateurs peuvent aussi publier un override après cette observation.
La qualification du graphe effectif, `FragmentPath`, `DropInPaths`, identités
des processus et durée de vie de leurs invocations reste distincte. Aucun
`daemon-reload`, démarrage ou grant n'est effectué par cette vérification.

Deux raccords restent nécessaires avant toute intégration active :

- Les parents `/run/inkyos-bootstrap` et `/run/inky-network` ne sont pas
  installés ou activés par la recette actuelle. Le module OS de préparation
  décrit ci-dessous sait créer ces parents avant admission, mais son installation
  épinglée et le provisionnement du parent persistant appartiennent au futur
  assemblage actif. Le profil passive conserve ce parent absent.
- L'entry point main actuel atteint encore `initialize_factory`, qui termine
  à **78** après préparation. Les templates ne raccordent pas le lifecycle
  Phase A, n'accordent pas l'autorité owner/B et ne livrent pas un first boot.

Les masks du profil **factory-passive** restent légitimes et inchangés. Ce
profil n'appelle pas le nouveau contrat runtime complet ; un candidat runtime
doit satisfaire sa propre fermeture avant une future activation explicitement
qualifiée. Les templates, nouveaux pins et cette politique restent hors de la
recette passive actuelle. L'ordre des pins reste : bundle et modules/unités,
puis support, manifest exporter lié à ce support, et enfin manifest runtime.
Les manifests support/runtime restent exclus de leur propre inventaire.

## Preuve native des templates et de leur fermeture

Le [banc Linux des writers](validation/2026-10-12-factory-writer-units.json)
passe **85 tests** répartis en quatre suites sous Debian 13 ARM64, en root avec
Python **3.13.5**, sans failure, error ou skip. Il a utilisé un snapshot gelé
non committé basé sur `11942d8` ; les octets des **12 inputs** sont identiques
au commit `368be24`, et leurs SHA-256 figurent dans le rapport.

La suite globale macOS au même commit passe **1 717 tests**, avec **15 skips**,
zéro failure ou error, et les **23 scripts Bash** passent le contrôle de syntaxe.
Les **378 sources**, HEAD et l'état Git restent identiques avant et après.

Les xattrs sous FD, les leases `flock`, l'héritage par `fork` et les identités
numériques utilisent les APIs Linux. Les inventaires candidats, `mountinfo`
et NSS restent des fixtures synthétiques explicites. Le launcher effectue
un vrai `exec` d'un enfant Python inerte, sans exécuter l'argv applicatif installé.

Ces preuves portent sur des bancs logiciels. Elles ne qualifient ni le graphe
PID1, ni l'admission installée, ni l'application, une image bootée, le Pi ou le
premier appairage. Aucun service, Studio, helper ou serveur IPC n'est lancé ou
importé par le banc natif. Le banc natif n'accède à aucune image ni carte SD.

## API partagée et contexte de boot

Le [banc du guard commun et de l'IPC](validation/2026-10-11-shared-writer-guard-tests.json)
passe 79 tests Linux ARM64 root sans skip, dont 19 cas de cette API, ainsi que
la suite locale de 1 531 tests avec 13 skips. Les cas admis du core utilisent le
vrai vérificateur de rôle sur des inventaires et identités synthétiques ; aucun
nouveau drop UID/GID n'est effectué. Les leases, xattrs et processus du banc
Linux sont réels. L'installation et le drainage de Studio restent à qualifier.

L'API du module est :

```python
contract = load_contract()
context = prepare_boot_context(contract)  # propriétaire root seulement, une fois
context = validate_context(contract)
digest = context_sha256(contract)         # aussi contract.context_sha256
verify_candidate(contract)               # root, inventaires complets
verify_role(contract, "main")             # main, helper ou ipc seulement
admission = import_admission(contract)
with writer_guard("main") as lease:        # main, helper ou ipc seulement
    # Les effets writer et leur drain doivent rester dans ce bloc.
    lease.check()
```

`Contract.manifest` contient le dictionnaire validé et
`Contract.candidate_sha256` le SHA des octets runtime. Les refus exposent
`Refused.reason`, sans détails de fichier arbitraires. Les arguments internes
`_root`, owners, mountinfo, boot et identité sont des seams de tests synthétiques,
refusés pour la racine `/` ; aucune CLI ne les expose.

Le contexte exact `/run/inkyos-factory/context.json`, root:root `0644`, est dans
un répertoire root:root `0755` contenant ce seul fichier :

```json
{"boot_id":"<UUID kernel courant>","candidate_sha256":"<SHA runtime>","version":1}
```

Ses octets sont le JSON trié, compact, ASCII, suivi d'un LF. Le contexte doit
correspondre au boot kernel courant. `/run` doit être un montage tmpfs root
`0755`, avec un mountpoint exact et un device correspondant. La préparation
exige une vue RW ; la validation accepte aussi la vue RO d'une unité durcie,
sans supposer un mount ID identique entre namespaces.

La préparation ne reprend ni contexte ni répertoire admission préexistant ; elle
crée le contexte avant `admission.prepare()` et donc avant `attempted`. Une erreur
I/O peut laisser un état partiel, jamais réparé ou remplacé. Une réponse incertaine
après création complète ne prouve pas l'absence du fichier. Le contexte est hors
inventaire admission ; la sortie du superviseur doit rester dans son répertoire
séparé. Le caller doit encore garantir un `/run` réellement renouvelé au boot :
supprimer/recréer un RuntimeDirectory au stop/restart ne constitue pas un reset
valide et pourrait séparer les verrous sur plusieurs inodes.

## Préparation stable des parents writers

`staging/bootstrap/writer-parents.py` est un module OS sans CLI, à installer
root:root `0555` à `/usr/lib/inkyos/writer-parents.py` dans le candidat actif.
Ce fichier est obligatoire dans `support.paths` ; son import par
`runtime.import_writer_parents(contract)` vérifie son inventaire et ses octets
avant compilation. Le schéma fermé des trois `os_module_pins` reste inchangé.
Les modules et units sont toujours inactifs dans la recette actuelle.

Le `prepare_boot` existant charge ce module public et appelle son
`preflight(contract)` en lecture seule avant de créer le contexte, puis appelle
`prepare(contract)` et `verify(contract)` entre
`prepare_boot_context(contract)` et `admission.prepare()`. Aucune nouvelle
unité ou dépendance de stop n'est ajoutée. Les droits du namespace existant de
prepare restent `/run` RW ; le parent persistant est seulement inspecté.

| Parent fixe | UID:GID | Mode | Préparation |
|---|---|---|---|
| `/run/inkyos-bootstrap` | root:`provisioning_gid` | `0750` | Création exclusive au boot |
| `/run/inky-network` | `helper_uid`:`provisioning_gid` | `0750` | Création exclusive au boot |
| `/var/lib/inky-network` | `helper_uid`:`provisioning_gid` | `0700` | Préexistant, validation seule |

Le module vérifie les identités NSS nommées utilisées par les units : `inky`
UID/GID `1000`, `inky-network` au `helper_uid` non-root du manifest, et
`inky-provisioning` au `provisioning_gid` du manifest. Les mappings nom/ID
réciproques doivent correspondre. Ces vérifications ne lisent aucun mot de
passe, journal, clé ou capsule réseau.

Le preflight vérifie avant création du contexte : candidat inchangé, owner root,
identités NSS, ancêtres root sans symlinks ni
écriture group/other, métadonnées exactes et xattrs vides du parent persistant,
absence d'admission, des deux parents runtime et du reçu. La préparation répète
ces vérifications et exige aussi le contexte valide du boot/candidat courant
avant son premier mkdir. Le persistant peut
être non vide : son contenu n'est ni listé ni ouvert. Un parent existant n'est
jamais réparé, chmod/chowned, adopté, remplacé ou supprimé.

La création exclusive du répertoire root:root `0755`
`/run/inkyos-writer-parents` constitue le latch avant les deux créations runtime.
Son unique fichier `parents.json`, root:root `0644`, est un reçu public canonique
contenant `version:1`, `boot_id`, `candidate_sha256` et le mapping `parents` des
trois chemins relatifs fixes vers `dev`, `ino`, `uid`, `gid` et `mode`.
Le répertoire contexte garde son seul `context.json` et l'inventaire admission
reste inchangé. Le contexte créé exclusivement fournit aussi le latch du caller
prepare complet. L'EX est acquis seulement par le superviseur suivant, pas par
cette préparation initiale.

`verify(contract)` ouvre uniquement le reçu public et inspecte les trois
répertoires par FD sans suivre de symlinks. Il compare identité d'inode,
owner/mode/xattrs, boot et candidat. Les timestamps et le nombre de liens des
répertoires ne sont pas figés : les écritures légitimes du helper les changent.
Un reçu partiel, parent manquant/remplacé ou boot/candidat changé provoque un
refus sans recréation. Après la première création de latch, une erreur I/O
peut laisser des objets partiels ; aucune reprise ou suppression automatique
n'est prévue. Le caller doit conserver `/run` jusqu'au vrai reboot, et garantir
son renouvellement au reboot.

Le superviseur appelle `verify` sous son EX avant lancement du worker, puis
après drain et observation finale de quiescence, avant son `publish_ready`
existant. Le module parents ne touche pas admission/Ready, ne prend pas de
lease et ne lance ni service ni child. Les unités writers conservent leurs
SH/drain et leurs identités ; aucun `RuntimeDirectory`, `StateDirectory` ou
nettoyage stop/restart n'est introduit.

Les fixtures macOS substituent explicitement les métadonnées numériques du
helper et l'API xattrs Linux. Elles exercent création, refus/reprise partielle,
remplacement d'inodes, absence, droits, NSS, symlinks et conservation d'un
persistant non vide sans lecture. Les tests supervisor vérifient l'ordre et
la possession de l'EX avec la vraie primitive admission et un PID1 inerte.
Ces tests ne prouvent pas l'ordre effectivement chargé par PID1, un namespace
booté, les invocations live, le Pi, le Wi-Fi, le Bluetooth ou le parcours app.

## Guard commun pour les entrées directes

`factory-runtime-contract.py` expose la primitive stdlib
`writer_guard(role, *, _contract=None, _identity=None, _environ=None)` :

```python
with runtime.writer_guard("main") as lease:
    # Opérations protégées, puis drain de leurs writers avant la sortie.
    lease.check()
```

Un appel de production fournit seulement le rôle `main`, `helper` ou `ipc`.
Le caller charge d'abord ce module OS depuis sa source publique root épinglée,
avant les imports applicatifs ou les effets qu'il veut protéger. Le guard charge
le contrat fixe, prend une **nouvelle SH indépendante non bloquante**, puis
vérifie Ready, le contexte courant, l'identité kernel, les pins et les sources
du rôle. Il revérifie le contexte et la lease avant de céder `lease`, qui expose
`fileno()` et `check()`.

Le triplet `INKYOS_WRITER_LEASE_FD`, `INKYOS_WRITER_ROLE`,
`INKYOS_WRITER_CONTEXT_SHA256` est facultatif, mais doit être complet et exact
s'il existe. Toute autre clé commençant par `INKYOS_WRITER_` est refusée. Le FD
doit être readonly, supérieur ou égal à 3, distinct de la nouvelle lease, et
désigner le même verrou stable avec les mêmes métadonnées. Rôle et SHA contexte
doivent correspondre à la validation courante. Le FD hérité n'est jamais adopté
ni converti : il est fermé seulement après tous les contrôles, sans `LOCK_UN`,
puis le triplet est retiré de l'environnement. Une copie dup/fork conserve sa
propre référence à la description ouverte initiale.

Tout refus de préparation devient `Refused('writer_admission_refused')`, sans
message brut. La nouvelle SH est fermée explicitement si la préparation échoue,
y compris sur `KeyboardInterrupt` ou `SystemExit` ; ces interruptions restent
propagées. Un héritage refusé par les contrôles n'est pas fermé. Les exceptions du corps du bloc
restent inchangées. Le guard ne crée ni contexte, ni Ready, ni autorité.

Les overrides ne sont permis qu'avec un objet `Contract` pour une racine
synthétique absolue, existante et canonique, différente de `/`. Ils ne sont
exposés par aucune CLI ni variable de contournement. Sans `_contract`, les
overrides d'identité ou d'environnement sont refusés.

La SH reste détenue pendant le bloc et s'hérite normalement au fork. Son FD est
non inheritable pour exec par défaut : un caller qui en a besoin doit transmettre
explicitement la lease. Le caller doit terminer ses writers, enfants et threads
avant de sortir du bloc, y compris en cas d'exception. Le guard n'effectue aucun
drain, ne supervise aucun processus et ne prouve pas la fin physique d'une
opération SPI/e-ink. Le serveur IPC délègue à cette primitive en conservant son
propre drain ; le launcher, le superviseur et les entrées Studio ne sont pas
modifiés par cette extraction. Aucun candidat installé n'est produit.

## Launcher et contrôle sous lease

L'entrée installée est
`/usr/bin/python3 -I -B -S /usr/lib/inkyos/writer-launcher.py <rôle>`.
Elle vérifie les sources OS publiques avant leur import. Elle prend ensuite
une **nouvelle SH non bloquante** via la primitive épinglée, vérifie Ready sous
SH, le contexte, les identités, les manifests et les sources de son rôle. Elle
revalide le SHA contexte et l'inode du lock avant `execve`. Un FD hérité fourni
par l'environnement n'est jamais adopté ni converti, notamment s'il porte EX.

| Rôle | Identité exigée | Argv après validation |
| --- | --- | --- |
| `main` | UID/GID réels, effectifs, sauvés `1000:1000` ; groupes spi, i2c, gpio, provisioning | `/usr/lib/inky-studio/server/.venv/bin/python -I -B -m inky_web.main` |
| `helper` | UID manifest, GID provisioning ; aucun autre groupe supplémentaire | `/usr/bin/python3 -I -B /usr/local/lib/inky-studio/network-helper.py` |
| `ipc` | UID `0`, GID provisioning, groupe supplémentaire `0` | `/usr/bin/python3 -I -B /usr/local/lib/inkyos/initialization-server.py` |

Les IDs doivent être appliqués par le caller avant le launcher. Il ne fait aucun
drop d'identité. Les noms NSS `spi`, `i2c`, `gpio`, `inky-provisioning` doivent être
uniques, cohérents dans les deux sens et donner quatre GID distincts de 1 à 999.
Le groupe primaire peut apparaître dans la liste supplémentaire sans constituer
un groupe additionnel. Tout autre groupe est refusé.

Tous les rôles vérifient les trois manifests publics et les trois modules OS.
Main vérifie tout son bundle ; helper vérifie sa copie et sa source app avec
égalité de SHA ; IPC vérifie server et receipt. Chaque rôle vérifie l'interpréteur.
Seul `verify_candidate`, exécuté root avant publication Ready par le futur
superviseur, parcourt le support privé intégral. Aucun `PermissionError` n'est
ignoré. Les rôles non-root ne revendiquent pas une seconde vérification intégrale
de ce support après Ready : ils reposent sur son immutabilité root.

L'environnement est reconstruit avec `PATH=/usr/bin:/bin`, `LANG=C.UTF-8` et :

- `INKYOS_WRITER_LEASE_FD` : FD décimal de la lease, explicitement inheritable ;
- `INKYOS_WRITER_ROLE` : le rôle fermé ;
- `INKYOS_WRITER_CONTEXT_SHA256` : SHA des octets exacts du contexte validé.

Main et helper reçoivent `INKY_STUDIO_FACTORY_REQUIRED=1` et
`INKY_STUDIO_DATA_DIR=/var/lib/inky-studio`. Main reçoit aussi
`INKY_STUDIO_DISPLAY_MODE=hardware` et `INKY_STUDIO_BLUETOOTH=1`.
IPC seul peut conserver `NOTIFY_SOCKET`, chemin absolu ou adresse abstract `@`,
sans caractère de contrôle et au plus 107 octets UTF-8. Aucun autre environnement
hérité ni argument libre n'est transmis.

La garde Studio future peut utiliser `writer_guard` avant ses effets pour prendre
sa propre SH, vérifier inode/boot/candidat puis fermer le FD initial sans
`LOCK_UN`. Le FD demeure
hérité au fork IPC. Chaque autre ExecStart doit obtenir sa propre lease : PID1
n'hérite pas de celle de `systemctl`. Le caller doit conserver une lease jusqu'à
la fin réelle des enfants ; ce launcher ne supervise pas leur durée de vie.

## Portée de la validation

Le [rapport du 11 octobre 2026](validation/2026-10-11-factory-runtime-tests.json)
consigne 81 tests Linux ARM64 root, sans skip, sur le contrat, les lanceurs et
le superviseur. Il conserve aussi le premier échec des fixtures sous umask
`077`, corrigé par des permissions explicites des nouveaux parents sans
assouplir les gardes de production. La suite globale macOS passe 1 467 tests,
avec 13 skips ; ce rapport ne lui attribue pas une exécution globale Linux.

Les tests synthétiques couvrent mutations de pins, owners, liens, inventaires,
contexte partiel/remplacé, groupes, absence de Ready, environnement fermé et
nettoyage des FD. Un vrai `exec` Python inerte confirme que SH survit et bloque
EX pendant la vie du child. Sur Linux root, deux tests supplémentaires utilisent
les UID/GID numériques réels ; leur NSS et leurs commandes restent des fixtures
déclarées. macOS substitue explicitement l'API xattr Linux et ne prouve pas les
montages, les UID Linux, systemd ou le comportement d'une image.

Les nouveaux tests du guard commun utilisent le vrai `ContractFixture`, ses
manifests et pins synthétiques, et de vrais verrous/processus inertes. Ils ne
remplacent pas les vérifications du rôle par un faux résultat. Boot, mountinfo
et identités portables restent des seams déclarés ; les octets app/support sont
inertes. Les fixtures de lifecycle IPC gardent explicitement leur `FakeRuntime`
pour ces vérifications et exercent désormais le guard commun pour l'admission.
Les rapports historiques ci-dessus ne qualifient pas cette nouvelle extraction.

Ready signifie seulement « factory terminée ». Il ne prouve pas à lui seul le
boot, le candidat, l'IPC readiness, le pairing ou une phase produit. La primitive
reste coopérative ; elle ne protège pas contre root ou une app compromise. Les
guards Studio, le graphe de services, les writers legacy et effets préalables
PID1, le support final, la quiescence NetworkManager et la fin physique e-ink
restent des obligations d'intégration distinctes. Ce lot n'active ni image,
superviseur, service, hardware, ni protocole Studio.
