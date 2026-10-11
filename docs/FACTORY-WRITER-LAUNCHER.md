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
aussi `/usr/lib/inkyos/factory-supervisor.py` `0555` et les deux unités `0644`
`/usr/lib/systemd/system/inkyos-admission-prepare.service` et
`/usr/lib/systemd/system/inkyos-factory-supervisor.service`.
Le manifest runtime et le manifest support restent hors inventaire support pour
éviter un cycle de hashes. Les manifests app/exporter sont épinglés séparément.

Les deux venv doivent déjà être installés à leur chemin final, sans editable,
avec interpréteur résolu vers `/usr/bin/python3.13` et `pyvenv.cfg` fermé. L'app
doit notamment contenir `inky_web/main.py` dans son site-packages. L'ancienne
installation editable TEST et son support ne satisfont pas ce contrat ; aucun
relocating ou conversion n'est effectué ici. Un nouvel inventaire factory et sa
revue de support restent nécessaires.

## API partagée et contexte de boot

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
