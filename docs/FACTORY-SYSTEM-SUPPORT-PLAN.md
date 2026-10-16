# Proposition offline du support système factory

`scripts/plan-factory-system-support.py` produit un inventaire proposé et des
observations ELF à partir d'un rootfs privé, offline, déjà assemblé jusqu'au
bundle Studio. Il n'installe rien et ne produit aucune revue indépendante.
La sortie ne contient **pas** `elf_closure_review` : elle ne peut donc pas être
consommée comme support approuvé par les verifiers/installers existants.

Le support historique `config/factory-exporter-system-support.json` décrit un
profil TEST. Il n'est ni copié ni repinné par ce planner. La policy doit couvrir
les cinq trees de support actuels, dont `usr/lib/python3/dist-packages`, les
guards d'absence et les modules/hooks/unités déclarés par le contrat local.
Les nouveaux fichiers setup/WLAN doivent être présents dans la policy et dans
le contrat de la même révision avant la génération d'une proposition active.

## Entrées explicites

Les chemins sont absolus. Les JSON et le binaire builder `readelf` ont chacun
un SHA-256 explicite. Les entrées restent hors du rootfs. Le rootfs ne peut pas
être `/`, avoir un parent `/`, ou traverser un symlink hôte. L'opérateur doit
fournir une copie de build privée, immobile et offline ; le script ne crée pas
de namespace/mount et ne démontre pas à lui seul cette propriété opérationnelle.

| Entrée | Contrat |
| --- | --- |
| `--app-manifest` | Manifest `factory-studio-bundle-manifest` du bundle déjà matérialisé dans `/usr/lib/inky-studio` ; tous ses records et son propre fichier `manifest.json` sont comparés au rootfs. |
| `--exporter-lock` | Lock `factory-exporter-v2` explicite, vérifié par le verifier existant avec les locks OS de la révision locale. |
| `--sources-dir`, `--wheels-dir` | Sources et wheelhouse exporter correspondant exactement aux pins du lock ; `expected_payload` et `expected_bundle` dérivent les octets/records attendus. L'exporter n'a **pas** besoin d'être installé. |
| `--provenance` | JSON fermé avec `base_image_sha256`, `base_lock_sha256`, `system_packages_lock_sha256`, `test_access_packages_lock_sha256`, `python_version`. Les quatre pins doivent correspondre au lock exporter. |
| `--policy` | Périmètre fermé d'inventaire et profil loader ci-dessous. |
| `--readelf` | Binaire GNU readelf du builder Linux, chemin canonique sans symlink, hashé avant/après chaque invocation. |
| `--output` | Nouveau fichier hors rootfs et hors inputs ; création exclusive en mode `0600`, aucun overwrite. |

Exemple d'appel sur le builder, après préparation/revue des entrées :

```sh
python3 scripts/plan-factory-system-support.py \
  --rootfs "$private_rootfs" \
  --policy "$policy_json" --policy-sha256 "$policy_sha256" \
  --provenance "$provenance_json" --provenance-sha256 "$provenance_sha256" \
  --app-manifest "$app_manifest" --app-manifest-sha256 "$app_manifest_sha256" \
  --exporter-lock "$exporter_lock" --exporter-lock-sha256 "$exporter_lock_sha256" \
  --sources-dir "$exporter_sources" --wheels-dir "$exporter_wheels" \
  --readelf "$canonical_builder_readelf" --readelf-sha256 "$builder_readelf_sha256" \
  --output "$proposal_json"
```

`readelf` reçoit uniquement `--wide --file-header --program-headers --dynamic`
et un memfd Linux contenant les octets à analyser. Aucun ELF/Python cible,
loader, `ldd`, `ldconfig`, app, helper ou service n'est exécuté/importé. Aucun
fichier temporaire n'est écrit dans le rootfs. Le protocole nécessite Linux
avec `memfd_create`; l'absence de readelf sur macOS ne change pas ce protocole.

## Policy fermée

Le JSON accepte exactement `schema_version`, `kind`, `trees`, `paths`, `absent`,
`elf_roots`, `loader`. La version est `1`, le kind
`factory-system-support-policy`. Toutes les listes de chemins sont relatives
au sysroot, sans doublons/traversal ; `paths` peut inclure `.`.

`trees` contient les sous-arbres **complets** à inventorier ; ils ne peuvent pas
se chevaucher entre eux, avec `paths`, ni avec les bundles. `paths` contient
les fichiers/symlinks/unités additionnels et les répertoires nécessaires hors
trees. Les parents structurels sont ajoutés et contrôlés. Modes, ownership,
xattrs/ACL, SHA-256, symlinks et hardlinks réutilisent les primitives du manifest
schema 2 et les règles du verifier/contrat existants. Les entrées non root,
writable, privilégiées, spéciales ou avec hardlinks sont refusées.

`absent` couvre les guards du contrat local, notamment TEST/Python/loader/unités.
Chaque absence est inspectée par parcours de directory fds sans follow ; les
symlinks sont interprétés dans la seule map inventoriée. Un parent non piné ou
un lien sortant refuse l'observation. Les chemins TEST présents sont refusés.

`elf_roots` déclare explicitement les autres exécutables/plugins natifs à
inclure (par exemple `env`, `setpriv`, plugins OpenSSL nécessaires au profil).
Le planner ajoute l'interpréteur Python, le loader ARM64 et toutes les `.so`
ou `.so.*` des trees Python système, de Studio et de l'exporter attendu.
Les `SETUP_FILES` du contrat final doivent être pinés avec leurs modes exacts ;
ses `NATIVE_COMMANDS` (busctl, iw, nmcli, systemctl) deviennent aussi des racines
ELF obligatoires, indépendamment d'un oubli dans la policy externe.
Les chargements `dlopen` calculés ne sont pas inférés : leur revue séparée doit
compléter ces racines avant de considérer un profil applicatif couvert.

`loader` accepte exactement :

```json
{
  "interpreter": "/lib/ld-linux-aarch64.so.1",
  "default_search_paths": [
    "lib/aarch64-linux-gnu", "usr/lib/aarch64-linux-gnu", "lib", "usr/lib"
  ]
}
```

Ce profil glibc ARM64 Debian suppose un environnement sans override `LD_*`,
preload ou audit. Le runtime et la revue indépendante doivent établir cette
hypothèse ainsi que l'identité/les chemins compilés du loader réel. Une autre
liste de defaults ou un autre interpréteur est refusé.

## Fermeture ELF : ensemble conservateur, aucun choix ABI

Le planner précontrôle ELF64 little-endian AArch64, puis extrait les vrais
`DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`, `DT_SONAME` et `PT_INTERP` via readelf.
Les sorties inconnues, warnings ou échecs readelf sont refusés.

Il parcourt récursivement **tous** les candidats du profil, en conservant les
RPATH héritées, les RUNPATH directes, toutes les entrées du cache, les defaults
et les variantes `glibc-hwcaps` pinées. L'ordre réel glibc et l'interposition
des objets déjà chargés ne sont pas simulés : les fallbacks qui pourraient
être écartés à l'exécution restent inclus dans les observations. RUNPATH n'est
pas propagée aux petits-enfants ; les RPATH des ancêtres sont conservées dans
l'ensemble conservateur. `$ORIGIN` et `${ORIGIN}` sont développés avec les deux
origines possibles nom chargé/cible résolue d'un symlink, sans choisir l'une.
Les paths relatifs, composantes vides, autres tokens, escapes root, mécanismes
audit/filter/config et `DF_1_NODEFLIB` sont refusés explicitement.

Le cache pris en charge est le nouveau format glibc `1.1` little-endian, avec
offsets/tailles/chaînes bornés. Tous les records ABI/hwcap sont conservés, sans
sélection CPU. Ancien cache/format inconnu, offset cassé, candidat non piné ou
lien sortant refusent une fermeture positive. La configuration loader est
inventoriée ; elle n'est jamais exécutée pour reconstruire un cache.

Les répertoires de recherche sont résolus dans la map sysroot. Les absences
de candidats sont prouvées par le tree complet ou par inspection ponctuelle
sans follow puis revérification ; les absences hors trees sont ajoutées au
support proposé. Aucun fallback vers `/lib` ou `/usr/lib` de l'hôte n'existe.

Les candidats multiples et collisions SONAME sont exposés avec leurs chemins,
même si tous leurs ELF sont analysés. Ils interdisent un résultat sans conflit.
Les erreurs/éléments non résolus restent dans `elf_observations.problems`.
`complete_without_conflicts=true` signifie uniquement que cet ensemble statique
déclaré est clos sans ambiguïté détectée. Cela ne certifie ni symbol versions,
ABI Python/glibc, instructions CPU, import/dlopen, hardware ou boot.

## Sortie et validation

Le kind global est `factory-system-support-proposal` et le status reste
`proposal-requires-independent-review`, y compris quand les observations sont
complètes. Le rapport contient pins d'entrées, commits app/exporter séparés,
`support_candidate`, objets ELF, arêtes, cache brut interprété, absences et
problèmes. Aucun hash de revue ni statut `reviewed` n'est fabriqué.

Code retour `0` : proposition écrite avec observations sans conflit ; `2` :
proposition écrite avec problèmes de fermeture ; `1` : entrée/inventaire/format
refusé, aucune proposition nouvelle publiée. Une erreur d'I/O de publication
peut laisser un fichier partiel exclusif à examiner ; aucun overwrite/réparation.
Les snapshots support/app, payload exporter, JSON pins et absences ponctuelles
sont revérifiés après inspection. L'inventaire n'inclut pas les timestamps et
ne prouve pas une reproductibilité byte-for-byte du disque.

Validation locale ciblée :

```sh
python3 -m unittest discover -s tests -p test_factory_system_support_plan.py -v
```

26 tests : parsing readelf/cache, closure transitive/RPATH/RUNPATH, ambiguïtés,
symlinks/escapes, absence, pins, collisions, dérive et non-mutation. Sur macOS,
25 exécutés et un test readelf réel Linux ignoré ; xattrs/identité de fixture
explicitement normalisés. Le test Linux utilise un véritable ELF ARM64 inerte,
sans section/exécutable payload, construit en stdlib et analysé par readelf.
Le run natif sur le candidat réel, puis une revue indépendante hashée, restent
nécessaires avant installation exporter ou plan runtime. Aucune image n'est
construite et aucune qualification matérielle n'est revendiquée ici.
