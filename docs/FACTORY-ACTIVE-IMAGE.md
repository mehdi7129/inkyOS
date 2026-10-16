# Recette privée de l'image factory active

`scripts/build-factory-active-linux.py` compose une **copie** d'image depuis des
entrées locales figées. Trois opérations séparées imposent une pause réelle :
`prepare` → `proposal` → revue indépendante fournie → `finalize`.
Il n'y a aucun fetch, flash, contact Pi, import app/helper, démarrage de service,
création de clé, QR, owner, pays ou profil Wi-Fi dans cette recette.

Le code cible exécuté pendant un futur build se limite aux opérations système
packages/NSS et à l'extraction stdlib confinée de l'installer exporter existant.
Les outils OS de configuration, inventaire, vérification et planning tournent
avec le Python du builder. Le planner ELF appelle seulement le readelf piné du
builder sur un memfd contenant les octets cibles ; jamais `ldd` ou le loader.

## Périmètre et source freeze

La production exige Linux ARM64, UID/GID root, le marqueur exact
`/var/lib/inkyos-build/owner` contenant `inkyos-builder-v1\n`, et un workspace
neuf root:root `0700` nommé
`/var/lib/inkyos-build/factory-image.<suffix alphanumérique>`.
Tous ses parents sont root-owned non writable par groupe/autres, sans symlink.
Les namespaces mount/net/UTS sont isolés par `unshare --propagation private` ;
seule l'interface `lo` est admise. Une variable d'environnement ne peut pas
simuler cette garde. La recette s'exécute depuis le snapshot piné du workspace.

**Ne pas figer les sources pendant que les lots OS/backend évoluent.** Les pins
sont des entrées explicites, pas un commit Studio historique ni un support TEST
recyclé. Une fois les deux lots figés et intégrés dans la même recette :

1. Produire/vérifier les inputs Studio (sources frontend/helper, app wheel et
   wheelhouse ARM64 cp313 complet), le manifest bundle attendu et les inputs
   writers depuis la source OS finale. Utiliser `factory-assembly-profile.stage`
   pour le snapshot `factory-inputs/`. Ses contrôles lient les bytes writers à
   cette recette, au helper du bundle et aux versions de schéma locales.
2. Préparer le lock exporter final, ses sources et son wheelhouse exact. Son
   éventuel ancien pin support n'est pas utilisé pour inventer une revue ; seule
   la revue indépendante fournira le nouveau pin avant l'installation.
3. Rassembler la base extraite et les trois `.deb` locaux verrouillés par les
   locks système/I2C de cette recette. Le nom historique `test-access` désigne
   seulement le delta `libi2c0`/`i2c-tools` réutilisé : aucun script/service TEST
   n'est installé. Conserver les preuves Debian authentifiées du lock local.
4. Construire une policy support fermée couvrant les vrais scripts/units setup,
   WLAN gate, roots ELF/dlopen nécessaires, arbres Python/dist-packages/loader
   et guards d'absence du **contrat final**. Aucun ancien inventaire n'est copié.
5. Figer le snapshot recette, puis les manifests de pins ci-dessous. Le même
   snapshot est rehashé avant/après chaque phase. Aucun fichier source du
   snapshot ne doit être ajouté/modifié pendant la composition.

Arborescence obligatoire, avant `prepare` :

```text
factory-image.<suffix>/
  factory-active-inputs.json
  base.img
  support-policy.json
  support-provenance.json
  recipe/
    recipe-inputs.json
    scripts/...
    staging/bootstrap/...
    overlay/...
    config/{base-image,system-packages,test-access-packages}.lock.json
    packages/<les deux .deb I2C, copies ordinaires pinées>
  factory-inputs/
    factory-assembly.json
    inputs.json
    factory-bundle-manifest.json
    writer-inputs.json
    sources/...        # snapshot Studio fermé
    wheels/...         # wheelhouse Studio fermé
    writer-sources/... # snapshot OS writer fermé
  exporter-inputs/
    lock.json
    sources/...
    wheels/...         # exactement les wheels du lock exporter
  packages/<tous les .deb des deux locks>
  provenance/
    InRelease
    Packages.xz
    Release.verified
    signature-verification.json
```

Les deux archives I2C existent aussi sous `recipe/packages/` car l'API existante
de leur installer lit `recipe/config/...` et `recipe/packages/...`. Leurs pins
doivent être identiques à ceux des copies sous `packages/`.

La recette vérifie les hashes/tailles `.deb` et leur correspondance aux locks,
ainsi que les hashes des preuves d'authentification Debian préalablement revues.
Il ne s'agit pas d'une nouvelle vérification cryptographique InRelease à chaque
build, ni d'une signature propre à chaque `.deb`. Le trust input est le lock
authentifié et revu, lié aux preuves locales préservées ; aucun APT/réseau.

Le snapshot recette comprend au minimum :

- Tous les fichiers de `factory-assembly-profile.TOOL_FILES` de la révision
  finale. Cette liste comprend les mappings writers/bootstrap de cette révision.
- `scripts/build-factory-active-linux.py`, `plan-factory-system-support.py`,
  `manifest-rootfs.py`, `configure-rootfs.py`, `verify-prototype.py`,
  `inspect-rootfs.py`, `fetch-base.py`, `fetch-packages.py`,
  `fetch-test-access-packages.py`, `install-test-access-packages.py`.
- `configure-factory-active-prerequisites.py`, `configure-factory-active-profile.py`,
  `plan-factory-runtime-manifest.py`, `factory-runtime-contract.py`,
  `install-factory-exporter-rootfs.py`, `verify-factory-exporter-rootfs.py`,
  `install-application-rootfs.py`, `inspect-application-archives.py`,
  `verify-application.py`, tous sous `scripts/`.
- Les trois locks OS indiqués, les fichiers `configure-rootfs.OVERLAY_FILES`
  sous `overlay/` et le template `staging/bootstrap/inkyos-factory-start.service`.
- Les deux archives I2C sous `recipe/packages/` et tout autre input ordinaire
  nécessaire aux APIs de la même révision finale.

`recipe/recipe-inputs.json` conserve le schéma existant de provenance recette
avec `files: {chemin relatif dans recipe: SHA256}`. Cette map couvre exactement
tous les fichiers de `recipe/`, sauf `recipe-inputs.json` lui-même. Les autres
champs documentent la source réellement figée et son état, sans ancien pin fixe.

`factory-active-inputs.json` est un JSON fermé :

```json
{
  "schema_version": 1,
  "kind": "factory-active-image-inputs",
  "files": {
    "base.img": {"sha256": "<sha256 réel>", "size_bytes": 0},
    "recipe/recipe-inputs.json": {"sha256": "<sha256 réel>", "size_bytes": 0}
  },
  "trigger_sha256": "<sha256 du template trigger final>",
  "readelf": {
    "path": "/usr/bin/aarch64-linux-gnu-readelf",
    "sha256": "<sha256 du binaire builder canonique>"
  }
}
```

L'exemple abrège `files` et n'est pas exécutable : la vraie map couvre **tous**
les fichiers ordinaires de `recipe/`, `factory-inputs/`, `exporter-inputs/`,
`packages/`, `provenance/` et les trois fichiers `base.img`, `support-policy.json`,
`support-provenance.json`, avec leurs vraies tailles. Tout fichier manquant,
supplémentaire, symlink, hardlink, unsafe metadata ou divergence de hash refuse
avant copie/mount. Les deux manifests restent hors de leur propre map récursive.

`support-provenance.json` contient exactement les quatre pins OS et
`python_version` attendus par le planner support. Le pin base correspond à la
base extraite locale. Les pins locks correspondent aux trois locks du snapshot.
Le profil support est documenté dans `FACTORY-SYSTEM-SUPPORT-PLAN.md`.

## Commandes et checkpoints

Depuis le builder dédié, avec les SHA relus par l'opérateur :

```sh
sudo python3 -I -B -S "$work/recipe/scripts/build-factory-active-linux.py" prepare \
  --work "$work" --inputs-sha256 "$inputs_sha256"

sudo python3 -I -B -S "$work/recipe/scripts/build-factory-active-linux.py" proposal \
  --work "$work" --inputs-sha256 "$inputs_sha256" --prepared-sha256 "$prepared_receipt_sha256"
```

`prepare` copie la base vérifiée en `candidate.img` privé. Loop/partitions sont
contrôlés avant mount : uniquement le backing file régulier privé, p1 vfat et
p2 ext4. Le `/dev` cible temporaire est un tmpfs contenant exactement null,
zero, random et urandom, sans bind de devices builder. `policy-rc.d` renvoie
101 pendant les packages ; aucune commande app/service n'est appelée.

L'ordre est : packages système → delta I2C vérifié → rename pi UID1000 en inky
et groupes spi/i2c/gpio/nologin/locked → configuration générique avec metadata
factory gardant WLAN=false → installation et vérification bundle/writers →
prérequis comptes/parents helper UID980 et provisioning GID980 → `stage-static`.
Le profil release intermédiaire `factory-passive` n'est jamais livré : il est
remplacé avant inventaire par `factory-active`, avec startup factory-start-trigger
et flags runtime/hardware false. La recette conserve et rehash boot cmdline,
kernels/initramfs, fstab, units grow/resize et scripts resize/partuuid.

Après vérifications statiques, les deux filesystems sont remontés RO,
inventoriés, démontés puis vérifiés avec e2fsck/fsck.fat sans écriture. Seulement
après cleanup/loop detach, `prepared-receipt.json` lie image préparée,
inventaire, entrées, fichiers préservés et rapports ; `exportable_image=false`.

`proposal` vérifie de nouveau le hash exact de cette image et de son inventaire.
Le loop est readonly ; ext4 est monté `ro,noload,nosuid,nodev,noexec`, FAT RO.
L'inventaire remonté doit être identique au checkpoint. Le support planner lit
ce vrai rootfs et les inputs exporter pré-install ; la proposition est publiée
après démontage et après confirmation que le hash image est inchangé.
Code `2` signale une proposition contenant des problèmes de fermeture à revoir.

## Revue indépendante fournie

Aucun champ `elf_closure_review` ni statut `reviewed` n'est généré par la recette.
Un reviewer distinct fournit sous `review/` root:root `0700` :

```text
review.json
support.json
exporter.lock.json
evidence.json
```

`support.json` doit être exactement le `support_candidate` proposé, complété
par la vraie `elf_closure_review` indépendante. Le nouveau lock exporter est
exactement le lock initial avec son seul `support_manifest_sha256` renouvelé.
Les sources/wheels/exporter ne changent pas. Les APIs support/lock existantes
vérifient ces contrats avant le premier mount writable de finalisation.

`review.json` accepte exactement :

```json
{
  "schema_version": 1,
  "kind": "factory-support-independent-review",
  "prepared_receipt_sha256": "<pin du checkpoint>",
  "proposal_sha256": "<pin de support-proposal.json>",
  "support_manifest_sha256": "<pin de support.json>",
  "exporter_lock_sha256": "<pin du nouveau lock>",
  "evidence_sha256": "<pin du vrai evidence.json>"
}
```

Le pin evidence doit être celui déclaré par la revue ELF du support. Le reçu
ne remplace pas le travail indépendant : il lie les preuves fournies à l'image
précise. Toute modification d'inventaire/source après préparation exige une
nouvelle composition, une nouvelle proposition et sa revue.

```sh
sudo python3 -I -B -S "$work/recipe/scripts/build-factory-active-linux.py" finalize \
  --work "$work" --inputs-sha256 "$inputs_sha256" \
  --prepared-sha256 "$prepared_receipt_sha256" --review-sha256 "$review_sha256"
```

`finalize` recontrôle l'image préparée avant mount, écrit un fence anti-retry,
recompare l'inventaire monté puis copie le support approuvé. Il installe/vérifie
l'exporter avec son installer existant, produit le plan runtime avec le vrai
verifier candidat complet, et appelle `install-runtime`, qui recalcule le plan
avant installation et revérifie le contrat installé. Aucun autorité/identifiant
n'est généré pendant cette phase. Une nouvelle vérification système adaptée au
profil actif conserve tous les checks génériques hors trois hypothèses de
profil remplacées explicitement : release active, WLAN fermé, état factory
générique permis. Machine-id, seeds/SSH, données runtime, clés et Wi-Fi restent
dans les guards statiques existants ; le scan n'est pas un détecteur universel
de secrets.

Après inventaire final RO, démontage, fsck et rehash des inputs/revue/image,
`candidate-receipt.json` est créé exclusivement. Il contient
`exportable_image=true`, les hashes image/inventaire/rapports et
`runtime_file_contract_verified=true`. `boot_qualified`, `hardware_qualified`
et `release_qualified` restent **false**. Le fichier image n'est pas copié hors
workspace, publié, flashé ou démarré automatiquement.

## Échecs et vérification de ce lot source

Les sorties ne sont jamais écrasées/réparées. Un échec conserve image/rapports
privés et ne produit aucun reçu exportable. Une finalisation commencée n'est
jamais rejouée automatiquement. Le cleanup démonte dans l'ordre inverse et ne
détache jamais un loop encore monté ; un cleanup incomplet exige inspection,
sans forced detach. Les commandes enfants ont un process group séparé ; une
interruption/timeout tue et attend ce groupe avant la sortie de son contexte.

```sh
python3.13 -m unittest discover -s tests -p test_factory_active_image.py -v
```

19 tests source passent : hashes réels des snapshots/checkpoints/revue,
extra/missing/symlink/hardlink/escape, ordre bundle→parents→static, release active,
mounts proposal RO/noload, devices privés, freeze avant fsck, cleanup incomplet,
absence de reçu sur échec et refus de reprise partielle. Mounts, dpkg/NSS,
installers et commandes OS sont simulés dans ces tests. Ce lot n'exécute pas de
VM, ne construit pas d'image et ne prétend pas valider un premier boot ; la
qualification native de la recette finale reste un travail séparé.
