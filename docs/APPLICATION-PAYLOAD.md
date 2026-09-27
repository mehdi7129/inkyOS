# Payload commun Inky Studio / InkyOS — proposition v1

Proposition du 27 septembre 2026, à valider avec la session Inky Studio.
**Aucun payload qualifié ni lock Python livré à cette date.** Le prototype
système InkyOS reste donc sans backend. Ce contrat de packaging ne change
aucune API HTTP/BLE et ne donne aucune qualification à `0.5.0-rc.2`.

## Garder le layout existant

La release conserve une seule archive applicative `.tar.gz` contenant
`server/`, `client/dist/`, `shared/` et `scripts/`, construite depuis un commit
complet et une UI déjà compilée. L'updater actuel choisit la première archive
`.tar.gz` : ne pas ajouter un wheelhouse sous cette extension à la même release.
Le packaging upstream doit vérifier le choix de l'asset, sans fork dans InkyOS.

Ajouter séparément :

- `inky-studio-manifest-v1.json` : release, commit Git complet, nom/taille/SHA-256
  de chaque asset, environnement compatible et références de qualification ;
- `inky-studio-python-arm64-cp313.zip` : wheelhouse ARM64/Python 3.13, dépendances
  transitives runtime **et build editable** (dont `hatchling`), accompagnées des
  licences ; roues `cp313`, `abi3` et `py3-none-any` compatibles admises ;
- `requirements-arm64-cp313.lock` : versions exactes et hashes des wheels
  réellement utilisées, sans URL mouvante ni compilation réseau implicite.

Le manifeste décrit explicitement `schema_version: 1`, `application_version`,
`source_commit`, `assets`, `compatibility` et `qualification`. `compatibility`
contient architecture `arm64`, version Python mineure, base Debian minimale,
références des contrats HTTP/BLE et du helper réseau. `qualification` référence
des preuves versionnées et distingue tests logiciels et essais Pi/iPhone.
Un champ disant seulement `qualified: true` n'est pas une preuve.

Chaque entrée d'asset a un rôle (`application`, `wheelhouse`, `python_lock`),
un nom de fichier simple, une taille strictement positive et un SHA-256. Le
manifest est lui-même épinglé par SHA-256 dans le futur lock InkyOS. Tous les
fichiers doivent appartenir à la même release/commit ; pas de fallback `main`.

## Intégration offline proposée

1. Télécharger les assets hors du stage d'assemblage puis vérifier tous les
   hashes. Refuser traversal, chemins absolus, liens sortants et fichiers
   spéciaux lors de l'extraction. N'importer aucun home ou état du Pi.
2. Installer le payload à `/home/inky/inky-studio`, avec propriétaire `inky`
   non-root et login verrouillé ; créer le venv à son emplacement final
   `server/.venv`. L'updater actuel doit pouvoir modifier ces deux chemins.
3. Installer les dépendances avec `pip --no-index --require-hashes` depuis le
   wheelhouse, puis le projet editable avec `--no-deps --no-build-isolation`.
   Le backend de build fait partie du lock. Aucune résolution Internet, aucun
   Node/npm et aucune compilation différée au premier boot.
4. Installer les units/CLI/helper/polkit issus de cette même release avec leurs
   propriétaires appropriés. Le helper et les règles restent root-owned ;
   seuls les droits sudo ciblés réellement utilisés sont accordés.
5. Activer les units sans les démarrer. Le build ne lance ni backend, lifespan,
   migration de données, génération TLS, QR, refresh écran ou enregistrement
   BLE. Ces actions créeraient de l'état propre à un cadre.

Le chemin des données demeure `/var/lib/inky-studio`, fixé de façon identique
pour le service et la CLI. Le venv utilise le Python de l'image. Un payload
CPython 3.11 ou construit seulement pour x86_64 n'est pas accepté pour cette
base ARM64/Python 3.13. Le cache pip ou les packages du builder ne sont jamais
une source implicite de dépendances.

## Questions qui restent côté application

| Contrat | Preuve attendue avant une image complète |
|---|---|
| Première adoption sans LAN | Déclencheur local autorisé, QR affiché par l'app, durée/consommation du secret, essais iPhone. |
| Horloge sans Internet | Comportement TLS au premier boot sans RTC/heure valide et méthode de mise à l'heure authentifiée. |
| Pays Wi-Fi | Transmission et validation du pays avant le scan/la connexion ; aucune valeur personnelle préchargée. |
| Updater / rollback | Compatibilité du payload offline avec l'updater ; reprise cohérente application+venv+helper à vérifier ensemble, limites du rollback OS séparées. |
| Packaging | Lock transitif, wheels ARM64, licences, tests sans réseau, manifest et assets immuables. |
| Qualification finale | Release exacte, version iOS distribuée et résultats sur Pi/panneau identifié. |

L'OS fournit uniquement les prérequis système et une identité hostname propre
au premier boot. Il n'ouvre pas une fenêtre QR à la place du backend et ne
contourne pas les contrôles de temps/TLS existants. La qualification SD attend
une carte dédiée ; la SD personnelle reste hors de ce chantier.

La session Inky Studio a relu cette proposition le 27 septembre : direction
acceptée pour poursuivre le prototype, sous réserve des points ci-dessus.
Cette revue ne constitue ni livraison d'assets ni qualification.

## Contrôle d'entrée exécutable

`scripts/verify-application.py` vérifie maintenant les **octets locaux** du
manifeste et des trois assets avant toute intégration. Le SHA-256 du manifeste
doit provenir du lock/relevé relu, pas être recalculé automatiquement depuis un
fichier inconnu pour le déclarer fiable.

```sh
python3 scripts/verify-application.py --manifest CHEMIN_MANIFESTE \
  --sha256 SHA256_RELU --assets-dir DOSSIER_ASSETS --output NOUVEAU_RAPPORT.json
```

Le rapport doit rester hors du dossier des assets. Le contrôle est sans réseau,
extraction ou exécution. Il exige un seul asset par rôle, des fichiers réguliers,
tailles et hashes exacts, noms simples et extensions `.tar.gz`, `.zip`, `.lock`
respectivement. Limites : manifeste 1 Mio, asset 1 Gio, ensemble 2 Gio.

Précision du schéma v1 proposé, sans champ additionnel implicite :

| Objet | Champs |
|---|---|
| Racine | `schema_version`, `application_version`, `source_commit`, `assets`, `compatibility`, `qualification` |
| Asset | `role`, `filename`, `size_bytes`, `sha256` |
| Compatibilité | `architecture: arm64`, `python_minor: 3.13`, `debian_release: trixie`, `http_contract`, `ble_contract`, `network_helper_contract` |
| Qualification | `evidence`, liste de références |
| Référence | `kind: software` ou `hardware`, `name`, `url` HTTPS sans credentials/query, `sha256` |

Les trois contrats doivent être référencés sous la forme
`git:<source_commit complet>#<chemin relatif canonique>`, avec le même commit
que le payload. Les chemins sortants et aliases mobiles, y compris `git:main`,
`git:latest` et `blob/main`, sont refusés. **HTTP n'a pas de version globale** :
`/api/health.version` donne la version du produit. La référence vise donc
`server/inky_web`, sans inventer HTTP v1. BLE et helper possèdent un protocole
v1 ; leurs références visent respectivement `docs/ios/BLE-PROTOCOL-V1.md` et
`scripts/inky-network-helper.py`. Ces précisions ont été relues avec Inky Studio.
Une liste de preuves vide reste représentable, mais le rapport signale les catégories
absentes. Les URLs/preuves externes ne sont ni téléchargées ni qualifiées par
ce contrôle.

Un résultat `passed: true` signifie intégrité et compatibilité **déclarée**.
L'origine réelle du source, la sûreté des archives, les tags des wheels,
la fermeture des dépendances, l'installation offline et les essais matériels
restent des contrôles ultérieurs. `integration_enabled` reste toujours `false`
dans cette étape ; aucune option ne transforme ce rapport en qualification.
