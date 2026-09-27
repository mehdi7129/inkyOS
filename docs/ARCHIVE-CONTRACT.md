# Contrôle inerte des archives applicatives

Le contrat ci-dessous précise le packaging commun accepté par le contrôleur
InkyOS. Il a été coordonné avec Inky Studio le 27 septembre 2026. Il ne qualifie
aucune release et n'autorise aucune intégration dans l'image.

`scripts/inspect-application-archives.py` appelle d'abord
`scripts/verify-application.py`, puis inspecte les deux archives épinglées.
Il ne les extrait jamais, ne lance aucun installateur et n'importe aucun code
du source, des wheels ou de leurs build backends. Seul le module de validation
adjacent, appartenant au dépôt InkyOS, est importé.

```sh
python3 scripts/inspect-application-archives.py \
  --manifest CHEMIN_MANIFESTE --sha256 SHA256_RELU \
  --assets-dir DOSSIER_ASSETS --output NOUVEAU_RAPPORT.json
```

Le SHA-256 doit venir du relevé relu, comme pour le validateur d'entrée. Le
rapport doit être nouveau et hors du dossier des assets. Aucun réseau, accès
au Pi, montage d'image ou privilège root n'est nécessaire. Python 3.9 ou plus
récent sur un hôte POSIX est requis. Utiliser un dossier local stable, sans
écrivain concurrent ; les parents du chemin de sortie sont sous le contrôle
de l'opérateur.

## Archive applicative plate

L'asset `.tar.gz` contient uniquement les chemins suivants, sans dossier
enveloppant et sans préfixe `./` :

| Chemin | Règle |
|---|---|
| `server/` | Source serveur ; `pyproject.toml` et `SOURCE_COMMIT` obligatoires. |
| `client/dist/` | UI compilée ; `index.html` obligatoire. |
| `shared/`, `scripts/` | Au moins un fichier régulier dans chacun. |
| `VERSION` | Fichier régulier obligatoire ; contenu non interprété. |
| `install.sh`, `README.md`, `LICENSE`, `CHANGELOG.md` | Fichiers réguliers autorisés à la racine, sans exigence de présence. |

Les entrées de dossiers explicites sont facultatives, y compris `client/`.
Les autres entrées sont des fichiers réguliers ou des dossiers situés dans
ces arbres. Les archives source automatiques GitHub qui ajoutent un dossier
racine ne respectent pas ce contrat ; le packaging offline doit produire
l'archive plate convenue.

`server/SOURCE_COMMIT` contient exactement les 40 caractères du `source_commit`
du manifeste, avec un LF final facultatif. Le fichier `SOURCE_COMMIT` à la
racine est refusé : ce nouvel emplacement casserait le contrat de l'updater
actuel. L'égalité vérifiée reste une déclaration du producteur, pas une preuve
que tous les fichiers proviennent réellement de ce commit.

Le parseur accepte les headers tar de fichiers réguliers et dossiers, ainsi
que des headers PAX locaux bornés. Les attributs PAX autorisés sont `path`,
`size`, `mtime`, `atime`, `ctime`, `uid`, `gid`, `uname`, `gname`, `comment` ;
seuls `path` et `size` influencent la lecture. Un seul header PAX global est
admis avant le premier membre, avec uniquement `comment`. Le nom interne d'un
header PAX, notamment le standard `././@PaxHeader`, est une métadonnée jamais
extraite ; le chemin effectif du membre reste soumis au contrôle strict.
Les extensions GNU longname/longlink/sparse et les attributs PAX inconnus sont
refusés. La taille d'un header PAX est bornée avant lecture de son contenu.

Le flux doit contenir un seul membre gzip, consommé jusqu'à sa fin avec
validation du trailer et du CRC. Les concaténations gzip, troncatures et
octets supplémentaires sont refusés. Le tar se termine par deux blocs nuls,
suivis uniquement d'un padding nul aligné sur 512 octets ; un second tar
concaténé ou des données après le terminateur sont refusés. Les paddings des
membres sont également nuls.

## Wheelhouse ZIP plat

Le ZIP contient au moins un fichier `*.whl` directement à la racine,
`provenance.json`, `licenses/index.json` et au moins un autre fichier régulier
sous `licenses/`. Les notices peuvent être organisées en sous-dossiers.
Aucune liste précise de wheels, de licences ou de noms de notices n'est
imposée ici. Les deux fichiers JSON sont contrôlés comme fichiers réguliers ;
leur JSON et leur schéma ne sont pas interprétés.

Seuls les modes de compression stored et deflate sont acceptés. Les archives
chiffrées, multi-volume et ZIP64 sont refusées. Les seuls extra fields admis
sont les timestamps `0x5455` et UID/GID `0x7875`, sans doublon ; ils ne sont
pas appliqués. Les chemins secondaires Unicode, extensions de liens et
autres extra fields ne sont pas acceptés. Les noms UTF-8 et CP437 standard
sont décodés avant contrôle des chemins.

Les headers locaux, le répertoire central, les tailles, les noms et les
éventuels data descriptors doivent être cohérents. Les zones ne se
chevauchent pas et aucun préfixe exécutable, espace non décrit ou suffixe
après le commentaire ZIP n'est admis. Chaque membre est décompressé en flux
pour contrôler sa taille réelle, son CRC et la fin effective de deflate,
même si une taille déclarée plus courte possède un CRC de préfixe valide.
Les octets des wheels sont lus à ce titre, mais leur ZIP interne n'est pas
ouvert.

## Refus et limites communes

Les chemins absolus, segments vides, `.` et `..`, antislashs, deux-points,
caractères de contrôle, doublons et collisions fichier/dossier sont refusés.
Le contrôle s'applique aussi aux chemins hérités des headers PAX. Les liens
symboliques, hardlinks, fichiers spéciaux et permissions suid/sgid sont
refusés ; aucune métadonnée de propriétaire n'est appliquée.

| Borne | Valeur par archive |
|---|---|
| Membres | 20 000 |
| Taille décompressée d'un membre | 256 Mio |
| Somme des fichiers décompressés | 2 Gio |
| Chemin UTF-8 / composant / profondeur | 1 024 octets / 255 octets / 32 segments |
| Flux tar total | 2 Gio + 64 Mio, headers et padding compris |
| Header PAX / ensemble PAX | 64 Kio / 8 Mio |
| Répertoire central ZIP | 16 Mio |

Le contrôle d'entrée conserve aussi ses limites : manifeste 1 Mio, chaque
asset comprimé 1 Gio, ensemble des trois assets 2 Gio. Le CLI n'offre aucun
commutateur pour desserrer ces bornes. Les tests utilisent des limites
réduites pour vérifier les refus sans créer des archives géantes.

Après la validation du manifeste, chaque archive est ouverte sans suivre
son lien final, puis taille et SHA-256 sont revérifiés sur le même descripteur
avant et après l'analyse. Le type régulier, les métadonnées de stabilité et
l'identité du fichier nommé sont également contrôlés. Une modification du
même inode pendant l'analyse est refusée. Ce contrôle ne verrouille pas le
stockage et ne remplace pas un workspace maîtrisé face à un acteur privilégié.

## Sens du rapport et preuves restantes

`passed: true` signifie que les octets épinglés et cette structure bornée
sont acceptés. Le rapport conserve `integration_enabled: false`,
`qualification_granted: false`, `target_code_executed: false` et
`files_extracted: 0`. Il ne contient pas les données des fichiers inspectés.

Restent hors périmètre : contenu interne des wheels, tags ABI/architecture,
métadonnées et RECORD, fermeture du lock Python, licences, provenance réelle,
contenu de `VERSION`, absence exhaustive de secrets, cohérence fonctionnelle
source/UI, installation offline, runtime et preuves externes de qualification.
Une future extraction devra appliquer sa propre politique ; le rapport ne
constitue pas une autorisation d'exécuter une archive.

Les fixtures adversariales réelles et les cas PAX/ZIP standards s'exécutent
localement, sans installation ni extraction :

```sh
python3 -m unittest discover -s tests -p 'test_application_archives.py' -v
```
