# Publication des credentials factory — staging

Le [publisher](../scripts/factory-credentials-publisher.py) collecte une seule
sortie du sérialiseur Studio et publie ses octets à destination fixe. Ce module
**STAGING** est maintenant appelé par le [hook factory](FACTORY-AUTHORITY.md),
après consommation durable de sa permission et avant création de l’autorité.
Aucune recette ni aucun service ne les installe ou ne les active. Le publisher
ne crée lui-même ni permission ni autorité IPC-A et ne dispose d’aucune CLI.
Le parcours réel de premier boot reste à intégrer.

Le contrat applicatif est celui de la [PR Studio #27](https://github.com/mehdi7129/inky-studio/pull/27),
figé pour cette revue au [commit `cf17a051`](https://github.com/mehdi7129/inky-studio/blob/cf17a0514989023143798570a8ae47739b829301/docs/inkyos/FACTORY-CREDENTIALS.md).
Cette référence documentaire ne remplace pas la vérification du candidat
réellement installé.
Le publisher staging utilise désormais le contrat
[`factory-exporter-v2`](FACTORY-EXPORTER-PROPOSAL.md), avec un runtime dédié
non modifiable par UID 1000. Le protocole et le format credentials v2 restent
identiques. Ce changement d’argv ne qualifie pas le parcours installé : les
preuves datées ci-dessous restent celles de l’ancien appel v1 via le venv
applicatif ou un interpréteur de fixture.

## Appel et responsabilités de l’intégration

L’API privée `publish()` retourne uniquement `{"status":"published"}`. Elle
lève `PublisherError` avec un code fermé : `configuration_invalid`,
`data_unavailable`, `producer_failed`, `producer_output_invalid`,
`producer_timeout`, `producer_unreaped` ou `publication_failed`. Aucun record,
extrait de pipe, stderr ou message d’exception interne n’est journalisé.
Les paramètres préfixés `_` servent aux fixtures avec racine synthétique ; ils
ne constituent pas une interface de configuration ou un protocole applicatif.

Avant cet appel, l’intégration devra vérifier le bundle exporter attendu et son
support système épinglé, puis exclure réellement l’app, le helper et tout autre
writer. Le hook consomme sa permission positive et synchronise cette
consommation. Son verrou stable reste détenu jusqu’après création durable de
l’autorité. Le publisher
ne prouve aucune de ces conditions et ne reçoit pas un booléen les simulant.
L’ordre prévu est :

1. Consommation durable de la permission sous verrou et barrière de démarrage.
2. Invocation unique du sérialiseur, EOF et enfant récupéré avec exit 0.
3. Publication exclusive, synchronisation et relecture réussies.
4. `create_authorization`, puis ouverture du parcours factory Studio prévu.

## Exécution et publication

Le parent Linux root lance sans shell cet argv fixe, avec **abandon des
privilèges dans l’enfant avant exec** vers UID/GID 1000 et suppression des
groupes supplémentaires. Le parent reste root pour la publication :

```text
/usr/lib/inkyos/factory-exporter/venv/bin/python -I -B -m inky_web.provisioning.factory_credentials --emit-v2
```

Le code Studio et le venv exporter ne sont jamais exécutés sous root. Le cwd vaut
`/`, stdin et stderr sont `DEVNULL`, stdout est un pipe anonyme privé. Les seuls
éléments d’environnement sont `HOME=/home/inky`, `PATH=/usr/bin:/bin` et
`LANG=LC_ALL=C.UTF-8`. Les FDs inutiles sont fermés et l’umask vaut `0077`.

La collecte accepte au maximum 8192 octets, LF comprise, une sortie ASCII
non vide terminée par une unique LF, puis EOF et exit 0. Les codes Studio 64
et 70, tout autre exit non nul, signal, dépassement ou sortie incomplète sont
refusés. Le budget du producteur est de 30 secondes, avec une réserve de
0,5 seconde pour arrêt et récupération ; seul un test synthétique peut réduire
ce budget. L’arrivée d’une ligne ne suffit jamais à déclencher une publication.

L’OS ne parse pas le JSON, ne connaît ni schéma credentials ni KDF et ne
reformate aucun octet. Studio produit le record v2 depuis ses sources vérifiées ;
la validation sémantique appartient au factory guard Studio. Un framing OS
valide ne prouve donc pas à lui seul la validité d’un record applicatif.

La destination unique est `/var/lib/inky-studio/credentials.json`. Avant
l’invocation, le dossier doit être vide, UID/GID 1000, mode `0700`, avec parents
vérifiés sans symlink et non modifiables par groupe ou autres. Le parent root
crée le fichier par FD ancré avec `O_CREAT | O_EXCL | O_NOFOLLOW`, impose
`0600` et UID/GID 1000, écrit tout le payload, puis appelle `fsync` sur le fichier
et le dossier. La relecture compare exactement les octets ; type, lien unique,
taille, permissions, propriétaires, inode et timestamps sont contrôlés. Les
bindings des parents sont revérifiés autour de la publication.

## Échec, reprise et limites

Après consommation de la permission, aucun échec n’autorise un retry du
générateur. Fichier partiel ou complet, erreur de synchronisation, réponse
perdue ou autorité non créée exigent la reprise explicite définie par le
hook. Le module ne supprime, ne remplace et ne répare aucun artefact. Un appel
sur une destination déjà présente est refusé avant toute nouvelle génération.
Une autorité durable existante devra suivre sa propre reprise : metadata
courantes et validation Studio, sans comparer un hash initial des credentials
qui empêcherait une rotation légitime. Le hook contrôle les metadata ; la
validation du format par Studio reste une obligation du runtime applicatif.

Le sérialiseur convenu est pur et ne fork pas. En cas d’échec, le publisher peut
arrêter son groupe de processus, puis attend le seul enfant direct dans le
budget restant. Il n’envoie aucun signal après récupération de cet enfant.
`producer_unreaped` interdit toute publication : le futur superviseur devra
fermer le cgroup et confirmer sa quiescence avant une récupération. Ce module
ne confine pas un descendant hostile et ne prouve pas l’exclusion des autres
processus UID 1000. La barrière, les pins du candidat et le cycle de vie du
cgroup restent des obligations externes.

## Tests locaux et preuves historiques

Les tests locaux suivent l’argv staging `factory-exporter-v2` et utilisent des
producteurs inertes. Les rapports datés liés dans cette section précèdent ce
changement : ils restent des preuves de l’appel v1 et ne sont ni réécrits ni
promus en preuve du hook composé avec l’exporter dédié installé.

Le budget ne rend pas annulables les appels noyau de création de processus ou
de filesystem, notamment `fsync`. Les [27 cas de test](../tests/test_factory_credentials_publisher.py)
locaux utilisent des racines synthétiques et des producteurs inertes : framing,
EOF/exit, limites, timeouts, erreurs, symlinks, substitutions, writes courts,
relecture et interruptions de processus. La preuve macOS historique passe avec
un cas Linux privilégié non exécuté (résultats locaux du 11 octobre 2026).
Le [banc Linux ARM64 root séparé](validation/2026-10-11-factory-credentials-publisher.json)
passe les 27 cas sans skip et vérifie les UID/GID réels, effectifs et sauvés à
1000, avec groupes supplémentaires vides, dans un interpréteur inerte.
Il n’exécute pas le vrai sérialiseur Studio ni son venv applicatif. Aucun
service, image ou comportement de SD n’est qualifié par ces résultats.

Le [banc du superviseur](FACTORY-SERVICE-FIXTURE.md) passe séparément dix cas
Linux : droits du parent et de l’enfant, limite de tâches, timeouts et arrêt
du cgroup. Il reste un modèle staging avec producteurs inertes ; il ne prouve
pas la barrière entre les services applicatifs.

Le [banc croisé avec le vrai sérialiseur Studio](validation/2026-10-11-factory-studio-serializer-native.json)
passe séparément sur Linux ARM64. Il utilise quatre fichiers exacts du commit
`cf17a051`, avec dix wheels épinglés provenant du payload TEST existant.
Le venv est construit offline sous UID 1000 ; le parent OS lance deux
générations dans deux racines privées. Le parser et la vérification de mot de
passe Studio, exécutés sous UID 1000, acceptent les deux records v2 et refusent
un mot de passe différent. Une nouvelle publication sur chaque destination
existante est refusée avant tout spawn. Les sorties différentes constituent
une observation sur ces deux générations, pas une preuve de qualité de l’entropie.

Les 311 fichiers de payload des wheels et les quatre sources sont revérifiés
après l’essai. L’unité du probe impose `TasksMax=2` ; cette limite ne concerne
pas la construction du venv. Les trois unités du banc sont arrêtées et leurs
cgroups vérifiés vides ou absents. Aucun credential n’est exporté du banc privé.
L’interpréteur utilise un chemin de fixture : ce résultat ne qualifie ni le
candidat applicatif complet, ni le chemin installé, ni le hook composé avec
le vrai générateur, ni le parcours usine sur SD.

```sh
python3 -I -B -m unittest discover -s tests -p test_factory_credentials_publisher.py -v
```
