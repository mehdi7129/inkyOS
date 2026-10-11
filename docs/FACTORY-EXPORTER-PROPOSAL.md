# Exporter factory dédié — contrat staging et intégration

Décision de conception coordonnée le 11 octobre 2026 : préparer un runtime
exporter distinct, non modifiable par l’utilisateur applicatif. Le
[publisher staging](FACTORY-CREDENTIALS.md), appelé par le hook, utilise
désormais l’argv `factory-exporter-v2` convenu avec Studio. **Aucune recette
d’image ni aucun service ne l’installe ou ne l’active.** Les preuves historiques
de l’appel v1 restent attachées à leur ancien chemin de venv applicatif ou de
fixture ; elles ne qualifient pas ce nouveau parcours installé.

## Pourquoi un runtime distinct

L’installation actuelle du backend et de son venv est editable et appartient à
UID 1000. Vérifier le fichier du sérialiseur, puis lancer Python avec `-I`, ne
vérifie pas tous les modules que Python peut importer. Empêcher tous les writers
UID 1000 de modifier ces modules pendant l’exécution ajouterait une contrainte
au runtime applicatif et à ses mises à jour.

L’exporter staging copie les mêmes sources applicatives épinglées et leurs
dépendances dans un petit runtime factory distinct. Il ne s’agit pas d’une
réimplémentation du schéma credentials : Studio conserve le sérialiseur, le KDF
et leur validation. Le backend ordinaire conserve son emplacement et ses droits.

## Contrat staging `factory-exporter-v2`

Le contrat d’installation staging est nommé **`factory-exporter-v2`**. Cette
version désigne le chemin et le bundle installés ; le format credentials v2 et
le protocole du sérialiseur restent identiques. Studio a confirmé cette
évolution ; elle ne constitue pas une promotion dans une recette d’image.
L’argv du publisher staging est :

```text
/usr/lib/inkyos/factory-exporter/venv/bin/python -I -B -m inky_web.provisioning.factory_credentials --emit-v2
```

Il conserve le protocole de sortie : pipe privé, ASCII compact, une LF finale,
8192 octets maximum, EOF et exit 0 ; erreurs Studio 64 et 70. Le parent root
abandonne les privilèges dans l’enfant avant exec : UID/GID 1000, aucun groupe
supplémentaire, cwd `/`, environnement fermé. Aucun import applicatif ni aucune
installation pip n’est exécuté sous root.

Le runtime installé doit satisfaire les conditions suivantes :

- Sources non editables, issues du candidat Studio identifié par son commit et
  ses octets ; aucun fichier source corrigé localement dans le bundle.
- Interpréteur, sources, dépendances et configuration du venv couverts par les
  entrées attendues. Les fichiers `.pth`, `.egg-link`, `sitecustomize` et
  `usercustomize` sont refusés dans le bundle. Les cibles de symlinks et les
  composants système utilisés doivent appartenir à la base OS épinglée ou au bundle.
- Aucun composant ni parent modifiable par UID 1000. Un manifeste attendu
  root-owned décrit la fermeture importable ; quatre hashes de sources ne
  remplacent pas cet inventaire. Pas de chemin vers un checkout editable,
  user site ou répertoire extérieur non vérifié.
- Vue en lecture seule pendant la génération ; seuls les fichiers de données
  individuels sont publiés par le parent, sous la permission consommable.

La construction en staging crée le venv à son emplacement final dans une racine
d’image jetable, sous UID 1000 et sans pip. Les wheels vérifiées sont extraites
selon un contrat limité : aucun `.data`, lien, script généré ou fichier de
personnalisation Python. Les fichiers `RECORD` sont conservés. Les octets et
chemins attendus sont calculés depuis les archives épinglées avant le build,
puis comparés exactement à l’arborescence figée après la fin des writers.
Le fichier attendu ne doit pas être généré au boot à partir de fichiers déjà
modifiables par l’app.

Cette stratégie évite de déplacer un venv, opération que la
[documentation Python 3.13](https://docs.python.org/3.13/library/venv.html)
ne considère pas portable. `-I` n’enlève pas le chargement de `site` : les
éventuels `.pth` et `sitecustomize` de la base doivent rester dans le support
système vérifié. [Documentation `site`](https://docs.python.org/3.13/library/site.html).
L’absence d’un manifeste attendu de ce support interdit l’installation ; les
seuls pins des wheels et sources ne suffisent pas.

Le launcher de build utilise le Python de confiance du builder et prépare ses
imports avant le `chroot`. Il applique ensuite directement les identifiants
numériques et vérifie la disparition des capabilities avant le premier exec
cible. Les erreurs après `chroot` terminent le processus sans charger de module
de diagnostic depuis l’image. Cela exclut les recherches NSS réalisées par
[`setpriv`, même avec un UID numérique](https://github.com/util-linux/util-linux/blob/v2.41/sys-utils/setpriv.c).

La revue du support couvre aussi la configuration OpenSSL, ses providers et
ses engines ; les dépendances ELF seules ne décrivent pas les modules que
cette configuration peut charger. [Configuration OpenSSL](https://docs.openssl.org/3.5/man5/config/).

## Support système vérifié

Le [manifeste attendu](../config/factory-exporter-system-support.json) couvre
4 284 entrées et 12 absences contrôlées. La [revue statique](validation/2026-10-11-factory-exporter-system-support.json)
vérifie 54 racines ELF et 126 dépendances, ainsi que les configurations Python,
loader et OpenSSL. Les fichiers `setpriv` et `env` restent des entrées examinées
supplémentaires ; le nouveau launcher ne les exécute pas dans l’image.

Ce pin correspond au profil TEST access non démarré de la recette `5ab139de`,
avec les paquets I²C épinglés. Il inclut aussi 19 scripts de recette inchangés
sous `/usr/local/lib`, hors des chemins d’import de l’exporter. Ces entrées ne
contiennent aucune identité de test. Un autre profil d’image nécessite sa propre
comparaison et son propre pin ; ce manifeste ne promeut pas le profil TEST en
recette destinée à la production.

Les scripts [installer](../scripts/install-factory-exporter-rootfs.py) et
[verifier](../scripts/verify-factory-exporter-rootfs.py) comparent le support
avant et après construction, puis le bundle aux octets attendus. Les quatre
sources Studio et dix wheels produisent 325 fichiers de payload attendus.
La génération de credentials et le démarrage applicatif restent séparés de
cette construction.

## Ordre et limites

Le runtime dédié résout l’intégrité des imports ; il ne remplace pas la barrière
sur les données. Avant toute consommation, l’app et le helper doivent être
exclus de cette initialisation. La recette factory prépare un dossier de données
`0700` vide, distinct de la préparation TEST actuelle `0755` avec `photos/`.
L’ordre reste : permission durable consommée, génération unique, publication
durable, autorité durable, fin de l’unité factory, readiness IPC, puis runtime
applicatif. Un processus resté en drain SPI n’est jamais arrêté de force pour
permettre cette séquence.

La [construction Linux ARM64 réelle](validation/2026-10-11-factory-exporter-native-install.json)
réussit sur une copie d’image : 325 fichiers de payload, 390 entrées du bundle,
puis vérification séparée après remontage en lecture seule. Le Python système
de l’image construit le venv sous UID/GID 1000 ; aucun code Studio n’est exécuté
pendant cette installation. La source reste inchangée et le montage, le loop
et l’unité de build sont nettoyés.

La génération depuis ce runtime, le hook composé, les reprises après
interruption et les unités doivent encore être vérifiés ensemble avant
l’intégration à une recette de premier boot. Cette installation ne qualifie ni
une release applicative complète, ni un parcours d’appairage sur le matériel.
