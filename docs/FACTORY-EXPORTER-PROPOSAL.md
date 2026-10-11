# Exporter factory dédié — proposition d’intégration

Décision de conception coordonnée le 11 octobre 2026 : préparer un runtime
exporter distinct, non modifiable par l’utilisateur applicatif. **Cette
proposition ne change aucun argv, hook, service ou artefact installé.** Le
[publisher actuel](FACTORY-CREDENTIALS.md) et son contrat Studio `cf17a051`
conservent le chemin du venv applicatif utilisé dans leurs preuves datées.

## Pourquoi un runtime distinct

L’installation actuelle du backend et de son venv est editable et appartient à
UID 1000. Vérifier le fichier du sérialiseur, puis lancer Python avec `-I`, ne
vérifie pas tous les modules que Python peut importer. Empêcher tous les writers
UID 1000 de modifier ces modules pendant l’exécution ajouterait une contrainte
au runtime applicatif et à ses mises à jour.

La variante proposée copie les mêmes sources applicatives épinglées et leurs
dépendances dans un petit runtime factory distinct. Il ne s’agit pas d’une
réimplémentation du schéma credentials : Studio conserve le sérialiseur, le KDF
et leur validation. Le backend ordinaire conserve son emplacement et ses droits.

## Contrat installé proposé

Le futur contrat devra versionner explicitement cet argv :

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
- Interpréteur, sources, dépendances, configuration du venv et éventuels `.pth`
  couverts par les entrées attendues. Les cibles de symlinks et les composants
  système utilisés doivent appartenir à la base OS épinglée ou au bundle.
- Aucun composant ni parent modifiable par UID 1000. Un manifeste attendu
  root-owned décrit la fermeture importable ; quatre hashes de sources ne
  remplacent pas cet inventaire. Pas de chemin vers un checkout editable,
  user site ou répertoire extérieur non vérifié.
- Vue en lecture seule pendant la génération ; seuls les fichiers de données
  individuels sont publiés par le parent, sous la permission consommable.

La construction peut utiliser un compte non privilégié et des wheels offline
vérifiées, puis figer l’arborescence et son manifeste. Le fichier attendu ne doit
pas être généré au boot à partir de fichiers déjà modifiables par l’app.

## Ordre et limites

Le runtime dédié résout l’intégrité des imports ; il ne remplace pas la barrière
sur les données. Avant toute consommation, l’app et le helper doivent être
exclus de cette initialisation. La recette factory prépare un dossier de données
`0700` vide, distinct de la préparation TEST actuelle `0755` avec `photos/`.
L’ordre reste : permission durable consommée, génération unique, publication
durable, autorité durable, fin de l’unité factory, readiness IPC, puis runtime
applicatif. Un processus resté en drain SPI n’est jamais arrêté de force pour
permettre cette séquence.

Le nouveau chemin, le bundle complet, sa construction offline, les droits Linux,
les reprises après interruption et les unités restent à implémenter et vérifier
ensemble avant toute installation dans une image. Le banc ponctuel des quatre
sources Studio avec des wheels existantes ne qualifie pas ce nouveau contrat
installé ni une release applicative complète.
