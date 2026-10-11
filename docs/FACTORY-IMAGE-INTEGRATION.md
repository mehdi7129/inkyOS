# Intégration du profil factory dans l’image

État du 11 octobre 2026. Ce document définit le prochain lot de recette ; il
ne décrit pas une image factory livrée. Le profil TEST et son couple
backend `c31b13a` / iOS build 9 restent distincts.

## Entrées et installation

Le profil opt-in doit réunir un candidat Studio complet, l’exporter dédié,
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

Deux adaptations de recette sont nécessaires avant cet assemblage :

1. Le build courant utilise `/var/tmp/inkyos-work/prototype.<token>/root`,
   tandis que l’installer exporter exige un workspace root-owned sous
   `/var/lib/inkyos-build/factory-exporter.<token>/root`. Le build doit adopter
   un workspace conforme, avec une règle explicite et testée pour le profil.
2. Le support exporter actuel ferme tout `/usr/local/lib`, avec les scripts
   du profil TEST. L’ajout des modules factory et IPC exige un nouveau
   manifeste attendu propre au profil complet. Le pin TEST ne peut pas être
   réutilisé en ignorant les nouvelles entrées.

Le configurateur applicatif TEST crée actuellement un dossier `0755` et
`photos/`. Un configurateur factory séparé doit préserver ces exigences TEST
et préparer les données vierges attendues par le publisher.

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
arrêter l’app ou interrompre le drain SPI pour obtenir l’exclusivité. Un échec,
une reprise ambiguë ou un enfant encore vivant conserve l’admission fermée.

## État coordonné du candidat Studio

La revue du candidat `cf17a0514989023143798570a8ae47739b829301`
confirme les points suivants. Ils décrivent le code candidat, pas les services
effectivement installés sur un Pi :

| Voie | Point d’intégration restant |
| --- | --- |
| `install.sh` / `inky-studio.service` | Les unités sont encore identiques à celles de c31 ; raccorder le nouveau graphe factory. |
| `scripts/install-bluetooth.sh` / `inky-network.service` | L’installateur active la radio et démarre le helper ; préparer une installation d’image passive distincte. |
| `scripts/inky-studio-cli` / `start`, `stop`, `restart` | Ces commandes appellent directement systemctl ; couvrir leur admission. |
| Updater | Écrit lock, backups, code et venv puis redémarre l’app ; exclure cette voie pendant factory. |
| `inky-studio-server` / `python -m inky_web.main` | Le lifespan applique le guard factory, mais le parcours produit n’est pas encore raccordé. |
| `uninstall.sh` | Peut réactiver l’ancien `inky-photo-frame.service` ; exclure cet autre propriétaire SPI du profil. |

Aucun timer, socket unit ou cron installé n’a été trouvé dans cette revue.
Le socket de contrôle réseau est créé par le helper lui-même. Son démarrage
peut créer une clé et un journal, puis reprendre un rollback NetworkManager.

Le guard `initialize_factory` de ce candidat termine encore avec le code 78
après la préparation. La politique actuelle `Restart=on-failure` provoquerait
des reprises sans fournir un parcours utilisateur. **Ni la fin du hook ni
IPC READY ne suffisent à autoriser ce candidat comme runtime factory livré.**
Le lifecycle QR/claim et l’[admission d’heure](BOOTSTRAP-TIME-POLICY.md) doivent
être raccordés dans le candidat commun avant son activation.

## Prochain lot et preuves attendues

Le [test du hook avec l’exporter installé](validation/2026-10-11-factory-installed-composition-native.json)
passe désormais ses quatre cas et la validation Studio. Le prochain lot est
le configurateur et le verifier du layout factory passif, sans activation.
Développer ensuite la barrière avec des writers synthétiques concurrents. Vérifier
l’admission fermée en cas d’échec, l’absence d’interruption d’un travail actif,
la reprise sans régénération et le graphe de services sans cycle.

Brancher ensuite ce profil au build avec le candidat Studio complet et son
support réépinglé. La validation offline doit contrôler les données vierges,
les pins, la permission générique, les unités et le Wi-Fi fermé. La validation
matérielle doit encore prouver le premier allumage sans réseau préconfiguré,
l’adoption iPhone et l’affichage. Ces preuves restent distinctes du
[banc exporter](FACTORY-EXPORTER-PROPOSAL.md).
