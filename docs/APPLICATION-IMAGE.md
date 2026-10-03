# Image applicative expérimentale

Le prototype système `make prototype` reste sans application. La cible opt-in
`make application-prototype` installe un payload local explicitement épinglé.
Elle ne télécharge pas une release mobile et n'active pas le backend.

```sh
make application-prototype \
  APPLICATION_MANIFEST=/chemin/candidat/inky-studio-manifest-v1.json \
  APPLICATION_SHA256=0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551 \
  APPLICATION_ASSETS=/chemin/candidat
```

Cette intégration déclarative accepte uniquement deux couples exacts revus :
le candidat `758a2bf7ed099aad41ef35316e53228e797b0b2b` et le manifeste ci-dessus,
ou l'ancien `6a697d134290ced0214fc74b903f4b3c336d70fa` avec
`2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f`.
Un commit seul, une version commune ou un autre manifeste sont refusés.
Pour changer de candidat, revoir le manifeste, les installers et leurs hashes,
puis adapter les tests d'équivalence. Le nouveau candidat conserve exactement
les quatre sources auditées d'installation, launcher et helper ; il corrige
uniquement les métadonnées de panneau. Il exige un nouveau build parent.
Le candidat est une entrée expérimentale, **pas la release finale qualifiée**.

## Assemblage

1. Vérifier les quatre fichiers, snapshotter et réinspecter les archives.
   Les octets du manifeste sont inclus dans la recette hashée : comparer deux
   images avec des payloads distincts ne peut pas déclarer leurs entrées égales.
2. Copier la base vérifiée et installer le delta Debian offline habituel.
3. Extraire le source vers `/home/inky/inky-studio` puis créer
   `server/.venv` à son chemin définitif. Dans le chroot ARM64 sans réseau,
   UID/GID 1000 et sans supplementary groups : venv, installation des wheels
   avec hashes, editable local sans build isolation ni dépendances, pip check.
   Aucun import ou lancement du backend, helper ou smoke applicatif.
4. Retirer wheelhouse temporaire, snapshot et bytecode généré. Conserver logs et
   rapports en dehors de l'image. La source et le venv appartiennent à `inky`.
5. Préparer `inky-provisioning` et `inky-network` verrouillé/nologin. Dériver les
   unités, polkit, sudo borné et launcher des templates du source épinglé sans
   exécuter ni sourcer les installers. Le helper copié est root-owned 0555.
6. Masquer les deux services applicatifs, désactiver le Wi-Fi sans pays présumé,
   vérifier les comptes, fichiers, permissions, absence d'état et source pin.
   Vérifier systemd et sudoers sans démarrer de service.
7. Exporter l'image avec manifests de fichiers/métadonnées, preuves statiques,
   logs et checksums ; les contrôles ext4/FAT et boot/grow restent obligatoires.

Les unités sont placées dans `/usr/lib/systemd/system` avec des masks locaux
dans `/etc/systemd/system`. Les drop-ins firstboot ajoutent une dépendance sur
le premier boot système. Ce sont des différences voulues par rapport à
l'installateur interactif. Les argv, identités et politiques de privilèges
restent ceux du candidat ; aucun droit heure/pays n'est ajouté.

## Preuves et limites

L'export `inkyos-application-prototype.img` porte `kind=application-prototype`,
le source et le SHA-256 du manifeste, `startup=masked-pending-firstboot-contract`
et `release_qualified=false`. `verify-artifacts.py` contrôle les rapports
obligatoires, leurs pins, les quatre étapes et logs d'installation, et les
gates statiques supplémentaires. La comparaison conserve la distinction entre
égalité du contenu décrit et identité octet pour octet de l'image.

Cette image ne propose pas encore le parcours sans LAN. Les services ne seront
activés qu'après livraison du [contrat exécutable commun](FIRST-BOOT.md), nouveau
payload épinglé et tests correspondants, ou dans la [variante TEST avec LAN
initial](TEST-LAN.md) après réception de ses contrôles propres. Cette variante
reste préparée et inactive à ce stade. Le banc offline applicatif précédent
prouve des imports/API dans la VM ; il ne prouve pas le boot du rootfs Raspberry
Pi. Les installations hors banc restent exclues.

## Résultat vérifié le 28 septembre

Deux builds propres du commit `1ee27e2b30633259bc31db8c21b4edde26a23191`
ont passé l'installation offline, 62 gates système, 26 gates applicatifs,
13 contrôles firstboot sur fixtures Linux, systemd, visudo et fsck FAT/ext4.
Les dix fichiers boot/grow protégés sont identiques avant/après personnalisation.
Il reste 161456128 octets libres dans le rootfs avant son extension au boot.

La comparaison complète des deux exports rehashés trouve zéro fichier ajouté,
supprimé ou modifié, y compris les permissions et métadonnées décrites. Les
images brutes ont des SHA-256 différents : aucune garantie octet pour octet.
Les [preuves et hashes](validation/2026-09-28-application-prototype.json) lient
ces résultats au candidat `6a697d1` et à la recette exacte.

Le second build s'est exécuté depuis une copie propre du même commit, après
récupération et vérification d'entrées localement indisponibles. Les deux
exports comparés sont conservés dans le `build/` du checkout utilisé.

## Candidat écran et arrêt du 3 octobre

Le candidat `c31b13afdc957425571810c46230eaaf52fa5d14` est reçu avec le manifeste
`c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1`.
Il fournit un mode hardware explicite, un profil TEST AC073 pour le tuple brut
observé, des erreurs écran visibles et le drain du propriétaire SPI lors de
l’arrêt. La version Inky reste 2.3.0. Le profil TEST ne doit pas être appliqué
aux écrans Spectra ni utilisé pour réécrire l’EEPROM.

La [validation offline](validation/2026-10-03-display-drain-candidate.json)
passe dans une VM ARM64 sous UID non privilégié, sans réseau : création du
venv, installation des 40 wheels hashées, installation locale de l’application,
`pip check` et smoke ASGI. Health/frontend retournent 200, une route protégée
401. Dix imports natifs passent ; RPi.GPIO reste bloqué par sa garde matérielle.
Le smoke n’entre pas dans le lifespan, n’initialise pas l’écran et ne crée
aucune identité applicative. Il ne teste pas le drain.

**Les pins de l’image restent inchangés.** Intégrer ce bundle demande une revue
des sources d’installation par couple source/manifest, de nouveaux units/drop-ins,
un parent reconstruit et la mise à jour cohérente des contrats TEST. L’unité
candidate demande SIGTERM, `KillMode=mixed`, `TimeoutStopSec=infinity` et
`SendSIGKILL=no`. Un driver bloqué peut donc rester en `deactivating` : l’OS ne
doit pas en déduire qu’il peut arrêter l’hôte. Le runtime opérateur livré garde
son refus de stop tant que l’app et le helper ne sont pas déjà inactifs et masqués.

Un démarrage hardware peut afficher le welcome. Il exige les gates et une
autorisation explicite d’affichage ; lire ensuite une API de diagnostic ne
transforme pas ce démarrage en observation passive. Aucun écran, appairage
iOS ou arrêt physique n’est qualifié par ce résultat logiciel.
