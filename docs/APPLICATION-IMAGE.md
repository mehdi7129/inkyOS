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
Pi. Le cadre personnel et sa SD restent hors des essais.

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

Le second build s'est exécuté depuis une copie propre du même commit dans
`~/Library/Caches/inkyos-checkout`. macOS avait évincé des
fichiers du Bureau (`dataless`), bloquant leur lecture. Les entrées ont été
récupérées/revérifiées, sans changement de configuration iCloud. Les deux
exports comparés sont maintenant dans le `build/` de ce checkout local.
