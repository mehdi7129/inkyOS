# Reprise du parcours QR sans Wi-Fi — 16 octobre 2026

## Résultat de ce lot

Le checkout `codex/factory-active-integration-20261016` ajoute trois composants
pour la future recette active. Le profil historique `factory-assembly` reste
file-only et ses cinq unités fermées conservent leurs octets et contrôles.

- `configure-factory-active-prerequisites.py` prépare les comptes réservés et
  deux parents persistants vides, avec relecture. Le verrou `.pwd.lock` déjà
  présent dans la base officielle est conservé et détenu jusqu'à la fin.
- `plan-factory-runtime-manifest.py` dérive les pins des fichiers installés,
  exige les trois inventaires explicitement épinglés, vérifie les comptes/NSS
  et le candidat réel. Il écrit seulement un plan hors de l'image, sans créer
  permission, contexte, admission ou manifeste runtime installé.
- `inkyos-factory-start.service` est un trigger distinct : premier boot système,
  superviseur puis main, avec propagation des échecs. Il n'active aucun des cinq
  noms fermés par un alias ou un lien `.wants`.

Le [rapport de validation](validation/2026-10-16-factory-active-foundations.json)
conserve les commits et hashes exacts. Les 126 cas Linux ARM64 root de la passe
principale passent sans skip ; la dernière garde GID et le roundtrip du manifest
passent ensuite séparément, soit 127 cas distincts vérifiés, sans additionner
les deux exécutions du même roundtrip. Les six scénarios PID1 réels avec services
inertes passent également et leurs unités temporaires sont toutes retirées.

## Vérification sur la base Raspberry Pi OS

Une copie privée de la base figée a été vérifiée par son hash complet
`49fafba626ec00e0f9800349b9edae6caf8cfc223f673b875b72ac2797ed9576`.
La lecture initiale se fait en `ro,noload`. Les outils génériques d'OS préparent
ensuite `inky` dans cette seule copie, selon le builder existant. Aucun backend,
driver, Bluetooth, réseau ou écran applicatif n'est lancé.

Les IDs d'exemple 991/992 sont déjà occupés par `systemd-timesync`/`render` dans
cette base et ont été correctement refusés avant écriture. Les IDs 980/980,
observés libres dans leurs espaces respectifs, ont été sélectionnés explicitement.
Le vrai CLI prépare les comptes et parents attendus ; le vrai
`writer-parents.identities()` vérifie les résolutions NSS dans le chroot cible,
et `writer-parents.record()` accepte le parent helper `980:980/0700`.
La sentinelle machine-id reste vierge, le verrou conserve son inode et ses
métadonnées, et une seconde configuration est refusée.

Le rootfs de travail est démonté, son loop détaché, et la VM `inkyos-build`
arrêtée après les vérifications. La SD et le Pi qui ont réussi le test photo
n'ont pas été modifiés.

## Reste avant une image utilisable

Ce lot ne constitue pas une nouvelle image SD. Il reste à réunir les composants
dans une recette active avec l'exporter, un support système/ELF réellement dérivé
du nouveau rootfs et le manifeste runtime installé. Le trigger doit alors faire
partie de cette fermeture et du graphe réellement observé.

Le backend usine s'arrête encore à `ADOPTED → system_setup`. Le raccord doit
authentifier le propriétaire courant, préparer l'heure et le pays, permettre le
Wi-Fi après scan, publier l'identité TLS normale sans changer UUID/SPKI, remettre
un accès PHOTO propre au premier iPhone puis démarrer le mode photo. Un reboot
normal doit préserver l'identité, le réseau, le propriétaire et la photo.
Les nouveaux composants ne reprennent pas implicitement le stockage Phase B
historiquement en pause et ne remplacent aucun de ses contrôles.

En parallèle, l'intégration backend factory `eb11790` avec les correctifs photo
et invitations `9ec89d726` avance dans un checkout distinct ; l'iOS invitations
avance dans la session Inky Studio autorisée. Leurs commits et validations doivent
être consignés dans le relais commun une fois ces lots clos. La build TestFlight
12 reste la dernière livraison vérifiée à ce point de reprise.
