# Première activation TEST et arrêt

Contrat du 4 octobre 2026 pour le Zero 2 W, pays confirmé France, candidat
applicatif `c31b13afdc957425571810c46230eaaf52fa5d14` et profil d’écran explicite
`ac073-800x480`. Ce raccord ne qualifie ni la dalle ni les autres modèles.
Les essais sur le Pi et l’iPhone restent nécessaires.

## Admission

L’image démarre avec l’app et le helper masqués. Les deux workers lifecycle
sont installés, sans lien d’activation au boot. Le premier boot crée
l’identité du Pi puis demande l’arrêt ; le retour offline et la capsule signée
précèdent le boot d’accès LAN. Aucun secret réseau ne figure dans l’image
générique ou dans les preuves publiques.

La requête SSH `activate` comprend `schema_version: 1`,
`confirm_test_refresh: true` et une référence UTC indépendante récente. Elle
écrit une demande privée liée au boot, au profil et au manifest, puis demande
le démarrage asynchrone du worker. L’accusé de réception signifie seulement
que la demande a été admise. Une demande existante n’est jamais remplacée.

La gate conserve les 24 checks historiques. Trois checks indisponibles ont
des remplacements TEST explicites, sans transformer l’ancien rapport en PASS :

- EEPROM fraîche : tuple exact 800 × 480, code couleur 4, variante 20,
  sélectionnant le candidat `ac073-800x480`.
- État runtime : services inactifs et masqués, versions et accès matériels
  vérifiés ; cela ne prouve aucun refresh physique.
- Radio : firmware FR/FR, global FR, label PHY FR ou 99 et limites des
  14 canaux conformes à la politique TEST déjà documentée.

Le cache signé et l’unique connexion sont réauthentifiés. L’heure NTP doit
être synchronisée et compatible avec la référence indépendante. La gate ne
change ni heure, ni pays, ni état Wi-Fi. Les données app/helper doivent être
vierges pour cette première admission.

Après ces contrôles natifs, le worker installe deux drop-ins volatils liés au
manifest, retire seulement les masques connus et vérifie les propriétés
effectives. Ils imposent `Restart=no`, `TimeoutStopSec=infinity`,
`SendSIGKILL=no` et une condition de démarrage qui consomme un permis privé.
Le helper est démarré en premier ; son socket, son processus et sa réponse
`health` exacte sont contrôlés avant le démarrage de l’application. L’heure
est vérifiée une nouvelle fois avant l’app.

Le préfixe `+` de l’ExecCondition donne les droits nécessaires au seul
consommateur de permis ; le processus principal conserve son utilisateur
restreint. Voir le [contrat systemd v257.13](https://github.com/systemd/systemd/blob/v257.13/man/systemd.service.xml).

L’app peut commencer le welcome dès son démarrage : l’admission autorise donc
bien un refresh de l’écran. `application_active_observed` constate un processus
actif, pas un serveur prêt ni des pixels correctement affichés. Le welcome du
candidat applicatif présente le mot de passe initial généré sur le Pi. Aucun
verbe SSH ne retourne ce secret ; si le welcome échoue, l’accès applicatif
reste bloqué pour analyse.

## Arrêt et observation

`stop` écrit d’abord une demande privée immutable sous le verrou court de
l’opérateur. Le worker drain invalide le permis et attend la fin du worker
d’activation, sans tenir ce verrou court. L’activation vérifie la demande
d’arrêt avant chaque admission ou démarrage. `status` reste interrogeable
pendant les attentes longues.

Le drain vérifie les unités chargées, demande SIGTERM à l’app et attend sans
deadline `inactive/dead`, PID principal et de contrôle à zéro, sans job.
Le helper reste disponible pendant cette attente. Le masque de l’app est
restauré seulement après sa sortie, puis le helper est arrêté et masqué.
Poweroff est demandé uniquement après la relecture des deux états, des
bindings et de l’absence de permis. Aucun SIGKILL, cancellation de job ou
`reset-failed` implicite n’est utilisé.

La déconnexion SSH ou son timeout ne prouve pas l’annulation de la demande.
L’accusé de réception du poweroff ne prouve pas que le Pi est éteint. Une
observation physique reste nécessaire avant de retirer la SD.

## Périmètre du premier essai

Une seule admission applicative est permise par boot, sur données vierges.
Les échecs, fichiers partiels et états existants sont conservés. Une coupure
imprévue avec masques retirés ne déclenche aucune remise en état automatique ;
une nouvelle admission demande une revue explicite. Aucun service applicatif
n’est enabled au boot, et les drop-ins TEST disparaissent au reboot.

L’essai prévu est : accès LAN, activation, observation du welcome, login iOS,
photo de test, fenêtre QR authentifiée puis adoption BLE/HTTPS avec la bêta
iOS compatible. Le premier appairage entièrement hors LAN reste distinct.
Les changements Wi-Fi et leur rollback attendent un secours vérifié et un
contrat de reprise après modification du profil initial.

Les fixtures vérifient le code et ses refus. Le banc systemd utilise des
processus inertes dans la VM, sans driver ni poweroff réel. Même ensemble,
ils ne qualifient pas l’arrêt du SPI sur le panneau physique.
