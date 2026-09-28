# Premier démarrage sans LAN

État au 28 septembre 2026 : chantier autorisé par l’opérateur, **pas encore un parcours
utilisable de bout en bout**. Le candidat applicatif `6a697d1` ne sait pas ouvrir
sa première fenêtre QR sans session LAN authentifiée. Son intégration dans
l'image reste expérimentale, avec services applicatifs masqués.

Le contrat commun de besoins (`inky-studio/blob/4bdaf6b12f550f8c3fd19a58c04294ba5221e8c3/docs/inkyos/FIRST-BOOT-CONTRACT.md`)
porte les cas FB-01 à FB-12. Cette révision ne définit ni wire format ni nouvelle
permission système. Inky Studio possède le backend, iOS, BLE, les helpers,
l'identité TLS, les credentials et l'affichage ; InkyOS possède la recette,
l'identité système, les prérequis et le gate Wi-Fi au boot. Les changements app
sont sur `codex/first-boot-contract`, distincts du candidat de packaging PR #13.

## Décisions communes retenues

- Une image ne contient aucune identité, clé, password, QR, owner ou photo.
  L'installation offline ne lance ni app, helper, lifespan, install.sh ni
  install-bluetooth.sh. Pip et le build backend Python s'exécutent sous UID 1000
  dans le rootfs isolé ; ce sont des opérations de build.
- Une panne réseau, un certificat expiré, un magasin applicatif manquant ou la
  révocation du dernier téléphone ne créent jamais une nouvelle autorité usine.
- Un reçu d'initialisation indépendant du magasin applicatif doit empêcher
  qu'effacer ce magasin fasse passer un appareil initialisé pour un appareil
  neuf. Le format OS, l'accès privilégié et la transaction commune restent à
  convenir avant activation. Les types internes du futur module app ne sont pas
  des preuves d'authentification BLE.
- Le premier claim accepté est terminal et atomique avec son owner. Le succès
  Wi-Fi et le login photo ne décident pas de l'adoption. La réponse perdue doit
  pouvoir être rejouée par le gagnant sans permettre un second propriétaire.
- Le téléphone doit pouvoir corriger l'heure d'un appareil neuf **et** celle
  d'un appareil déjà adopté, sans le remettre en mode usine. L'authentification,
  l'expiration et les limites du bootstrap doivent fonctionner avant l'UTC.
- L'app confirme le pays d'utilisation. La langue, la timezone et le Mac de
  build ne déterminent pas ce pays. Aucun scan ou autoconnect n'est autorisé
  avant application et vérification de l'état réglementaire.

## Heure : mécanisme encore à choisir

Le socle contient systemd/timesyncd `257.13-1~deb13u1`. Son interface
[`SetTime`](https://github.com/systemd/systemd/blob/v257.13/src/timedate/timedated.c)
refuse un changement lorsque NTP est actif, même sans synchronisation acquise.
La [règle polkit](https://github.com/systemd/systemd/blob/v257.13/src/timedate/org.freedesktop.timedate1.policy)
associe aussi les droits `set-timezone` et `set-ntp` au droit `set-time`.

Une opération étroite utilisant
[`clock_settime_ns(CLOCK_REALTIME, …)`](https://docs.python.org/3.13/library/time.html#time.clock_settime_ns)
éviterait de suspendre NTP, mais exige `CAP_SYS_TIME`. Le helper actuel est
non-root et sans capability ; élargir son service n'est donc pas une simple
option d'installation. Comparer cette extension à un composant privilégié
strictement limité avant de choisir les unités. Le backend ordinaire ne reçoit
aucun sudo général, droit timedate ou capability.

Le contrat doit borner les valeurs entières, les corrections avant/arrière,
le débit et la durée d'autorisation. Une borne supérieure fixée à la date de
release ne doit pas rendre une image stockée longtemps inutilisable. Une heure
fournie par un téléphone authentifié n'est pas une preuve indépendante d'UTC.
Les durées de session utilisent monotonic, indépendamment des sauts d'horloge.

[timesyncd sauvegarde un plancher](https://github.com/systemd/systemd/blob/v257.13/man/systemd-timesyncd.service.xml)
dans le mtime de son fichier clock, y compris périodiquement hors NTP ; ce n'est
ni une heure exacte après extinction ni un accusé de persistance immédiate.
Conserver NTP pour la correction ultérieure et distinguer « initialisée par
téléphone » de « synchronisée ». Aucune mutation réelle de l'heure du Mac ou de
la VM partagée n'est nécessaire aux fixtures.

## Pays Wi-Fi : gate système

Le socle contient NetworkManager `1.52.1-1+rpt4`, iw `6.9-1+b1`, wireless-regdb
`2026.05.30-1~deb13u1` et raspi-config `20260730`. Le code officiel distribué dans
[raspi-config-core](https://archive.raspberrypi.com/debian/pool/main/r/raspi-config/raspi-config-core_20260730_all.deb)
persiste `cfg80211.ieee80211_regdom=XX` dans cmdline, appelle `iw reg set XX`,
puis active la radio NetworkManager. SHA-256 du paquet lu :
`642a4b61aa852bca5c9be46141d1f9e1782c27fe190508f5340e173235f658fb`.
Cette recherche a vérifié les octets HTTPS et la version, sans revérifier un
index APT signé ; elle n'ajoute aucun paquet à l'image.

Le flux InkyOS doit garder la radio fermée pendant cette opération, préserver
les autres tokens de cmdline dont `resize`, sérialiser les demandes et distinguer
pays demandé, persisté et observé. Ne pas exécuter toute la fonction raspi-config
comme transaction : elle active la radio avant notre vérification. Aucun
`rfkill unblock all` ; BLE doit rester disponible indépendamment du Wi-Fi.

Le [kernel 6.18](https://github.com/torvalds/linux/blob/v6.18/net/wireless/reg.c)
traite le domaine comme un hint réglementaire. Le
[driver brcmfmac](https://github.com/torvalds/linux/blob/v6.18/drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c)
peut rencontrer un refus du firmware après la demande : `iw` avec exit 0 ne
suffit pas. Le critère domaine global/phy/canaux doit être qualifié sur le Pi,
sans exiger arbitrairement un même code dans toutes les sections de `iw reg get`.

La persistance et la réconciliation avant NetworkManager doivent partager une
seule règle avec le futur helper. Une erreur doit laisser le Wi-Fi fermé et
permettre la correction via BLE. Une mise à jour app d'un cadre existant exige
une migration conservant sa configuration ; elle ne doit pas lui appliquer
automatiquement le gate d'une image usine vierge.

## Intégration et prochaines preuves

Le [modèle de reçu OS](../scripts/initialization-receipt.py) est implémenté et
testé séparément, sans CLI, service ou hook dans l'image. `create_authorization`
exige un répertoire neuf explicitement autorisé ; `begin(intent)` consomme le
reçu sous verrou, avec écritures atomiques et fsync fichier/répertoire.
`newly_consumed` autorise la seule création initiale ; `already_consumed` permet
uniquement de rouvrir un magasin existant. Une coupure entre consommation OS
et création de la DB applicative exige une récupération explicite. L'absence
de DB n'autorise aucune nouvelle émission.

Le lot applicatif état/receipt (`inky-studio/blob/2c03466464f1b45f4baf1763e0416da52a8bef24/docs/inkyos/FACTORY-STATE.md`)
fournit les assertions internes `InitializationReceipt(UUID, digest)` et
`FactoryIdentity(UUID, SPKI)`, puis `pending → factory → adopted`. Les formats
UUID canoniques et digest hex64 concordent ; le raccord réel privilégié reste
à intégrer. Ce lot est distinct du payload `6a697d1`, sans assemblage de fichiers
provenant de branches différentes. Les tests de crash sont des sorties de
processus sur fixtures, pas des coupures électriques sur SD.

La cible `application-prototype` prend un manifeste et son SHA-256 explicitement
épinglés, installe le payload offline, dérive les fichiers système depuis les
installers de ce même commit et garde `inky-studio.service` et
`inky-network.service` masqués. Le Wi-Fi est désactivé dans ce prototype ; aucun
pays n'est choisi. Voir [APPLICATION-IMAGE.md](APPLICATION-IMAGE.md).

Les fixtures doivent couvrir les coupures entre écritures, les pertes de
magasin, les claims concurrents, l'appareil adopté à certificat expiré, les
requêtes rejouées, le pays refusé et l'absence de précédent réseau à restaurer.
Puis viennent l'interopérabilité backend/iOS, les adapters système simulés,
le rootfs cible et enfin une SD de test dédiée. Ni la VM ni l'égalité des images
ne qualifient la radio, le panneau, le QR physique ou l'iPhone.
