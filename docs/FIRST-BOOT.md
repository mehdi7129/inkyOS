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

## Heure : profil TLS et opération système

La décision TLS commune (`inky-studio/blob/efda86e4e759039fd6045afc57f0dbcadc7c7879/docs/inkyos/BOOTSTRAP-TLS-DECISION.md`)
retient un profil bootstrap distinct, épinglé sur la clé du QR physique ou sur
celle du propriétaire connu. Il doit conserver la preuve de possession de clé
TLS 1.3 et limiter l'exception aux dates du certificat de ce profil. Le claim
initial précède tout changement d'heure ; une réparation ultérieure exige un
owner toujours autorisé. Après renouvellement du certificat sous la même clé,
une nouvelle connexion TLS normale précède le pays et toute opération Wi-Fi.
Ce choix est un prototype applicatif séparé, encore absent du payload `6a697d1`.

Les sessions HTTP sont passées à monotonic dans le commit applicatif
`ce4ab47` (`inky-studio/commit/ce4ab473e669e31502d4b697949289238ebce7a4`).
Cela ne qualifie pas à lui seul tous les consommateurs d'heure, notamment le
scheduler et le cycle certificat. Les politiques numériques et l'autorisation
de chaque mutation restent à raccorder avant activation système.

Le socle contient systemd/timesyncd `257.13-1~deb13u1`. Son interface
[`SetTime`](https://github.com/systemd/systemd/blob/v257.13/src/timedate/timedated.c)
refuse un changement lorsque NTP est actif, même sans synchronisation acquise.
La [règle polkit](https://github.com/systemd/systemd/blob/v257.13/src/timedate/org.freedesktop.timedate1.policy)
associe aussi les droits `set-timezone` et `set-ntp` au droit `set-time`.

Une opération étroite utilisant
[`clock_settime_ns(CLOCK_REALTIME, …)`](https://docs.python.org/3.13/library/time.html#time.clock_settime_ns)
éviterait de suspendre NTP, mais exige `CAP_SYS_TIME`. Le helper actuel est
non-root et sans capability ; élargir son service n'est donc pas une simple
option d'installation. La direction commune retient un composant privilégié
distinct, aux opérations bornées ; unités, capabilities et autorisation effective
restent à revoir avant activation. Le backend ordinaire ne reçoit aucun sudo
général, droit timedate ou capability.

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

Le [gate avant NetworkManager](WIFI-BOOT-GATE.md) est désormais une fonction
testée, toujours inactive : écriture atomique de `WirelessEnabled=false` avant
chaque démarrage/restart du daemon. Son futur `ExecStartPre` restera indépendant
du firstboot hostname pour éviter qu'un échec Wi-Fi bloque également Bluetooth.
Il ne prouve pas à lui seul la fermeture physique du radio avant NM.

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

Un [banc croisé de 11 cas](validation/2026-09-28-factory-contract-cross.json)
exécute ces deux sources exactes ensemble : nouveau reçu, création/claim,
reprise après adoption, DB perdue, interruption entre consommation et DB,
intent différent et bindings incompatibles. Tous passent ; les assertions
d'identité restent synthétiques et l'ownership OS utilise un override de fixture.
Ce résultat ne qualifie ni l'IPC privilégié futur ni un parcours de boot.

Un second banc assemble ensuite le reçu OS réel et les cores applicatifs
d'identité/coordinator : [20 cas sur `5b5ad6e`](validation/2026-09-28-first-boot-core-cross.json)
passent, dont deux processus indépendants, pertes de DB/identité/réponse,
publication et réparation de certificat sous la même clé et le même UUID.
La [passe précédente sur `f244fd2`](validation/2026-09-28-first-boot-core-cross-f244fd2.json)
conserve le comportement antérieur : des credentials absents consommaient déjà
le reçu et laissaient un ledger pending. Le correctif vérifié refuse désormais
avant préparation et consommation ; les 19 autres cas restent inchangés.
La [comparaison des deux révisions](validation/2026-09-28-first-boot-core-delta.json)
lie les rapports, snapshots et dépendances exacts.
Ce banc Mac utilise un override d'ownership de fixture et une assertion locale
`ClockResult` simulée. Il ne vérifie ni autorisation owner, ni heure réelle,
ni handshake TLS, ni dispatcher ou chemin BLE/iPhone.

Le [modèle système heure/pays](../scripts/bootstrap-system-model.py) fournit
un parseur borné, un contrôle d'UID numérique, des bornes UTC explicites et
l'ordre « radio fermée → intention persistée → application → observation
vérifiée → confirmation persistée ». Tous les adapters sont injectés : aucune
horloge, radio, socket, unité ou capability réelle n'est utilisée. Le modèle
renvoie une décision de gate, il n'active pas le Wi-Fi. Un succès d'application
seul ne suffit pas à confirmer le pays ; le vérificateur réglementaire doit
accepter l'observation, puis la persistance doit réussir. Les messages refusés
avant authentification/parsing ne modifient aucun état.
Ses 32 tests ciblés font partie d'une suite de 243 tests passée sur Mac et Linux
ARM64, avec [entrées et résultats hashés](validation/2026-09-28-bootstrap-inspection.json).

L'opération interne `begin_initialization` appelle le reçu une
seule fois pour un UID applicatif distinct de celui du helper. Son résultat
valide conserve exactement `newly_consumed` ou `already_consumed`. Un échec
du callback ne devient jamais un nouveau grant et cette opération ne change
pas le gate Wi-Fi. Le helper ne peut pas initialiser ; l'app ne peut pas régler
l'heure ou le pays. Aucun chemin ni commande n'est accepté dans les messages.
`InitializationUncertain` distingue une erreur après appel potentiellement
consommant d'un refus préalable sans effet. Après cette erreur, conserver le
même intent et consulter l'état pour rouvrir ou récupérer ; ne jamais en déduire
un nouveau droit de création. Les callbacks ne doivent pas réentrer le modèle.

`inspect_initialization` est également réservée à l'UID app et n'accepte aucun
argument. Elle consulte le vrai modèle de reçu sans consommation : `authorized`
seul, ou `consumed` avec intent/receipt stricts. Un état manquant, corrompu ou une
réponse invalide est refusé sans grant, retry, changement du gate ni autorisation
implicite. Le callback est explicitement trusted et readonly ; l'UID app n'accède
pas directement au fichier root.

Les quatre opérations JSON de ce modèle sont internes et expérimentales. Elles
ne sont pas ajoutées au protocole BLE ou au helper v1. L'adapter réel devra
obtenir l'UID par `SO_PEERCRED`, sérialiser entre processus, imposer délais et
persistance root-owned et vérifier le driver cible. Le verrou actuel ne
sérialise que les threads d'un objet de test.

Le [banc Linux privilégié](BOOTSTRAP-PROBE.md) vérifie séparément les credentials
kernel et un vrai reçu root-owned : 62 checks passent, dont la réponse perdue
après consommation durable. Il utilise les mêmes modèles et des adapters
temps/pays simulés ; il n'installe aucun IPC de production ni hook de boot.

Deux raccords restent explicites : le backend doit obtenir `newly_consumed`
par un appel privilégié réellement à usage unique, sans réutiliser un grant
stocké dans `/run` après un restart ; le gate initial doit permettre le démarrage
de NetworkManager avec radio fermée, car le helper actuel dépend de ce service.
Attendre un pays avant de lancer tout NetworkManager créerait un cycle.

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
