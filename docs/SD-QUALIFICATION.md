# Qualification InkyOS sur SD dédiée

Procédure préparée le **27 septembre 2026**. **Aucun essai SD consigné ici.**
l’opérateur ne dispose pas encore de SD de test ; sa SD personnelle reste intacte.
Ce document ne lance aucun flash, accès Pi ou changement matériel.

Références : [plan de réalisation](BUILD-PLAN.md), [contrats et responsabilités](HANDOFF.md),
[sources matériel](HARDWARE-SOURCES.md), [outils offline](DEVELOPMENT.md) et
[payload applicatif proposé](APPLICATION-PAYLOAD.md).

## Deux campagnes distinctes

| Campagne | Conditions d'entrée | Ce qu'un résultat positif permet d'affirmer |
|---|---|---|
| Prototype système | Image personnalisée inspectée, SHA-256 connu, banc et SD dédiés, moyen de diagnostic local validé. Aucune app nécessaire. | Le système boote sur cette combinaison, initialise son hostname, agrandit le rootfs et conserve son état. |
| InkyOS complet | Conditions précédentes, release app/helper/iOS qualifiée et épinglée, panneau identifié, packaging offline vérifié, contrats heure/adoption sans LAN/pays Wi-Fi/recovery livrés. | Les scénarios réellement exécutés fonctionnent sur la combinaison exacte testée. |

La campagne système peut avancer avant l'app. Elle ne valide ni welcome/QR,
certificats, écran, adoption iPhone, ni transactions Wi-Fi. Ces lignes restent
**BLOQUÉES** tant que leurs contrats ou composants manquent. Un prototype sans
backend ne devient pas une image prête à installer Inky Studio.

Pour le prototype, prévoir un diagnostic local sur le banc : console validée ou
variante de diagnostic identifiée séparément. Les commandes ci-dessous supposent
ce moyen disponible ; elles ne justifient pas un login partagé, un contournement
des comptes verrouillés ou l'ouverture de SSH dans l'image distribuée.

## Préparer le banc et les preuves

1. Réserver deux SD de test, étiquetées **A** et **B**, et un banc dédié. Elles
   peuvent être démarrées successivement sur le même Pi de test. La SD et le
   cadre personnels ne servent pas aux essais de coupure.
2. Partir deux fois du **même artefact vierge**, jamais d'une copie de A après
   son premier boot. Vérifier SHA-256, manifeste, rapport d'inspection final et
   absence d'identités/profils/photos avant tout essai physique.
3. Consigner Pi, PCB/panneau, alimentation, câbles et SD. Ne pas déduire la
   famille du panneau de la seule résolution 800 × 480. La table Pimoroni
   référencée distingue notamment EEPROM 20/AC073TC1A (7 couleurs) et
   22/E673 (Spectra 6).
4. Avant les essais écran, faire relever la variante EEPROM et la classe driver
   par la procédure coordonnée avec Inky Studio, sans refresh d'identification.
   Aucun scan I²C générique ni second processus propriétaire de SPI n'est requis
   par ce document. Relever aussi la référence visible du panneau et ses boutons
   réels ; ne pas supposer un mécanisme de recovery physique.
5. Employer exclusivement réseaux, comptes et images de test. Conserver les
   preuves utiles : hashes d'artefacts, comparaisons d'identités, mesures et
   extraits d'erreurs expurgés. Ne pas exporter clés privées, mots de passe,
   QR actif, profils Wi-Fi, bases applicatives ou photos personnelles.

L'image Lite de septembre inventoriée a un kernel différent du banc applicatif
transmis. Le statut du banc antérieur ne se transfère pas au nouveau kernel,
firmware, Python ou driver : relever les versions réellement démarrées.

## Séquence système

| ID | Essai sur A puis B | Critère et preuve |
|---|---|---|
| S01 | Premier boot sans LAN ni profil Wi-Fi préchargé. | Boot observé ; `inkyos-firstboot.service` termine sans dépendre du réseau. Pas de wizard concurrent. Les erreurs sont consignées, pas compensées par une configuration personnelle. |
| S02 | Identités après premier boot. | `/etc/machine-id` généré par systemd, état version 1 sous `/var/lib/inkyos/system.json`, hostname kernel et `/etc/hostname` cohérents, une entrée locale cohérente dans `/etc/hosts`. Identités système différentes entre A et B. Conserver égalité/différence ou empreintes, pas les valeurs brutes. |
| S03 | Services et permissions. | Ordre firstboot avant NetworkManager/Avahi/Bluetooth vérifié ; services attendus en état sain. Compte app verrouillé si présent, état InkyOS 0700/0600, SSH selon politique désactivée. Aucun profil ou état applicatif hérité. |
| S04 | Resize de la SD. | Taille de partition et capacité ext4 cohérentes avec la SD et le layout prévu ; espace libre mesuré. `rpi-resize`/`systemd-growfs-root` et éventuel reboot initial observés. Ne pas exécuter manuellement resize/growfs pour transformer un échec en succès. |
| S05 | Un reboot normal de chaque carte pour le prototype. | Identités identiques à celles de leur premier boot ; état et hostname cohérents, aucun nouveau wizard ni erreur de service. |
| S06 | Série de 10 reboots par carte pour qualification complète. | Aucune identité régénérée, aucune panne de boot/FS/service. Rapporter chaque échec ; cette série n'est pas requise pour déclarer uniquement le premier prototype observé. |
| S07 | Mesures au repos puis charge représentative. | Temps de boot et disponibilité des services, RAM disponible, swap, stockage, température, OOM et throttling/undervoltage relevés. Pour le prototype sans app, la charge applicative reste non testée. |
| S08 | Échec d'initialisation contrôlé, sur carte de test sacrifiable. | État corrompu refusé explicitement, aucune nouvelle identité émise ; services réseau dépendants ne démarrent pas après cet échec. Scénario et remise à zéro du banc préparés séparément. |

La présence statique d'une unit ne prouve pas son démarrage. Une unit oneshot
peut être `active (exited)` ou avoir fini normalement : vérifier `Result` et son
code de sortie, pas seulement une recherche de processus. Les seuils de temps,
RAM et température doivent être fixés à partir des besoins et mesures avant la
qualification complète ; aucun chiffre arbitraire n'est présenté ici comme acquis.

Commandes de diagnostic **en lecture seule**, à exécuter plus tard uniquement
sur le banc préparé ; elles ne configurent pas le réseau et ne démarrent aucun
service. Une commande absente est notée comme telle, sans installation implicite.

```sh
uname -r
dpkg --print-architecture
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'
systemd-analyze time
systemctl --failed --no-pager
systemctl show inkyos-firstboot.service NetworkManager.service avahi-daemon.service bluetooth.service -p ActiveState -p SubState -p Result -p ExecMainStatus
systemctl show rpi-resize.service systemd-growfs-root.service -p LoadState -p Result -p ExecMainStatus
findmnt -no SOURCE,FSTYPE,OPTIONS /
lsblk -b -o NAME,SIZE,FSTYPE,MOUNTPOINTS
df -B1 / /boot/firmware
free -b
swapon --show --bytes
cat /sys/class/thermal/thermal_zone0/temp
vcgencmd get_throttled
date -u
timedatectl show -p NTPSynchronized
```

La température sysfs est relevée avec son unité (habituellement milli°C), sans
confusion avec °C. Le bloc d'alimentation nominal ne mesure pas le courant du
cadre ; tout chiffre de consommation doit préciser l'instrument et le point de
mesure. Pour OOM, erreurs FS et undervoltage, consulter les journaux localement
et ne conserver que les événements nécessaires, sans export complet non relu.

## Campagne applicative coordonnée avec Inky Studio

La session Inky Studio conserve la responsabilité app iOS/backend/BLE, écran,
changement Wi-Fi et rollback. InkyOS fournit le manifeste OS et le banc SD ; les
résultats applicatifs sont référencés dans la fiche, sans modifier le protocole
pour faire passer un test.

| ID | Scénario après levée des prérequis | Critère / responsable |
|---|---|---|
| A01 | Premier boot totalement sans LAN. | Welcome et première adoption physique fonctionnent selon le contrat livré. Le parcours actuel qui ouvre une fenêtre QR depuis une session LAN authentifiée ne valide pas cet essai. Inky Studio. |
| A02 | Heure absente/erronée, date valide, certificat expiré, image stockée longtemps. | Comportement défini et sûr, validation TLS conservée. Attendre le contrat de temps authentifié ; ne pas forcer une date ni désactiver TLS comme contournement. Campagne conjointe. |
| A03 | Deux installations vierges, puis reboots. | UUID/clé/certificat applicatifs différents entre A/B ; identité et ownership stables sur une même SD. L'app crée et observe ses identités ; comparer seulement les empreintes publiques autorisées. Pas de lecture de clé privée par un script OS. |
| A04 | Adoption iPhone et réseau de test. | QR correct/erroné/expiré, mauvais password, confirmation HTTPS, timeout/rollback, perte BLE et reboot vérifiés. Hotspot 2,4 GHz et pays Wi-Fi traités selon le contrat. Inky Studio, preuves du téléphone et du Pi. |
| A05 | Refreshs et ressources. | Panneau/EEPROM/driver concordants, `is_mock=false`, au moins cinq refreshs successifs, pas de conflit GPIO, durée et charge mesurées. Un seul display owner. Inky Studio. |
| A06 | Mise à jour et récupération. | Couple app/helper/OS compatible ; persistance des photos de test et des identités ; limites du rollback venv explicites. Restauration sur carte de secours éprouvée, sans deux cadres actifs portant la même clé. Campagne conjointe. |

Les réseaux ouverts, WPA Enterprise, portails captifs et 5 GHz ne deviennent pas
compatibles parce qu'un test WPA2 personnel 2,4 GHz passe. Un test mock ou radio
Mac/Pi ne remplace pas l'adoption par un iPhone physique.

## Coupures : simulations et essais réels

Les tests de `tests/test_firstboot.py` injectent des interruptions entre les
écritures, rename, `fsync` et application du hostname. Ils vérifient la reprise
logique depuis l'état commis et le refus d'un état corrompu. Ils ne reproduisent
pas la perte de caches, les écritures du contrôleur SD, le comportement électrique
ou une corruption ext4. Une VM et un arrêt du processus ne constituent pas une
coupure d'alimentation du Pi.

La campagne physique est distincte et attend un banc et des SD sacrifiables.
Définir les points de coupure et l'observation avant de commencer : initialisation
système, adoption, transaction Wi-Fi et update, ces trois derniers avec Inky
Studio. Pour chaque essai, consigner phase réelle, méthode, résultat au boot
suivant, stabilité d'identité, état du FS et action de récupération. Ne pas
déduire un rollback automatique de la seule présence de `fsync` ou d'un test réussi.

## Fiche de campagne à remplir

Statuts autorisés : **NON TESTÉ**, **BLOQUÉ**, **PASS**, **FAIL**, **SANS OBJET**
(avec justification). Une case vide ou bloquée ne vaut jamais PASS.

| Métadonnée | Valeur |
|---|---|
| ID campagne / date / opérateur du banc | À remplir |
| Portée : prototype système ou InkyOS complet | À remplir |
| Commit recette / image SHA-256 / rapport offline | À remplir |
| Image source / packages ajoutés / manifeste | À remplir |
| Pi modèle/révision ; panneau PCB/référence/EEPROM/driver | À remplir |
| Alimentation/câble ; SD A/B modèle et capacité | À remplir — aucun identifiant personnel requis |
| Kernel/firmware/userland/Python réels | À remplir |
| Release app / helper / iOS / preuves Inky Studio | BLOQUÉ si composants non qualifiés |
| Méthode de diagnostic local | À remplir |

| Essai | SD | Statut | Mesures / preuve expurgée / écart ou blocage |
|---|---|---|---|
| S01–S04 : premier boot, identités, services, resize | A / B | NON TESTÉ | À remplir séparément par essai |
| S05 : premier reboot | A / B | NON TESTÉ | À remplir |
| S06 : série 10 reboots | A / B | NON TESTÉ | À remplir |
| S07 : ressources / alimentation | A / B | NON TESTÉ | À remplir |
| S08 : échec firstboot | Carte sacrifiable | NON TESTÉ | À remplir |
| A01–A06 : scénarios applicatifs | A / B | BLOQUÉ | Prérequis et résultats à référencer séparément |
| Coupures physiques par phase | Carte sacrifiable | NON TESTÉ | À remplir |
| Installation/récupération par une seconde personne | Carte dédiée | NON TESTÉ | À remplir avant distribution |

Décision finale à dater : **non qualifié**, **prototype système observé**, ou
**combinaison matérielle/applicative qualifiée pour les scénarios listés**.
Joindre les FAIL/BLOQUÉ restants et les limites. Une autre SD, un autre panneau,
une autre version kernel ou une nouvelle release app exige l'analyse de son
impact ; aucune compatibilité supplémentaire n'est obtenue par déduction.
