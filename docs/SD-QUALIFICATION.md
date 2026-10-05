# Qualification InkyOS sur SD dédiée

Procédure préparée le **27 septembre 2026**, état matériel mis à jour le
**5 octobre 2026**. **Premiers boots du prototype système observés sur deux SD,
identités initiales distinctes, persistance observée sur Qumox ; qualification
complète encore ouverte.** Le banc initial associe
une SD de test de 128 Go, détectée dans le lecteur Secure Digital du Mac,
et un Raspberry Pi Zero 2 W. Les autres installations restent hors des essais.
Une seconde carte, Qumox 16 Go selon l’inventaire de test, a ensuite été insérée dans le Mac :
15938355200 octets détectés. La comparaison des identités initiales A/B passe ;
le second boot Qumox conserve son identité. **La campagne active se poursuit
uniquement sur Qumox ; A est retirée du périmètre pour cette campagne.**
La série complète et la récupération restent à réaliser. Après un
[premier essai ambigu](validation/2026-09-30-sd-qumox-flash-observation.json),
une écriture unique avec Imager 2.0.11.1 termine sans erreur et éjecte la SD.
Ce [flash propre](validation/2026-09-30-sd-qumox-clean-flash.json) a été suivi
d'un [boot système observé](validation/2026-09-30-sd-qumox-first-boot.json).
Aucune relecture raw indépendante ou qualification complète de cette carte
n'est revendiquée.

Le **3 octobre**, la même capacité de SD dédiée est identifiée puis reçoit
l'[image privée d'enrôlement](TEST-ENROLLMENT.md). La
[preuve de ce nouveau flash](validation/2026-10-03-sd-enrollment-flash.json)
consigne la vérification Imager observée, la fin sans erreur et l'éjection.
L’opérateur confirme ensuite son boot et son arrêt, puis rapporte la SD. Le
[contrôle FAT préliminaire](validation/2026-10-03-sd-enrollment-return-preliminary.json)
correspond aux pins attendus. La [récupération privée](SD-RECOVERY.md) est ensuite
terminée : copie complète et relecture locale vérifiées, puis contrôle natif
ext4/FAT **21/21 PASS**, sans lecture du fichier de clé privée. La
[preuve complète réduite](validation/2026-10-03-sd-enrollment-return.json)
établit la cohérence du retour ; les sondes panneau/radio restent bloquées
sans cause enregistrée et aucun essai applicatif n'est qualifié. Les observations
système du 30 septembre ci-dessous concernent l'image diagnostic précédente.

Le **4 octobre**, la variante privée avec accès opérateur et workers
d’activation/drain reçoit à son tour un [flash terminé avec éjection
observée](validation/2026-10-04-sd-test-access-flash.json) sur la SD dédiée
de 16 Go. Le hash de l’image est contrôlé avant écriture. La phase de
vérification Imager n’a pas été observée directement et aucune relecture raw
indépendante n’est revendiquée. Le boot et l’arrêt sont ensuite confirmés par
l’opérateur. Le [rapport FAT retourné](validation/2026-10-04-sd-test-access-return-preliminary.json)
déclare l’enrôlement et passe neuf contrôles de cohérence avec l’export privé.
La radio possède une observation non qualifiée ; l’observation panneau reste
bloquée. Le **5 octobre**, la [copie complète et sa vérification native](validation/2026-10-05-sd-test-access-return.json)
sont terminées : 35 contrôles ext4/FAT et 10 contrôles d’infrastructure passent.
État, payloads attendus et clé publique hôte sont cohérents ; le contexte SSH
privé est exporté après démontage et détachement du loop, contrôlés de nouveau
indépendamment. Le premier accès Wi-Fi et l’activation applicative restent à faire.

La cible produit est une **microSD de 16 Go nominales**, sans marque imposée.
La référence sera choisie selon disponibilité/prix, puis qualifiée sur le banc.
L'image diagnostic actuelle mesure 3061841920 octets ; le contrôle de flash
compare la taille réelle de l'artefact à la capacité réelle du média, sans
exiger arbitrairement 16 milliards d'octets. Les 11,89 Go disponibles observés
sur Qumox ne sont pas une promesse valable pour toute carte de 16 Go.
Les résultats historiques sur A restent conservés ; ses essais non exécutés
ne sont ni relancés ni déclarés réussis.

Le premier essai utilise une [variante de diagnostic automatique](SD-DIAGNOSTIC.md),
distincte de la release : rapport expurgé sur FAT, puis demande de poweroff.
Le rapport récupéré après l'arrêt confirme le boot réel en ARM64 sur ce Pi.
La [preuve réduite](validation/2026-09-30-sd-first-boot.json) distingue le
snapshot du système, les tailles de partitions lues sur le Mac et l'arrêt
confirmé par l’opérateur. La seconde carte est préparée depuis ce même artefact
vierge, sans copier les identités de la carte déjà initialisée.

## Première observation physique — 30 septembre

Sur la SD de 127865454592 octets, `inkyos-firstboot`, `rpi-resize` et
`systemd-growfs-root` terminent avec succès, code 0. L'état firstboot version 1,
le hostname, le kernel et `/etc/hosts` sont cohérents. La partition Linux mesure
127320195072 octets ; ext4 offre 125269159936 octets, dont 117598322688 disponibles
(117,60 Go décimaux). Aucun resize manuel n'a été effectué.

NetworkManager, Avahi et Bluetooth sont actifs ; SSH, app/helper et les mises
à jour automatiques prévues sont masqués. Le kernel démarré est
`6.18.50+rpt-rpi-v8`. Au prélèvement : 290742272 octets de RAM disponibles,
40,242 °C et `get_throttled=0`. Les 46 secondes sont l'uptime au prélèvement,
pas une durée de boot. Ce snapshot ne mesure ni charge ni consommation.

| Essai | État lors de cette première observation sur A | Limite restante à ce stade |
|---|---|---|
| S01 | PASS : boot initial système de la variante sans Wi-Fi | Le rapport ne mesure pas une connexion radio ; pas d'adoption applicative. |
| S02 | Identité et cohérence observées ; critère complet NON TESTÉ | Comparaison initiale A/B ; persistance après redémarrage suivie par S05. |
| S03 | États des services et masques observés ; critère complet NON TESTÉ | Ordre réel, comptes et permissions exhaustives non mesurés. |
| S04 | PASS : partition et ext4 agrandis automatiquement | Éventuel reboot interne initial et sa durée non observés. |
| S05–S06 | NON TESTÉ | Redémarrage manuel et série de dix reboots. |
| S07 | Snapshot disponible ; critère complet NON TESTÉ | Charge, swap/OOM, temps de boot et mesures électriques. |
| S08 et coupures | NON TESTÉ | Banc et scénario préparés séparément. |
| A01–A06 | BLOQUÉ | App/helper inactifs ; écran, iPhone et transactions réseau non testés. |

Le rapport est écrit avant la demande d'arrêt ; le collecteur y apparaît
normalement `activating/start`. L’opérateur a confirmé séparément que le Pi était
arrêté avant de retirer la SD. À ce stade, un redémarrage restait nécessaire
pour vérifier la persistance ; A a ensuite été retirée des essais actifs.

Le [comparateur local](SD-DIAGNOSTIC.md#comparer-les-observations-localement)
prépare S02/S05 : il contrôle cohérence et stabilité/distinction des identités
sans publier leurs empreintes. Il exige des boots distincts ; sa disponibilité
et ses fixtures ne remplacent pas un second démarrage physique ou une seconde SD.

## Première observation Qumox et comparaison A/B — 30 septembre

La Qumox revient dans le Mac avec un rapport. Le boot réel ARM64 du Pi Zero 2 W,
le succès firstboot, la cohérence état/hostname/kernel/hosts et les états des
services attendus sont observés. La partition Linux mesure 15393095680 octets ;
ext4 offre 15080513536 octets, dont 11886649344 disponibles (11,89 Go décimaux).
Resize/growfs ont terminé avec succès, sans intervention manuelle.

Le comparateur exécuté sur les deux rapports initiaux termine avec le code 0 :
boots distincts, machine-id et hostname différents, cohérence et firstboot
acceptés sur A et B. **S02 est établi pour les identités initiales A/B.** La
stabilité après un nouveau démarrage relève de S05 ; elle n'était pas encore
testée à ce stade. Les empreintes d'identité restent locales ; la
[preuve réduite](validation/2026-09-30-sd-qumox-first-boot.json) conserve les
SHA-256 des artefacts et les résultats booléens.

| Essai | État actuel A/B | Limite restante |
|---|---|---|
| S01 | PASS : premier boot système observé sur A et B | Variante diagnostic ; aucun parcours applicatif sans LAN. |
| S02 | PASS : identités initiales cohérentes et distinctes sur A/B | Persistance après redémarrage suivie par S05. |
| S03 | États des services et masques observés sur A/B ; critère complet NON TESTÉ | Ordre réel, comptes et permissions exhaustives. |
| S04 | PASS : expansion automatique observée sur A/B | Reboot interne éventuel et durée non mesurés. |
| S05 | PASS sur B dans le périmètre observé ; NON TESTÉ sur A, retirée du périmètre actif | Snapshots limités aux services sélectionnés ; aucun nouveau test demandé sur A. |
| S06 | NON TESTÉ : un redémarrage manuel observé sur B ; A retirée du périmètre actif | Poursuivre la série de dix sur Qumox seule. |
| S07 | Snapshots disponibles sur A/B ; critère complet NON TESTÉ | Charge, OOM, temps de boot et mesures électriques. |
| S08 et coupures | NON TESTÉ | Banc et scénario à préparer séparément. |
| A01–A06 | BLOQUÉ | Release applicative et runtime sans LAN non qualifiés. |

Au prélèvement Qumox : 282222592 octets de RAM disponibles, 37,014 °C et
`get_throttled=0`. L'uptime de 56 secondes n'est pas une durée de boot. L’opérateur
a répondu « c'est fait » aux étapes de boot, arrêt, débranchement et retour
de la carte ; aucun constat indépendant de l'arrêt n'est déduit du rapport
écrit avant poweroff. Le second démarrage manuel de la même installation
Qumox, sans reflash, a ensuite été observé comme décrit ci-dessous.

## Persistance Qumox après second boot — 30 septembre

Deux rapports sont retrouvés sur la carte ; le premier est identique à la
copie conservée. La comparaison `same-card` passe, code 0 : boots distincts,
machine-id et hostname conservés, cohérence et firstboot réussis. NetworkManager,
Avahi et Bluetooth restent actifs ; les masques diagnostic sont conservés.
Resize et growfs sont désormais inactifs, sans échec rapporté, comme attendu
après l'expansion initiale. Leur état inactif seul n'atteste pas la non-exécution.

La capacité ext4 reste 15080513536 octets, dont 11886645248 disponibles.
Au prélèvement : 295190528 octets de RAM disponibles, 34,862 °C,
`get_throttled=0` et 46 secondes d'uptime. Ces snapshots ne mesurent pas la
durée de boot ni les erreurs transitoires ou la charge. La
[preuve du second boot](validation/2026-09-30-sd-qumox-second-boot.json)
documente S05 sur B pour l'identité, la cohérence, les services sélectionnés
et la capacité conservée ; elle ne qualifie pas toute la campagne.

Précision de métadonnées : `diskutil list` mesure une partition FAT de
536870912 octets ; `diskutil info` donne un volume FAT de 528593408 octets.
La capacité vue depuis Linux est encore une autre mesure. Les preuves des
premiers boots avaient nommé la mesure du volume `boot_partition_bytes` :
le champ est corrigé en `boot_volume_mac_total_bytes`, sans changer sa valeur
ni déduire rétroactivement la taille de partition de A.

La SD de 128 Go (A) est ensuite retirée du périmètre : le contrôle de persistance
prévu sur A n'est pas exécuté et sort des travaux actifs.
La Qumox conserve son installation actuelle. Pour S06, B compte un redémarrage
manuel observé : il en reste neuf pour la série de dix ; le premier boot et
un éventuel reboot interne de resize ne sont pas comptés.

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

La matrice générale ci-dessous conserve les comparaisons de deux installations
requises pour une qualification étendue future. Elle ne demande pas de réutiliser
A : le banc actif est Qumox seule. Toute nouvelle carte sera choisie séparément.
Le prototype système et les premiers essais applicatifs peuvent avancer sur
la carte retenue sans terminer la matrice de distribution.

1. Réserver deux SD de test, étiquetées **A** et **B**, et un banc dédié. Elles
   peuvent être démarrées successivement sur le même Pi de test. Les installations
   hors banc ne servent pas aux essais de coupure.
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

Inky Studio conserve la responsabilité app iOS/backend/BLE, écran,
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
