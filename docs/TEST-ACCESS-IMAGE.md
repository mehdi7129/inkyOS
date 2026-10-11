# Image privée pour le premier accès TEST

État du 11 octobre 2026. La [nouvelle image TEST](validation/2026-10-11-system-prerequisites-access-image.json)
intègre les corrections Bluetooth, I²C et observation de l'heure ; ses 132
contrôles offline passent. Elle a été [flashée et relue](validation/2026-10-11-system-prerequisites-sd-flash.json) ;
le premier démarrage a été lancé et le retour d'enrôlement reste à vérifier.
Le [boot réseau précédent](validation/2026-10-11-radio-readiness-network-observation.json)
confirme Wi-Fi et SSH authentifié sur l'ancienne image, avec préflight bloqué
à 17 contrôles sur 24. Les tentatives plus anciennes décrites ci-dessous
restent des preuves historiques, sans transfert de qualification.

Cette variante assemble l’enrôlement, l’import privé,
le contrôle du pays, la connexion Wi-Fi, un accès SSH restreint et les workers
d’[activation explicite et d’arrêt](TEST-ACCESS-LIFECYCLE.md). La
[variante diagnostique construite et vérifiée](validation/2026-10-10-diagnostic-access-image.json)
a été flashée. Son [retour d’enrôlement](validation/2026-10-10-diagnostic-sd-enrollment-return.json)
passe 35 contrôles ext4/FAT et 10 contrôles d’infrastructure en lecture seule,
sur un dérivé privé décrit ci-dessous. Le contexte SSH privé est exporté après
nettoyage vérifié. Une nouvelle capsule signée est liée à ce contexte,
installée et relue sur la SD, puis la carte éjectée. Le boot réseau suivant a
échoué à l'activation de la connexion ; l’affichage et l’appairage iPhone
restent à effectuer. Le retour d'enrôlement n'atteste pas un arrêt physique.
Le [diagnostic du retour réseau](BOOT-NETWORK-DIAGNOSIS.md) confirme l'import,
mais aucune connexion sur la tentative précédente. Le runtime conserve
maintenant des rapports privés bornés, retrouvés sur le nouvel enrôlement.
La [construction lifecycle](validation/2026-10-04-test-access-lifecycle-image.json),
le [retour complet du 5 octobre](validation/2026-10-05-sd-test-access-return.json) et
la [première construction d’accès seule](validation/2026-10-04-test-access-image.json)
restent des preuves historiques distinctes.

## Parent et séparation des états

Le parent accepté est le TEST LAN inactif du candidat applicatif
`c31b13afdc957425571810c46230eaaf52fa5d14`, manifest applicatif
`c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1`,
image parent
`2b946f688cf1689c38cdceb63ee467aad99541a311693b7443c10c3efb8bad3a`.
Ce parent a été [reconstruit et vérifié le 11 octobre](validation/2026-10-11-rebuilt-test-lan-parent.json)
depuis la même base figée et les mêmes archives applicatives vérifiées.
La recette conserve le commit `851007f` et `worktree_dirty=true`, avec les
octets de ses entrées archivés et hashés. Elle contient le preflight courant,
qui sera hérité à l’identique par l’image d’accès. Cette reconstruction ne
revendique aucune reproductibilité bit à bit ni nouvelle qualification matérielle.
L’[ancien parent reconstruit le 10 octobre](validation/2026-10-10-rebuilt-test-lan-parent.json),
`dcc451dc…`, reste la référence des preuves qui le désignent ; son image
supprimée n’est pas revalidée par cette reconstruction.
Les preuves du 4 et du 5 octobre désignent le parent historique
`0854663168acf7986d26a473e9116dddeb7d6fbef8226f5d1d96cf190f77e286`.
La variante et son profil sont privés. Elle ne réutilise pas une identité
issue d’une autre image ou d’une ancienne SD.

Le [candidat du 11 octobre](validation/2026-10-11-nm-diagnostic-access-image.json)
intègre le diagnostic numérique d'activation NetworkManager, sans modifier
la connexion ni le candidat applicatif. Ses contrôles offline passent. Il a
été flashé et relu ; une éjection initialement refusée par le service
d'indexation macOS a ensuite réussi, sans réécriture. Son
[rapport FAT d'enrôlement](validation/2026-10-11-nm-diagnostic-enrollment-preliminary.json)
est cohérent avec son profil. Son [retour natif](validation/2026-10-11-nm-diagnostic-enrollment-return.json)
passe maintenant ses propres 35 + 10 contrôles ; un nouveau contexte privé est
exporté après nettoyage vérifié. La nouvelle capsule signée est installée et
relue, puis la SD éjectée. L’accès réseau n’est pas encore qualifié. Le relevé
préliminaire reste une preuve historique distincte.

La [correction de disponibilité radio](validation/2026-10-11-radio-readiness-tests.json)
est postérieure à ce candidat issu des sources `07271cf`. Sa suite historique
passe 1 047 tests sur macOS et Linux ARM64. Elle a ensuite été intégrée et
testée dans le [boot réseau observé](validation/2026-10-11-radio-readiness-network-observation.json).

L’ancien enrôlement reste inchangé. Le profil **v2** ajoute le hash du manifest
des programmes d’accès ; l’état durable d’enrôlement conserve son schéma 1.
La consommation de capsule possède son propre état, dans un autre dossier.

| Étape | Action permise | Application |
|---|---|---|
| Image jamais bootée | Aucun réseau ni clé hôte précréée | App/helper masqués |
| Premier boot | Clé hôte créée sur le Pi, observations, rapport v2, demande d’arrêt | App/helper masqués |
| Retour offline | Comparaison du rapport avec ext4 et l’export privé attendu | Aucune activation |
| Boot suivant avec capsule signée | Import, pays observé en direct, connexion puis demande de démarrage SSH | App/helper masqués |
| Reboot après import achevé | Réauthentification du cache, nouvelle garde pays, connexion | App/helper masqués |

Une capsule ou un état incomplet ne déclenche aucune réparation automatique.
Les fichiers sont conservés pour analyse. Un cache entièrement validé est
réutilisable sans relire la capsule FAT ; les données FAT ne sont pas effacées
par le runtime.

## Réseau

Avant **chaque démarrage de NetworkManager**, un `ExecStartPre` attend le
service systemd-rfkill, bloque WLAN, vérifie son état et écrit durablement
`WirelessEnabled=false`. Un échec empêche le daemon de démarrer. Bluetooth
n’est pas modifié par cette garde.

La capsule authentifiée produit un seul profil sous `/run`, root 0600 :
WPA2 personnel, RSN, bande 2,4 GHz, interface `wlan0`, UUID fixe et
`autoconnect=false`. Aucun SSID ni secret n’est passé dans les arguments de
commande. Le SSID est encodé en octets ; une passphrase est dérivée en PSK
hexadécimal avant écriture pour éviter les ambiguïtés du format keyfile.

Le connecteur refuse les autres profils et les PHY supplémentaires. Il appelle
le contrôle France avec Wi-Fi désactivé, relit les gardes immédiatement avant
l’activation, puis vérifie l’unique connexion autorisée. En cas d’échec après
la tentative d’activation radio, il demande Wi-Fi off et relit l’état.

Dans les sources corrigées, l’acquittement radio est suivi d’une attente bornée
de `wlan0` managed, disconnected et sans UUID actif, avant l’unique activation.
Le plafond est de 10 secondes, dans le budget existant de 90 secondes ; 37 secondes
d’activation, 9 de contrôles suivants et 6 de nettoyage sont réservées.
`radio_enable_acknowledged=true` signifie désormais acquittement **et disponibilité** ;
`radio_enable_failed` couvre aussi une disponibilité absente ou invalide.
Le [diagnostic détaillé](BOOT-NETWORK-DIAGNOSIS.md#attente-de-disponibilité-radio) distingue
ces tests logiciels de la qualification Wi-Fi physique.

Le banc exécutant **NetworkManager 1.52.1-1+rpt4** du parent a confirmé que
le daemon crée une connexion loopback par défaut. La variante ajoute donc
`[keyfile] unmanaged-devices=interface-name:lo` : loopback reste actif dans
le kernel, mais ne figure plus dans les connexions de NetworkManager. Le
banc vérifie le format du profil avec libnm et son chargement par le daemon,
dans des namespaces privés dépourvus de radio et de réseau externe.

Références : [format keyfile officiel](https://networkmanager.dev/docs/api/1.52.0/nm-settings-keyfile.html),
[configuration NetworkManager](https://networkmanager.dev/docs/api/1.52.0/NetworkManager.conf.html),
[propriétés des connexions](https://networkmanager.dev/docs/api/1.52.0/nm-settings-nmcli.html).
Ces tests ne prouvent ni une connexion Wi-Fi physique ni une mesure RF.

## Accès opérateur

L’image ajoute le seul compte `inky-test`, UID/GID 1001, mot de passe verrouillé,
sans home ni groupe privilégié. Une collision de nom ou d’identifiant est
refusée. La clé publique autorisée est root-owned ; la clé privée opérateur
reste sur le poste qui construit l’image.

Le daemon dédié écoute sur le port **2222**. Seuls les quatre verbes du
[runtime opérateur](TEST-ACCESS-RUNTIME.md) sont admis. Shell, transfert de
fichiers, forwarding, TTY, connexion root et authentification par mot de passe
sont désactivés. Les services SSH génériques restent masqués.

SSH est demandé après la connexion vérifiée. Son `ExecCondition` relit le
cache et la connexion, et contrôle un reçu volatil lié au boot courant et au
PID de NetworkManager. Le résultat du boot distingue la demande de démarrage
SSH de la présence réelle du daemon. Un restart NetworkManager arrête et
réévalue cette chaîne.

Le profil v2 est pris en charge par le runner. `activate` exige une demande
explicite de refresh et une gate native fraîche ; `stop` démarre un worker
qui attend la sortie de l’app avant d’arrêter le helper. `status` permet de
suivre ces opérations. Aucun chemin ou commande de configuration libre
n’est accepté. Les anciennes images sans les sept payloads lifecycle
gardent le refus d’activation et l’arrêt limité au runtime inactif.

Le [banc SSH v2](validation/2026-10-04-test-access-transport-return.json)
passe 39 contrôles de transport et 25 contrôles du runner. Il utilise le
rootfs applicatif exact et des identités synthétiques sur tmpfs ; aucune
application ni connexion radio n’est lancée.

## Vérification du retour

Le rapport d'installation des paquets est validé dans l'export attendu. Leurs
fichiers ne sont pas relus sur le retour SD : ce contrôle reste une comparaison
ciblée de l'enrôlement. Le préflight sur le Pi vérifie séparément leur présence
requise ; aucun de ces contrôles n'atteste l'intégrité de tout le rootfs.

`verify-test-access-return.py` compare le rapport v2, le profil, l’état,
les programmes installés et les clés publiques avec l’export privé attendu.
Les deux partitions doivent être montées en lecture seule. Le vérificateur
ne lit aucune clé privée et n’exécute aucun programme provenant de la SD.

Après les 35 contrôles natifs, `--context-output` peut créer un nouveau
dossier privé contenant `context.json` et `known_hosts`. Ce dernier lie le
hostname observé à la clé hôte SSH sur le port 2222. Les fichiers sont relus
avant de déclarer la création réussie. Un dossier sur le système de fichiers
de la SD, un fichier existant ou une modification concurrente est refusé.
Les 26 tests de cette étape sont des fixtures. La comparaison native complète
ext4/FAT du 5 octobre passe les 35 contrôles ; le contexte n’est exporté qu’après
le nettoyage vérifié par le wrapper puis contrôlé indépendamment.

Le [retour diagnostique du 10 octobre](validation/2026-10-10-diagnostic-sd-enrollment-return.json)
passe également les 35 contrôles et les 10 contrôles du wrapper. L’acquisition
intégrale a été relue et rehachée localement, puis conservée. Pour limiter
l’espace de travail, l’analyse Linux utilise un dérivé `e2image -ra` : fichiers
et métadonnées utiles du rootfs, préfixe MBR/FAT et octets après le filesystem
préservés. Des blocs inutilisés et certaines métadonnées inutilisées sont omis :
ce dérivé n’est pas un clone intégral de la SD. Son hash de flux et sa relecture
dans la VM concordent ; cette vérification ne relit pas indépendamment la SD.

Sur ce retour historique, deux rapports diagnostiques privés sont présents avec les permissions attendues.
Celui de la garde WLAN est complet et ses 10 contrôles passent. Celui du boot
reste au marqueur initial incomplet `bind`, sans erreur enregistrée. Il ne
localise donc aucune panne et ne contredit pas l’enrôlement vérifié ; un arrêt
pendant le premier boot peut interrompre l’écriture finale du diagnostic.

Le [nouveau retour du 11 octobre](validation/2026-10-11-nm-diagnostic-enrollment-return.json)
utilise une acquisition différente : la SD est ouverte en lecture seule et le
dérivé `e2image` est transmis directement à la VM. Aucune copie intégrale de
la SD n’est créée pour ce retour. L’indicateur ext4 propre est contrôlé, sans
rejeu du journal. Le hash du flux émis correspond au flux reçu et à sa relecture
dans la VM. Le wrapper inchangé vérifie ensuite ce dérivé et l’export attendu :
35 contrôles d’enrôlement et 10 contrôles d’infrastructure passent. Les deux
nouveaux fichiers de contexte sont exportés après nettoyage vérifié, avec une
relecture indépendante de leurs liens et permissions. Cela ne constitue ni
une seconde lecture indépendante de la SD, ni une attestation d’arrêt physique.

Le wrapper `check-test-access-return-linux.sh` vérifie une **copie privée**
dans la VM de build ARM64 marquée. Son `--help` décrit le staging fermé :
44 entrées scellées, dont les 21 sources locales, l’export attendu et la copie
retournée. Les tailles et SHA-256 des deux images sont imposés en arguments.
Il utilise un loop en lecture seule, ext4 avec `ro,noload` et FAT avec `ro`,
sans exécuter de code provenant de la SD. Le contexte n’est exporté qu’après
PASS, relecture, démontage et détachement du loop vérifiés ; chaque tentative
utilise un nouveau staging. Ses 13 fixtures ne constituent pas un retour SD réel.

Le client `test-operator-client.py` utilise exclusivement ce dossier privé et
la clé opérateur correspondante. Il impose la vérification de clé hôte, sans
trust-on-first-use, agent SSH, proxy, forwarding ou connexion par mot de passe.
Le client ne lit pas lui-même la clé privée ; OpenSSH l’utilise localement.
Un timeout reste un résultat non confirmé, jamais l’annulation du worker.

```sh
python3.13 scripts/test-operator-client.py \
  --context-directory private/VERIFIED_CONTEXT \
  --identity private/ACCESS_EXPORT/client_ed25519 status
```

Les autres verbes sont `preflight`, `stop` et `activate`. Ce dernier exige
`--confirm-test-refresh`. Le client fournit alors l’heure du Mac comme
référence indépendante ; il ne modifie pas l’horloge du Pi.

## Construction

```sh
python3.13 scripts/build-test-access.py build/TEST_LAN_C31 --country FR
python3.13 scripts/verify-test-access.py private/test-access.EXPORT
```

Le builder utilise une nouvelle copie régulière du parent dans la VM dédiée.
Il ne monte aucune SD et ne lance aucun service cible. L’export contient
l’image privée, les entrées figées et les rapports. Le vérificateur compare
les hashes, permissions et différences de fichiers. Les ajouts déclarés,
l’append du compte aux quatre bases système et le delta I²C vérifié sont les
seuls changements autorisés. Pour la prochaine construction, le parent TEST
LAN doit déjà contenir le préflight courant : ses octets et métadonnées sont
hérités à l’identique. Un ancien préflight est refusé, sans remplacement.
Le préflight historique reste conservé comme fixture de refus ; ses anciens
rapports ne sont pas réinterprétés. Le nouveau parent est vérifié et épinglé ;
la construction de l’image d’accès dérivée reste une étape distincte.
La partition boot et les dix fichiers boot/grow protégés doivent rester
identiques. L’existence des pages man est exclue du contrôle systemd offline,
car le rootfs est monté avec `nodev` ; les unités et leurs exécutables sont
bien vérifiés.

Le delta I²C contient uniquement `libi2c0` et `i2c-tools` ARM64 `4.4-2`,
décrits dans [le lock de paquets TEST](../config/test-access-packages.lock.json).
Le builder vérifie leurs archives avant le transfert et les installe sans réseau,
sans résolution APT ni mise à niveau des dépendances. Les appels udev du
post-install sont neutralisés pendant la transaction. Le rapport
`test-access-packages.json` lie les payloads et les changements de métadonnées
de paquets à l'inventaire final. L'installation offline n'effectue aucun accès
au bus I²C ni au panneau.

Les hashes locaux établissent la cohérence des artefacts, pas leur authenticité
indépendante. Aucun export de cette variante n’est une release publique ou une
qualification de la SD. Le [premier appairage sans LAN](FIRST-BOOT.md) reste un
contrat distinct ; le premier essai prévu utilise un LAN configuré par l’opérateur.

La [validation finale des outils](validation/2026-10-04-test-access-lifecycle-image.json)
compte 997 tests sur chacun des hôtes macOS et Linux ARM64 (4 et 1 skips
respectivement), sans échec. Elle inclut le client SSH local et le wrapper
de retour ; elle ne prouve aucun boot ou échange réseau physique.
