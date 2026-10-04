# Image privée pour le premier accès TEST

État du 4 octobre 2026. Cette variante assemble l’enrôlement, l’import privé,
le contrôle du pays, la connexion Wi-Fi et un accès SSH restreint. L’activation
de l’application reste indisponible dans cette tranche. La
[construction et ses vérifications](validation/2026-10-04-test-access-image.json)
passent ; les essais sur le Pi et l’appairage iPhone restent à effectuer.

## Parent et séparation des états

Le parent accepté est le TEST LAN inactif du candidat applicatif
`c31b13afdc957425571810c46230eaaf52fa5d14`, manifest applicatif
`c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1`,
image parent
`0854663168acf7986d26a473e9116dddeb7d6fbef8226f5d1d96cf190f77e286`.
La variante et son profil sont privés. Elle ne réutilise pas une identité
issue d’une autre image ou d’une ancienne SD.

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

Le daemon dédié écoute sur le port **2222**. Seuls les trois verbes du
[runtime opérateur](TEST-ACCESS-RUNTIME.md) sont admis. Shell, transfert de
fichiers, forwarding, TTY, connexion root et authentification par mot de passe
sont désactivés. Les services SSH génériques restent masqués.

SSH est demandé après la connexion vérifiée. Son `ExecCondition` relit le
cache et la connexion, et contrôle un reçu volatil lié au boot courant et au
PID de NetworkManager. Le résultat du boot distingue la demande de démarrage
SSH de la présence réelle du daemon. Un restart NetworkManager arrête et
réévalue cette chaîne.

Le profil v2 est aussi pris en charge par le runner. La CLI SSH n’accepte
aucun nouveau droit de configuration : `activate` reste indisponible et
`stop` refuse un runtime applicatif actif. L’arrêt pendant un refresh et la
gate d’activation TEST doivent être livrés avant le test applicatif complet.

Le [banc SSH v2](validation/2026-10-04-test-access-transport-return.json)
passe 39 contrôles de transport et 25 contrôles du runner. Il utilise le
rootfs applicatif exact et des identités synthétiques sur tmpfs ; aucune
application ni connexion radio n’est lancée.

## Vérification du retour

`verify-test-access-return.py` compare le rapport v2, le profil, l’état,
les programmes installés et les clés publiques avec l’export privé attendu.
Les deux partitions doivent être montées en lecture seule. Le vérificateur
ne lit aucune clé privée et n’exécute aucun programme provenant de la SD.

Après les 35 contrôles natifs, `--context-output` peut créer un nouveau
dossier privé contenant `context.json` et `known_hosts`. Ce dernier lie le
hostname observé à la clé hôte SSH sur le port 2222. Les fichiers sont relus
avant de déclarer la création réussie. Un dossier sur le système de fichiers
de la SD, un fichier existant ou une modification concurrente est refusé.
Les 26 tests de cette étape sont des fixtures ; aucun retour physique v2
n’a encore été accepté.

## Construction

```sh
python3.13 scripts/build-test-access.py build/TEST_LAN_C31 --country FR
python3.13 scripts/verify-test-access.py private/test-access.EXPORT
```

Le builder utilise une nouvelle copie régulière du parent dans la VM dédiée.
Il ne monte aucune SD et ne lance aucun service cible. L’export contient
l’image privée, les entrées figées et les rapports. Le vérificateur compare
les hashes, permissions et différences de fichiers : seuls les ajouts
déclarés et l’append du compte aux quatre bases système sont permis.
La partition boot et les dix fichiers boot/grow protégés doivent rester
identiques. L’existence des pages man est exclue du contrôle systemd offline,
car le rootfs est monté avec `nodev` ; les unités et leurs exécutables sont
bien vérifiés.

Les hashes locaux établissent la cohérence des artefacts, pas leur authenticité
indépendante. Aucun export de cette variante n’est une release publique ou une
qualification de la SD. Le [premier appairage sans LAN](FIRST-BOOT.md) reste un
contrat distinct ; le premier essai prévu utilise un LAN configuré par l’opérateur.
