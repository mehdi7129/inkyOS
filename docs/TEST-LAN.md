# Variante TEST LAN préparée

État du 3 octobre 2026 : préparation expérimentale autorisée et relue avec
Inky Studio, **aucune activation ni nouvelle opération SD/Pi**. Le premier essai
visé utilise un LAN initial configuré par l'opérateur. Ce n'est pas le bootstrap
factory sans LAN suivi par l’issue #15 d’Inky Studio.

La cible active est Pi Zero 2 W + SD de 16 Go nominales. La Qumox est le média
d'essai actuel ; l'ancienne carte de 128 Go n'est plus utilisée. La qualification
complète de distribution reste distincte de ce premier prototype applicatif.

L’opérateur a confirmé le pays d'essai **France (`FR`)**. Cette valeur reste une
entrée explicite de la future personnalisation privée ; elle n'est pas ajoutée
à l'image générique. L'inventaire corrigé du panneau indique un PCB 7,3″,
800×480, cohérent avec l'ancienne famille sept couleurs. Son tuple EEPROM
800×480 / variante 20 / couleur 4 demande un profil TEST contrôlé ; le driver
physique reste à qualifier. Voir le [suivi du panneau](DISPLAY-COMPATIBILITY.md).

## Entrées et sortie attendue

| Élément | Pin / état |
|---|---|
| Parent | Export `application-prototype` vierge, contrôlé avec son image et tous ses rapports. Jamais l'image diagnostic ni une copie de SD initialisée. |
| Application | Candidat `c31b13afdc957425571810c46230eaaf52fa5d14`, backend `0.5.0-rc.2`, gestion de l'écran et drain SPI à l'arrêt. |
| Manifeste | SHA-256 `c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1`. Assets/lock immuables, contrôlés sans install.sh/latest/main. |
| Export | `kind=test-lan-prepared`, `no_active_application=true`, `ready_for_activation=false`, qualification matérielle/release false. |
| iOS Bluetooth | Un build compatible et effectivement distribuable doit être confirmé par Inky Studio avant le banc Bluetooth ; les anciens numéros de build ne prouvent pas cette disponibilité. |
| iOS LAN | Le parcours photo LAN reste à tester depuis cette image avec un build iOS disponible et compatible. |

L'assemblage copie le parent dans une image régulière neuve, ajoute un preflight
readonly et une copie exacte du manifeste, puis masque les mises à jour
firmware/APT. App, helper et SSH restent masqués. Un marqueur root-owned
`/etc/inkyos-test-lan.json` nomme la phase préparée/inactive et les pins.
Les métadonnées du payload parent restent inchangées ; le marqueur et le
manifest d'export distinguent cette variante.

Le candidat utilise un **nouveau parent applicatif**, distinct des prototypes
historiques. Les trois [couples exacts revus](APPLICATION-IMAGE.md) restent
vérifiables ; les builders TEST acceptent uniquement `758a2bf7` / `0d58…`
ou `c31b13af` / `c418…`. Un couple croisé ou inconnu est refusé. La sélection
de la politique statique suit le manifeste validé ; seule l'unité applicative
diffère dans la table de fichiers parent. Le preflight ajoute le nouveau
couple sans assouplir les contrôles d'activation. Aucun driver physique ni
panneau n'est qualifié par cette compatibilité logicielle.

Aucun timer diagnostic, auto-arrêt, hook d'activation ou overlay `disable-wifi`
n'est ajouté. L'état NetworkManager reste `WirelessEnabled=false` ; aucun pays,
profil réseau, identité, credential, clé TLS ou photo n'est préchargé. Les dix
fichiers boot/grow protégés restent identiques. Le build ne lance ni backend,
helper, migration, génération TLS ou driver écran.

```sh
make test-lan-prepared PYTHON=python3.13 PARENT_EXPORT=build/PARENT
python3.13 scripts/verify-test-lan.py build/EXPORT --output build/EXPORT.integrity.json
```

Ces commandes construisent/contrôlent des artefacts locaux. Elles ne flashent
pas une SD et ne rendent pas l'app accessible. Les rapports lient l'image,
la recette, les sources archivées, les inventaires parent/dérivé, les gates
statiques et fsck. Les hashes locaux ne sont pas des attestations indépendantes.

## Preflight et inventaire avant activation

Le programme installé est `/usr/local/lib/inkyos/test-lan-preflight.py`, root
0555. Sans demande live explicite, il ne sonde rien. Les commandes live seront
réservées au banc autorisé, avec accès opérateur authentifié préparé séparément.
Il ne règle ni l'heure ni le pays, ne connecte pas un réseau, n'importe pas
l'app, ne lit pas les clés/passwords et ne modifie aucun service. Sa sortie
fermée n'expose pas SSID/IP/MAC, identité de cadre ou journaux bruts.
Le champ `activation_authorized` reste `false`, même si les contrôles de fixtures passent.

Interface prévue sur le banc, après préparation de son accès (l'inventaire doit
être un fichier root-owned contrôlé ; la référence UTC doit être prise sur une
source indépendante au moment du contrôle) :

```sh
/usr/local/lib/inkyos/test-lan-preflight.py --live \
  --operator-access-confirmed --country FR --country-confirmed \
  --utc-reference SECONDS --utc-reference-age 0 \
  --utc-reference-source independent-device --panel-inventory /etc/inkyos-panel.json
```

La présence de `timedated` n'est pas provoquée par ce contrôle : une lecture
D-Bus sans auto-start ne trouvant pas le daemon laisse l'heure `BLOCKED`.
L'absence de preuve ne signifie pas que l'horloge est fausse. Le runtime panneau
reste également `BLOCKED` dans cette première livraison du preflight.

| Contrôle | Preuve / limite |
|---|---|
| Accès opérateur | Canal local/authentifié et secours explicitement préparés et vérifiés. Ils ne sont pas fournis par cette image ; `inky` reste verrouillé/nologin et SSH masqué. Aucun login root ouvert automatiquement. |
| Identité et pin | Firstboot système réussi, manifeste réel rehashé, source et marqueur attendus. |
| Données | Répertoires vierges avant première activation. Tout état existant/incomplet conduit à une reprise explicite, jamais à une suppression automatique. |
| Réseau/pays | `wlan0` géré par NetworkManager, LAN établi et pays réel confirmé/appliqué avant scan/connexion. `iw` exit 0 ou domaine global seul ne suffisent pas ; un domaine phy custom non interprété reste bloqué, sans conclure que le pays est faux. |
| Heure | Synchronisation effective et comparaison avec une référence indépendante récente avant toute création TLS. Le timestamp du build et le seuil 2026-01-01 ne prouvent pas l'UTC correcte. |
| Bluetooth | BlueZ/D-Bus/paquets/permissions et `hci0` présent, powered, unblocked. L'enregistrement GATT/advertisement attend le lancement applicatif. |
| Panneau | Référence physique, EEPROM, dimensions et classe driver concordantes ; SPI/I²C et permissions vérifiés. Une simple assertion d'inventaire ne vaut pas observation matérielle. |

Inventaire panneau à compléter avant activation, sans lancer le backend pour
identifier le matériel :

| Champ | État actuel |
|---|---|
| Pi / kernel | Zero 2 W, kernel `6.18.50+rpt-rpi-v8` observés lors du diagnostic. |
| Référence PCB/panneau visible | PCB 7,3″, 800×480, 170×111 mm ; ancienne famille sept couleurs corroborée. Référence exacte de dalle non confirmée. |
| Variante EEPROM / dimensions | Tuple observé : variante 20, 800×480, couleur 4 non reconnue ; aucune réécriture ni normalisation. |
| Mapping officiel v2.3.0 | 20 = AC073TC1A, 800×480, 7 couleurs ; 22 = E673, 800×480, Spectra 6 ; 21 = EL133UF1, 1600×1200, Spectra 6 ; 25 = E640, 600×400, Spectra 6. |
| Classe driver / non-mock | À contrôler après activation autorisée, contre l'inventaire réel. |
| Alimentation / câble / accès secours | À consigner et vérifier. |

La méthode vendor [eeprom.py v2.3.0](https://github.com/pimoroni/inky/blob/v2.3.0/inky/eeprom.py)
positionne puis lit 29 octets sur bus I²C 1/adresse 0x50 ; aucun scan générique,
SPI ou refresh n'est nécessaire. Aucun chemin EEPROM sysfs universel n'est
supposé. Le [mapping officiel](https://github.com/pimoroni/inky/blob/v2.3.0/inky/auto.py)
ne qualifie pas à lui seul le panneau présent. Le candidat corrige le libellé
AC073TC1A/Spectra 6 du parent historique ; aucun patch app ou nouveau protocole
n'est introduit dans l'OS. Le preflight prépare un catalogue fermé des
inventaires 20/AC073TC1A, 22/E673, 21/EL133UF1 et 25/E640, et garde l'observation
runtime du panneau bloquée. Une variante différente demande la réception de
son mapping officiel. Aucun de ces modèles n'est attribué au panneau présent
à partir de sa taille décrite.

`scripts/observe-test-panel.py` est livré dans les sources, inactif par défaut,
hors image préparée et hors preflight. Son `passed=true` signifie uniquement
qu'un tuple EEPROM du catalogue est reconnu ; il n'autorise aucun affichage.
`scripts/observe-test-radio.py` est également hors image : GET firmware ciblé,
observations Linux séparées et tuple firmware toujours non qualifié. Ses
fixtures ne sont pas des lectures du Pi. Le gate panneau du preflight et
l'autorisation d'activation restent bloqués.

## Ordre proposé et reprise, soumis à relecture

1. Relire les pins, l'image préparée, le preflight, le canal opérateur et le
   panneau réel. Aucun flash de la Qumox actuelle n'est effectué par la préparation.
2. Préparer le canal opérateur et son secours ; configurer localement réseau,
   pays effectif et UTC. Garder les secrets hors de l'artefact générique et des
   preuves publiques. Conserver Bluetooth indépendant du Wi-Fi.
3. Observer le panneau et exécuter le preflight. Un contrôle bloqué arrête cette
   séquence ; aucun démasquage de compensation. Le consentement TEST avancé
   durable, son binding et l'accès opérateur restent à implémenter/revoir avant
   activation ; ils ne constituent pas l'autorité factory de #15.
4. Après accord sur l'activation, démarrer le helper seul et vérifier socket
   vivant 0660, `health.ready=true` et `protocol=1`. Son démarrage peut reprendre
   un rollback antérieur ; ne pas le lancer pour une inspection innocente.
5. Démarrer l'app seulement après ces contrôles. TLS est créé avant le lifespan,
   puis DB/credentials/driver sont initialisés et le welcome-refresh est programmé
   en tâche asynchrone : l'autorisation porte aussi sur ce premier affichage et
   ses écritures. Une API joignable ne prouve pas sa fin ; observer séparément
   la completion et l'affichage effectif avant la réception photo.
6. Contrôler HTTPS/auth, capabilities, GATT/advertisement et `/api/display`
   non-mock face au panneau observé. Un health HTTP seul n'est pas une réception
   applicative. Mesurer stockage et ressources du Zero 2 W.
7. Tester les photos LAN avec build 3 si la réception passe. Tester claim QR/BLE
   seulement lorsque build 5 est réellement disponible sur l'iPhone physique.
   Aucun changement Wi-Fi sans accès de secours indépendant vérifié.

Après interruption ou démarrage partiel, arrêter la progression et préserver
`/var/lib/inky-studio`, son provisioning et l'état helper. Ne pas effacer DB,
credentials, clé TLS, ownership ou journal pour obtenir un nouvel appareil neuf.
Le prochain démarrage exige une revue de l'état existant ; une réactivation
automatique au reboot n'est pas livrée. Après claim, garder un accès au password
app : l'owner BLE ne remplace pas le login photo.

Cette recette et ces contrôles seront transmis à Inky Studio avant activation.
Ils ne livrent pas encore une image prête pour l'installation iPhone sans LAN.
L'[accès opérateur privé proposé](TEST-OPERATOR.md) précise l'enrôlement,
SSH/PAM et les preuves encore nécessaires avant le premier essai LAN.

## Résultat exécuté le 30 septembre

Parent neuf `build/prototype.GKiGyY0d` et dérivé
`build/test-lan-prepared.wIV9Vjtj`, recettes propres à `2f168ec8` : installation
offline du candidat `758a2bf7`, 62 contrôles système, 26 applicatifs,
17 de préparation, systemd, visudo et fsck réussis. Les dix fichiers boot/grow
restent identiques. Les deux images mesurent 3061841920 octets.
Inky Studio a rehashé intégralement images/assets/rapports et relu le commit
figé sans défaut confirmé dans la portée préparée/inactive.

Après corrections séparées du banc, **443 tests** passent sur Mac/Linux ARM64
(4/1 skips) et **39 contrôles SSH/PAM/sudo** passent sur copie jetable avec
runner inerte. Les cinq tentatives du banc, dont quatre échouées, restent
conservées ; leur cleanup a réussi. La [preuve réduite](validation/2026-09-30-test-lan-prepared.json)
lie images, recettes, rapports, source du banc et fichiers des suites exécutées.
Les modifications du banc n'altèrent pas les deux exports construits.

Ce résultat historique ne livre pas l'accès opérateur ni l'activation.
Le runtime opérateur est désormais développé et testé séparément ; son
installation, la connexion physique et l'activation restent à intégrer.
Cette image ne suffit pas encore pour tester l'app iPhone.

## Nouveau parent vérifié le 3 octobre

Le candidat `c31b13af` est installé dans un parent neuf, puis dérivé en
TEST LAN préparé et inactif. Les deux images mesurent 3 061 841 920 octets :

| Image | SHA-256 |
|---|---|
| Parent applicatif | `8b951d84bf6925e531d643bd3c785283f37bb847372ab9265356cbf3b12a7727` |
| TEST LAN préparé | `0854663168acf7986d26a473e9116dddeb7d6fbef8226f5d1d96cf190f77e286` |

Chaque image passe 62 contrôles système et 26 applicatifs. La variante passe
aussi ses 17 contrôles de préparation ; les dix fichiers boot/grow protégés
restent identiques. Le nouveau preflight est installé root-owned 0555 ;
l'unité applicative dérivée mesure 799 octets, hash `c9d7e4c1…`.
App, helper et SSH restent masqués, Wi-Fi désactivé. Aucun accès opérateur,
identité ou profil TEST écran n'est ajouté à ces parents.

Les [preuves réduites](validation/2026-10-03-display-drain-images.json)
consignent les exports, recettes, **709 tests par hôte** macOS/Linux ARM64
(4/1 ignorés) et **61 contrôles SSH/PAM/runtime/signature**. Ce dernier banc
utilise une copie du parent historique `758a2bf7`, avec données synthétiques ;
il ne prouve pas le démarrage du nouveau parent. L'ancien export TEST LAN
reste vérifiable par le vérificateur actuel. Aucun flash ni essai Pi n'a eu lieu.
