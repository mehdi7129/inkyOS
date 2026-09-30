# Variante TEST LAN préparée

État du 30 septembre 2026 : préparation expérimentale autorisée et relue avec
Inky Studio, **aucune activation ni nouvelle opération SD/Pi**. Le premier essai
visé utilise un LAN initial configuré par l'opérateur. Ce n'est pas le bootstrap
factory sans LAN de l'issue #15 (`inky-studio/issues/15`).

La cible active est Pi Zero 2 W + SD de 16 Go nominales. La Qumox est le média
d'essai actuel ; l'ancienne carte de 128 Go n'est plus utilisée. La qualification
complète de distribution reste distincte de ce premier prototype applicatif.

l’opérateur a confirmé le pays d'essai **France (`FR`)**. Cette valeur reste une
entrée explicite de la future personnalisation privée ; elle n'est pas ajoutée
à l'image générique. Le panneau est décrit comme « Inky Spectra, format carte
postale » : cette description ne fixe pas encore sa référence ni son driver.

## Entrées et sortie attendue

| Élément | Pin / état |
|---|---|
| Parent | Export `application-prototype` vierge, contrôlé avec son image et tous ses rapports. Jamais l'image diagnostic ni une copie de SD initialisée. |
| Application | Candidat `758a2bf7ed099aad41ef35316e53228e797b0b2b`, backend `0.5.0-rc.2`, correction des métadonnées de panneau. |
| Manifeste | SHA-256 `0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551`. Assets/lock immuables, contrôlés sans install.sh/latest/main. |
| Export | `kind=test-lan-prepared`, `no_active_application=true`, `ready_for_activation=false`, qualification matérielle/release false. |
| iOS Bluetooth | `1.0.0 (5)`, source `80dfc37629fe4d3853ed80bf614c5fad2e8512ba`. Selon la vérification App Store Connect de la session app du 30 septembre : traité, Internal Only, conformité manquante, aucun groupe ; pas distribué. |
| iOS LAN | Build 3 disponible pour les photos ; ne fournit pas le nouveau parcours BLE. |

L'assemblage copie le parent dans une image régulière neuve, ajoute un preflight
readonly et une copie exacte du manifeste, puis masque les mises à jour
firmware/APT. App, helper et SSH restent masqués. Un marqueur root-owned
`/etc/inkyos-test-lan.json` nomme la phase préparée/inactive et les pins.
Les métadonnées du payload parent restent inchangées ; le marqueur et le
manifest d'export distinguent cette variante.

Le candidat exige un **nouveau parent** ; il ne remplace pas les octets du
prototype historique `6a697d134290ced0214fc74b903f4b3c336d70fa` / manifeste
`2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f`.
Les deux couples exacts restent contrôlables ; aucun autre commit/manifeste
n'est accepté par l'intégration statique. La réception des archives a confirmé
40 wheels inchangés et seulement deux fichiers source modifiés : `SOURCE_COMMIT`
et les métadonnées de `display.py`. Elle ne qualifie aucun driver natif ni panneau.
Le builder de la nouvelle variante TEST exige le couple `758a2bf7` / `0d58…` ;
la compatibilité du vérificateur avec l'ancien couple conserve les audits historiques.

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
| Référence PCB/panneau visible | « Inky Spectra, format carte postale » selon l’opérateur ; référence exacte à relever sur le banc. |
| Variante EEPROM / dimensions | À observer par méthode ciblée préparée et relue. |
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

L'accès opérateur et l'activation restent à implémenter ; ces résultats ne
rendent pas cette image prête à flasher ni à tester l'app iPhone.
