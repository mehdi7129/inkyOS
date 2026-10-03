# InkyOS — sources matériel et système

Recherche du **27 septembre 2026**. Copie de référence du dossier Inky Studio ;
les liens applicatifs sont figés au commit `ae61df1`. Ce document prépare la future image InkyOS
et le maintien d'une installation classique pour utilisateurs avancés. **Aucune
image InkyOS n'est construite ou qualifiée par ce document.** Les sources externes
ci-dessous sont celles des fabricants ou des mainteneurs officiels ; les constats
du projet sont identifiés séparément. Aucun accès SPI, lecture EEPROM, changement
réseau ou installation n'a été effectué pour cette recherche.

## 1. Ce que le projet a effectivement constaté

| Élément | Preuve disponible dans le dépôt | Portée |
|---|---|---|
| Raspberry Pi Zero 2 W Rev 1.0 | `inky-studio/docs/ios/BLUETOOTH-BENCH.md#matériel-et-accès-vérifiés` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`) | Identification SSH antérieure, pas une nouvelle mesure ici. |
| Debian 13 Trixie, kernel `6.12.75+rpt-rpi-v8`, Python 3.13.5 | Même banc | Ne désigne pas le fichier image d'origine ni son checksum ; ne suffit pas à reproduire l'installation. |
| BlueZ 5.82 et NetworkManager 1.52.1 | Même banc | Versions de la machine qualifiée, pas versions minimales universelles. |
| Écran 800 × 480 | `inky-studio/docs/ios/VALIDATION.md` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`) | La résolution seule ne distingue pas un ancien panneau 7 couleurs d'un Spectra 6. |
| Pilote Python `inky==2.3.0` | `inky-studio/server/pyproject.toml` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`) et `inky-studio/docs/ios/PRODUCT-EVOLUTION-PLAN.md` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`) | Pin volontaire du projet ; les dépendances transitives et le kernel font aussi partie de la qualification. |
| Installation classique | `inky-studio/install.sh` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`), `inky-studio/scripts/install-bluetooth.sh` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`) | L'existant active SPI/I²C, prépare le venv et les services ; ce n'est pas un générateur d'image système. |

Le contrôleur `inky-studio/server/inky_web/inky/display.py` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`) utilise
`inky.auto.auto(ask_user=False)` puis conserve le pilote choisi. Son fallback mock
permet le développement sans matériel ; un écran mock ne prouve jamais que le
cadre physique est correctement détecté.

## 2. Identifier le bon panneau : écart documentaire trouvé

Les tables officielles Pimoroni **v2.3.0** distinguent les variantes suivantes :

| Variante EEPROM upstream | Pilote | Format | Famille |
|---|---|---|---|
| 20 | `inky_ac073tc1a.Inky` | 800 × 480, 7,3 pouces | 7 couleurs |
| 22 | `inky_e673.Inky` | 800 × 480, 7,3 pouces | Spectra 6 |
| 21 | `inky_el133uf1.Inky` | 1600 × 1200, 13,3 pouces | Spectra 6 |

Sources : [sélection du pilote, `auto.py` v2.3.0](https://github.com/pimoroni/inky/blob/v2.3.0/inky/auto.py#L20),
[libellés des variantes, `eeprom.py` v2.3.0](https://github.com/pimoroni/inky/blob/v2.3.0/inky/eeprom.py#L13).

**À corriger dans l'identification du projet :** le fallback de `display.py`
associe actuellement le nom de module AC073TC1A à Spectra 6. Cette association
contredit upstream. Le driver reste choisi par `inky.auto` ; l'erreur concerne
au minimum le libellé et potentiellement le nombre de couleurs annoncé lorsque
l'attribut explicite du pilote est absent. Ne pas utiliser ce libellé comme
preuve physique du modèle installé. Aucun correctif de code n'est inclus ici.

Le [guide officiel Pimoroni](https://learn.pimoroni.com/article/getting-started-with-inky-impression)
explique l'autodétection par EEPROM et la distinction Gallery Palette/Spectra.
Le lecteur upstream utilise I²C bus 1, adresse `0x50`, et retourne les champs de
variante. **Ces champs du cadre réel n'ont pas été lus dans cette recherche.**
Un futur inventaire doit conserver le résultat daté, les références du PCB/panneau
et la classe Python effectivement sélectionnée, sans déclencher de refresh.

La [fiche produit actuelle](https://shop.pimoroni.com/products/inky-impression)
décrit désormais les Spectra 6, avec plusieurs révisions de fabrication ; l'ancien
lien `inky-impression-7-3` redirige vers cette gamme. Elle ne permet donc pas de
déduire la révision d'un ancien cadre à partir de sa seule taille. Le constructeur
mentionne notamment des boutons arrière depuis novembre 2025 et une évolution
du panneau 7,3 pouces depuis avril 2026. Les temps de refresh indiqués pour ces
révisions ne sont pas des mesures du matériel du banc.

## 3. Connexion, GPIO et alimentation

Pour un Pi Zero avec header 40 broches, Pimoroni prévoit l'emboîtement direct sur
le connecteur du HAT ; le montage se fait Pi débranché. Les entretoises/header
de rehausse concernent le montage mécanique, selon la taille du Pi. Ce ne sont
pas des instructions de raccordement d'une dalle nue par fils.
[Guide constructeur, montage](https://learn.pimoroni.com/article/getting-started-with-inky-impression#attaching-inky-impression-to-your-pi).

Brochage **du pilote AC073TC1A v2.3.0**, à ne pas généraliser sans vérification aux
autres panneaux :

| Signal | Numéro GPIO BCM | Broche physique du header 40 broches |
|---|---:|---:|
| MOSI SPI0 | 10 | 19 |
| SCLK SPI0 | 11 | 23 |
| Chip select piloté en GPIO | 8 | 24 |
| Data/command | 22 | 15 |
| Reset | 27 | 13 |
| Busy | 17 | 11 |
| I²C1 SDA / SCL pour le lecteur EEPROM upstream | 2 / 3 | 3 / 5 |

Le pilote ouvre SPI0, demande le contrôle de CS/DC/RESET/BUSY via libgpiod et
désactive le chip select matériel lorsqu'il le peut. Référence :
[constantes et setup AC073TC1A](https://github.com/pimoroni/inky/blob/v2.3.0/inky/inky_ac073tc1a.py#L26).
Conversion BCM/header : [schéma officiel Zero 2 W](https://datasheets.raspberrypi.com/rpizero2/raspberry-pi-zero-2-w-reduced-schematics.pdf).
Les broches HAT ID_SD/ID_SC du schéma ne doivent pas être confondues avec le bus
I²C1 utilisé par ce lecteur Pimoroni.

Les GPIO logiques sont en **3,3 V**. La documentation Raspberry Pi donne une
capacité recommandée d'alimentation de **2 A pour le Zero 2 W** ; ce chiffre
n'est pas une mesure de consommation du cadre assemblé. Pimoroni emploie une
alimentation micro-USB officielle dans son guide Zero 2 W. La référence du bloc
réel, les chutes de tension et le courant pendant un refresh restent à relever.
[GPIO et niveaux](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#gpio),
[besoins d'alimentation](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#typical-power-requirements).

Le Zero 2 W dispose de Wi-Fi **2,4 GHz 802.11n** et Bluetooth **4.2/BLE** ; le
header est à vérifier selon la variante achetée. Cette spécification constructeur
n'est pas une qualification des connexions d'hôtel ou de tous les réseaux.
[Fiche officielle Zero 2 W](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/).

## 4. SPI et pin du pilote : préserver les faits, vérifier la cause

L'installateur du projet ajoute `dtoverlay=spi0-0cs` pour libérer les lignes CS
que le pilote commande lui-même. L'overlay officiel évite effectivement de
réserver les chip selects de SPI0 :
[référence firmware, entrée `spi0-0cs`](https://github.com/raspberrypi/firmware/blob/bead686816848038563a542dc854346ab13253a2/boot/overlays/README).
SPI/I²C se configurent via les interfaces Raspberry Pi ; `config.txt` se trouve
sur les systèmes récents dans `/boot/firmware/`.
[Activation SPI](https://www.raspberrypi.com/documentation/computers/configuration.html#enable-or-disable-spi),
[config.txt et overlays](https://www.raspberrypi.com/documentation/computers/config_txt.html#dtoverlay).

Le commentaire de `server/pyproject.toml` attribue le pin 2.3.0 à une régression
2.4.0 qui réacquerrait les GPIO à chaque `show()`. **Cette explication n'est pas
confirmée par la comparaison upstream effectuée ici** : les fichiers
[`v2.3.0/inky_ac073tc1a.py`](https://raw.githubusercontent.com/pimoroni/inky/v2.3.0/inky/inky_ac073tc1a.py)
et [`v2.4.0/inky_ac073tc1a.py`](https://raw.githubusercontent.com/pimoroni/inky/v2.4.0/inky/inky_ac073tc1a.py)
téléchargés le 27 septembre sont identiques, SHA-256
`ab31898c7c291ce1b63a4c21798860a40e3a9c2a68e57dab933f882d5ecf5582`.
Ils comportent une garde `_gpio_setup` avant l'acquisition des lignes.

Cela n'invalide pas un incident observé avec une autre combinaison de packages,
un artefact distribué différent ou plusieurs processus. Le pin reste inchangé.
Avant toute montée de version : conserver les hashes des artefacts réellement
installés, le traceback, les versions de `gpiod`, `gpiodevice`, `spidev`, le kernel,
les overlays et l'état des processus ; reproduire sur une carte de test. Un
second processus d'affichage peut contredire la propriété exclusive du matériel.

## 5. Base OS, réseau et Bluetooth : références correspondant à l'existant

| Sujet | Source officielle consultée le 27 septembre 2026 | Utilité pour InkyOS |
|---|---|---|
| Raspberry Pi OS | [Documentation OS](https://www.raspberrypi.com/documentation/computers/os.html) | Distinguer éditions, architecture et base Debian ; choisir ultérieurement une image précise avec checksum. |
| Installation sur SD | [Raspberry Pi Imager](https://www.raspberrypi.com/documentation/computers/getting-started.html#install-an-operating-system) | Parcours de flash et personnalisation de l'installation classique ; aucune SD modifiée ici. |
| Gestion Wi-Fi actuelle | [Configuration réseau Raspberry Pi](https://www.raspberrypi.com/documentation/computers/configuration.html#connect-to-a-wireless-network) | Référence `nmcli`/NetworkManager et profils ; ne pas transposer un ancien parcours `wpa_supplicant.conf` sans vérifier l'OS. |
| Transactions réseau | [API NetworkManager 1.52.0](https://networkmanager.dev/docs/api/1.52.0/gdbus-org.freedesktop.NetworkManager.html) | Famille documentaire correspondant à la 1.52.1 constatée : `AddAndActivateConnection2`, profils mémoire, checkpoints, rollback/destroy. |
| Serveur GATT | [BlueZ 5.82 — GattManager](https://github.com/bluez/bluez/blob/5.82/doc/org.bluez.GattManager.rst) et [GattCharacteristic](https://github.com/bluez/bluez/blob/5.82/doc/org.bluez.GattCharacteristic.rst) | Contrats D-Bus du service Bluetooth et des échanges, sans supposer que l'appairage radio remplace l'authentification Inky. |
| Advertising BLE | [BlueZ 5.82 — LEAdvertisingManager](https://github.com/bluez/bluez/blob/5.82/doc/org.bluez.LEAdvertisingManager.rst) et [LEAdvertisement](https://github.com/bluez/bluez/blob/5.82/doc/org.bluez.LEAdvertisement.rst) | Enregistrement et cycle de vie des annonces. |

Les API documentées ne constituent pas une preuve de rollback après coupure
électrique. La qualification applicative, les limites WPA2/2,4 GHz actuelles et
les tests restant à effectuer sont suivis dans
`inky-studio/docs/ios/BLUETOOTH-INTEGRATION.md` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`), pas déduits de cette
liste de références.

## 6. Deux outils officiels à comparer pour la future image

| Outil | Documentation/version consultée | Ce qui est établi |
|---|---|---|
| `rpi-image-gen` | [README au commit bb4dbeed](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/README.adoc), [démarrage](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/getting_started.adoc), [index technique](https://github.com/raspberrypi/rpi-image-gen/blob/bb4dbeed8cc4231a4fcf4ca50be51038550c6fa1/docs/index.adoc) | Outil Raspberry Pi de génération d'images personnalisées. Hôtes natifs documentés : Debian Bookworm/Trixie ARM64. Les environnements QEMU/conteneurs ne sont pas le chemin officiellement pris en charge. |
| `pi-gen` | [README au commit 6a0419c1](https://github.com/RPi-Distro/pi-gen/blob/6a0419c199dbb1f561c3b372d2e2c7d496461d8c/README.md), [branche arm64](https://github.com/RPi-Distro/pi-gen/tree/arm64) | Outil utilisé pour les images Raspberry Pi OS. Le README distingue `master` pour 32 bits et `arm64` pour 64 bits ; configuration et étapes permettent la personnalisation. |

Ces références ne sélectionnent pas un builder, une version OS ou une architecture
pour InkyOS. Le plan produit `inky-studio/docs/ios/PRODUCT-EVOLUTION-PLAN.md` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`) prévoit cette
comparaison avec un build reproductible et une carte de test dédiée. L'installation
classique et la future image doivent conserver la même application et les mêmes
contrats, sans présenter le premier démarrage Bluetooth entièrement hors ligne
comme déjà livré.

Complément du relais InkyOS du 27 septembre : la comparaison ARM64 utilise
[`pi-gen` au SHA `74d08a337bd29da289b9aedbe5b48c79fb2e5a03`](https://github.com/RPi-Distro/pi-gen/tree/74d08a337bd29da289b9aedbe5b48c79fb2e5a03),
résolu depuis `arm64`. Le SHA `6a0419c1…` du tableau est celui de `master`
(32 bits). Le [plan de réalisation](BUILD-PLAN.md) détaille cette piste et
`rpi-image-gen`. Après seconde lecture du projet, il prévoit d'éprouver
d'abord une image officielle Lite datée et personnalisée offline ; pi-gen reste
un recours. Aucune de ces bases n'est construite ou qualifiée ici.

## 7. Informations encore nécessaires avant une matrice de compatibilité

- Identifier physiquement le panneau du cadre et relever sa variante EEPROM ;
  corriger les métadonnées du projet à partir de cette identification.
- Figer image OS, architecture utilisateur, kernel, firmware et tous les packages
  du couple Pi/panneau effectivement testé.
- Mesurer plusieurs refreshs consécutifs, redémarrage, erreur GPIO et alimentation
  sur ce matériel, puis qualifier chaque autre panneau annoncé séparément.
- Construire et tester InkyOS sur SD dédiée ; identité unique au premier boot,
  provisioning, mises à jour et récupération restent du travail futur.

Une résolution identique, la compatibilité du connecteur 40 broches et des tests
en mock ne suffisent pas à déclarer tous les modèles compatibles.
