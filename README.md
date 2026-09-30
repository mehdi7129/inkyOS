# InkyOS

Image Raspberry Pi dédiée aux cadres photo **Inky Studio**.

**État : prototypes expérimentaux, 28 septembre 2026.** Une image officielle
Lite ARM64 figée est personnalisée offline dans une VM dédiée. Premier boot
système, compte applicatif verrouillé, services et prérequis matériels sont
préparés et contrôlés. Le prototype système reste sans app ; une cible opt-in
intègre un candidat Inky Studio épinglé avec ses services masqués.
**Le parcours sans LAN reste en développement ; aucune qualification SD.**

```sh
make test
make test-linux
make inspect
make prototype
make vm-stop
```

Voir [le guide de développement et les résultats](docs/DEVELOPMENT.md) pour les
prérequis, rapports, limites et prochaines adaptations.

## Deux façons d'installer son cadre

| Parcours | Usage prévu |
|---|---|
| Installation avancée | Installer Raspberry Pi OS, puis l'application depuis Inky Studio (`inky-studio`). |
| InkyOS | Flasher une image SD incluant l'application et ses dépendances ; configurer le cadre depuis l'iPhone au premier démarrage. Ce parcours reste à développer. |

La même application, le même protocole et les mêmes mises à jour applicatives
devront servir les deux parcours. InkyOS ne doit pas devenir un fork d'Inky Studio.

## Documents de départ

- [Transmission à la session InkyOS](docs/HANDOFF.md) : état réel, contrats, étapes et critères de validation.
- [Matériel et sources officielles](docs/HARDWARE-SOURCES.md) : Pimoroni, Raspberry Pi, NetworkManager, BlueZ et builders.
- [Réception du relais](docs/RECEPTION.md) : périmètre pris en charge et points ouverts.
- [Plan de réalisation de l'image](docs/BUILD-PLAN.md) : comparaison des builders, recette proposée et qualification.
- [Développement sans SD](docs/DEVELOPMENT.md) : outils exécutables, environnement isolé et observations vérifiées.
- [Delta système vérifié](docs/BASE-CUSTOMIZATION.md) : premier boot et croissance SD de la base exacte.
- [Payload applicatif commun](docs/APPLICATION-PAYLOAD.md) : proposition relue avec Inky Studio, assets encore attendus.
- [Compatibilité Python ARM64](docs/PYTHON-COMPATIBILITY.md) : audit initial des dépendances et limites de résolution depuis PyPI.
- [Compilation des wheels natives](docs/NATIVE-WHEELS.md) : essai ARM64 réussi et artefacts expérimentaux transmis à Inky Studio.
- [Contrôle des archives](docs/ARCHIVE-CONTRACT.md) : contrat commun et inspection inerte avant extraction.
- [Qualification logicielle offline](docs/OFFLINE-QUALIFICATION.md) : candidat applicatif installé et testé dans une VM isolée, hors image.
- [Intégration applicative dans l'image](docs/APPLICATION-IMAGE.md) : installation offline et fichiers système du candidat, startup masqué.
- [Premier démarrage sans LAN](docs/FIRST-BOOT.md) : contrat partagé, heure, pays Wi-Fi et limites restant à résoudre.
- [Banc privilégié Linux](docs/BOOTSTRAP-PROBE.md) : UID kernel, reçu root et perte de réponse ; heure/radio simulées.
- [Gate Wi-Fi au boot](docs/WIFI-BOOT-GATE.md) : préparation durable de l'état NM sur fixtures, intégration encore inactive.
- [Qualification SD](docs/SD-QUALIFICATION.md) : procédure future et fiche de preuves, sans essai matériel effectué.
- [Diagnostic SD sans LAN](docs/SD-DIAGNOSTIC.md) : variante de test avec rapport automatique sur FAT et arrêt propre.
- [Reproductibilité mesurée](docs/REPRODUCIBILITY.md) : différences des images, causes identifiées et limite de la garantie.

## Avant l'image complète

Terminer la qualification Bluetooth iPhone/Raspberry dans le projet Inky Studio,
figer une release compatible et identifier exactement le panneau. Le premier
propriétaire n'est actuellement adopté qu'après connexion réseau authentifiée :
le premier démarrage entièrement hors ligne est une nouvelle fonctionnalité,
pas une simple option du générateur d'image.

Aucun mot de passe, clé privée, identité de cadre, profil Wi-Fi ou image issue de
la carte SD personnelle de développement ne doit entrer dans les sources ou
les artefacts distribués. Construire une image vierge, puis créer chaque identité
au premier démarrage.

Dépôt public depuis le 28 septembre 2026, à la demande de l’opérateur. Les images
restent expérimentales : aucune release d'image qualifiée n'est publiée.
La publication d'une image nécessite encore sa qualification et la vérification
des licences de redistribution.
