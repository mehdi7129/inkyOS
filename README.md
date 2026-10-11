# InkyOS

Une image Raspberry Pi dédiée aux cadres photo à écran e-paper **Inky Studio**.
InkyOS prépare le système et son premier démarrage ; Inky Studio fournit le
backend, le Bluetooth et l’application iOS.

Le parcours visé est simple : **allumer le cadre, scanner le QR, confirmer le
pays, choisir le Wi-Fi et envoyer une photo**.

> **Prototype expérimental — état au 11 octobre 2026.**
> Aucune image prête à l’emploi n’est publiée. Le premier appairage iPhone et
> le parcours complet sans LAN préalable restent à intégrer et à qualifier.

## État vérifié

| Composant | État |
|---|---|
| Base | Raspberry Pi OS Lite ARM64 figé, assemblé offline dans une VM Linux dédiée. |
| Pi de test | Boots physiques sur Pi Zero 2 W, identité persistante et agrandissement de partition observés. |
| Réseau | Wi-Fi connecté et échanges SSH authentifiés observés. La stabilité dans la durée reste à qualifier. |
| Nouvelle image TEST | Corrections Bluetooth, observation de l’horloge et paquets I²C intégrés ; **132 contrôles offline réussis**. SD flashée et relue, premier démarrage lancé ; retour d’enrôlement à vérifier. |
| Application | Backend épinglé, services masqués dans l’image. Welcome, photo, QR/BLE et arrêt actif restent à tester ensemble. |
| Initialisation sans LAN | Service IPC local développé et banc Linux réussi ; il n’est pas installé dans l’image TEST. Le raccord backend/iOS est en cours. |
| Écran | PCB 7,3″ dont les marquages corroborent l’ancienne famille sept couleurs ; driver physique et affichage non qualifiés. |

Le dernier banc global consigné passe **[1 273 tests sur macOS et Linux ARM64](docs/validation/2026-10-11-factory-exporter-workspace-tests.json)**,
sans échec (8 skips macOS, 2 skips Linux). Le [banc IPC natif](docs/INITIALIZATION-IPC.md)
vérifie séparément les droits des processus, la consommation unique de
l’autorisation et la reprise après redémarrage.
La readiness du service et le [vrai client Studio passent les deux bancs Linux](docs/validation/2026-10-11-ipc-notify-readiness-native.json) :
10 contrôles chacun, complétés par 57 tests ciblés sans échec.
Le [publisher de credentials factory](docs/FACTORY-CREDENTIALS.md) passe
27 tests ciblés Linux, dont la chute effective de privilèges. Le hook compose
désormais permission, publication puis autorité. Le vrai sérialiseur Studio
passe aussi un [banc Linux isolé](docs/validation/2026-10-11-factory-studio-serializer-native.json),
et le [superviseur passe dix cas](docs/FACTORY-SERVICE-FIXTURE.md).
Le [runtime exporter dédié](docs/FACTORY-EXPORTER-PROPOSAL.md) est installé sur
une copie d’image et [vérifié en Linux ARM64](docs/validation/2026-10-11-factory-exporter-native-install.json) :
325 fichiers de payload et 390 entrées contrôlées.
Le [test de composition installé](docs/FACTORY-INSTALLED-FIXTURE.md) passe
52 fixtures inertes et un [banc Linux réel](docs/validation/2026-10-11-factory-installed-composition-native.json) :
création, reprise sans régénération et deux refus attendus, avec validation des
credentials par Studio sous UID 1000. L’intégration au premier boot et les
essais matériels restent à qualifier. Le [lot de recette factory](docs/FACTORY-IMAGE-INTEGRATION.md)
recense les raccords OS/Studio encore nécessaires avant une image utilisable.

Le [dernier boot réseau observé](docs/validation/2026-10-11-radio-readiness-network-observation.json)
reste associé à l’ancienne image de test : son préflight est bloqué à 17 contrôles
sur 24. La [nouvelle image](docs/validation/2026-10-11-system-prerequisites-access-image.json)
contient les corrections des prérequis Bluetooth, I²C et heure. Sa construction
réussie ne prouve pas encore leur fonctionnement sur le Pi.
La [relecture du flash SD](docs/validation/2026-10-11-system-prerequisites-sd-flash.json)
est vérifiée ; le nouveau boot reste à qualifier.

Le prochain essai accompagné conserve le couple **backend `c31b13a` / iOS
`1.0.0 (9)`**, décrit dans [l’alignement OS/app](docs/OS-APP-ALIGNMENT.md).
Les développements en cours ne remplacent pas implicitement ce payload.
L’accès opérateur signé de l’image TEST sert à qualifier le matériel ; il ne
constitue pas le premier démarrage destiné à l’utilisateur final.

## Matériel visé

La cible actuelle est le **Raspberry Pi Zero 2 W** avec une **microSD de 16 Go**.
La recette vise les écrans **Spectra 6 4″, 7,3″ et 13,3″**, ainsi que les anciens
**Impression sept couleurs 5,7″ et 7,3″**. Chaque modèle d’écran et référence de
carte doit être qualifié séparément sur le matériel réel.

Voir la [matrice de compatibilité](docs/DISPLAY-COMPATIBILITY.md).

## Développer

Le chemin de build testé utilise macOS Apple Silicon, Python 3.11+, Git et
Lima 2.0+. Les tests locaux utilisent la bibliothèque standard Python ;
la VM de build utilise Linux ARM64 et Python 3.13.

```sh
make test          # tests locaux
make test-linux    # mêmes fixtures dans la VM ARM64 dédiée
make inspect       # inspection de la base figée
make prototype     # prototype système sans application
make vm-stop
```

Les images et rapports restent sous `build/`. Ces commandes ne flashent aucune
SD. L’intégration d’Inky Studio exige un payload applicatif vérifié et épinglé.
Voir le [guide de développement](docs/DEVELOPMENT.md) pour les prérequis,
l’espace disque et les limites du builder.

## Documentation

- [Plan commun de finalisation et critères de réussite](docs/COMPLETION-PLAN.md)
- [Architecture et recette](docs/BUILD-PLAN.md)
- [Matériel et sources officielles](docs/HARDWARE-SOURCES.md)
- [Intégration applicative](docs/APPLICATION-IMAGE.md)
- [Premier démarrage, heure et pays Wi-Fi](docs/FIRST-BOOT.md)
- [Service d’initialisation IPC en staging](docs/INITIALIZATION-IPC.md)
- [Image TEST et accès opérateur](docs/TEST-ACCESS-IMAGE.md)
- [Qualification sur SD](docs/SD-QUALIFICATION.md)
- [Diagnostic du boot et du réseau](docs/BOOT-NETWORK-DIAGNOSIS.md)
- [Reproductibilité et limites](docs/REPRODUCIBILITY.md)
- [Rapports de validation](docs/validation/)

## Avant une release

Il reste à qualifier les parcours réels : adoption, photo, affichage,
changement de Wi-Fi, redémarrage, arrêt et récupération. Le parcours sans LAN
nécessite encore son intégration complète. La release applicative commune et
les licences des composants devront être vérifiées avant redistribution.

Les clés, identités de cadres, profils Wi-Fi, photos et copies de SD bootées
restent hors des sources et artefacts publics. `private/`, `build/` et `cache/`
sont exclus de Git. Chaque cadre doit créer ses propres identités au premier boot.
