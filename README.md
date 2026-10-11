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

Les validations logicielles restent distinctes des essais sur le cadre :

| Lot vérifié | Preuve et limite |
|---|---|
| Suite globale consignée | [1 273 tests macOS/Linux ARM64](docs/validation/2026-10-11-factory-exporter-workspace-tests.json), sans échec, avec 8/2 skips. Ce rapport correspond à son commit épinglé. |
| Initialisation locale | [Service IPC et client Studio testés en Linux](docs/INITIALIZATION-IPC.md), sans installation dans l’image TEST. |
| Création factory | [Exporter installé](docs/FACTORY-EXPORTER-PROPOSAL.md) et [quatre cas de composition](docs/FACTORY-INSTALLED-FIXTURE.md), dont reprise sans régénération ; premier boot complet encore à intégrer. |
| Préparation du système | [30 tests du layout passif](docs/validation/2026-10-11-factory-passive-layout-tests.json), sans activation des services. |
| Admission des processus | [Primitive coopérative](docs/FACTORY-WRITER-ADMISSION.md), [lanceurs](docs/FACTORY-WRITER-LAUNCHER.md) et [superviseur](docs/FACTORY-SUPERVISOR.md) développés ; [81 tests Linux ARM64](docs/validation/2026-10-11-factory-runtime-tests.json), sans skip. Les services et guards Studio restent à installer et qualifier. |
| Suite locale actuelle | [1 467 tests macOS](docs/validation/2026-10-11-factory-runtime-tests.json), sans échec, avec 13 skips explicites. Le banc Linux de ce rapport porte sur le nouveau lot de 81 tests, pas sur toute la suite. |

Le [plan d’intégration factory](docs/FACTORY-IMAGE-INTEGRATION.md) recense les
raccords OS/Studio avant une image utilisable. Le nouveau contrat QR/Bluetooth
a un [candidat backend/iOS en draft](https://github.com/mehdi7129/inky-studio/pull/29) ;
ses interfaces sont encore injectables, sans activation dans une image.

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
