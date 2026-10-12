# InkyOS

Une image Raspberry Pi dédiée aux cadres photo à écran e-paper **Inky Studio**.
InkyOS prépare le système et son premier démarrage ; Inky Studio fournit le
backend, le Bluetooth et l’application iOS.

Le parcours visé est simple : **allumer le cadre, scanner le QR, confirmer le
pays, choisir le Wi-Fi et envoyer une photo**.

> **Prototype expérimental — état au 12 octobre 2026.**
> Aucune image prête à l’emploi n’est publiée. Le premier appairage iPhone et
> le parcours complet sans LAN préalable restent à intégrer et à qualifier.

## État vérifié

| Composant | État |
|---|---|
| Base | Raspberry Pi OS Lite ARM64 figé, assemblé offline dans une VM Linux dédiée. |
| Pi de test | Boots physiques sur Pi Zero 2 W, identité persistante et agrandissement de partition observés. |
| Réseau | Wi-Fi connecté et échanges SSH authentifiés observés sur l’image précédente. Le réseau de la nouvelle image et la stabilité dans la durée restent à qualifier. |
| Nouvelle image TEST | **132 contrôles offline réussis**, puis [retour d’enrôlement vérifié : 35 + 10 contrôles](docs/validation/2026-10-11-prerequisites-enrollment-return.json). Nouveau boot réseau lancé ; accès SSH non confirmé, application arrêtée. |
| Image factory passive | [Assemblage réel en Linux ARM64](docs/validation/2026-10-12-factory-passive-image.json) avec le bundle Studio `a071f19` : 64 contrôles système, 4 contrôles layout et intégrité d’export réussis. Services masqués ; runtime et premier appairage encore à intégrer. |
| Application | Backend épinglé, services masqués dans l’image. Welcome, photo, QR/BLE et arrêt actif restent à tester ensemble. |
| Initialisation sans LAN | Service IPC local développé et banc Linux réussi ; il n’est pas installé dans l’image TEST. Le raccord backend/iOS est en cours. |
| Écran | PCB 7,3″ dont les marquages corroborent l’ancienne famille sept couleurs ; driver physique et affichage non qualifiés. |

Les validations logicielles restent distinctes des essais sur le cadre :

| Lot vérifié | Preuve et limite |
|---|---|
| Suite globale consignée | [1 273 tests macOS/Linux ARM64](docs/validation/2026-10-11-factory-exporter-workspace-tests.json), sans échec, avec 8/2 skips. Ce rapport correspond à son commit épinglé. |
| Initialisation locale | [Service IPC et client Studio testés en Linux](docs/INITIALIZATION-IPC.md), sans installation dans l’image TEST. |
| Guard commun et arrêt IPC | [79 tests Linux ARM64](docs/validation/2026-10-11-shared-writer-guard-tests.json), sans skip : verrous/processus réels, contrat et identités synthétiques. Le garde installé reste à qualifier. |
| Création factory | [Exporter installé](docs/FACTORY-EXPORTER-PROPOSAL.md) et [quatre cas de composition](docs/FACTORY-INSTALLED-FIXTURE.md), dont reprise sans régénération ; premier boot complet encore à intégrer. |
| Préparation du système | [30 tests du layout passif](docs/validation/2026-10-11-factory-passive-layout-tests.json), sans activation des services. |
| Admission des processus | [Primitive coopérative](docs/FACTORY-WRITER-ADMISSION.md), [lanceurs](docs/FACTORY-WRITER-LAUNCHER.md) et [superviseur](docs/FACTORY-SUPERVISOR.md) développés ; [81 tests Linux ARM64](docs/validation/2026-10-11-factory-runtime-tests.json), sans skip. Les services et guards Studio restent à installer et qualifier. |
| Contrats des services | [85 tests Linux ARM64](docs/validation/2026-10-12-factory-writer-units.json), sans skip, sur les templates et leurs influences statiques. Services encore hors de l’image ; graphe PID1 et application non qualifiés par ce banc. |
| Parents des services | [110 tests Linux ARM64](docs/validation/2026-10-12-factory-writer-parents.json), sans skip, dont les owners numériques réels des parents. Préparation et vérifications sous EX développées ; installation active et graphe PID1 restent à qualifier. |
| Bundle applicatif | [Planner et installation offline](docs/FACTORY-STUDIO-BUNDLE.md), [102 tests Linux ARM64](docs/validation/2026-10-11-factory-image-workspace-tests.json) des deux installers avec workspace commun et inputs synthétiques ; candidat réel et support encore à qualifier. |
| Dépendances applicatives | [39 tests Linux ARM64 à `8102d08`](docs/validation/2026-10-11-factory-studio-dynamic-tests.json), sans skip, dont les métadonnées Dynamic ; fixtures uniquement. Les [33 tests précédents](docs/validation/2026-10-11-factory-studio-dependency-tests.json) restent liés à `619e4a0`. |
| Métadonnées et plan réels | [34 wheels atteintes, 8 sources, 2 405 records attendus](docs/validation/2026-10-11-factory-studio-real-input-plan.json) pour Studio déclaré `a071f19`, outils `8102d08`. Ce rapport statique précède l’assemblage passif et ne qualifie pas le support, l’ABI ou le runtime. |
| Nouveau bundle Studio | [Build et plan statique pour `eb11790`](docs/validation/2026-10-12-studio-eb117-static-bundle.json) : 34 dépendances atteintes, 8 sources et 2 399 entrées attendues. Contrôle ciblé de confidentialité relu ; notices, audit complet, ELF et runtime encore à qualifier. |
| Installation des fichiers factory | [23 tests de copie/relecture inactive](docs/validation/2026-10-12-factory-writer-file-tests.json) pour le mapping fermé de 17 fichiers. [Installer et verifier](docs/FACTORY-WRITER-INSTALLATION.md) développés ; aucune installation native ni activation effectuée par ce lot. |
| Données packagées NumPy | [152 tests Linux ARM64](docs/validation/2026-10-11-factory-studio-numpy-data-tests.json), sans skip, pour la politique commune du planner et des installers ; aucune exécution du candidat. |
| Composition du premier boot | [63 tests Linux ARM64](docs/validation/2026-10-12-factory-graph.json), sans skip, du graph et du wrapper avec fixtures synthétiques. Composition encore inactive ; PID1, permissions installées et parcours sans LAN restent à qualifier. |
| Permissions natives | [Mesure Linux ARM64 sous UID 1000 sans capabilities](docs/FACTORY-GRAPH-NATIVE-PERMISSIONS.md) : PIDFD, propriétés systemd typées et peer du bus observés. Sandbox, IPC réel et graph installé restent à qualifier. |
| Calculs de l'heure initiale | [24 tests macOS](docs/validation/2026-10-12-bootstrap-time-policy.json), sans skip, de la conversion UTC, de l'expiration et de la tolérance du readback. Calculs purs inactifs ; admission et service privilégié encore à développer. |
| Diagnostics TEST | [74 tests ciblés](docs/validation/2026-10-12-test-boot-phase-checkpoints.json), sans skip, des checkpoints avant les phases et avant l'arrêt d'enrôlement. Correction source, hors de la SD actuelle. |
| Suite locale actuelle | [1 875 tests macOS à `0833cb4`](docs/validation/2026-10-12-factory-writer-file-tests.json), sans échec, avec 16 skips explicites. Les rapports précédents restent associés à leurs commits épinglés. |

Le [plan d’intégration factory](docs/FACTORY-IMAGE-INTEGRATION.md) recense les
raccords OS/Studio avant une image utilisable. Le nouveau contrat QR/Bluetooth
a un candidat backend/iOS en draft ;
ses interfaces sont encore injectables, sans activation dans une image.

Le [dernier boot réseau observé](docs/validation/2026-10-11-radio-readiness-network-observation.json)
reste associé à l’ancienne image de test : son préflight est bloqué à 17 contrôles
sur 24. La [nouvelle image](docs/validation/2026-10-11-system-prerequisites-access-image.json)
contient les corrections des prérequis Bluetooth, I²C et heure. Sa construction
réussie ne prouve pas encore leur fonctionnement sur le Pi.
La [relecture du flash SD](docs/validation/2026-10-11-system-prerequisites-sd-flash.json)
et le [retour d’enrôlement](docs/validation/2026-10-11-prerequisites-enrollment-return.json)
sont vérifiés. La garde WLAN a ses 10 checks vrais ; le diagnostic de boot
reste incomplet à `bind`, sans erreur enregistrée. Dans cette version, ce marqueur
est écrit avant l'enrôlement : il peut subsister après sa réussite et ne localise
pas un blocage à cette étape. La [correction des checkpoints](docs/TEST-ACCESS-IMAGE.md)
est développée et testée, sans remplacement de la SD actuelle. Aucun diagnostic
de cette SD ne confirme encore la connexion ou le Bluetooth.
Au nouveau boot, le nom réseau ne se résout pas et aucun
échange SSH authentifié n’est confirmé. Cela ne permet pas de conclure à un
problème de boot ou de mot de passe Wi-Fi. Wi-Fi, Bluetooth et application
restent à tester sur cette nouvelle image.

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
Lima 2.0+. Les tests locaux utilisent la bibliothèque standard Python et une copie
épinglée de `packaging` pour vérifier les dépendances offline, incluse dans
le dépôt sans installation ni accès réseau. La VM de build utilise Linux
ARM64 et Python 3.13.

```sh
make test          # tests locaux
make test-linux    # mêmes fixtures dans la VM ARM64 dédiée
make inspect       # inspection de la base figée
make prototype     # prototype système sans application
make vm-stop
```

Ces commandes supposent que `python3` désigne Python 3.11 ou plus. Sur macOS,
si le Python système est encore en 3.9, choisir explicitement l'interpréteur
installé, par exemple `make test PYTHON=python3.13`.

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
