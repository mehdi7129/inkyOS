# InkyOS

Une image Raspberry Pi dédiée aux cadres photo à écran e-paper **Inky Studio**.

InkyOS prépare le système, ses dépendances et son premier démarrage. À terme,
une carte microSD flashée permettra de configurer le cadre depuis l’application
iOS. L’application et son protocole restent communs avec Inky Studio.

> **Prototype expérimental — état au 11 octobre 2026.**
> Aucune image prête à l’emploi n’est publiée. L’installation complète et le
> premier appairage iPhone depuis InkyOS restent à qualifier.

## État actuel

| Composant | État vérifié |
|---|---|
| Base système | Raspberry Pi OS Lite ARM64 figé ; assemblage offline dans une VM Linux dédiée. |
| Premier démarrage | Boots physiques observés sur Raspberry Pi Zero 2 W ; identité persistante et agrandissement de la partition vérifiés. |
| Application | Nouveau candidat écran/arrêt intégré dans une image ARM64 vérifiée, services masqués. Affichage réel et arrêt actif restent à qualifier. |
| Enrôlement de test | Nouvelle SD corrigée : 35 contrôles ext4/FAT et 10 contrôles d’infrastructure réussis ; nouveau contexte privé exporté après nettoyage vérifié. |
| Écran | PCB 7,3″ dont les marquages sont cohérents avec l’ancienne famille sept couleurs ; code couleur EEPROM non reconnu. Driver physique et affichage non qualifiés. |
| Wi-Fi | Sur la SD corrigée, NetworkManager observe `wlan0` connecté lors d’un échange authentifié. La stabilité dans la durée reste à qualifier. |
| Accès opérateur | Deux STATUS SSH authentifiés passent. Le préflight vérifié reste bloqué avec 17 contrôles sur 24 réussis ; l’application reste arrêtée et masquée. |
| Appairage iOS | Build TestFlight 9 disponible. Contrats du parcours LAN/QR/BLE comparés au backend de la SD ; essais de bout en bout encore à réaliser. |
| Premier allumage sans LAN | Cible convenue ; modèles et bancs disponibles, raccords runtime/iOS/OS encore nécessaires. |

La cible matérielle actuelle est le **Raspberry Pi Zero 2 W** avec une
**microSD de 16 Go**. La compatibilité d’un écran ou d’une référence de carte
doit être vérifiée sur le matériel réel. Les tests logiciels ne remplacent
pas cette qualification.

La [compatibilité visée](docs/DISPLAY-COMPATIBILITY.md) couvre les **Spectra 6
4″, 7,3″ et 13,3″**, ainsi que les anciens **Impression sept couleurs 5,7″ et
7,3″**. Une même recette d’image doit servir ces formats, avec détection du
panneau par l’application. Cette cible ne signifie pas qu’ils sont déjà qualifiés.

L'[alignement OS/app](docs/OS-APP-ALIGNMENT.md) fixe le couple du prochain essai :
backend `c31b13a` et iOS `1.0.0 (9)`. Le payload ARM64 et son manifeste restent
épinglés ; la tête de la branche iOS ne remplace pas les corrections matériel
et arrêt intégrées dans l'image.

La dernière suite enregistrée compte [**1 047 tests sur macOS et Linux ARM64**](docs/validation/2026-10-11-radio-readiness-tests.json),
sans échec (4 skips macOS, 1 skip Linux). Le
[retour d’enrôlement de la SD corrigée](docs/validation/2026-10-11-radio-readiness-enrollment-return.json)
passe 35 contrôles du système et 10 contrôles d’infrastructure. Son nouveau
contexte privé est vérifié ; la configuration Wi-Fi signée liée à cet enrôlement
est installée et relue, puis la carte éjectée. Le
[boot réseau suivant](docs/validation/2026-10-11-radio-readiness-network-observation.json)
établit des échanges SSH authentifiés et observe `wlan0` connecté.

Sur l’image précédente, le [diagnostic réseau](docs/validation/2026-10-11-network-device-state-return.json)
confirme que le Pi démarre et importe sa configuration, puis échoue à connecter
le Wi-Fi. NetworkManager renvoie le code 4 ; l’interface est encore indisponible
(état 20, raison 2), avant sa désactivation par le nettoyage. Ces codes ne
prouvent pas un refus du mot de passe. Le [dossier de diagnostic](docs/BOOT-NETWORK-DIAGNOSIS.md)
détaille les observations et leurs limites.

La [correction de synchronisation radio](docs/validation/2026-10-11-radio-readiness-tests.json)
attend désormais que l’interface soit disponible avant de demander la connexion.
Les tests passent ; le retour avant correctif renforce cette piste sans prouver sa cause
exacte. Une [image privée corrigée](docs/validation/2026-10-11-radio-readiness-access-image.json)
est maintenant construite ; ses 123 contrôles offline passent. Elle est
[écrite et relue sur la SD de test, puis éjectée](docs/validation/2026-10-11-radio-readiness-sd-flash.json).
Son nouvel enrôlement est vérifié et deux STATUS SSH authentifiés passent.
Un premier préflight reste non confirmé ; le suivant fournit une réponse
authentifiée **bloquée, avec 17 contrôles sur 24 réussis**. Quatre contrôles requis
restent faux, ainsi que trois contrôles historiques remplacés par des gardes
spécifiques au test. Ces observations ne qualifient ni la stabilité réseau,
ni la cause exacte de l’ancien échec, ni l’affichage ou l’appairage iPhone.

Le prochain essai accompagné doit examiner les prérequis encore bloqués,
puis observer le welcome, une photo et l'adoption QR/BLE depuis une
session LAN authentifiée. La cible produit est plus simple : **allumer le cadre,
scanner le QR, confirmer le pays, choisir le Wi-Fi et envoyer une photo**.
Ce parcours sans LAN préalable reste à intégrer et à qualifier.

## Développer

Le chemin de build testé utilise **macOS Apple Silicon**, **Python 3.11+**,
**Git** et **Lima 2.0+**. Les tests locaux utilisent la bibliothèque standard
Python. La VM de build utilise Linux ARM64 et Python 3.13.

```sh
make test          # tests locaux
make test-linux    # tests dans la VM ARM64 dédiée
make inspect       # inspection de la base figée
make prototype     # construction du prototype système sans application
make vm-stop
```

Les images et rapports sont créés sous `build/`. Ces commandes ne flashent
pas de carte SD et ne publient aucun artefact. L’intégration d’Inky Studio
demande un payload applicatif vérifié séparément.

Voir le [guide de développement](docs/DEVELOPMENT.md) pour les prérequis,
l’espace disque nécessaire et les limites du builder.

## Documentation

- [Alignement OS/app et prochain essai](docs/OS-APP-ALIGNMENT.md)
- [Architecture et plan de réalisation](docs/BUILD-PLAN.md)
- [Matériel et sources officielles](docs/HARDWARE-SOURCES.md)
- [Compatibilité des écrans et qualification par modèle](docs/DISPLAY-COMPATIBILITY.md)
- [Intégration applicative](docs/APPLICATION-IMAGE.md)
- [Premier démarrage, heure et pays Wi-Fi](docs/FIRST-BOOT.md)
- [Qualification sur SD](docs/SD-QUALIFICATION.md)
- [Diagnostic de l’écran et de la radio](docs/OBSERVER-DIAGNOSTIC.md)
- [Runtime du premier accès opérateur](docs/TEST-ACCESS-RUNTIME.md)
- [Image privée avec accès opérateur signé](docs/TEST-ACCESS-IMAGE.md)
- [Préparation des paramètres privés signés](docs/TEST-ACCESS-CAPSULE.md)
- [Reproductibilité et limites](docs/REPRODUCIBILITY.md)
- [Rapports de validation](docs/validation/)

## Avant une release

Il reste à identifier et tester le panneau, qualifier le Wi-Fi et l’appairage
iOS, éprouver les redémarrages et la récupération, puis figer une release
applicative compatible. La redistribution de l’image demande également la
vérification des licences de ses composants.

Les clés, identités de cadres, profils Wi-Fi, photos et copies de SD bootées
restent hors des sources et des artefacts publics. Les dossiers de travail
`private/`, `build/` et `cache/` sont exclus de Git. Les identités propres à
chaque cadre doivent être créées au premier démarrage.
