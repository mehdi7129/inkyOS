# InkyOS

Une image Raspberry Pi dédiée aux cadres photo à écran e-paper **Inky Studio**.

InkyOS prépare le système, ses dépendances et son premier démarrage. À terme,
une carte microSD flashée permettra de configurer le cadre depuis l’application
iOS. L’application et son protocole restent communs avec Inky Studio.

> **Prototype expérimental — état au 3 octobre 2026.**
> Aucune image prête à l’emploi n’est publiée. L’installation complète et le
> premier appairage iPhone depuis InkyOS restent à qualifier.

## État actuel

| Composant | État vérifié |
|---|---|
| Base système | Raspberry Pi OS Lite ARM64 figé ; assemblage offline dans une VM Linux dédiée. |
| Premier démarrage | Boots physiques observés sur Raspberry Pi Zero 2 W ; identité persistante et agrandissement de la partition vérifiés. |
| Application | Candidat épinglé intégré dans une image expérimentale ; services applicatifs et SSH masqués. |
| Enrôlement de test | Retour SD vérifié : 21 contrôles de cohérence ext4/FAT réussis. |
| Écran | PCB 7,3″ dont les marquages sont cohérents avec l’ancienne famille sept couleurs ; code couleur EEPROM non reconnu. Driver physique et affichage non qualifiés. |
| Wi-Fi | Réponses firmware et regulatory analysées ; format des fréquences corrigé et testé dans les sources. Pays et connexion non qualifiés. |
| Appairage iOS | Tests de bout en bout et premier démarrage sans LAN encore à réaliser. |

La cible matérielle actuelle est le **Raspberry Pi Zero 2 W** avec une
**microSD de 16 Go**. La compatibilité d’un écran ou d’une référence de carte
doit être vérifiée sur le matériel réel. Les tests logiciels ne remplacent
pas cette qualification.

La [compatibilité visée](docs/DISPLAY-COMPATIBILITY.md) couvre les **Spectra 6
4″, 7,3″ et 13,3″**, ainsi que les anciens **Impression sept couleurs 5,7″ et
7,3″**. Une même recette d’image doit servir ces formats, avec détection du
panneau par l’application. Cette cible ne signifie pas qu’ils sont déjà qualifiés.

Les deux premiers [diagnostics](docs/OBSERVER-DIAGNOSTIC.md) ont produit leurs
rapports. La tentative radio v3 n’en a pas produit : le script est retrouvé
intact sous un nom de récupération FAT. Le candidat à nom court passe les
616 tests sur Mac et Linux ARM64 ; sa persistance après retrait/réinsertion
au Mac est vérifiée. Le nouveau boot de comparaison est préparé, relu et la
SD éjectée : son exécution sur le Pi et son rapport restent attendus.
Le correctif radio n’est pas installé dans le rootfs. Le code couleur EEPROM
reste à traiter.

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

- [Architecture et plan de réalisation](docs/BUILD-PLAN.md)
- [Matériel et sources officielles](docs/HARDWARE-SOURCES.md)
- [Compatibilité des écrans et qualification par modèle](docs/DISPLAY-COMPATIBILITY.md)
- [Intégration applicative](docs/APPLICATION-IMAGE.md)
- [Premier démarrage, heure et pays Wi-Fi](docs/FIRST-BOOT.md)
- [Qualification sur SD](docs/SD-QUALIFICATION.md)
- [Diagnostic de l’écran et de la radio](docs/OBSERVER-DIAGNOSTIC.md)
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
