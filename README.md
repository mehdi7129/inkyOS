# InkyOS

Le système Raspberry Pi des cadres photo e-paper **Inky Studio**. Il prépare
Linux, le Wi-Fi, les pilotes de l’écran et le service local qui reçoit les
photos depuis l’iPhone.

## Les trois projets

| Projet | Rôle |
|---|---|
| [inkyImager](https://github.com/mehdi7129/inkyImager) | App macOS : installer InkyOS sur une SD et renseigner le Wi-Fi depuis le Mac. |
| **InkyOS** | Image Raspberry Pi, premier démarrage, service et intégration matérielle. |
| [Inky Studio](https://github.com/mehdi7129/inky-studio) | App iPhone et backend : connexion par QR, Face ID, photos, file et programmation. |

## Parcours actuel

1. Dans inkyImager sur le Mac, choisir la SD et renseigner le Wi-Fi.
2. Installer l’image, attendre la relecture et l’éjection confirmées.
3. Mettre la SD dans le Pi éteint, puis l’allumer.
4. Sur l’iPhone connecté au même réseau, scanner le QR affiché par le cadre.
5. Valider l’accès protégé par l’iPhone, puis envoyer une photo.

Le Wi-Fi est importé au premier démarrage, puis le fichier temporaire de
configuration est retiré de la partition de démarrage. Ce profil utilise
le réseau local préparé par le Mac. Les prototypes Bluetooth et SoftAP restent
archivés dans les sources et la documentation.

## État au 23 octobre 2026

| Élément | État et portée |
|---|---|
| inkyImager 0.1.1 | Flash, relecture et éjection de la SD réussis sur le Mac de test. |
| Premier démarrage | Pi démarré et QR visible sur l’écran physique, confirmés par l’utilisateur. |
| Inky Studio 1.0.0 (16) | Connexion, photo et reconnexion confirmées par l’utilisateur sur le cadre de test. |
| Inky Studio 1.0.0 (17) | Disponible sur TestFlight interne ; comprend l’interface de partage PHOTO. |
| Partage QR iPhone → iPhone | Backend candidat `716104b`, tests logiciels réussis ; installation sur le Pi et essai physique encore en attente. |
| Maintenance conservant les données | Outils natifs et éditeur ext4 vérifiés sur fixtures, avec revue indépendante. Sauvegarde de la SD actuelle requise avant toute écriture. |

La référence fonctionnelle du service testé est `b75bf1e`. Le candidat de
partage reste distinct du service actuellement installé. Les résultats sur
fixtures, la livraison TestFlight et les retours utilisateur constituent des
preuves de niveaux différents.

Le parcours essayé utilise un **Raspberry Pi Zero 2 W**, une microSD de 16 Go
et le profil d’écran **800 × 480** du prototype. Les autres références d’écran,
les installations à grande échelle et une distribution publique prête à
l’emploi restent à qualifier. Voir la [compatibilité des écrans](docs/DISPLAY-COMPATIBILITY.md).

## Sources et assemblage

- [Profil Wi-Fi préparé par inkyImager](inkyImager/OS/ASSEMBLY.md).
- [Builder et configuration du profil](inkyImager/OS/).
- [Maintenance de la carte actuelle](inkyImager/OS/MAINTENANCE.md).
- [Application macOS et outils de maintenance](https://github.com/mehdi7129/inkyImager).

La recette assemble offline une base Raspberry Pi OS Lite ARM64 et un lot
Inky Studio épinglé. L’image générique ne contient aucun Wi-Fi personnel ni
identité de cadre. Les identités et les accès sont créés sur le cadre.

Les sources de l’app Mac sont maintenant maintenues dans **inkyImager**. Le
répertoire historique `inkyImager/OS` de ce dépôt contient le profil système ;
`inkyImager/Tests/OS` en vérifie l’import réseau et la configuration.

## Développement et vérification

Le build d’image utilise une VM Linux ARM64 dédiée. Les tests système courants
utilisent Python 3.11+ ; le profil Imager possède aussi sa suite ciblée :

```sh
python3 -I -B -m unittest discover -s inkyImager/Tests/OS -p 'test_*.py'
make test PYTHON=python3.13
```

Les tests du profil Imager couvrent notamment UTF-8, dérivation WPA, permissions,
reprise, refus des liens et rendu des unités. Ils n’activent pas de radio et
n’écrivent aucune SD physique. Le [guide de développement](docs/DEVELOPMENT.md)
détaille le builder et ses prérequis.

## Documentation

- [Architecture et recette](docs/BUILD-PLAN.md)
- [Matériel et sources](docs/HARDWARE-SOURCES.md)
- [Intégration du service](docs/APPLICATION-IMAGE.md)
- [Plan de qualification](docs/SD-QUALIFICATION.md)
- [Rapports datés](docs/validation/)
- [Ancien README et état du 12 octobre](docs/history/README-2026-10-12.md)

Les images, sauvegardes SD, photos, profils Wi-Fi, clés et accès réels restent
hors de Git. Les instructions de maintenance préservent la carte existante ;
le bouton **Flasher** d’inkyImager installe une image neuve et efface son contenu.
