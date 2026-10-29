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

## État au 29 octobre 2026

| Élément | État et portée |
|---|---|
| Cadre existant | Flash par inkyImager 0.1.1, démarrage, connexion et photos confirmés par Mehdi. |
| Service de partage | `716104b130d34d1973001e78f15e25989d4c2e76` installé le 25/10, partition relue et éjectée, identité/TLS/Wi-Fi/photos conservés. |
| Inky Studio 1.0.0 (19) | Disponible dans le groupe TestFlight interne, avec correction de reprise après Face ID. |
| Partage QR iPhone → iPhone | Fonctionnement du premier coup confirmé par Mehdi le 25/10, puis retour de stabilité sur plusieurs jours le 29/10. |
| Nouvelle installation | Image générique avec le service 716104 construite et contrôlée offline ; candidate Mac 0.1.2 (3) préparée localement. |
| Distribution publique | Sources publiques. Téléchargement final Developer ID/notarisé et publication restent des étapes séparées. |

La configuration existante est validée par l'utilisateur ; les contrôles de
relecture, les tests logiciels et les retours d'usage gardent leur portée
respective. La nouvelle image générique n'a pas encore été observée au premier
démarrage sur une nouvelle SD. Elle ne contient aucun Wi-Fi, identité, accès
ou photo personnel et ne provient pas d'une copie de la carte de Mehdi.

Le profil actuel utilise **Python 3.13.5/aarch64, inky 2.5.0** et le profil
**`ac073-800x480-timed-wait`**. Les anciennes notes de septembre/octobre qui
citent inky 2.3.0 concernent des instantanés historiques distincts.

Le parcours essayé utilise un **Raspberry Pi Zero 2 W**, une microSD de 16 Go
et le profil d’écran **800 × 480** du prototype. Les autres références d’écran,
les installations à grande échelle et le téléchargement public final
restent à valider et livrer. Voir la [compatibilité des écrans](docs/DISPLAY-COMPATIBILITY.md).

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
