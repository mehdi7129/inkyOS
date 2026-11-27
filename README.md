# InkyOS

Image Raspberry Pi pour les cadres photo e-paper Inky Studio. Elle prépare le
Wi-Fi, choisit le pilote de l’écran et lance le service local qui reçoit les
photos d’un iPhone.

[![Tests](https://github.com/mehdi7129/inkyOS/actions/workflows/tests.yml/badge.svg)](https://github.com/mehdi7129/inkyOS/actions/workflows/tests.yml)

## Installer

**[Télécharger inkyImager 0.1.5 pour Mac (.dmg)](https://github.com/mehdi7129/inkyImager/releases/download/v0.1.5/inkyImager-0.1.5-Universal.dmg)**
pour sélectionner la SD et renseigner le Wi-Fi. Le DMG inclut
[InkyOS 2026.11.27-rc3](https://github.com/mehdi7129/inkyOS/releases/tag/2026.11.27-rc3)
et le [service PHOTO 0.5.0rc4](https://github.com/mehdi7129/inky-studio/releases/tag/imager-backend-0.5.0rc4).

1. Flashez la SD depuis le Mac et attendez la fin de la vérification.
2. Insérez la carte dans le Raspberry Pi éteint, puis démarrez-le.
3. Connectez l’iPhone au même Wi-Fi et scannez le QR dans Inky Studio.
   Le QR initial est à usage unique et expire après cinq minutes.

L’image est générique. Au premier démarrage, InkyOS enregistre le Wi-Fi dans
un profil privé et retire la configuration transitoire avant d’activer la
radio. Les instructions du QR utilisent la langue transmise par inkyImager.

La release InkyOS fournit aussi l’image ARM64 compressée pour les développeurs,
avec manifeste, hashes et provenance. Un flash de l’image brute seule laisse
le Wi-Fi à configurer.

## Matériel et validation

Le profil `pimoroni-auto` repose sur l’EEPROM et le pilote Pimoroni `inky` 2.6.0.
Consultez la [matrice des écrans](docs/DISPLAY-COMPATIBILITY.md) pour les
Impression, Spectra 6, pHAT, wHAT et les limites de la détection.

Cette image est une **release candidate**. Les fichiers, unités systemd et
dépendances ont été contrôlés en Linux ARM64. Les tests logiciels couvrent les
pilotes, les variantes EEPROM et les rendus du QR. Le premier démarrage sur SD,
la lecture optique à l’iPhone et le rafraîchissement sur écran réel restent à
vérifier pour cette image.

## Développer

- [Assembler l’image et vérifier les entrées épinglées](inkyImager/OS/ASSEMBLY.md).
- [Tester le builder](docs/DEVELOPMENT.md) et [qualifier une SD](docs/SD-QUALIFICATION.md).
- [Maintenir une carte existante](inkyImager/OS/MAINTENANCE.md). Le flash neuf
  efface la carte. Suivez le parcours de maintenance pour préserver le contenu.
- [Changelog](CHANGELOG.md) et [rapports datés](docs/validation/).

```sh
python3 -I -B -m unittest discover -s inkyImager/Tests/OS -p 'test_*.py'
make test PYTHON=python3.13
```

Le builder utilise une base Raspberry Pi OS Lite ARM64 et des dépendances
épinglées. Le dossier historique `inkyImager/OS` contient le profil système.
L’application Mac et le backend sont maintenus dans les dépôts
[inkyImager](https://github.com/mehdi7129/inkyImager) et
[Inky Studio](https://github.com/mehdi7129/inky-studio).

Les sources InkyOS sont sous [licence MIT](LICENSE). Les paquets et les
[composants tiers](vendor/build-tooling/README.md) conservent leurs licences.
