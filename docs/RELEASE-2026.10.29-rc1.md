# InkyOS 2026.10.29-rc1

## Installer

Utiliser [inkyImager 0.1.2](https://github.com/mehdi7129/inkyImager/releases/tag/v0.1.2), qui contient cette image. Mac Apple Silicon avec macOS 14+, environ 6 Go libres ; Pi Zero 2 W, microSD de 16 Go ou plus, prototype Inky Impression 7,3 pouces 800 × 480 / profil AC073, réseau WPA2 2,4 GHz en France. Les autres matériels ne sont pas qualifiés par cette release.

Saisir le Wi-Fi sur le Mac, choisir la SD, flasher puis attendre la relecture et l’éjection confirmées. La carte sélectionnée est effacée. L’insérer dans le Pi éteint, l’allumer, puis scanner le QR avec Inky Studio sur le même réseau. Aucun Bluetooth nécessaire dans ce parcours. Les photos et accès d’une carte existante ne sont pas conservés par un flash neuf.

Le XZ seul, publié pour vérification et intégration, ne contient pas de Wi-Fi : le flasher avec un outil générique sans configuration ne reproduit pas le parcours préparé par inkyImager.

## Provenance exacte

| Élément | Pin |
|---|---|
| Code OS de l’image | `a70197adcc9168bf826d9c6ac7376d23056b23fe` |
| Backend Inky Studio | `716104b130d34d1973001e78f15e25989d4c2e76` |
| Manifeste fermé d’entrée | `9d72994d04c63c5752028263e6b31dce42f6374ae066784d2aff83b401857b92` |
| XZ SHA-256 | `1888b0724b817a344d5ef08fedcf6a327c70faf9a3ba3eb98c93211bbed4f65d` |
| RAW SHA-256 | `ad176c1f5354c4bcc8944370733da132228bcc6810098c75b58fc568161d021a` |

XZ : 631 336 868 octets. RAW : 3 061 841 920 octets. Les commits documentaires du tag peuvent être postérieurs au code OS qui a produit l’image. `InkyOS.json`, `VALIDATION.json` et `SHA256SUMS` sont joints à la release.

## Portée

L’image générique a été contrôlée en lecture seule, ses fichiers privés attendus absents, ses imports exécutés sous Python ARM64 isolé et son XZ entièrement relu. Le service cible et les radios n’ont pas été démarrés pendant ces contrôles. Premier boot physique de cet artefact non observé. La configuration existante a été validée par l’utilisateur, y compris le partage QR et plusieurs jours sans bug ; ce résultat n’établit pas la compatibilité de tous les matériels.

Les notices des paquets restent présentes dans `/usr/share/doc` de l’image. Les sources amont Raspberry Pi OS sont accessibles sur https://github.com/RPi-Distro et les sources du backend dans le dépôt Inky Studio. Aucune sauvegarde personnalisée n’est distribuée.
