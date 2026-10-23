# inkyImager

Application macOS native pour installer InkyOS et préparer le Wi-Fi de son cadre.

1. Saisir le nom et le mot de passe du Wi-Fi 2,4 GHz.
2. Choisir la carte SD et cliquer sur **Flasher la carte**.
3. Autoriser l’écriture avec le mot de passe macOS.
4. Une fois la carte vérifiée et éjectée, la placer dans le Pi éteint, puis l’allumer.
5. Scanner le QR affiché avec Inky Studio.

Le mot de passe Wi-Fi reste dans une image temporaire privée pendant la préparation.
Le Pi importe la configuration au premier démarrage, puis supprime le fichier
de configuration de sa partition de démarrage. Le Mac ne transmet aucun secret
dans les arguments de commande ou les journaux. L’app ne nécessite ni Python,
ni Homebrew, ni VM chez son utilisateur.

L’accès à la carte passe par `authopen`, l’outil système macOS qui remet un
descripteur autorisé au programme resté dans la session utilisateur. L’app ne
lance pas son moteur en root avec AppleScript. L’identité de la carte est
revérifiée avant et après l’autorisation, puis les données écrites sont relues.
Les erreurs de commande conservent leur code et leur diagnostic ; un petit reçu
privé sans paramètres Wi-Fi est conservé dans
`~/Library/Caches/fr.mehdiguiard.inkyimager/Diagnostics/` après un échec.

Ce mécanisme suit la [recommandation Apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/AccessControl.html)
et le principe d’ouverture utilisé par [Raspberry Pi Imager](https://github.com/raspberrypi/rpi-imager/blob/23e528b9b0fdbf53fc59fef246cb025e7bc4647f/src/mac/macfile.cpp).

Le premier profil est prévu pour la France et le Pi Zero 2 W. Le parcours iPhone
utilise un accès PHOTO protégé par l’iPhone. Le partage de nouveaux QR depuis
cet accès n’est pas encore disponible dans ce profil.

## Développement

Xcode/Swift et les headers liblzma sont requis pour compiler. Les exécutables
finaux utilisent seulement les bibliothèques système macOS.

```sh
swift test
python3 scripts/build-app.py --image /chemin/InkyOS.img.xz --manifest /chemin/InkyOS.json
```

L’assembleur demande une destination neuve et vérifie la signature locale ainsi
que l’absence de dépendances dynamiques Homebrew. Aucun flash n’est lancé au build.
