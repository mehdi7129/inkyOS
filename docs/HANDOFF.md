# Contrats et responsabilités InkyOS

État du **27 septembre 2026**, avant qualification finale du Bluetooth. Ce dossier
prépare le travail ; il ne donne pas le statut « prêt à flasher » à une image.

## Objectif du projet

Deux parcours doivent rester disponibles : un utilisateur avancé installe son
Raspberry Pi OS puis Inky Studio ; un autre flashe InkyOS avec l'application et
ses dépendances déjà intégrées. Au premier allumage, le cadre accompagne
l'association de l'iPhone et la configuration Wi-Fi par Bluetooth. Le nom InkyOS
est un nom de projet ; aucune affiliation Raspberry Pi n'est revendiquée.

Le développement de l'image vient après stabilisation de l'application et du
Bluetooth. Les sources système et l'étude de reproductibilité peuvent avancer
sans utiliser une installation hors banc.

## Répartition des dépôts

| Dépôt | Responsabilité |
|---|---|
| `inky-studio` | App iOS, backend, UI web, protocole BLE/HTTPS, écran, helper réseau, installation classique et updates applicatives. |
| `inkyOS` | Recette d'image, base OS figée, intégration premier boot, configuration système, qualification SD, maintenance et récupération OS. |

Conserver des checkouts distincts pour InkyOS et Inky Studio. Vérifier la
branche, le worktree et l'état Git avant toute intégration entre composants.

Utiliser une release applicative publiée et vérifiée, jamais une copie d’une
installation existante ou un téléchargement non figé de `main`/`latest` pendant
le build OS.
Le code applicatif reste maintenu dans son dépôt ; toute extension de son
protocole demande une modification testée des deux côtés, pas un fork caché.

## État réel de départ

- Le backend `0.5.0-rc.2`, source `ae61df1`, est désormais déployé sur le cadre
  de qualification. HTTP/HTTPS, auth obligatoire, détection du driver et
  enregistrement BlueZ passent ; ce n’est pas encore une release publique.
- Le candidat iOS `1.0.0 (3)` ne prend pas en charge Bluetooth. Le build 4
  Bluetooth n'est pas qualifié pour la release décrite ici.
- La PR #11 d’Inky Studio est draft.
  CI backend et iOS verte ; banc radio Mac/Pi et bancs synthétiques passés.
  L'adoption QR par iPhone et le changement/rollback Wi-Fi physiques restent
  à qualifier. Ces preuves ne sont pas interchangeables.
- Un compte-rendu actualisé doit confirmer la release et les tests avant de
  figer la première recette InkyOS. Les versions de ce paragraphe ne constituent
  pas un manifeste de release autorisée.

Les [sources matériel](HARDWARE-SOURCES.md) sont séparées des hypothèses.
Le Pi observé est un Zero 2 W ; le modèle exact de panneau exige encore une
vérification. Le mapping actuel `AC073TC1A = Spectra 6` est contredit par
Pimoroni : il s'agit du panneau 7 couleurs dans la table officielle. Ne pas
réutiliser cette étiquette comme preuve de matériel.

## Contrats applicatifs à préserver

Référence de code pour cet inventaire : `inky-studio`, commit `ae61df1c0f01408861ccb1210ec85986768d6784`.
Les valeurs par défaut ne sont pas des chemins imposés à tous les utilisateurs.

| Élément | Contrat existant |
|---|---|
| Installation | `${HOME_utilisateur}/inky-studio`, configurable ; utilisateur non-root choisi à l'installation, pas obligatoirement `pi`. |
| Données | `/var/lib/inky-studio` par défaut : credentials, base photos/file/historique, photos et `provisioning/`. Persistantes et indépendantes du code. |
| Service app | `inky-studio.service`, cwd `server/`, exécutable `server/.venv/bin/inky-studio-server`. Un seul propriétaire de l'écran/SPI. |
| CLI | `/usr/local/bin/inky-studio`, wrapper stable vers le payload ; consultation du mot de passe initial et récupération. Personnalisation via app/API. |
| API | HTTP 8000 historique ; avec Bluetooth activé, HTTPS 8443, même lifecycle et mêmes sessions. Cadre adopté : identité HTTPS vérifiée, aucun repli HTTP. |
| Bluetooth | BlueZ GATT et TLS 1.3 applicatif. Le QR physique fournit l'identité attendue ; la découverte BLE seule n'accorde aucun droit. |
| Helper | `inky-network.service`, compte système `inky-network`, groupe `inky-provisioning`, code root-owned sous `/usr/local/lib/inky-studio/`. |
| IPC réseau | Socket `/run/inky-network/control.sock` 0660 ; état privé `/var/lib/inky-network` 0700. Permissions NetworkManager limitées au helper. |
| Portée Wi-Fi | `wlan0`, WPA2 personnel, 2,4 GHz, IPv4 ; tentative de 180 secondes, confirmation HTTPS, rollback à défaut. |

Lire les scripts `inky-studio/install.sh` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`)
et `inky-studio/scripts/install-bluetooth.sh` (commit `ae61df1c0f01408861ccb1210ec85986768d6784`).
L'installateur classique n'est pas directement un stage de build d'image : il
attend un utilisateur normal et peut installer des paquets, agir sur les services
ou redémarrer. Concevoir des étapes adaptées à une image hors ligne et qualifier
leur équivalence ; ne pas l'exécuter aveuglément dans le Mac ou son chroot.

## Premier démarrage : ce qui reste à développer

Le **mot de passe Inky Studio** et le **mot de passe Linux/SSH** sont distincts.
L'application génère déjà un mot de passe initial aléatoire en absence de
credentials ; sa valeur initiale en clair est consultable temporairement dans
un fichier privé. La personnalisation supprime cette valeur de bootstrap, tout
en conservant le fichier de credentials et son hash scrypt. L'écran de bienvenue
affiche actuellement URL et mot de passe initial lorsque cette valeur de
bootstrap existe encore et que l'historique est vide.

Le premier QR Bluetooth se demande encore depuis une session réseau authentifiée
(`POST /api/provisioning/adoption/window`). Un téléphone déjà adopté peut ensuite
changer le Wi-Fi sans réseau commun. **Cela ne permet pas encore l'installation
initiale entièrement hors ligne d'InkyOS.**

Définir puis implémenter conjointement avec l'app :

1. Un état « cadre neuf » fiable, distinct d'une panne réseau ou d'un reboot.
2. Une première adoption locale avec preuve de présence physique, QR à durée
   limitée et secret unique ; aucune réouverture automatique de droits après
   un redémarrage d'un cadre déjà adopté.
3. Le choix du pays Wi-Fi, la découverte locale et le comportement sans réseau.
   mDNS/Avahi et domaine réglementaire ne sont pas provisionnés par les scripts
   actuels : les traiter explicitement.
4. La gestion de l'heure hors réseau. Le code actuel exige une horloge au moins
   égale au 1er janvier 2026 et produit des certificats de 396 jours. La validation
   TLS doit rester active ; une date approximative ou une suppression du contrôle
   de validité ne constitue pas une solution qualifiée.
5. Le retour au parcours normal après adoption et une récupération physique
   documentée quand aucun téléphone autorisé n'est disponible.

Conserver le design iOS arrondi clair/sombre et les parcours déjà acceptés.
Les portails captifs d'hôtel, WPA Enterprise, réseaux ouverts, 5 GHz et l'envoi
Internet distant de photos ne sont pas couverts par la fonction actuelle. Le
partage de connexion 2,4 GHz fait partie des scénarios du banc.

## Identités et image générique

Construire une image vierge à partir de composants identifiés. Ne jamais
redistribuer un clone du cadre de développement, même après suppression de
quelques fichiers visibles.

À générer pour chaque installation, après disponibilité de l'aléa système :
identité machine, clés hôte SSH si SSH activé, mot de passe app initial,
identité du cadre (UUID/clé P-256), certificats et état privé du helper.
Aucune clé, association de téléphone, photo, historique, QR actif ou profil
NetworkManager personnel ne doit être livré dans l'image.

Les identités du cadre et son ownership doivent ensuite survivre aux updates.
Un reset utilisateur explicite a un contrat distinct d'un redémarrage ou d'une
réparation système. Désactiver l'accès SSH par mot de passe partagé par défaut ;
définir le parcours avancé de support sans créer de compte universel.

## Mises à jour : deux responsabilités

L'updater app reste lié au dépôt applicatif Inky Studio. Il sélectionne actuellement
la dernière release puis un asset `.tar.gz`, remplace du code et installe les
packages Python dans le venv. Le payload doit contenir `server`, `client/dist`,
`shared` et `scripts`.

Il ne met pas à jour l'OS, les unités root-owned ou le helper réseau. Son rollback
restaure des fichiers, pas le venv, et n'est pas une stratégie A/B avec validation
post-boot. **Ne pas présenter ce mécanisme comme une récupération complète OS.**

InkyOS doit définir séparément versions OS/app/helper, compatibilité, persistance
des données, validation de démarrage et récupération sur carte de secours.
Comparer une stratégie A/B et une reconstruction/reflash documentée selon coût
SD, complexité et besoins. Ne pas changer le dépôt surveillé par l'updater app
pour le faire pointer sur les images InkyOS.

## Étapes et critères de passage

| Étape | Livrable vérifiable | Critère avant la suite |
|---|---|---|
| 0. Stabilisation app | Release/commit précis, tests iPhone + Pi, identification réelle du panneau | QR physique, connexion, mauvais mot de passe, rollback et recovery vérifiés. |
| 1. Choix de base | Comparaison `rpi-image-gen` / `pi-gen`, OS/architecture figés, environnement de build documenté | Builder upstream accessible ; versions et checksums consignés, pas de SD utilisateur touchée. |
| 2. Image minimale | Recette et manifeste reproductibles, payload app précompilé, paquets système et licences recensés | Deux builds comparés ; écarts expliqués ; absence de secrets testée. |
| 3. Premier boot | Machine d'états et extension d'adoption initiale testées avec l'app | Deux SD ont des identités différentes ; reboot conserve chaque identité ; configuration possible sans Ethernet/Wi-Fi préalable. |
| 4. Qualification | Matrice Pi/panneau et preuves réelles | Refreshs consécutifs, coupures à chaque phase critique, mauvais réseau, perte de BLE, reboot et récupération. |
| 5. Distribution | Image compressée, SHA-256, provenance/licences, guide Imager, limites et maintenance | Flash d'une SD vierge par une seconde personne, installation et restauration réussies. |

Le Zero 2 W est la première cible à confirmer ; aucun autre Pi ou écran n'est
annoncé compatible sans test. Ne pas utiliser une installation hors banc comme seule
carte de qualification d'image ou de coupure électrique.

## Coordination des composants

L'[état d'intégration et les points ouverts](RECEPTION.md) distinguent les
travaux système et applicatifs. Une fois la base applicative qualifiée,
mettre à jour ce contrat avec le commit, les artefacts de release et les
preuves de tests. La documentation de coordination ne qualifie pas à elle
seule l'application ou l'image.
