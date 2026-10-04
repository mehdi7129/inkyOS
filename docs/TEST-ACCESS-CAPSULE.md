# Paramètres privés du premier accès TEST

Le transfert proposé utilise deux fichiers de **données** : `INKYACC.JSN` et
`INKYACC.SIG`. Les outils locaux de préparation et de vérification sont livrés ;
**l’importeur au boot et la connexion ne le sont pas encore**. Aucun de ces
fichiers n’est actuellement à copier sur la SD.
La [preuve de validation](validation/2026-10-03-test-access-capsule.json)
consigne 699 tests sur Mac et Linux ARM64, ainsi que le banc de 61 contrôles
sur l’image jetable, dont quatre essais de signature avec son OpenSSH exact.

Le runtime et son vérificateur seront installés dans une nouvelle image propre.
La partition FAT ne fournira jamais le programme à exécuter. Après le retour
d’enrôlement contrôlé, une signature par la clé opérateur déjà épinglée permettra
de détecter la modification des paramètres de cette tentative. Ce mécanisme
est réservé au banc TEST et ne remplace pas le futur appairage iOS sans LAN.

## Contenu et confiance

La [capsule](../scripts/test-access-contract.py) est un JSON canonique fermé,
limité à 4 096 octets. Elle contient le pays `FR`, un seul réseau WPA2 Personal
2,4 GHz, ainsi que les bindings suivants :

| Champ | Source de confiance requise |
|---|---|
| `nonce` | Challenge du profil d’enrôlement vérifié. |
| `profile_sha256` | Octets canoniques du profil privé contrôlé. |
| `host_public_key_sha256` | Clé publique hôte réelle vérifiée offline ; hash des 51 octets SSH Ed25519, comme le rapport d’enrôlement. |
| `application_source_commit`, `application_manifest_sha256` | Couple applicatif revu pour ce candidat. |
| `access_runtime_manifest_sha256` | Manifest statique du runtime d’accès installé et revu. |

Le SSID est encodé en hexadécimal pour conserver ses 1 à 32 octets sans
interprétation de caractères spéciaux. La PSK est une passphrase ASCII de
8 à 63 caractères imprimables ou une clé de 64 caractères hexadécimaux minuscules.
Le fichier contient donc un **secret en clair** : la signature garantit
l’intégrité et l’authentification de l’opérateur, pas la confidentialité.

La signature SSHSIG utilise le namespace `inkyos-test-access-v1` et le principal
fixe `inkyos-test-operator`. La clé publique attendue vient du profil de
confiance, jamais de la capsule ou d’une découverte réseau. La vérification
porte sur les octets exacts et les bindings attendus. Aucun timestamp ne sert
d’autorité : le Pi peut encore avoir une heure incorrecte.

Le résultat de vérification ne restitue ni PSK, ni SSID, ni clé, ni chemin,
ni sortie brute d’OpenSSH. Une signature valide ne prouve pas que le contexte
fourni a été contrôlé sur une SD, n’empêche pas à elle seule un replay et
n’autorise pas la connexion. Ces responsabilités restent celles de l’importeur
et du contrôle offline.

## Préparation locale

La clé privée opérateur existante reste sur le Mac. Le builder d’enrôlement
accepte désormais sa moitié publique via `--operator-public-key CHEMIN.pub`.
Sans cette option, son comportement historique de création d’une nouvelle
clé dédiée est conservé. Le mode réutilisation ne lit ni ne copie la moitié
privée et ne lance pas `ssh-keygen`.

Le [préparateur](../scripts/prepare-test-access-capsule.py) lit deux entrées
privées, sous des dossiers 0700, avec fichiers 0600 :

- `context.json` : schéma 1, kind `verified-test-access-context`,
  `operator_public_key` et objet fermé `bindings` contenant les six bindings
  ci-dessus, avec `challenge` à la place de `nonce`.
- `network.json` : exactement `ssid` (texte UTF-8) et `psk`. Les secrets ne
  sont jamais passés en arguments de commande.

Une fois ces entrées produites par la chaîne de contrôle, la commande sera :

```sh
python3 scripts/prepare-test-access-capsule.py \
  --context private/access-input/context.json \
  --network private/access-input/network.json \
  --operator-key private/operator/client_ed25519 \
  --output private/access-capsule
```

Le dossier de sortie doit être nouveau. Le préparateur appelle OpenSSH pour
signer, vérifie ensuite la signature avec la clé publique du contexte, puis
écrit un reçu privé d’authentification. Ce reçu ne déclare pas la préparation
achevée : la commande ne retourne `prepared=true` qu’après ses écritures et
leur synchronisation. Il conserve aussi le fichier de signature produit par
OpenSSH et les preuves d’un échec éventuel. Il ne copie rien sur la SD, ne
modifie aucune entrée et n’ouvre aucun réseau. Une clé chiffrée nécessitant
une interaction ne fait pas partie de cette première recette non interactive.

Le champ `context_provenance_verified=false` reste explicite : ce programme
vérifie les données fournies et leur signature, pas leur provenance physique.
Le manifest d’accès est désormais produit par le
[builder de la variante v2](TEST-ACCESS-IMAGE.md). Le producteur automatique
du contexte reste à valider ; il ne faut pas fabriquer ses valeurs.

## Intégration restante

La nouvelle variante remplacera le lien d’activation automatique de l’ancien
hook d’enrôlement par un seul orchestrateur de phase. Au boot vierge, il
appellera l’enrôlement existant. Après contrôle offline, il vérifiera la capsule
à partir des fichiers ext4 de confiance, puis consignera durablement sa
consommation avant l’accès. Une interruption ou incohérence devra conduire à
une reprise explicite, en conservant l’identité existante.

Le marqueur PREPARED de l’application restera inchangé. Le contrôle du pays
devra être exécuté réellement avec Wi-Fi désactivé juste avant la connexion,
jamais remplacé par un ancien reçu JSON. App et helper resteront masqués.
Une garde devra précéder **chaque démarrage de NetworkManager**, y compris
après une coupure : une connexion précédente peut avoir persisté l’état radio
activé. L’état Wi-Fi désactivé de l’image initiale ne suffit donc pas. Le seul
profil importé restera sans autoconnect ; une garde en échec bloquera le daemon
au lieu de laisser un accès démarrer avant le contrôle du pays.
Le daemon SSH dédié utilisera la clé hôte créée sur le Pi ; la confiance Mac
sera préparée depuis le retour offline, sans accepter une autre clé par mDNS.

Les tests de cette tranche utilisent uniquement des clés et réseaux fictifs.
Ils éprouvent la signature, les changements de données et de bindings, les
permissions, les erreurs fermées et la conservation des entrées. Ils ne
qualifient ni l’import sur FAT, ni la connexion Wi-Fi, ni un affichage ou
l’appairage iPhone.
