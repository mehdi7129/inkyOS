# Paramètres privés du premier accès TEST

État du 5 octobre 2026. Le transfert utilise deux fichiers de **données** :
`INKYACC.JSN` et `INKYACC.SIG`. Le préparateur et le vérificateur de retour
sont livrés ; l’importeur au boot et le connecteur sont intégrés à la
[variante privée TEST](TEST-ACCESS-IMAGE.md), construite, vérifiée et
[flashée](validation/2026-10-04-sd-test-access-flash.json).
Après les neuf contrôles du [retour FAT préliminaire](validation/2026-10-04-sd-test-access-return-preliminary.json),
la [comparaison complète ext4/FAT du 5 octobre](validation/2026-10-05-sd-test-access-return.json)
passe les **35 contrôles natifs et les 10 contrôles du wrapper**, sur la copie
privée acquise. Le démontage et le détachement du loop sont vérifiés avant
l’export du contexte. La préparation de la capsule peut suivre ce retour
contrôlé ; la connexion physique reste à éprouver.

La partition FAT ne fournit aucun programme à exécuter. Le runtime installé
vérifie les paramètres signés avec la clé opérateur épinglée dans le profil
d’enrôlement. Ce mécanisme est réservé au candidat applicatif `c31b13a`, pays
France, et au banc TEST ; il ne remplace pas le futur appairage iOS sans LAN.

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

Après production et transfert privé du contexte vérifié, la commande est :

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
[builder de la variante v2](TEST-ACCESS-IMAGE.md). Le contexte est produit par
le [vérificateur de retour](../scripts/verify-test-access-return.py), après
ses 35 contrôles natifs : il compare rapport, profil, état durable, programmes
installés et clés publiques avec l’export privé attendu. Il ne lit aucune clé
privée et n’exécute aucun programme de la SD. Il crée aussi `known_hosts`, qui
lie le hostname observé à la clé hôte SSH sur le port 2222.

Le [wrapper Linux](../scripts/check-test-access-return-linux.sh) vérifie une
copie privée dans la VM ARM64 dédiée, avec loop en lecture seule, ext4
`ro,noload` et FAT `ro`. Il contrôle tailles, hashes et sources scellées, puis
exporte le contexte privé vers l’opérateur seulement après PASS, relecture et
nettoyage des montages vérifiés. La [recette de retour](TEST-ACCESS-IMAGE.md#vérification-du-retour)
décrit ce staging. Les fixtures de ces outils ne remplacent pas le contrôle
de la copie réellement acquise ; il ne faut jamais fabriquer les bindings.

## Import et accès au boot

L’[orchestrateur](../scripts/test-access-boot.py) remplace l’activation
automatique de l’ancien hook d’enrôlement. Au boot vierge, il appelle
l’enrôlement existant, puis demande l’arrêt. Après contrôle offline et apport
des deux fichiers signés, l’[importeur](../scripts/test-access-import.py)
authentifie la capsule depuis les fichiers ext4 de confiance. Il écrit
durablement l’état `importing`, le cache privé puis l’état `imported` avant
l’accès. Aux boots suivants, il réauthentifie le cache complet. Une interruption
ou incohérence bloque la suite et conserve les fichiers pour une reprise
explicite ; aucune identité n’est remplacée automatiquement.

Le marqueur PREPARED de l’application reste inchangé. La
[garde Wi-Fi](../scripts/test-access-wifi-gate.py) précède **chaque démarrage
de NetworkManager**, y compris après une coupure : elle bloque WLAN et écrit
durablement `WirelessEnabled=false`. Son échec empêche le daemon de démarrer.
Le seul profil importé reste sans autoconnect. Le
[connecteur](../scripts/test-access-connect.py) exige le contrôle France en
direct, Wi-Fi désactivé, puis relit les gardes juste avant la connexion ; un
ancien reçu JSON ne donne aucune autorisation.

Le daemon SSH dédié utilise la clé hôte créée sur le Pi. Le
[client opérateur](../scripts/test-operator-client.py) impose le `known_hosts`
issu du retour contrôlé, sans accepter une autre clé par mDNS. Il n’admet que
`preflight`, `activate`, `status` et `stop`. App et helper restent masqués
pendant l’accès initial ; leur [activation et leur arrêt](TEST-ACCESS-LIFECYCLE.md)
sont des opérations distinctes, explicitement demandées.

## Portée des preuves

La [validation historique de capsule](validation/2026-10-03-test-access-capsule.json)
consigne 699 tests sur Mac et Linux ARM64 et un banc de 61 contrôles, dont
quatre signatures avec l’OpenSSH exact du parent. Les clés et réseaux de ces
tests sont fictifs. La [validation intégrée](validation/2026-10-04-test-access-lifecycle-image.json)
consigne l’image courante et 997 tests par hôte, sans échec. Ces preuves portent
sur les contrats, les mécanismes et la construction ; elles ne qualifient pas
l’import physique de la capsule, la connexion Wi-Fi, l’affichage ou l’appairage
iPhone. L’image, la capsule, le contexte et les clés restent privés.
