# Runtime du premier accès opérateur TEST

État du 3 octobre 2026 : les sources du dispatcher SSH, du runner privilégié
et du contrôle du pays sont livrées. Le banc SSH utilise désormais les mêmes
sources de runtime. **Aucun compte, daemon SSH, profil Wi-Fi ou nouveau hook
n’est installé sur la SD par cette livraison.** L’activation applicative reste
indisponible. Voir la [preuve de validation](validation/2026-10-03-test-access-runtime.json).

## Commandes opérateur

Le [dispatcher](../scripts/test-operator-dispatch.py) accepte exactement
`preflight`, `activate` ou `stop`, sans argument. Il transmet un JSON fermé
au [runner](../scripts/test-operator-runner.py), par sudo vers un chemin fixe
sans arguments. Aucun shell, chemin de fichier ou commande libre ne vient du
client. Les deux frontières refusent doublons, valeurs flottantes, types
incorrects, champs inconnus et entrée dépassant 4 096 octets. Elles exigent
la fin du stdin sous cinq secondes ; le délai d’exécution du runner est distinct.

La requête minimale est `{"schema_version":1}`. `preflight` accepte aussi
le trio indivisible `utc_reference`, `utc_reference_age` et
`utc_reference_source` (`independent-device` ou `gnss`). Ces valeurs ne règlent
pas l’heure. Sans référence UTC, le rapport reste utile mais incomplet.
Le pays vient uniquement du profil privé ; le client SSH ne peut pas le
remplacer ni fournir une déclaration d’autorisation.

- `preflight` appelle le module readonly épinglé. Le rapport restitue ses
  contrôles, jamais une autorisation. L’observation panneau et l’ancien critère
  de pays PHY restent bloquants ; ils ne sont pas contournés par ce runner.
- `activate` retourne explicitement `activation_unavailable`, même si une
  fixture du preflight passe tous ses contrôles. Aucun démarrage n’est simulé.
- `stop` exige d’abord que l’app **et** le helper soient déjà inactifs et
  masqués. Un runtime actif ou un état impossible à vérifier provoque un refus
  sans mutation ni poweroff. Une fois cette garde passée, il invalide le
  permis volatil éventuel, demande l’arrêt de l’app puis du
  helper, restaure leurs masks persistants sans `--force`, vérifie leur état,
  puis demande poweroff. Cette opération ne dépend pas du succès du preflight.
  Un échec intermédiaire donne un résultat partiel ; une réponse de systemd
  n’atteste ni l’annulation d’un job après timeout ni l’arrêt physique du Pi.

Cette restriction évite d’exécuter le délai d’arrêt applicatif actuel de vingt
secondes pendant un refresh plus long. L’arrêt d’un runtime actif demande un
contrat coordonné de fin des E/S SPI et des unités adaptées ; il n’est pas livré
par cette tranche. Un timeout du client ne doit pas devenir une raison de tuer
le processus qui possède encore le bus.

Les requêtes sont sérialisées par un verrou exclusif non bloquant sous `/run`.
Les données app, identités et clés ne sont ni effacées ni réinitialisées.
La CLI de production ne propose aucun mode fixture ou rootfs alternatif.

## Installation et binding privés à raccorder

Les chemins prévus sont `/usr/local/lib/inkyos-test-ssh/dispatch.py` et
`/usr/local/lib/inkyos-test-ssh/runner`, root-owned 0555 dans un dossier 0755.
Le répertoire historique `/usr/local/lib/inkyos` conserve son mode 0700.
Le compte `inky-test` et la configuration SSH dédiée suivent
[TEST-OPERATOR.md](TEST-OPERATOR.md).

Le marqueur `/etc/inkyos-test-operator.json`, root-owned 0600, lie les UID/GID
du compte, le profil d’enrôlement, son état `enrolled`, l’identité système,
la clé **publique** hôte et les quatre sources de runtime. Les valeurs
`SUDO_USER`, `SUDO_UID` et `SUDO_GID` doivent correspondre au compte unique
de `/etc/passwd`. Le runner ne lit jamais la clé privée hôte. Les bindings
sont relus avant l’opération et après les observations.

Le configurateur de cette transition n’est pas encore livré. Il doit consommer
un retour d’enrôlement contrôlé, conserver ses bindings et préparer la confiance
SSH du Mac. La présence de ce marqueur seule n’ouvre aucun réseau ni service.
Les images génériques restent dépourvues de ces données privées.

## Pays avant connexion

[test-access-network.py](../scripts/test-access-network.py) propose une seule
opération explicite, `--apply-country FR`, sur Linux ARM64/root et le Zero 2 W
attendu. Le programme exige les sources épinglées, firstboot réussi, app/helper
arrêtés et masqués, NetworkManager actif avec Wi-Fi désactivé, aucune connexion
active et `wlan0` déconnecté.

Après une unique demande `iw reg set FR`, il relit le mapping `wlan0`/brcmfmac,
le firmware, le domaine kernel et les canaux, puis répète les gardes. La
politique de test demande firmware `FR/FR`, global `FR`, quatorze canaux avec
14 désactivé et puissance annoncée au plus égale à 2 000 mBm pour les canaux
actifs 1–13. Le label PHY `99` est admis comme domaine custom du
[kernel épinglé](https://github.com/raspberrypi/linux/blob/cff533aec2fa601846766b32ff57204e0a61bed7/drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c#L203),
sans le traduire en code pays. Les codes firmware alternatifs ne sont pas
remappés implicitement.

`test_country_ready` décrit uniquement cette observation. Il n’ouvre pas la
radio et ne doit jamais être consommé depuis un JSON sauvegardé pour autoriser
une connexion ultérieure. Aucun scan, profil réseau, connexion, service SSH,
changement d’heure ou activation app n’est effectué. Le futur orchestrateur
devra vérifier de nouveau l’état immédiatement avant connexion. Les locks et
observations ne bloquent pas tous les clients privilégiés concurrents.

La transition réelle vers `FR` et la lecture firmware dans cet état restent
à éprouver sur le Pi. Les tests ne constituent ni mesure RF ni certification
réglementaire ; `firmware_tuple_qualified` et les qualifications restent false.
L’heure sera contrôlée avant TLS/app, sans bloquer l’accès SSH par clé.

## Reproduire le banc

```sh
make test PYTHON=python3.13
make test-linux
PYTHON=python3.13 bash scripts/probe-test-ssh.sh --operator-runtime build/PARENT
```

`build/PARENT` doit être l’export `application-prototype` exact accepté par
le banc. Une copie jetable est utilisée dans la VM ARM64 dédiée, avec namespaces
mount/network/UTS/PID privés et loopback seul. Les clés sont neuves et restent
sur tmpfs. Le parent et les sources exécutées sont rehashés et liés aux receipts.

Le banc conserve les 39 contrôles SSH/PAM/sudo historiques et ajoute 18 contrôles
du runtime : preflight natif avec les fichiers d’un enrôlement **synthétique**,
refus d’activation, requêtes incorrectes, changements de bindings, verrou réel
et stdin SSH sans fin transmis pendant plus de cinq secondes. Le preflight
est natif dans cette copie Linux ; il n’observe pas un Pi.

L’algorithme `stop` utilise exclusivement un adaptateur fixture dans ce banc.
Aucun `systemctl stop`, mask ou poweroff réel n’y est exécuté. Le nettoyage
contrôle processus, montages, loop device et suppression de la seule copie
jetable. Les rapports n’exportent ni clés ni diagnostics SSH bruts.

## Prochaine intégration

Réunir le configurateur privé, le profil Wi-Fi initial, l’ordonnancement pays/
connexion et le daemon opérateur dans un candidat TEST cohérent. Le candidat
écran d’Inky Studio, son pin et les contrôles d’activation restent une livraison
coordonnée distincte. Aucun nouveau boot de parsing n’est requis par ce travail.
