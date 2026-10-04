# Runtime du premier accès opérateur TEST

État du 4 octobre 2026 : le dispatcher SSH, le runner privilégié et le contrôle
du pays sont raccordés dans une [image privée TEST](TEST-ACCESS-IMAGE.md).
Le runner accepte les profils historiques v1 et les nouveaux profils v2,
avec des bindings distincts. Aucun essai réseau sur Pi ni flash de cette
variante n’est qualifié. Le nouveau raccord [activation et drain](TEST-ACCESS-LIFECYCLE.md)
ajoute deux workers explicitement demandés ; les anciennes images restent inactives.
Le [banc SSH historique](validation/2026-10-03-test-access-runtime.json)
et la [nouvelle intégration image](validation/2026-10-04-test-access-image.json)
ont des périmètres de preuve différents.

## Commandes opérateur

Le [dispatcher](../scripts/test-operator-dispatch.py) accepte exactement
`preflight`, `activate`, `status` ou `stop`, sans argument. Il transmet un JSON fermé
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
- `activate` exige `confirm_test_refresh: true` et le trio UTC. Sur une image
  comportant les sept payloads de lifecycle liés au manifest, il soumet une
  demande à un worker systemd. Celui-ci refait les contrôles natifs, démarre
  le helper, vérifie son IPC puis admet l’application avec un permis consommable.
  Une requête minimale ou une ancienne image retourne `activation_unavailable`.
- `status` observe les états de l’activation et du drain, avec les contrôles
  de gate sous forme de booléens. Il n’ouvre aucun journal ou fichier arbitraire.
- `stop` soumet un drain séparé, qui attend la sortie de l’application sans
  timeout ni SIGKILL, puis arrête le helper, masque les deux services et ne
  demande poweroff qu’après les dernières vérifications. L’heure et le panneau
  n’ont pas à être valides pour demander l’arrêt.

Le chemin historique sans lifecycle reste limité aux deux services déjà
inactifs et masqués. Il vérifie aussi PID et absence de job ; toute étape
incomplète bloque désormais le poweroff.

Une réponse de soumission ne signifie pas que l’application est prête ou le
Pi éteint. Un timeout du client SSH n’annule pas le worker systemd. Les états
et limites du premier essai sont détaillés dans le [contrat lifecycle](TEST-ACCESS-LIFECYCLE.md).

Les requêtes sont sérialisées par un verrou exclusif non bloquant sous `/run`.
Les données app, identités et clés ne sont ni effacées ni réinitialisées.
La CLI de production ne propose aucun mode fixture ou rootfs alternatif.

## Installation et binding privés

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

Le configurateur et l’orchestrateur de cette transition sont intégrés à la
variante privée. Le [vérificateur de retour v2](TEST-ACCESS-IMAGE.md#vérification-du-retour)
prépare la confiance SSH après comparaison complète ; son premier retour
physique reste à vérifier. La présence du marqueur seule
n’ouvre aucun réseau ni service. Les images génériques restent dépourvues
de ces données privées.

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
changement d’heure ou activation app n’est effectué par ce module. Le nouvel
orchestrateur vérifie de nouveau l’état immédiatement avant connexion. Les locks et
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
du runtime ainsi que quatre contrôles de signature des paramètres privés.
Le runtime couvre : preflight natif avec les fichiers d’un enrôlement **synthétique**,
refus d’activation, requêtes incorrectes, changements de bindings, verrou réel
et stdin SSH sans fin transmis pendant plus de cinq secondes. Le preflight
est natif dans cette copie Linux ; il n’observe pas un Pi.

Les quatre contrôles de signature exécutent le vrai OpenSSH et le vérificateur
de capsule dans cette même copie : signature valide, message modifié, mauvaise
clé et binding différent. Les seules clés utilisées sont celles créées pour
le banc. Aucun profil réseau n’est installé.

L’algorithme `stop` utilise exclusivement un adaptateur fixture dans ce banc.
Aucun `systemctl stop`, mask ou poweroff réel n’y est exécuté. Le nettoyage
contrôle processus, montages, loop device et suppression de la seule copie
jetable. Les rapports n’exportent ni clés ni diagnostics SSH bruts.

## Essais restants

Le premier boot du nouveau candidat doit créer sa propre identité. Il ne
réutilise aucune identité obtenue avec l’image historique. Le retour offline,
la capsule signée, la connexion réelle, le welcome et le premier arrêt pendant
refresh restent à exercer sur la SD dédiée.

La [préparation locale des paramètres signés](TEST-ACCESS-CAPSULE.md) et
l’importeur au boot sont intégrés. Le reçu de préparation n’est jamais une
autorisation de connexion ; le Pi revalide la capsule et ses bindings.
