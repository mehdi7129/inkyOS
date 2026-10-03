# Diagnostic des sondes sur la SD déjà enrôlée

Le retour du 3 octobre passe les 21 contrôles de cohérence ext4/FAT,
mais les observations écran/radio sont `blocked`. Le runtime d'enrôlement
a réduit leurs erreurs à cet état ; aucun journal persistant ne permet
d'en retrouver la cause. L'inspection readonly confirme les scripts installés,
la configuration I²C/SPI et la présence de `iw`.

Le boot diagnostic exécute les deux sondes existantes et conserve leurs erreurs
et checks fermés. Il utilise la même Qumox 16 Go, sans reflash, changement
de protocole, régénération de clé ou lancement applicatif. Ce diagnostic
ne qualifie ni le panneau, ni la radio, ni le parcours iOS.

La [preuve de préparation](validation/2026-10-03-observer-diagnostic-preparation.json)
lie les sources, les 18 tests ciblés sur Mac et Linux ARM64 et les 14 contrôles
natifs des generators. Ces essais ne démarrent aucune unité sur le Pi.

**SD préparée et éjectée le 3 octobre 2026.** La CI du commit `93aa88d` est
verte. Le script et la ligne de démarrage ont été relus après remontage FAT
readonly ; le rapport d'enrôlement précédent reste identique. L'original de
`cmdline.txt` est conservé localement. La
[preuve SD](validation/2026-10-03-observer-diagnostic-sd.json) distingue cette
préparation du retour physique décrit ci-dessous.

## Retour physique v1 — 3 octobre 2026

Le [rapport récupéré](validation/2026-10-03-observer-diagnostic-return.json)
passe les **10 contrôles de cohérence**, avec `state_unchanged=true`. Le script,
la ligne de boot préparée et l'ancien rapport d'enrôlement sont identiques
aux valeurs attendues. `/dev/i2c-1` et `wlan0` sont présents.

- **Écran** : les cinq gardes passent et 29 octets sont reçus. L'erreur
  `eeprom_unreviewed` signifie que le tuple EEPROM ne figure pas dans le
  catalogue accepté ; elle n'établit aucun modèle de panneau.
- **Radio** : `firmware_response_valid=true`, mapping `wlan0` valide et
  `country_abbrev` différent de `FR`, puis `kernel_observation_invalid`.
  Le rapport v1 ne distingue pas l'échec du parseur regulatory de celui des
  channels. Aucun pays n'est appliqué et la radio reste non qualifiée.

Les bytes originaux de `cmdline.txt` sont restaurés puis relus en FAT readonly.
Les anciens rapports, la réservation et le script sont préservés. Aucune
nouvelle acquisition ext4 n'est réalisée pour ce retour FAT ; les contrôles
ne constituent donc pas une nouvelle inspection exhaustive du filesystem.

Un complément **v2 est préparé dans les sources, mais n'est pas installé sur
la SD**. Il doit préciser l'en-tête EEPROM par des champs numériques fermés
et isoler les observations radio en échec, sans exporter de données brutes
ou d'identifiant. Aucun refresh écran ou lancement applicatif n'est autorisé
par ces résultats.

## Mécanisme limité à la partition FAT

Un script, `scripts/diagnose-enrollment-observers.py`, est copié sous
`/boot/firmware/inkyos-observer-diag.py`. Les bytes originaux de `cmdline.txt`
sont sauvegardés dans le dossier privé de préparation sur le Mac, puis le
fragment suivant est ajouté à sa ligne unique, en conservant tous les autres
paramètres :

```text
systemd.mask=inkyos-test-enrollment.service systemd.run="/usr/bin/python3 -I /boot/firmware/inkyos-observer-diag.py" systemd.unit=kernel-command-line.target systemd.run_success_action=poweroff systemd.run_failure_action=poweroff
```

Le mécanisme est celui utilisé par
[Raspberry Pi Imager](https://github.com/raspberrypi/rpi-imager/blob/v2.0.0/src/downloadthread.cpp#L1081)
pour son premier démarrage. Aucun script de personnalisation Imager n'est
repris. [systemd-run-generator](https://github.com/systemd/systemd/blob/v257/man/systemd-run-generator.xml)
crée une unité oneshot ; le
[debug-generator](https://github.com/systemd/systemd/blob/v257/man/systemd-debug-generator.xml)
masque ENROLL pour ce boot. Les actions succès **et** échec demandent poweroff.
La cible dédiée ne démarre pas la cible multi-user habituelle.

L'image retournée contient systemd `257.13-1~deb13u1` et les deux generators
root-owned exécutables ; `/boot/firmware` figure dans fstab en vfat/defaults.
Aucun ancien `systemd.run`, `systemd.unit`, `systemd.mask` ou `init=` n'est
présent dans sa ligne originale. Dans la VM, les mêmes generators passent
14 contrôles de sortie et `systemd-analyze verify` offline ; aucune unité n'est
exécutée et le manager reste inchangé. Le montage FAT reste à contrôler
effectivement au runtime : l'ordre systemd seul n'atteste pas son succès.

## Garde du script

Le script exige Linux ARM64/root et le Zero 2 W exact, puis une partition FAT
montée en écriture au chemin attendu. Une réservation exclusive interdit toute
réexécution dès le premier essai ; rapport ou fichier partiel préexistant
provoque également un refus. Aucun artefact existant n'est effacé.

Les scripts installés et l'unité firstboot sont épinglés par SHA-256 avant
leur emploi. Le profil final et l'état `enrolled` doivent être valides ;
l'identité firstboot doit déjà exister. Le fichier de clé privée n'est jamais
ouvert. App, helper, SSH et génération automatique des clés restent masqués
et arrêtés ; NetworkManager reste inactif, son état impose Wi-Fi désactivé
et aucun profil de connexion n'est ajouté.

Seul `inkyos-firstboot.service` est démarré explicitement, avec délai borné,
pour que les sondes retrouvent leur garde `active/exited/success`. Ce service
réconcilie l'identité existante ; son état, le profil d'enrôlement et l'état
`enrolled` doivent rester identiques après le démarrage et après les sondes.
Le timeout du client `systemctl` ne garantit pas l'annulation de son job ;
le service conserve sa propre limite et systemd demande l'arrêt à la fin.
Une attente bornée des devices précède les deux commandes existantes inchangées.
Aucun country setter, scan, association Wi-Fi, refresh écran, accès SSH ou
lancement applicatif n'est exécuté.

Le nouveau rapport FAT, `inkyos-observer-diag.json`, contient une projection
fermée des checks, erreurs, codes de sortie et contexte live. Aucun stdout ou
stderr arbitraire, challenge, hostname ou clé n'y est copié. Les données radio
partielles sont omises : `data=null` ne prouve pas une absence de réponse du
firmware. La radio renvoie normalement exit 1 même lorsque ses observations
sont complètes, car son tuple n'est toujours pas qualifié. Le runner existant
ne distingue pas timeout et sortie indisponible ; cette limite est conservée.

## Préparation et retour opérateur

1. Réidentifier la SD par device, capacité et objet IORegistry. Relier son
   rapport FAT exact à la copie complète déjà contrôlée ; conserver localement
   la ligne de boot originale et les pins du script préparé.
2. Contrôler les tests et la relecture du script. Préparer une écriture des
   deux fichiers seulement : publication exclusive du script, puis remplacement
   atomique de `cmdline.txt` en dernier, après relecture et synchronisation.
   Un fichier préexistant ou une identité média différente bloque la suite.
3. Remonter FAT readonly, relire les deux fichiers et le rapport d'enrôlement,
   puis éjecter proprement. La relecture filesystem ne devient pas une relecture
   raw indépendante de la SD.
4. L’opérateur insère la carte dans le Pi, l'alimente, constate l'arrêt puis remet
   la carte dans le Mac. Le rapport précède l'arrêt demandé et ne l'atteste pas.
5. Récupérer uniquement le petit rapport FAT, contrôler son schéma et le script
   préparé, puis restaurer les bytes originaux de `cmdline.txt` depuis leur
   sauvegarde vérifiée. Conserver les rapports et la réservation ; aucun cleanup
   ni rejeu automatique. La restauration doit être consignée séparément.

La lecture FAT suffira à diagnostiquer ces observations. Une nouvelle preuve
exhaustive ext4 demanderait une nouvelle acquisition complète. Le contexte de
cette unité diffère de celui de l'unité ENROLL durcie : un succès autonome
peut aider à isoler le timing ou les permissions, sans reproduire à lui seul
l'échec initial.
