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

**SD v1 préparée et éjectée le 3 octobre 2026.** La CI du commit `93aa88d` est
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

## Complément v2 — retour physique récupéré

La version du commit `dcfedeb` de
[detail-enrollment-observers.py](../scripts/detail-enrollment-observers.py),
utilisée pour ce boot, est relue au SHA-256
`33421c00f8368ef92e09141b10f28ec33c3392afbba9e53bf6bf776c3e858512`.
Les suites ciblées v1/v2 passent **30 tests sur Mac et 30 sur Linux ARM64**.
La [preuve de préparation v2](validation/2026-10-03-observer-detail-preparation.json)
consigne les pins et le périmètre des essais.
Ces fixtures vérifient notamment les sorties fermées, le pin v1, la conservation
des gardes et le refus du rejeu ; elles ne constituent pas un boot du Pi.
**Le boot et l'arrêt v2 sont observés sur le banc ; le rapport est récupéré.
Le panneau et la radio restent non qualifiés.**
La [preuve SD v2](validation/2026-10-03-observer-detail-sd.json) consigne la CI
verte du commit `dcfedeb`, la relecture FAT readonly et la conservation exacte
des quatre fichiers antérieurs. Seuls le nouveau script et `cmdline.txt` sont
écrits ; l'original de la ligne de boot reste sauvegardé en privé.

Ce boot utilise `/boot/firmware/inkyos-observer-detail.py`, écrit
`inkyos-observer-detail.json` et réserve `.inkyos-observer-detail.started`.
Il conserve le mécanisme systemd décrit plus bas, avec le chemin du script v2.
Après l'arrêt et le retour de la carte, le rapport est récupéré et la ligne de
boot originale restaurée, en conservant les artefacts des deux essais.

Le script charge uniquement le diagnostic v1 épinglé par SHA-256 et conserve
ses gardes système, profil, identité et services. Ses noms de script, rapport
et réservation sont distincts ; les artefacts v1 restent conservés. Le profil,
l'état d'enrôlement et l'identité existante doivent toujours rester inchangés.

- **EEPROM** : export limité à `width`, `height`, `color_code`,
  `display_variant` et au booléen `reviewed_catalogue_match`. Un tuple inconnu
  reste accompagné de `eeprom_unreviewed` ; aucune entrée de catalogue ou
  sélection de driver n'est ajoutée. Révision PCB et timestamp sont omis.
- **Radio** : une collecte par l'adapter existant alimente trois parsers
  indépendants : firmware, regulatory et channels. Un parser en échec ne
  supprime plus les données validées par les autres. Les résumés structurels
  exposent seulement compteurs, flags connus et libellés pays validés ; aucun
  texte brut, identifiant radio ou message d'exception arbitraire n'est copié.
  Une requête indisponible bloque encore la collecte complète de l'adapter.

Les accès matériel restent ceux des sondes épinglées. Aucun country setter,
scan, association Wi-Fi, refresh écran, accès SSH ou lancement applicatif
n'est ajouté. Les résultats gardent `firmware_tuple_qualified=false` et
n'autorisent aucune activation ou qualification.

### Résultats et restauration — 3 octobre 2026

Le [retour v2](validation/2026-10-03-observer-detail-return.json) passe les
**10 contrôles de cohérence**, dont l'état inchangé, et les **cinq gardes des
sondes**. `/dev/i2c-1` et `wlan0` sont présents. Le démarrage et l'arrêt sont
observés par l'opérateur ; le rapport, écrit avant poweroff, ne prouve pas
à lui seul cet arrêt.

- **EEPROM** : `width=800`, `height=480`, `color_code=4`, `display_variant=20`,
  `reviewed_catalogue_match=false`, erreur `eeprom_unreviewed`. Upstream
  sélectionnerait AC073TC1A 800×480 d'après la variante 20, mais ne donne aucun
  libellé EEPROM au code couleur 4. Le rapport conserve la référence initialement
  communiquée **Inky Impression 7,3″ PIM773**. Cette identification Spectra 6
  est depuis retirée : l’examen visuel du PCB corrobore l’ancienne famille sept
  couleurs, cohérente avec la variante 20. Le code couleur reste non interprété,
  et le bon driver physique non qualifié ; aucun refresh n’a été effectué.
  Le [suivi d’identification](DISPLAY-COMPATIBILITY.md#identification-du-banc)
  complète le rapport historique sans en modifier les mesures.
- **Radio** : firmware `country_abbrev=XY`, `ccode=XY`, `revision=0` ; parser
  regulatory réussi, avec global `00`, PHY `99` et header `plain`. Le parser
  channels échoue : un header Wiphy correspond à la cible, 14 tokens de
  fréquence sont rejetés par le contrôle d'entier, aucune ligne de bande
  2,4 GHz n'atteint l'analyse détaillée. Cela ne signifie pas que le matériel
  ne propose aucun canal. Aucun pays n'est appliqué.

Les bytes originaux de `cmdline.txt` sont restaurés puis relus en FAT readonly ;
les **sept fichiers** de rapports, scripts et réservations sont conservés.
La SD reste connectée en lecture seule au terme de ce contrôle. Aucune nouvelle
acquisition complète ext4 n'est réalisée et aucune clé privée n'est ouverte.

Le [comparatif avec les sources officielles](HARDWARE-SOURCES.md) établit un
défaut de compatibilité du parser : `iw 6.9` peut imprimer une fréquence avec
le suffixe `.0`, rejeté par la version installée sur la SD. Les données brutes n'étant pas conservées,
les 14 rejets ne prouvent pas 14 suffixes `.0` et ne permettent pas de reconstruire
canaux, puissances ou flags. Le correctif strict, sans conversion `float`, est
livré dans les sources seulement ; il n'est pas installé sur la SD. La
[preuve logicielle](validation/2026-10-03-iw-frequency-parser.json) consigne
**595 tests sur Mac et Linux ARM64**, sans échec, avec respectivement quatre
et un tests ignorés. Elle couvre aussi les lignes de capacités `short GI for
40 MHz`, qui doivent être ignorées par le parser des fréquences.

Les pins radio → diagnostic v1 → détail v2 des sources sont mis à jour ensemble
pour les prochains builds. Ils ne désignent plus les fichiers historiques de
cette SD : ne pas copier isolément un diagnostic actuel sur l'ancien rootfs.
Les 30 tests cités plus haut et les preuves du boot conservent leurs anciens
hashes. Une nouvelle observation matérielle sera nécessaire après intégration.

## Comparaison radio v3 sur la carte déjà enrôlée

Le pin du preflight conservé par le diagnostic d'observation est `fdf5a12b…`,
celui de l'ancien rootfs d'enrôlement. Le prochain parent applicatif `c31b13af`
utilise un nouveau preflight `9cda15bf…` ; il ne remplace pas ce pin historique.
Une fixture exacte conserve les anciens octets pour les tests, qui vérifient
aussi le refus du nouveau helper avant tout import. Cette compatibilité de
hash ne rend pas les diagnostics interchangeables entre les images.

Le [comparateur](../scripts/compare-enrollment-radio.py) prépare une nouvelle
observation du correctif radio sans reflasher la SD ni remplacer les sondes
installées. Il charge le **v2 historique** au hash `33421c00…`, qui charge le
v1 historique `1a7e96e5…` et garde ses pins rootfs. Le parser corrigé
`8423207c…` est une source FAT distincte : seule sa fonction `parse_channels`
est utilisée, jamais son adapter matériel. Ce montage est volontairement lié
à ce banc historique ; ce n’est pas l’installation du correctif dans l’image.

L’adapter radio historique collecte **un seul échantillon**. L’analyse v2 reste
dans les champs existants ; `corrected_channels` contient le résultat du parser
corrigé sur les mêmes bytes. `same_sample=true` indique ce partage seulement
si la collecte a été validée. Une erreur de collecte ne déclenche aucun second
essai. Aucun texte brut, identifiant radio, scan ou setter de pays n’est ajouté.
L’EEPROM n’est pas relue par ce diagnostic radio.

La [preuve de préparation logicielle](validation/2026-10-03-radio-compare-preparation.json)
consigne **616 tests sur Mac et Linux ARM64**, sans échec, et trois cas de
comparaison par hôte utilisant les sources historiques exactes avec I/O inertées.
Les contrôles du writer FAT passent dix fixtures ; une revue indépendante
couvre le comparateur et ce writer. Ces résultats n’établissent aucun nouveau
boot physique ni qualification radio.

**SD préparée et éjectée le 3 octobre 2026.** La CI de `88782a6` est verte.
Les deux nouvelles sources et la ligne de boot temporaire sont relues après
remontage FAT readonly ; les sept artefacts antérieurs restent identiques.
La [preuve de préparation SD](validation/2026-10-03-radio-compare-sd.json)
ne revendique ni nouvelle acquisition raw/ext4 ni boot v3 observé.

Deux nouveaux fichiers sont nécessaires sur FAT : `inkyos-radio-compare.py`
et `inkyos-radio-parser.py`. Le rapport `inkyos-radio-compare.json` et la
réservation `.inkyos-radio-compare.started` ont leurs propres noms ; les anciens
scripts, rapports et réservations restent conservés. Les sources supplémentaires
sont vérifiées avant les sondes et à la vérification finale de l’état inchangé.
Les gardes d’enrôlement, identité, firstboot et services masqués restent celles
du v1 ; l’application, le helper, SSH et NetworkManager ne sont pas activés.

Le boot temporaire conserve le mécanisme systemd ci-dessous en remplaçant
uniquement le chemin du script par `/boot/firmware/inkyos-radio-compare.py`.
Succès et échec demandent toujours poweroff. Au retour, conserver le rapport,
vérifier les sources et les contrôles fermés, puis restaurer la ligne de boot
originale. Un rapport de comparaison réussi ne qualifie ni le pays Wi-Fi, ni
une connexion, ni l’écran ou l’appairage iOS.

### Retour v3 incomplet et candidat à nom court — 3 octobre 2026

Le [retour conservé](validation/2026-10-03-radio-compare-return.json) confirme
la ligne de boot préparée, les sept artefacts antérieurs et le parser corrigé.
L’opérateur observe le boot et l’arrêt, mais **aucun claim ni rapport v3 n’est
présent**. Le script manque sous le nom attendu. Ses **8 057 octets sont
retrouvés à l’identique sous `FSCK0000.000`**, hash `9bfdebc6…` ; un second
fichier `FSCK0000.001` est aussi conservé. L’exécution du comparateur et le
résultat radio ne sont donc pas établis.

Dans [dosfstools 4.2](https://github.com/dosfstools/dosfstools/blob/v4.2/src/check.c#L237),
`auto_rename` produit ce type de nom et retire le nom long associé, notamment
pour un nom court invalide ou un alias dupliqué. Cette correspondance indique
une piste de renommage ; sans l’ancien répertoire brut ni journal fsck, le
motif précis n’est pas démontré. Elle ne prouve pas des clusters orphelins,
une carte défectueuse ou une suppression par le diagnostic.

Le contrôle Mac `diskutil verifyVolume`, qui exécute **`fsck_msdos -n`**, termine
à zéro sans réparation demandée. Il vérifie l’état actuel, pas l’état avant
renommage. L’accès raw à la partition reste refusé par les permissions macOS.
Les deux fichiers récupérés sont sauvegardés en privé et conservés sur la carte.
Seule la ligne de boot normale est restaurée, puis relue en FAT readonly ;
les dix autres fichiers contrôlés restent identiques.

Le candidat actuel utilise **`/boot/firmware/INKYCMP.PY`**, nom court 8.3
explicite, à la place de l’ancien nom long. Les pins v1/v2/rootfs/parser et le
comportement de comparaison restent inchangés. Les 616 tests et les trois cas
du banc historique passent à nouveau sur Mac et Linux ARM64. Ce contournement
n’établit pas la cause de l’incident : préparer d’abord ce fichier avec le boot
normal conservé, puis contrôler sa persistance après retrait/réinsertion au Mac
avant d’armer un nouveau boot du Pi. Aucune preuve historique n’est réécrite.

Le [stage à nom court](validation/2026-10-03-radio-short-sd.json) est réalisé
depuis `72143c7`, CI verte : seul `INKYCMP.PY` est ajouté, puis relu après
remontage readonly. Les onze fichiers contrôlés, dont la ligne de boot normale
et les deux fichiers récupérés, restent identiques. La carte est éjectée pour
un contrôle de retrait/réinsertion **au Mac**. Le hook de diagnostic reste
désactivé ; cette préparation ne demande pas encore un boot du Pi.

Le [contrôle après réinsertion et l’armement suivant](validation/2026-10-03-radio-short-armed.json)
sont ensuite terminés. Une nouvelle identité média est figée ; les douze
fichiers relus en FAT readonly correspondent au stage, dont `INKYCMP.PY`
(`d851db37…`) et la ligne de boot normale. Aucun nouveau nom de récupération,
claim ou rapport de comparaison n’est présent. Seule `cmdline.txt` est ensuite
remplacée pour exécuter `/usr/bin/python3 -I /boot/firmware/INKYCMP.PY`, avec
ENROLL masqué et poweroff demandé en succès comme en échec. Un fichier
temporaire à nom court `INKYRUN.TMP` est créé exclusivement puis renommé.
Après remontage readonly, la ligne préparée et les onze autres fichiers sont
vérifiés, puis la carte est éjectée. Cette preuve porte uniquement sur la
préparation ; ni relecture raw indépendante ni nouvelle inspection ext4
ne sont revendiquées.

### Retour du comparateur à nom court — 3 octobre 2026

Le [nouveau retour physique](validation/2026-10-03-radio-short-return.json)
contient cette fois le claim et le rapport. Les douze fichiers préparés sont
identiques, `INKYCMP.PY` garde son nom et aucun nouveau fichier `FSCK` n’est
apparu. Les quatre pins correspondent aux sources attendues ; dix contrôles
et cinq gardes passent, avec `completed=true`, `live_evidence=true` et
`state_unchanged=true`.

Sur **une même collecte** (`same_sample=true`), l’ancien parser renvoie
`kernel_observation_invalid`, tandis que le corrigé accepte quatorze canaux :
1–13 annoncés actifs à 2 000 mBm et 14 désactivé. Il s’agit des valeurs
rapportées par le driver, pas de transmissions mesurées. Le firmware reste
`XY/XY`, révision 0, et le kernel global `00` / PHY `99` ; aucun pays n’est
appliqué et aucune connexion n’est qualifiée. L’observation écran n’est pas
demandée. Cette preuve clôt la comparaison du parser sur ce banc, sans
installer le correctif dans le rootfs ni établir la cause du renommage FAT.

Après sauvegarde privée et validation du retour, seule la ligne de boot
originale est restaurée. Les treize autres fichiers, dont le nouveau rapport,
le claim et les deux fichiers récupérés, restent identiques après remontage
FAT readonly. La carte reste sur le Mac en lecture seule ; aucun autre boot
de diagnostic de parsing n’est préparé.

## Mécanisme v1 limité à la partition FAT

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
