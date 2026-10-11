# Diagnostic du boot réseau TEST

État au **11 octobre 2026**. Le nouveau reçu persistant localise l'arrêt à
l'activation de la connexion : import, garde Wi-Fi, pays et demande d'allumage
radio passent ; la connexion échoue et la radio est refermée. La cause exacte
reste inconnue. Aucune connexion Wi-Fi ou SSH réussie n'est établie.

Les retours historiques et le [dernier relevé réduit](validation/2026-10-11-network-activation-return.json)
sont distingués ci-dessous. Aucun ne qualifie l'écran ou l'appairage iPhone.

## Retour historique sans diagnostic persistant

- Copie complète de la SD acquise en lecture seule, relue localement et
  vérifiée par hash. L'original et tous les paramètres restent privés.
- Analyse dans la VM Linux dédiée, avec loop en lecture seule, ext4
  `ro,noload` et FAT `ro`, sans exécuter le code de la SD. Démontages et
  détachement du loop vérifiés après lecture.
- État d'enrôlement `enrolled`, profil cohérent ; cache d'accès `imported`
  complet avec exactement les quatre fichiers attendus.
- Hashes du profil, de la clé publique au format wire SSH, du manifeste
  runtime, de la capsule, de sa signature et du profil réseau cohérents.
  Capsule et signature en cache identiques aux fichiers installés sur FAT.
- Configuration opérateur absente ; état NetworkManager enregistré avec
  `WirelessEnabled=false` ; aucun profil de connexion persistant.
- Répertoire des journaux persistants vide et absence de `syslog`.

L'import a donc abouti au moins une fois. Le cache n'est ni incomplet ni
bloqué dans l'état `importing`. L'absence de configuration opérateur ne prouve
pas à elle seule qu'aucune association Wi-Fi n'a jamais eu lieu. L'état radio
sauvegardé peut provenir du verrou initial ou du nettoyage après échec.

## Limites

Le système de fichiers demande une récupération de journal après la coupure
d'alimentation ; aucun replay ni réparation n'a été effectué. Les fichiers
persistants peuvent être antérieurs au dernier boot. Les fichiers sous `/run`
et les journaux volatils ne survivent pas à l'arrêt.

Pour limiter la duplication, l'analyse utilise une dérivée contenant les
blocs ext4 utilisés, y compris les données de fichiers, et le préfixe MBR/FAT
original. Ses hashes ont été vérifiés au transfert et à la lecture dans la VM.
La copie complète est conservée ; les blocs ext4 libres ne font pas partie de
cette dérivée. L'acquisition n'était pas protégée contre toutes les écritures
automatiques de macOS dès l'insertion.

## Rapports persistants de la variante diagnostique

Le runtime conserve deux petits fichiers sous
`/var/lib/inkyos-test-diagnostics`, répertoire root `0700` créé par systemd :

- `last-wifi-gate.json` : résultat du verrou WLAN précédant NetworkManager,
  après validation de ses sources.
- `last-boot.json` : marqueur initial incomplet, puis résultat final après
  nettoyage, avec l'étape atteinte et les observations d'import, de connexion
  et du contrôle pays lorsqu'elles sont disponibles.

Chaque fichier est root `0600`, borné à 8 Kio et remplacé atomiquement avec
fsync et relecture. Le schéma ne conserve que des erreurs énumérées et des
booléens, jamais de SSID, mot de passe, clé ou sortie brute de commande.
Un identifiant aléatoire de boot du kernel permet uniquement de rapprocher
les deux reçus privés ; ce n'est pas une identité de cadre et il n'est pas
destiné à un export public.

Ces observations ne sont jamais une autorisation de connexion ou d'activation.
L'`ExecCondition` SSH n'écrit aucun diagnostic. Une erreur de stockage est
ignorée après les opérations métier ; elle ne relâche aucun contrôle radio.
La persistance possède son propre budget de deux secondes dans un enfant :
au dépassement, le parent demande sa fin et poursuit sans attente bloquante.
Une attente kernel non interruptible peut retarder la fin effective de
l'enfant, qui reste dans le cgroup du service.

Un temporaire laissé par une écriture interrompue est conservé pour analyse,
sans réparation automatique. Il peut empêcher les écritures suivantes. Un
reçu ancien peut aussi subsister si les sources ne passent pas les contrôles
initiaux, si le disque est plein ou si le service est tué. Même un identifiant
de boot commun ne prouve donc pas que les reçus représentent le dernier essai.
`complete=true` signifie que la procédure s'est terminée, pas qu'elle a réussi.
Un marqueur incomplet ne localise pas précisément une interruption ultérieure.

Le banc `scripts/probe-test-diagnostic-storage.py`, exécuté comme root dans
la VM Linux ARM64 marquée, crée un service systemd temporaire et inerte avec
`ProtectSystem=strict`, `PrivateNetwork=yes`, `StateDirectory` privé et les
mêmes primitives d'écriture. Il vérifie création, remplacement, permissions,
persistance après sortie et refus d'écriture hors du répertoire autorisé.
Il ne lance ni NetworkManager, ni radio, ni application.

Le retour réseau décrit ci-dessus ne contient pas encore cette instrumentation.

Deux fragilités ont été reproduites sur fixtures : le périphérique rfkill
peut manquer au premier relevé, et le readback du pays peut arriver après
la première observation. Aucune n'est encore identifiée comme la cause
matérielle de cet échec. Ne pas les transformer en diagnostic confirmé.

Modifier le runtime change son manifeste, lié au profil d'enrôlement et à la
capsule. Un remplacement isolé des scripts sur la carte invaliderait ces
bindings. La nouvelle variante a donc été construite et vérifiée avec un nouvel
enrôlement, sans modifier le protocole Studio ni affaiblir les contrôles existants.

Le [relevé réduit](validation/2026-10-10-test-access-boot-return.json) ne contient
aucun identifiant de carte, clé, hash de copie privée ou paramètre réseau.

## Retour de la nouvelle variante

Le [nouvel enrôlement vérifié](validation/2026-10-10-diagnostic-sd-enrollment-return.json)
passe 35 contrôles ext4/FAT et 10 contrôles d'infrastructure sur un dérivé
e2image privé ; l'acquisition intégrale est conservée. Les deux rapports
persistants sont présents avec les permissions privées attendues. La garde
Wi-Fi rapporte dix contrôles réussis. Le rapport de boot contient son marqueur
initial incomplet : ce n'est pas une preuve de l'étape d'une panne.

Une nouvelle capsule liée à cet enrôlement a été signée, installée et relue,
puis la carte éjectée. Le boot réseau suivant a été effectué ; son retour est
décrit ci-dessous, séparément de la validation d'enrôlement.

## Retour réseau du 11 octobre 2026

La lecture ciblée des deux reçus par `debugfs` 1.47.4, en mode read-only,
a réussi après vérification de l'identité du média et du binding du rapport
FAT. Aucun montage ext4, replay du journal, accès aux fichiers de clés ou
lecture de la capsule réseau n'a été effectué par cette inspection. Le
`PASS` porte sur la lecture ; le [relevé public](validation/2026-10-11-network-activation-return.json)
indique `CONNECTION_FAILED` pour le résultat de connexion observé.

- La garde Wi-Fi rapporte ses dix contrôles réussis.
- `last-boot.json` est complet, à l'étape `connect`. L'import signé a réussi,
  avec un nouvel import plutôt qu'une réutilisation du cache.
- Le profil runtime est exact, chargé et restreint ; les bindings et
  l'inventaire passent les contrôles précédant l'allumage radio.
- Le contrôle pays rapporte des observations live cohérentes pour FR :
  firmware, kernel et canaux autorisés passent les contrôles.
- La commande d'allumage radio est acquittée, puis l'activation de connexion
  échoue : `radio_enable_acknowledged=true`, `connection_acknowledged=false`,
  erreur `connection_failed`.
- Le nettoyage demande l'arrêt radio, reçoit son acquittement et vérifie
  l'état désactivé. Aucun démarrage SSH n'est demandé par ce reçu.

Les contrôles placés après l'activation restent à `false` parce qu'ils n'ont
pas été atteints ; ils ne décrivent pas plusieurs échecs indépendants. Le reçu
ne conserve ni le code de retour d'activation ni sa raison précise. Il ne
permet donc pas de conclure à un mauvais mot de passe, à une incompatibilité
du point d'accès ou à un défaut de disponibilité de l'interface.

Le système ext4 demande une récupération de journal ; aucun replay ni
réparation n'a été effectué. Des mises à jour en attente peuvent donc manquer
et les reçus peuvent précéder le dernier boot. Cette inspection ciblée ne
répète pas l'acquisition complète ni les 35 + 10 contrôles d'enrôlement.
Le démontage préalable peut vider des écritures déjà en attente dans macOS :
l'absence d'écriture émise par l'outil ne constitue pas une protection contre
toutes les écritures depuis l'insertion.

Le relevé public ne contient que la projection fermée des diagnostics et
les limites de qualification. Les identifiants de boot, leur corrélation,
les timestamps et les traces de commandes restent privés.

## Recherche des journaux existants

L'[inventaire ciblé du 11 octobre](validation/2026-10-11-system-log-inventory.json)
a réussi en lecture seule, avec binding FAT et contrôles d'identité du média.
Le répertoire `/var/log/journal` est présent mais vide. Aucun journal système
sélectionné ni fichier `/var/log/syslog`, `/var/log/daemon.log` ou
`/var/log/wpa_supplicant.log` n'a été trouvé : zéro fichier, zéro octet copié.
Cette recherche ne fournit donc aucune raison supplémentaire de l'échec
d'activation.

La sélection couvre uniquement les noms de journaux système autorisés sous
des sous-répertoires de journal à nom hexadécimal de 32 caractères et les
trois fichiers texte ci-dessus. Les journaux utilisateur et fichiers
auxiliaires restent hors périmètre. Aucun contenu brut n'est publié.
Le journal ext4 demande toujours une récupération et n'a pas été rejoué ;
des écritures en attente peuvent manquer. Ce résultat ne démontre pas une
absence globale ou forensique de traces sur la carte, ni leur absence lors
du dernier boot. Aucun nouveau démarrage ou essai réseau n'a été effectué
par cet inventaire.

## Diagnostic ajouté après ce retour

Les sources conservent désormais le code de retour connu de `nmcli up`, si
disponible, et deux indicateurs de budget : disponibilité des 37 secondes
d'attente externe avant l'appel et épuisement du budget à sa sortie. Une
commande sans résultat reste indéterminée : le runner commun ne distingue
pas un timeout, une sortie trop grande ou une erreur de lancement.

Sur échec seulement, une lecture de `GENERAL.STATE` et `GENERAL.REASON`
observe l'interface avant l'arrêt radio. Elle est limitée à une seconde dans
le budget de travail restant ; la réserve de nettoyage reste protégée.
Seuls les codes numériques autorisés par NetworkManager 1.52 sont conservés,
jamais les libellés, SSID, secrets ou sorties brutes. La projection du boot
revalide indépendamment ces valeurs. Aucun nouvel essai de connexion, scan
ou changement des contrôles pays n'est ajouté.

Les [codes de sortie nmcli](https://networkmanager.dev/docs/api/1.52.0/nmcli.html#exit_status)
et les [états et raisons d'interface](https://networkmanager.dev/docs/api/1.52.0/nm-dbus-types.html)
décrivent des observations distinctes : un état relu après l'échec peut déjà
avoir changé et ne prouve pas à lui seul un mauvais mot de passe.
Cette extension n'est pas présente sur la SD du retour réseau ci-dessus ;
son chemin d'échec de connexion attend encore un essai sur le Pi.
Une [nouvelle image privée](validation/2026-10-11-nm-diagnostic-access-image.json)
est construite depuis les sources `07271cf` : 18 contrôles de configuration,
17 du parent, 62 système et 26 applicatifs passent. Le backend épinglé ne
change pas. Cette image a depuis été flashée et relue. Après le premier
démarrage, le [rapport FAT revenu](validation/2026-10-11-nm-diagnostic-enrollment-preliminary.json)
correspond au nouveau profil. Le [retour natif vérifié](validation/2026-10-11-nm-diagnostic-enrollment-return.json)
passe désormais ses propres 35 contrôles d’enrôlement et 10 contrôles
d’infrastructure. Un dérivé `e2image` est transmis directement de la SD vers
la VM, sans copie intégrale intermédiaire ni rejeu du journal ; le hash du
flux et sa relecture concordent. Le nouveau contexte privé est exporté après
nettoyage vérifié ; sa capsule signée est installée et relue, puis la SD éjectée.
Aucune connexion Wi-Fi réussie ni cause matérielle de la panne n’est encore établie.
Les [1 039 tests macOS et Linux ARM64](validation/2026-10-11-activation-diagnostics-tests.json)
passent, avec une revue indépendante du bornage et de la projection.
Le lecteur hors ligne de la future image devra être mis à jour et épinglé
pour valider le nouveau champ `connection.activation` ; les lecteurs de
l'ancienne SD conservent leur schéma actuel.

## Attente de disponibilité radio

Une course est reproduite en simulation : l’acquittement de `nmcli radio wifi on`
peut précéder la disponibilité du périphérique, alors que le connecteur demandait
immédiatement l’activation. Dans NetworkManager 1.52.1, la [commande radio](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/nmcli/general.c#L1058-L1102)
acquitte la propriété ; l’[interface supplicant démarre de façon asynchrone](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/devices/wifi/nm-device-wifi.c#L3292-L3312).
Ce défaut de synchronisation n’est pas encore identifié comme la cause du boot réel.

Les sources corrigées attendent `wlan0` managed, état 30 (disconnected), sans UUID
actif, avec des pauses de 250 ms au plus entre lectures, pendant 10 secondes au maximum.
Le budget global reste 90 secondes : l’attente préserve 37 secondes pour l’unique
activation, 9 pour les contrôles suivants et les 6 de nettoyage, avec marge de
terminaison de commande. Aucun scan ni second essai d’activation n’est ajouté.
Une sortie invalide, un délai dépassé ou un budget insuffisant provoque le nettoyage.
Le schéma est inchangé : `radio_enable_acknowledged=true` signifie maintenant
acquittement **et disponibilité** ; `radio_enable_failed` inclut l’échec de cette attente.
Les anciens reçus conservent leur sens antérieur. En sortie terse, un
[UUID inactif nul](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/nmcli/devices.c#L229-L231)
devient une [ligne vide](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/nmcli/utils.c#L1068-L1074), vérifiée strictement.

Les [tests de la correction](validation/2026-10-11-radio-readiness-tests.json)
passent : 39 ciblés relus indépendamment, puis 1 047 sur macOS et Linux ARM64.
Ils couvrent notamment readiness retardée, absente ou invalide, budgets et activation
unique. Ils ne réalisent aucune association Wi-Fi physique ou simulée par hwsim.
La SD du retour réseau analysé provenait des sources `07271cf`. La
[nouvelle image corrigée](validation/2026-10-11-radio-readiness-access-image.json)
est construite depuis `2e435c9` ; son flash et sa relecture sont maintenant vérifiés.

## Retour avec état du périphérique

Le [relevé réduit](validation/2026-10-11-network-device-state-return.json)
provient de la lecture ciblée des deux rapports de la SD issue de `07271cf`.
L’import, la garde radio et les contrôles du pays passent. L’activation renvoie :

| Champ | Valeur observée | Sens dans NetworkManager 1.52.1 |
|---|---|---|
| Sortie nmcli | 4 | Échec d’activation ; ce n’est pas le code dédié au timeout (3). |
| État wlan0 | 20 | Périphérique pris en gestion, mais indisponible. |
| Raison d’état | 2 | Périphérique désormais pris en gestion. |

Sources officielles : [codes nmcli](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/nmcli/nmcli.h#L14-L28),
[états et raisons](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/libnm-core-public/nm-dbus-interface.h#L475-L525).
La raison décrit le changement d’état ; ce n’est pas nécessairement la cause
de l’échec d’activation. Le budget complet est disponible et le budget de travail
n’est pas épuisé.

Dans les sources de la SD, cet état est lu après l’échec de la commande, **avant**
notre nettoyage qui désactive la radio. Il n’est donc pas produit par cette
coupure. La disponibilité tardive est une hypothèse mieux étayée, que corrige
`52ddfc1`, mais cet échantillon ne constitue pas un historique des transitions.
Il ne prouve ni la cause exacte ni un rejet du mot de passe.

Les deux rapports partagent le même identifiant de boot, conservé en privé.
La lecture et ses contrôles de média passent ; le système de fichiers demande
une récupération et aucun journal n’est rejoué. Les horodatages ne permettent
pas d’attester indépendamment qu’il s’agit du dernier boot. La correction
est désormais intégrée à une image, mais reste à valider sur le Pi ; SSH, BLE
et l’appairage iOS restent non qualifiés.

## Image intégrant l’attente radio

La recette `2e435c9`, contenant la correction `52ddfc1`, produit une image privée
de 3 061 841 920 octets à partir du parent figé, sans reconstruire le backend.
Les 123 contrôles offline passent : 18 de configuration, 17 du parent préparé,
62 du système et 26 de l’application. Le hash du connecteur corrigé est vérifié
dans la recette et l’inventaire de l’image. Aucun secret réseau n’est incorporé.

L’image est [flashée, relue et éjectée](validation/2026-10-11-radio-readiness-sd-flash.json).
L’éjection initiale était bloquée par macOS ; une récupération séparée sur le
même média a réussi, sans relancer l’écriture. Le reçu initial est conservé.
La recette conserve le parcours de test :
premier boot d’enrôlement et arrêt, retour SD pour les 35 + 10 contrôles,
puis installation d’une capsule nouvellement signée avant le boot réseau.
Le changement de manifeste interdit de réutiliser l’ancien contexte ou de
remplacer seulement le connecteur sur la SD existante.
