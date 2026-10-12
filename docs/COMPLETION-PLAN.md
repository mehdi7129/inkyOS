# Finalisation commune InkyOS / Inky Studio

État du 12 octobre 2026. Une release est considérée prête lorsque les parcours
ci-dessous sont vérifiés ensemble, sur une image et un couple backend/iOS
épinglés. Une CI verte ou un modèle de protocole ne remplace pas ces essais.

## Parcours et responsabilités

| Parcours attendu | Travail restant | Responsable principal | Preuve attendue |
|---|---|---|---|
| Flasher puis allumer un Pi Zero 2 W | Intégrer et vérifier les prérequis système, conserver une image générique sans identité | InkyOS | Build ARM64, relecture SD, boot et partition agrandie |
| Premier allumage sans LAN | Raccorder reçu OS durable, identité usine et QR, bootstrap TLS, pays et heure | OS + backend + iOS | SD vierge, aucun Wi-Fi préconfiguré, adoption depuis un iPhone |
| Configurer le Wi-Fi depuis l'iPhone | Pays confirmé avant radio, transaction Bluetooth, résultat HTTPS et erreurs récupérables | Backend/iOS + garde OS | Bon et mauvais mot de passe, perte de liaison, nouvel essai |
| Envoyer une photo et voir le résultat | Remonter l'état et les erreurs réels du driver jusqu'à l'iPhone | Backend/iOS | Photo affichée, état busy cohérent, timeout sans rafraîchissement concurrent |
| Redémarrer un cadre adopté | Conserver identité, propriétaire, configuration et photos ; reconnecter sans nouvel appairage | OS + backend/iOS | Redémarrages répétés, coupure réseau, reconnexion |
| Changer de réseau | Confirmer la nouvelle liaison ou revenir à la précédente | Backend/iOS | Changement réel, échec, rollback et résultat après reconnexion |
| Arrêter et récupérer | Attendre l'écran et les écritures, fermer les services, rendre l'échec observable | OS + backend | Arrêt au repos et pendant un travail ; récupération après réponse perdue |
| Utiliser les écrans visés | Même release, détection cohérente, dimensions et palette correctes | Backend + recette OS | Qualification séparée de chaque modèle disponible |
| Publier une image | Release applicative commune, sources/paquets figés, licences et confidentialité | OS + Studio | Recette et rapports publics sans identité, clé, photo ni configuration privée |

La matrice détaillée des écrans reste dans [DISPLAY-COMPATIBILITY.md](DISPLAY-COMPATIBILITY.md).
Un modèle indisponible reste explicitement non qualifié ; aucune preuve d'un
autre écran ne lui est transférée.

Le candidat driver de la [PR Studio #34](https://github.com/mehdi7129/inky-studio/pull/34)
épingle `inky==2.5.0` au commit `5671ba4`, avec sept contrôles CI réussis ;
la PR reste draft et non fusionnée. Il prépare les Spectra 4″, 7,3″ et 13,3″
et les Impression sept couleurs, dont le 5,7″. La fermeture native ARM64,
les pins du nouveau bundle et chaque panneau physique restent à qualifier.
Le catalogue de modèles et les tests BUSY ne prouvent pas l'affichage réel.
Le couple TEST actuel conserve son driver 2.3.0 jusqu'à livraison qualifiée
d'un candidat commun.

## Ordre de réalisation

1. Qualifier la nouvelle image TEST : retrouver un accès SSH authentifié,
   vérifier les prérequis Bluetooth/I²C/heure puis le parcours LAN accompagné
   welcome, photo, QR, adoption BLE et reconnexion HTTPS sur le matériel disponible.
2. Installer et qualifier la Phase A sans LAN : support et bundle épinglés,
   graphe PID1 et permissions réelles sous UID 1000, identité individuelle,
   QR affiché avant advertising, premier claim durable et drains au shutdown.
   Le reboot conserve owner, clé et reçu sans rouvrir l'adoption initiale.
3. Concevoir la Phase B en parallèle de cette qualification A. Après accord
   commun sur les interfaces, développer ses composants injectables et fixtures :
   admission owner/epoch/latch réservée, UTC, certificat, transition BLE normale,
   clôture durable, reprise du ledger factory v2, helper et pays Wi-Fi.
   L'installation et l'activation B attendent A qualifiée et les preuves propres
   à B ; les prototypes numériques ne donnent aucune admission.
4. Réunir les changements dans un seul candidat applicatif et une seule
   recette. Effectuer les parcours complets et les essais de récupération,
   puis épingler la release correspondant aux preuves.

La qualification matérielle et le développement injectable peuvent avancer
en parallèle. Chaque candidat assemblé a des sources et preuves propres ;
chaque changement de protocole est coordonné entre dépôts et testé des deux côtés.
Les adaptations de recette, les voies de lancement à couvrir et les limites
du candidat Studio sont recensées dans
[FACTORY-IMAGE-INTEGRATION.md](FACTORY-IMAGE-INTEGRATION.md).

## État vérifié et limites actuelles

| Composant | Preuve consignée | Travail restant |
|---|---|---|
| Nouvelle image TEST | [132 contrôles offline](validation/2026-10-11-system-prerequisites-access-image.json), [flash relu](validation/2026-10-11-system-prerequisites-sd-flash.json), [retour d'enrôlement : 35 + 10 contrôles PASS](validation/2026-10-11-prerequisites-enrollment-return.json) | Accès SSH du nouveau boot non confirmé, application arrêtée. Wi-Fi, Bluetooth et affichage restent à observer sur cette image. |
| Image factory passive | [Assemblage ARM64 réel avec Studio déclaré `a071f19`](validation/2026-10-12-factory-passive-image.json) : 64 contrôles système et 4 contrôles layout réussis, bundle matérialisé et export relu | Services masqués, runtime/support non qualifiés, premier appairage non intégré. |
| Graph et wrapper Phase A | [63 fixtures Linux ARM64 sans skip et suite globale de 1 822 tests Mac avec 16 skips ; syntaxe de 23 scripts Bash](validation/2026-10-12-factory-graph.json) | Composition inactive ; PID1, sandbox UID 1000, permissions, peers connectés, budgets Pi et parcours physique restent à qualifier. |
| Permissions natives du graph | [Mesure fixture Linux ARM64 sous UID 1000 sans capabilities](FACTORY-GRAPH-NATIVE-PERMISSIONS.md), PIDFD et propriétés systemd disponibles | Sandbox installé, IPC réel, graph complet et identité du sender par message non qualifiés. |
| Diagnostic des phases TEST | [74 tests ciblés et 1 852 tests globaux macOS](validation/2026-10-12-test-boot-phase-checkpoints.json), sans échec ; 16 skips dans la suite globale | Nouvelle source hors de la SD actuelle ; ancien marqueur `bind` insuffisant pour localiser un blocage. |
| Politique UTC pure | [24 tests Mac PASS et deux revues source réussies](validation/2026-10-12-bootstrap-time-policy.json) | Arithmétique seule : setter, worker, journal et admission owner/latch absents ; origine BOOTTIME et heure actuelle non prouvées. |
| Fichiers factory | [23 tests ciblés et 1 875 tests globaux macOS](validation/2026-10-12-factory-writer-file-tests.json), sans échec, pour la copie/relecture inactive de 17 fichiers | Installation native, support, comptes réservés, graph R35 et raccord de boot encore à qualifier. |

Le [service IPC-A](INITIALIZATION-IPC.md), la
[permission factory consommable](FACTORY-AUTHORITY.md), le
[superviseur](FACTORY-SUPERVISOR.md) et les
[installers offline](FACTORY-STUDIO-BUNDLE.md) fournissent les composants à
composer. Les rapports historiques restent conservés dans
[validation/](validation/) et associés à leurs commits ; leurs preuves ne sont
pas transférées automatiquement au nouveau candidat.

Le candidat source Studio `eb11790` de la
[PR #35](https://github.com/mehdi7129/inky-studio/pull/35), draft non fusionnée,
retire la référence personnelle du dépôt par défaut de l'updater ; ses quatre
contrôles CI sont réussis. Ses sorties backend et frontend sont maintenant
construites ; le [nouveau plan statique](validation/2026-10-12-studio-eb117-static-bundle.json)
atteint les 34 dépendances `[pi]` et définit 2 399 entrées attendues.
Le premier essai privé de build a été abandonné sur un défaut du superviseur macOS
avant la construction applicative. Le build suivant conserve son reçu bloqué
par trois observations de chemins virtuels HEIC ; une complétion statique distincte
les classe à leurs sites et hashes exacts, sans modifier les sorties ni le reçu initial.
Audit de confidentialité complet, ELF, installation et runtime restent à qualifier ;
aucun nouveau bundle n'est admis dans une image.
Les attributions de licence sont conservées et leur livraison reste à régler
avant image ou redistribution. Les entrées de build privées restent préservées.
Le couple TEST accompagné reste backend `c31b13a` / iOS `1.0.0 (9)` ; le bundle
passif `a071f19` et le candidat source `5671ba4` ont leurs preuves distinctes.

## Raccords B à décider et développer ensemble

Studio reste l'autorité owner/epoch ; le canal UTC direct coordinateur→OS est
l'orientation convenue, avec réservation durable et arbitrage refus/engagement.
Révocation pending, effet et quiescence restent distincts ; la v0 conserve une
récupération explicite sur issue incertaine, sans retry du setter. Les interfaces
injectables sont encore à spécifier ensemble. L'OS doit vérifier l'admission réservée
jusqu'à la fin réelle du worker et au drain. Receipt A, UID helper, verrou writer
et graph ne suffisent pas. La [politique UTC](BOOTSTRAP-TIME-POLICY.md) reste
un prototype initial : aucune autorité système nouvelle ne découle des calculs.

La transition doit exposer un BLE normal limité pour vérifier le nouveau
handshake strict **avant la clôture complète**, sans ouvrir pays/Wi-Fi/photo.
Le runtime normal complet reprend ensuite le même ledger factory v2 sous clôture
vérifiée. iOS doit promouvoir durablement la même identité, le même owner/token
et `claimRequestID`, sans second claim. HTTPS confirme le cadre après connexion
Wi-Fi ; il n'est pas un préalable au handshake BLE sans LAN. Après clôture,
une heure invalide ou un certificat expiré nécessitent une réparation
authentifiée séparée, sans rouvrir l'adoption ni le setter initial.

Le pays d'utilisation est confirmé explicitement, puis observé sur la radio
avant scan/autoconnect ; le premier parcours vise la France. Le choix coordonné
pour les horaires est un fuseau **IANA persistant par cadre**, côté serveur et
scheduler ; l'OS reste en UTC, sans setter timezone privilégié. Le mode `daily`
utilise l'heure locale : migration des anciens horaires/fuseaux, défaut explicite,
proposition iPhone confirmée, pin et mise à jour tzdata, cas DST ambigus/inexistants,
`history.current().displayed_at` et reprise au reboot restent à définir avant API/code. Le voyage
du téléphone ne signifie pas que le cadre a changé de pays ou de fuseau.

Le parcours TEST avec accès opérateur signé est un outil de qualification.
Il ne constitue pas le premier démarrage destiné à l'utilisateur final.
La cible finale reste : **allumer le cadre, scanner le QR, confirmer le pays,
choisir le Wi-Fi, envoyer une photo**.
