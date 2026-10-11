# Finalisation commune InkyOS / Inky Studio

État du 11 octobre 2026. Une release est considérée prête lorsque les parcours
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

Le lot écrans reste commun aux deux projets : évaluer `inky` 2.4.0, adapter
l'observateur busy AC073 qui exige actuellement 2.3.0, puis aligner les
catalogues OS (notamment variantes 14, 26 et 27), validateurs et manifeste
applicatif. Un changement de dépendance seul ne suffit pas. Le catalogue de
modèles présenté par l'app ne constitue pas une qualification matérielle.
Le couple TEST actuel reste en 2.3.0 jusqu'à livraison d'un candidat commun.

## Ordre de réalisation

1. Corriger ensemble les trois écarts système observés : initialisation
   Bluetooth, dépendance I²C et observation de l'heure. Refaire le préflight
   sur la nouvelle image avant d'activer le candidat applicatif actuel.
2. Vérifier le parcours LAN accompagné : welcome, photo, QR, adoption BLE et
   reconnexion HTTPS. Ce parcours permet de qualifier le matériel disponible.
3. Raccorder le parcours usine sans LAN. Commencer par l'IPC local
   `initialization.inspect` / `initialization.begin`, puis le raccord distinct
   heure/pays et le lifecycle backend/iOS. Les prototypes existants ne sont
   pas des services installés dans l'image.
4. Réunir les changements dans un seul candidat applicatif et une seule
   recette. Effectuer les parcours complets et les essais de récupération,
   puis épingler la release correspondant aux preuves.

Les étapes 2 et 3 peuvent avancer en parallèle. Les composants provisoires ne
sont pas assemblés implicitement à partir de branches différentes. Chaque
changement de protocole est coordonné entre dépôts et testé des deux côtés.
Les adaptations de recette, les voies de lancement à couvrir et les limites
du candidat Studio sont recensées dans
[FACTORY-IMAGE-INTEGRATION.md](FACTORY-IMAGE-INTEGRATION.md).

## Limites actuelles

Les trois corrections système sont maintenant intégrées dans une
[nouvelle image TEST](validation/2026-10-11-system-prerequisites-access-image.json)
qui passe 132 contrôles offline. La suite complète compte
[1 273 tests par plateforme](validation/2026-10-11-factory-exporter-workspace-tests.json),
sans échec. Cette image a été [flashée et relue](validation/2026-10-11-system-prerequisites-sd-flash.json) ;
son premier démarrage a été lancé, sans retour d'enrôlement encore vérifié.

Le [service IPC-A](INITIALIZATION-IPC.md) et son client Studio sont développés
séparément ; le banc Linux du service passe, sans installation dans l'image TEST.
Le vrai client Studio passe maintenant le [banc croisé Linux](validation/2026-10-11-initialization-studio-native.json).
La [permission factory consommable](FACTORY-AUTHORITY.md) est développée et testée,
sans installation dans une recette. Son hook compose désormais consommation
durable, publication des credentials puis création de l’autorité.
Studio propose désormais un sérialiseur de credentials v2 à sortie privée ;
le [publisher OS isolé](FACTORY-CREDENTIALS.md) passe ses fixtures macOS et
Linux ARM64. Le raccord au hook est testé avec des producteurs inertes ;
le [vrai sérialiseur Studio](validation/2026-10-11-factory-studio-serializer-native.json)
passe aussi un banc isolé sous UID 1000, avec deux publications validées par
Studio. Le [superviseur](FACTORY-SERVICE-FIXTURE.md) passe dix cas distincts.
Le [test de composition installé](FACTORY-INSTALLED-FIXTURE.md) est développé
avec 41 fixtures inertes ; son exécution native reste à faire.
Ces bancs ne qualifient pas l’intégration complète dans l’image. Le verrou
couvre publication et autorité, et une reprise après consommation ne génère
jamais de nouveaux credentials implicitement. Le futur profil doit encore
exclure les processus applicatifs concurrents et installer
l’[exporter dédié proposé](FACTORY-EXPORTER-PROPOSAL.md).
La [politique d'heure proposée](BOOTSTRAP-TIME-POLICY.md) fixe les bornes,
le délai et les preuves attendues ; l'admission partagée avec Studio et le
service privilégié restent à développer. Ce document ne règle aucune horloge.
Le raccord usine exige un mode explicite de l'unité
`INKY_STUDIO_FACTORY_REQUIRED=1`, `INKY_STUDIO_DATA_DIR=/var/lib/inky-studio`
et le marqueur root `/etc/inky-studio/factory-v1.json` :
`{"version":1,"app_uid":1000,"data_dir":"/var/lib/inky-studio"}`.
Le marqueur permanent ne crée aucune autorité : l'autorisation positive
consommable, les credentials individuels et la disponibilité réelle du socket
restent des prérequis distincts. Le profil TEST/c31 ne reçoit pas cet opt-in.
Un raccord qui quitte avec `factory_runtime_pending` reste une étape de
développement, pas un parcours utilisable ni un service à relancer en boucle.

Le [boot réseau observé](validation/2026-10-11-radio-readiness-network-observation.json)
prouve l'accès SSH authentifié et une interface Wi-Fi connectée. Le préflight
reste bloqué et l'application de cette SD reste masquée. Le couple pour ce
premier essai reste backend `c31b13a` / iOS `1.0.0 (9)` ; les nouveaux travaux
Studio ne remplacent pas silencieusement le payload installé.

Le parcours TEST avec accès opérateur signé est un outil de qualification.
Il ne constitue pas le premier démarrage destiné à l'utilisateur final.
La cible finale reste : **allumer le cadre, scanner le QR, confirmer le pays,
choisir le Wi-Fi, envoyer une photo**.
