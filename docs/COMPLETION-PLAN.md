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

## Limites actuelles

Le [boot réseau observé](validation/2026-10-11-radio-readiness-network-observation.json)
prouve l'accès SSH authentifié et une interface Wi-Fi connectée. Le préflight
reste bloqué et l'application de cette SD reste masquée. Le couple pour ce
premier essai reste backend `c31b13a` / iOS `1.0.0 (9)` ; les nouveaux travaux
Studio ne remplacent pas silencieusement le payload installé.

Le parcours TEST avec accès opérateur signé est un outil de qualification.
Il ne constitue pas le premier démarrage destiné à l'utilisateur final.
La cible finale reste : **allumer le cadre, scanner le QR, confirmer le pays,
choisir le Wi-Fi, envoyer une photo**.
