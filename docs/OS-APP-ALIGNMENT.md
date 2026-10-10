# Alignement InkyOS / Inky Studio

État du **9 octobre 2026**. Cette revue compare les sources et les contrats
avec la session Inky Studio. Elle ne constitue pas un nouvel essai Pi/iPhone.
Le relevé correspondant côté Studio est
`docs/inkyos/ALIGNMENT-2026-10-09.md` ; les données locales de ce relevé ne sont
pas reproduites ici.

**Complément du 10 octobre :** installation du build 9 confirmée par l'opérateur.
Le [retour SD réseau](BOOT-NETWORK-DIAGNOSIS.md) contient un import Wi-Fi complet
et cohérent, sans preuve de connexion validée. Le détail du dernier échec
n'a pas été conservé. La variante diagnostique décrite en fin de document a
depuis été flashée ; son nouvel enrôlement passe les contrôles du retour SD.
Une nouvelle capsule signée est installée, relue et la carte éjectée. Le prochain
boot doit encore établir le réseau, avant activation et appairage ; aucun
contrat applicatif ne change.

## Couple retenu pour le prochain essai

| Composant | Référence |
|---|---|
| Outillage OS au relevé du 9 octobre | `0f2d22242ef41e07b14f674e8280dcfc827d6544` |
| Variante TEST désormais sur la SD | [Recette diagnostique épinglée et vérifiée](validation/2026-10-10-diagnostic-access-image.json) |
| Backend et helper intégrés | `0.5.0-rc.2`, source `c31b13afdc957425571810c46230eaaf52fa5d14` |
| SHA-256 du manifeste applicatif | `c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1` |
| Candidat iPhone | Inky Studio `1.0.0 (9)` |
| Source de l'archive iOS build 9 | `181edb2f89034bb0c411b145c95fe303f112b460` |
| Tête de la PR iOS #21 examinée | `52a5c64d2de3d729b87026389b9b3d1f8447dc86` ; documentation postérieure à l'archive |

La session Studio a revérifié App Store Connect le 9 octobre à 11:17 UTC :
build 9 validé et affecté à un groupe interne, sans blocage de conformité.
Au relevé du 9 octobre, sa disponibilité TestFlight était confirmée et son
installation sur l'iPhone restait à confirmer. L'opérateur a confirmé cette
installation le 10 octobre ; l'acceptation physique reste à observer. Les cinq
checks de la PR #21 consultés le 9 octobre étaient verts ; la PR était alors ouverte.

Les sources iOS et backend sont sur des branches parallèles. Remplacer le
payload de la SD par la tête iOS ferait perdre les changements de packaging,
d'affichage et d'arrêt du candidat matériel. Le couple source/manifeste ci-dessus
reste la référence de l'image ; aucune mise à jour applicative n'est effectuée
par cette synchronisation.

La comparaison des sources du build 9 et de `c31b13a` ne relève pas de changement
wire dans le client API, le QR, le transport/coordinator BLE ou les endpoints
de provisioning utilisés par le parcours existant. Le helper réseau est identique
(SHA-256 `6e5c00862bff1d02c575b422f2d1e1112cd20f2c9e9141894557a698e2d5f431`).
La vérification iOS de `digitalSignature` dans le certificat est satisfaite par
le générateur de certificat de `c31b13a`. Cela justifie l'essai de ce couple,
sans démontrer son fonctionnement de bout en bout sur le matériel.

La branche iOS apporte aussi l'expiration monotonic des sessions et des
primitives factory opt-in. Le candidat SD possède, de son côté, un endpoint
de statut écran et un événement d'erreur additionnels. Le build 9 ne consulte
pas cet endpoint : la présentation détaillée des diagnostics matériels n'est
pas intégrée. Ces différences doivent être réunies et testées dans le futur
candidat commun ; aucune équivalence globale des deux arbres n'est revendiquée.

## Parcours actuellement disponible

Le parcours reste **LAN authentifié → ouverture de la fenêtre QR → adoption
QR/BLE v1 → HTTPS avec identité vérifiée**. Les primitives factory et TLS
bootstrap présentes dans les sources récentes ne sont pas raccordées au
parcours iOS/serveur. Le build 9 ne fournit pas les opérations pays, heure et
reçu OS nécessaires à une première adoption hors LAN.

Lors du précédent essai réseau, le contrôle SSH exécuté sur le Mac renvoyait
`name_resolution_failed` : le nom `.local` n'est pas résolu. La présence du Pi
sur le Wi-Fi, le port SSH et les services applicatifs ne sont donc pas confirmés.
L'application et le helper n'ont pas été activés dans cet essai. Le
[nouveau retour diagnostique](validation/2026-10-10-diagnostic-sd-enrollment-return.json)
passe 35 contrôles ext4/FAT et 10 contrôles d'infrastructure, sur un dérivé
e2image privé dont l'acquisition intégrale d'origine est conservée. Le nouveau
contexte SSH remplace l'ancien pour le prochain essai.

Ordre du prochain essai accompagné sur la SD dédiée :

1. Vérifier la présence réseau ; si une adresse DHCP est trouvée, tester SSH
   en conservant la clé hôte issue du retour SD vérifié.
2. Lire le statut et les prérequis du [lifecycle TEST](TEST-ACCESS-LIFECYCLE.md) :
   pays, heure, services masqués, données vierges et bindings exacts.
3. Activer explicitement le candidat TEST et observer réellement le welcome
   sur le panneau. Un processus actif ne prouve pas un affichage réussi.
4. Vérifier la version installée sur l'iPhone, se connecter sur le LAN,
   ouvrir le QR depuis la session authentifiée, puis tester l'adoption et
   l'envoi d'une photo.
5. Qualifier l'arrêt applicatif avec drain de l'affichage. Le changement Wi-Fi
   et son rollback attendent un chemin de récupération éprouvé.

La variante TEST admet une seule activation par boot avec données vierges.
Elle ne fournit pas encore la reprise produit après reboot : ne pas déduire
ce comportement du scénario cible et ne pas modifier le réseau du banc avant
d'avoir éprouvé sa récupération.

Le manifest applicatif conserve `qualification.evidence: []` : ce candidat
n'est pas une release matérielle qualifiée. Une CI verte ou la disponibilité
TestFlight ne remplace aucune de ces observations physiques.

## Cible du premier allumage utilisateur

Le parcours visé est : **allumer → scanner le QR → confirmer le pays → choisir
le Wi-Fi → envoyer une photo**. L'app traite l'identité, le claim et l'heure
sans saisie technique. Aucun Terminal, accès à la box ou profil réseau préparé
sur un Mac ne doit être nécessaire à ce parcours produit.

| Livraison commune restante | Responsable principal | Critère d'acceptation |
|---|---|---|
| Démarrage factory et QR physique | Studio, raccord OS | Un cadre neuf affiche son QR sans réseau ni session LAN préalable ; le driver correspond au panneau. |
| Initialisation durable et claim | Studio + OS | Reçu OS à usage unique, owner atomique, réponse perdue rejouable seulement par le gagnant. Une DB perdue ou un reboot ne recrée aucune autorité usine. |
| Heure et TLS bootstrap | Studio + OS | Claim avant correction de l'heure, opération privilégiée bornée, même clé, puis nouvelle session TLS normale avant le Wi-Fi. Un owner existant peut réparer l'heure. |
| Pays et radio | iOS/Studio + OS | Pays confirmé dans l'app ; persistance et observation réglementaire avant scan/connexion. NetworkManager démarre radio fermée ; BLE reste disponible en cas d'échec. |
| Wi-Fi et récupération | Studio, qualification OS | Mauvais mot de passe corrigeable depuis l'app ; reprise après réponse perdue, extinction et reboot sans réappairage implicite. |
| Payload commun | Studio, intégration OS | Un commit complet avec installers, lock ARM64/Python 3.13, assets et manifeste épinglés ; aucune composition cachée de branches. |
| Qualification produit | Les deux dépôts | SD vierge → QR/BLE → heure/pays/Wi-Fi → photo → reboot/reconnexion → arrêt, avec résultats par écran et SD. |

Les modèles et bancs existants du [contrat first boot](FIRST-BOOT.md) fournissent
une base testée pour ces travaux. Ils ne sont pas des services de production
déjà branchés. L'étape suivante du développement est un candidat applicatif
commun intégrant ces raccords, puis son intégration dans une nouvelle image
et sa qualification sur SD dédiée.

## Répartition et publication

Studio conserve iOS, backend, écran, BLE/HTTPS, helper et packaging applicatif.
InkyOS conserve base système, recette d'image, raccord système du premier boot
et qualification SD. Aucun fork du protocole ni remplacement implicite du
payload n'est introduit.

Les preuves publiques restent expurgées. Les profils réseau, clés, identités
de cadres, adresses locales, photos et copies de SD bootées demeurent privés.

## Variante diagnostique du 10 octobre

La [nouvelle image TEST](validation/2026-10-10-diagnostic-access-image.json)
conserve le backend `c31b13a`, son manifeste `c4183e7` et le couple iOS build 9.
Le parent inactif a été reconstruit depuis les mêmes entrées vérifiées ; les
programmes et profils d’accès sont liés au nouveau manifeste runtime. Les
[rapports persistants](BOOT-NETWORK-DIAGNOSIS.md) concernent seulement le
diagnostic système. Aucun protocole Studio ni build iOS supplémentaire n’est
requis pour ce changement. Le nouvel enrôlement est vérifié, les deux rapports
diagnostiques sont présents et la nouvelle capsule Wi-Fi est installée.
Le rapport de boot est encore un marqueur initial incomplet ; il ne permet
pas de localiser une interruption. Le réseau, l'écran et QR/BLE restent à
qualifier sur le matériel.
