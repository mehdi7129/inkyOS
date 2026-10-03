# Accès opérateur privé pour le premier essai

Proposition du 30 septembre 2026, séparée de la [variante préparée](TEST-LAN.md).
**Canal et activation non livrés à ce stade.** Le banc OpenSSH/PAM réel avec
dispatcher inerte a passé 39/39 contrôles dans la VM sur une copie jetable
du parent épinglé. Il ne qualifie ni le Pi, ni l'activation applicative.
Les échecs, corrections et hashes sont conservés dans la
[preuve réduite](validation/2026-09-30-test-lan-prepared.json).

Le chemin retenu évite de supposer une console, un réseau USB ou une confiance
dans mDNS. Il utilise la Qumox de test et un aller-retour physique après un
premier boot d'enrôlement avec arrêt automatique explicitement prévu pour cette
phase privée. L'image générique PREPARED garde app/helper/SSH masqués et ne
contient aucun compte opérateur, profil Wi-Fi, pays ou clé hôte.

## Personnalisation distincte

PERSONALIZED sera construite depuis le candidat courant neuf, non booté et
rehashé. Jamais depuis la SD diagnostic ou une installation hors banc. Les entrées
privées sont fournies localement par l'opérateur, hors de Git, preuves publiques
et logs : profil initial WPA2 Personal 2,4 GHz, pays confirmé `FR`, clé publique
unique du compte `inky-test` et consentement TEST avancé. La clé privée reste
sur le Mac. L'image personnalisée contient un secret réseau ; elle doit rester
privée et ne peut pas être publiée comme image générique.

Les paquets nécessaires sont déjà épinglés dans la recette : OpenSSH, PAM,
sudo, systemd, NetworkManager et outils radio. Aucun nouvel IPC du helper,
droit heure/pays applicatif ou protocole BLE n'est ajouté.

| Phase | Condition et comportement prévus |
|---|---|
| `ENROLLMENT_PENDING` | Wi-Fi/profil dormants, app/helper/SSH masqués. Après firstboot, création de la clé hôte sur le Pi, rapport public limité sur FAT, sync et arrêt propre. |
| Contrôle offline | Au retour physique de la SD, vérifier rapport, clé hôte réelle, parent/payload et méthode de reprise dans la VM. Écrire un flag privé root-owned lié à cette carte et clé ; préparer le `known_hosts` Mac. |
| `ACCESS_READY_INACTIVE` | Au second boot, confirmer le binding, appliquer et vérifier le pays avant connexion. Activer le seul profil initial et le daemon SSH dédié ; aucun app/helper lancé. |
| `ACTIVATING` | Après examen live complet et consentement TEST, permis volatil sous `/run`, démarrage helper puis app avec réception de leurs états réels. |
| `REVIEW_REQUIRED` | État incomplet, interruption ou échec : conserver toutes les données, bloquer la poursuite automatique et préparer la reprise explicite. |

La clé hôte n'est jamais préchargée dans l'image. Une clé découverte sur le LAN
ne remplace pas la preuve offline de la SD. L'arrêt propre d'enrôlement et
la récupération offline devront être réellement éprouvés avant connexion et
activation. Aucun accès USB/série opérationnel n'est revendiqué.

## Compte et commandes bornées

`inky-test` est distinct des comptes app/helper, sans groupes sudo/admin/netdev.
Il utilise `/bin/sh` pour exécuter ForceCommand, un password verrouillé et aucune
expiration ni password aging. App/helper restent `nologin`. Un timestamp shadow
de changement de password à zéro est exclu pour ce compte TEST : PAM peut
imposer un changement de password même lors d'une authentification par clé.

Configuration SSH dédiée sans `Include` : clés uniquement, `UsePAM yes`, root,
password et keyboard-interactive interdits ; `AllowUsers inky-test`. Désactiver
forwarding, TTY, tunnel, rc utilisateur et environnement client. Vérifier aussi
`/etc/ssh/sshrc`. Clé publique autorisée root-owned **0644**, parents non
modifiables : OpenSSH ouvre ce fichier sous l'UID utilisateur. Les clés privées,
profil réseau et état privé restent 0600. [Code Debian exact](https://sources.debian.org/src/openssh/1:10.0p1-7%2Bdeb13u4/auth2-pubkey.c/),
[sshd_config](https://manpages.debian.org/trixie/openssh-server/sshd_config.5.en.html).

Le dispatcher et son runner doivent résider dans un dossier dédié root-owned
0755, tel que `/usr/local/lib/inkyos-test-ssh`, avec exécutables 0555.
`/usr/local/lib/inkyos` reste privé 0700 : le placer sous ce dossier a donné
un vrai échec de transport (exit 126) lors du premier banc. Ces permissions
privées ne sont pas modifiées pour donner accès au compte opérateur.

ForceCommand vers un launcher root-owned 0555 acceptant exactement `preflight`,
`activate` ou `stop`, sans arguments ni espaces supplémentaires. Un JSON stdin
unique et borné à 4096 octets / 5 secondes transporte seulement les champs
fermés nécessaires, jamais un chemin ou une commande arbitraire. Le futur runner root
revalidera le schéma, les doublons et la référence UTC indépendante récente.
Le stub du banc valide seulement `schema_version: 1` et ne règle rien. Sudo
n'autorise qu'un runner fixe avec `""` pour imposer zéro argument. [sudoers](https://manpages.debian.org/trixie/sudo/sudoers.5.en.html).

SSH reste accessible sans UTC valide afin de diagnostiquer NTP. L'activation
app/helper/TLS exige ensuite l'heure réelle, le pays/radio, le panneau et les
préconditions vérifiés. `NoNewPrivileges` sur sshd empêcherait l'élévation sudo
de la session ; ce paramètre ne peut pas être ajouté sans banc réel. Les units
SSH vendor restent masquées au profit du daemon TEST dédié.

`stop` doit invalider le permis, arrêter app puis helper, restaurer les masks,
préserver toutes les données et demander un arrêt propre même si heure/panneau
sont invalides. Aucun `enable` applicatif ni redémarrage automatique. Un simple
`unmask --runtime` ne retire pas les masks actuels situés dans `/etc`.

## Preuves restant nécessaires

Le banc VM a utilisé le vrai rootfs/OpenSSH/PAM épinglé, loopback dans un
namespace privé, clés jetables et dispatcher d'activation inerte. Vérifier clés,
PAM, aging/nologin négatifs, sudo zéro argument, injections, JSON excessif,
shell/SFTP/SCP refusés et vrais canaux de forwarding. Un listener client ouvert
ne démontre pas un tunnel utilisable. Les secrets et fingerprints ne vont pas
dans les rapports publics.

Ces contrôles passent désormais : 39/39, dont les négatifs PAM/nologin/aging,
les trois verbes, sudo sans argument et les vrais canaux refusés. Le refus TUN
est celui d'[OpenSSH 10.0p1](https://github.com/openssh/openssh-portable/blob/V_10_0_P1/serverloop.c#L469),
`CONNECT_FAILED` avec message de refus politique, différent du motif
`ADMINISTRATIVELY_PROHIBITED` de direct-tcpip. Le test exige aussi l'ouverture
locale effective puis l'absence d'interface résiduelle. Aucun runner applicatif,
compte ou unit d'accès opérateur n'est installé par ce résultat.
Le délai de lecture de cinq secondes est couvert par une fixture Python ;
aucun client SSH à stdin volontairement lent n'a été mesuré dans ces 39 gates.

La [première phase d'enrôlement](TEST-ENROLLMENT.md) est simplifiée : aucun
profil Wi-Fi ni PSK n'est demandé ou préchargé au premier boot. La clé publique
opérateur nouvelle et un challenge local sont les seules personnalisations,
dans une image privée distincte. Le réseau viendra au retour de la SD, après
contrôle offline du rapport et de la clé hôte réellement générée sur le Pi.

La sonde EEPROM est livrée comme outil source inactif ; son intégration et
son essai matériel restent à faire. La sonde radio est également livrée hors
image et garde le tuple firmware non qualifié. Le gate pays/radio runtime
reste à qualifier et à intégrer.
PHY `98`/`99` ne sont pas des codes pays et ne sont pas acceptés comme `FR`.
Le rapport readonly du preflight n'est jamais une autorisation d'activation.
Une première session photo LAN puis claim BLE peut être envisagée après ces
contrôles ; toute mutation Wi-Fi attend un secours indépendant effectivement
testé et la bêta Bluetooth réellement disponible sur l'iPhone.
