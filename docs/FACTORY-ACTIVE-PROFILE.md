# Profil factory actif offline

`configure-factory-active-profile.py` complète la recette privée, après les
installers bundle/writers et la configuration générique gardant le WLAN fermé.
Ce profil explicite autorise la création initiale au prochain vrai démarrage.
Il ne crée aucun identifiant, QR, clé, owner, certificat, profil Wi-Fi ou état
d'admission pendant le build. Aucun service ou code cible n'est exécuté.

L'interface de production accepte seulement un rootfs Linux root:root dans
`/var/lib/inkyos-build/factory-image.<suffix>/root` et le marqueur du builder
dédié. Tous les parents sont ouverts sans suivre les symlinks. `/` est refusé,
y compris avec les seams internes des fixtures. Le workspace doit être exclusif.

## Ordre de composition

1. Installer les packages figés et configurer le système générique hors réseau.
   Renommer le compte UID1000 et garder NetworkManager WirelessEnabled=false.
2. Installer puis vérifier bundle Studio et fichiers writers, avant de créer
   les répertoires persistants app/helper, conformément à leurs préconditions.
3. Préparer comptes et parents offline avec le prérequis dédié.
4. Lancer `stage-static` avec le SHA256 exact du template trigger de cette recette.
   Les unités setup/gate et leurs dépendances appartiennent au lot OS vertical.
5. Inventorier le support réellement installé, revoir la fermeture ELF,
   installer/vérifier l'exporter, puis produire le plan runtime externe depuis
   les trois inventaires épinglés. Ne pas réutiliser le support TEST historique.
6. Lancer `install-runtime` avec le SHA256 du plan relu. Le script recalcule le
   plan avec le vrai verifier candidat avant de copier les octets, puis vérifie
   de nouveau le contrat installé.
7. Terminer l'inventaire disque, fsck, vérifications d'absence de secrets, et
   le reçu d'export de la recette complète avant de publier une image de test.

`stage-static` crée uniquement :

- Le marqueur factory générique root:root0644.
- Le parent système root:root0700 et le journal setup vide root:root0700.
- La permission initiale root:root0700 contenant un lock vide et `pending.json`
  root:root0600. C'est le consentement explicite de cette recette, pas une clé.
- Le trigger distinct, épinglé au template source, et son lien multi-user.
- Les masques systemd-rfkill.service/socket et le drop-in NetworkManager
  Requires/After=inkyos-wlan-close.service.

Le gate ferme seulement le WLAN ; ce profil ne masque pas Bluetooth. Les
unités writers fermées ne sont jamais activées par un lien direct ou alias.
Le runtime sans son manifeste complet refuse l'admission ; une image partielle
n'est pas exportable. Le lock de permission sera conservé, puis pending sera
consommé durablement au premier boot par l'autorité existante.

## Commandes du builder

```sh
python3 -I -B -S scripts/configure-factory-active-profile.py stage-static \
  --rootfs "$private_rootfs" --trigger-sha256 "$reviewed_trigger_sha256"

python3 -I -B -S scripts/configure-factory-active-profile.py install-runtime \
  --rootfs "$private_rootfs" --plan-file "$reviewed_plan_json" \
  --plan-sha256 "$reviewed_plan_sha256"
```

La première phase exige machine-id uninitialized, état WLAN fermé exact,
absence de profils réseau et de toute ancienne permission/admission/autorité.
Un ancien journal setup, même vide, est refusé. Les créations sont exclusives ;
un échec garde les éléments déjà écrits et exige un nouveau workspace. Aucune
réparation, restauration, adoption ou relance automatique n'est effectuée.

## Validation ciblée

11 fixtures passent sur Mac : refus avant écriture d'un ancien boot/profil
Wi-Fi/état runtime, pins, symlink sortant, préservation des inodes à la relance,
échec partiel conservé et refus d'installer le plan quand le vrai planner
refuse. Ces cas ne démontrent pas un boot ou l'assemblage de la recette complète.

```sh
python3 -m unittest discover -s tests -p test_factory_active_profile.py -v
```

Le run natif et l'image complète restent à produire. Aucun flash/Pi, publication
ou qualification physique n'est effectué par cet outil.
