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
- Le drop-in journald root:root0644
  `/etc/systemd/journald.conf.d/zz-inkyos-factory-persistent.conf`, sous parent
  root:root0755, avec `Storage=persistent`, `SplitMode=none`,
  `SystemMaxUse=32M` et `SystemMaxFileSize=8M`.

Le gate ferme seulement le WLAN ; ce profil ne masque pas Bluetooth. Les
unités writers fermées ne sont jamais activées par un lien direct ou alias.
Le runtime sans son manifeste complet refuse l'admission ; une image partielle
n'est pas exportable. Le lock de permission sera conservé, puis pending sera
consommé durablement au premier boot par l'autorité existante.

## Journaux des premiers boots

La base officielle contient
`/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf` : ses 27 octets
`[Journal]\nStorage=volatile\n` correspondent au pin préparé
`c0c9a711f7554fdd02650409b098fc0636b8f3f574f03d927c6df84f5ec82a7f`.
La seule présence de `/var/log/journal` n'activait donc pas la persistance.
Le fragment factory `zz-…` passe lexicalement après les deux fragments vendor
observés (`40-rpi-volatile-storage.conf` et `syslog.conf`), sans les modifier.
La sélection du namespace et les unités factory restent inchangées.

`SplitMode=none` évite que les messages du main UID1000 soient séparés dans
`user-1000.journal` : ils restent avec les autres services dans `system.journal`,
couvert par le lecteur offline actuel. Les budgets de 32/8 Mio sont des limites
de gestion journald, pas une garantie de conservation après coupure ni un quota
matériel strict. Ces journaux peuvent contenir des informations privées et
restent soumis aux permissions journald existantes ; aucun droit de lecture
app/helper supplémentaire n'est accordé.

Le mécanisme de flush est déjà installé :
`sysinit.target.wants/systemd-journal-flush.service` pointe vers l'unité vendor
dont les 943 octets, SHA256
`469693d108ff3e4b38b385cd8fce418f548406902c38bde3d2fc0e2c717bd667`,
égalent l'[unité upstream systemd v257.13](https://github.com/systemd/systemd/blob/v257.13/units/systemd-journal-flush.service).
Elle exécute `journalctl --flush`, après remount/journald et avec
`RequiresMountsFor=/var/log/journal`. Aucun nouveau service ou appel cible n'est
ajouté. Le comportement Storage/SplitMode est documenté dans
[journald.conf v257](https://github.com/systemd/systemd/blob/v257/man/journald.conf.xml).

Le nouveau fragment doit être absent avant `stage-static` : un préexistant est
refusé, jamais adopté/remplacé. `install-runtime` exige encore les octets exacts
de ce fragment, en plus du marqueur et de la permission initiale.

Delta packaging à intégrer avant nouvelle composition : ajouter au policy
support les deux chemins `etc/systemd/journald.conf.d` (directory root:root0755)
et `etc/systemd/journald.conf.d/zz-inkyos-factory-persistent.conf` (file
root:root0644), si aucun tree déjà approuvé ne les couvre. Le parent
`etc/systemd` est déjà piné dans l'inventaire support stage4. Refaire prepare/proposal,
la revue de support, les pins exporter/runtime et la vérification candidat
avec les vrais nouveaux octets ; les anciens reçus ne valent pas approbation
de ce delta. Aucun ajout ELF root/tree, nouveau privilège ou autorité TEST.

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
Seul `/etc/machine-id` admet les deux modes officiels `0444` ou `0644`, sans
chmod, remplacement ou modification de ses octets/inode. Les autres lectures
conservent leur mode unique exact, notamment `NetworkManager.state` en `0600`.
Le parent `/var/lib/inkyos` est créé en `0700` s'il est absent ; s'il existe,
il doit déjà être privé `0700` et reste inchangé. Aucun dossier existant n'est
automatiquement corrigé pour passer la garde.
Un ancien journal setup, même vide, est refusé. Les créations sont exclusives ;
un échec garde les éléments déjà écrits et exige un nouveau workspace. Aucune
réparation, restauration, adoption ou relance automatique n'est effectuée.

## Validation ciblée

19 fixtures passent sur Mac : refus avant écriture d'un ancien boot/profil
Wi-Fi/état runtime, pins, symlink sortant, préservation des inodes à la relance,
échec partiel conservé et refus d'installer le plan quand le vrai planner
refuse, machine-id officiel readonly préservé et modes hors contrat refusés.
Ces cas ne démontrent pas un boot ou l'assemblage de la recette complète.
Les trois cas supplémentaires vérifient la configuration effective après
conflits vendor et priorité /etc, le refus sans écriture d'un fragment
préexistant, et le refus du plan runtime si le fragment manque ou a changé.

```sh
python3 -m unittest discover -s tests -p test_factory_active_profile.py -v
```

Le run natif et l'image complète restent à produire. Aucun flash/Pi, publication
ou qualification physique n'est effectué par cet outil.
