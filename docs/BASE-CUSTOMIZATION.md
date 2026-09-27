# Base officielle : premier boot et adaptations minimales

Lecture du **27 septembre 2026**, sur la copie de l'image publique figée dans
[base-image.lock.json](../config/base-image.lock.json). Image décompressée :
`2026-09-15-raspios-trixie-arm64-lite.img`, SHA-256
`49fafba626ec00e0f9800349b9edae6caf8cfc223f673b875b72ac2797ed9576`, revérifié dans
la VM avant lecture. Les chemins ci-dessous désignent **le contenu de l'image**.

Montages loop readonly, ext4 `ro,noload,nosuid,nodev,noexec` et FAT
`ro,nosuid,nodev,noexec`, puis démontage et détachement. Aucune modification de
l'image, aucun chroot, service cible, boot Raspberry Pi ou accès au cadre.

## Croissance de la SD : déjà indépendante de cloud-init

La base possède une chaîne Raspberry Pi complète ; ajouter un autre mécanisme
de croissance ne paraît pas nécessaire pour le premier prototype :

1. `/boot/firmware/config.txt:23` active `auto_initramfs=1` et
   `/boot/firmware/cmdline.txt:1` contient le mot `resize`.
2. Le hook `/usr/share/initramfs-tools/scripts/local-premount/resize_early`
   vérifie ce mot (lignes 11–13), identifie le disque root, puis agrandit sa
   **partition n°2** avec `parted resizepart` (lignes 19–46).
3. Le hook `scripts/local-bottom/set_partuuid` change l'identifiant MBR depuis
   `/dev/hwrng`, adapte `/etc/fstab` et `cmdline.txt`, puis retire `resize`
   (lignes 30–58). Il ne faut pas remplacer ces références par celles du builder.
4. `/etc/machine-id` contient `uninitialized` ; `/var/lib/dbus/machine-id` est
   absent. Ce premier boot systemd permet à `rpi-resize.service`, activé sous
   `sysinit.target.wants`, de demander `systemd-growfs-root.service`.
5. Ce dernier exécute `/usr/lib/systemd/systemd-growfs /` pour agrandir le
   filesystem. `rpi-resize.service` se désactive ensuite lui-même.

Les deux hooks, `parted` et `fdisk` sont effectivement présents dans
`/boot/firmware/initramfs8`, vérifié avec le `lsinitramfs` du builder. Les hooks
et `rpi-resize.service` appartiennent au paquet `raspberrypi-sys-mods`.
L'ancien `/usr/lib/raspi-config/init_resize.sh` existe aussi, mais **n'est pas
le chemin sélectionné par ce cmdline**, qui ne contient pas son paramètre `init=`.

**À préserver :** les deux partitions dans leur ordre actuel, le root n°2,
les initramfs, `resize`, le sentinel `uninitialized` et l'activation de
`rpi-resize.service`. Mettre un machine-id vide à la place changerait le
comportement de `ConditionFirstBoot=yes`.

Cela prouve le câblage, pas son exécution réussie sur SD. La modification de
l'identifiant disque, des deux fichiers de référence et la croissance ext4
sont des phases distinctes à qualifier après coupure. Le service utilise
`Wants`, pas `Requires`, pour le growfs : ne pas traiter sa seule désactivation
comme preuve que la croissance a réussi.

## Ce qui déclenche encore la configuration utilisateur

| Élément lu | Fait de cette image | Conséquence |
|---|---|---|
| FAT `user-data`, `network-config`, `meta-data` | Les deux premiers contiennent seulement des commentaires/exemples. Le troisième fixe `dsmode: local` et `instance_id: rpios-image`. | Ce ne sont pas des credentials personnels ni un réseau configuré ; ces exemples ne constituent pas un onboarding InkyOS. |
| `/etc/cloud/cloud.cfg` | Modules utilisateurs, SSH, hostname, réseau/commandes et packages ; **aucun `growpart` ou `resizefs` dans les listes exécutées**. Défaut utilisateur `pi`, groupes larges et sudo sans mot de passe dans la configuration cloud. | Cloud-init n'est pas nécessaire à la croissance existante. |
| `/etc/cloud/cloud.cfg.d/99_raspberry-pi.cfg` | Datasources `[NoCloud, None]`, seed `file:///boot/firmware`. | Une simple absence de réseau ne désactive pas cloud-init. |
| Units cloud-init, y compris hotplug | Condition `!/etc/cloud/cloud-init.disabled`. | Le marqueur de désactivation est le delta minimal, sans désinstaller de paquets ni exécuter leurs maintainer scripts. |
| `userconfig.service` | Activé ; lance le dialogue sur tty8 après `cloud-config.service`. | À masquer explicitement ; désactiver cloud-init seul laisse ce wizard. |
| `systemd-firstboot.service` | Activé par le système, condition de premier boot, prompts locale/keymap/timezone/root password. | À masquer pour éviter tout wizard interactif ; conserver les services machine-id. |
| `sshswitch.service` | Activé ; un fichier FAT `ssh` ou `ssh.txt` lui fait activer SSH. | À neutraliser avec `ssh.service`/`ssh.socket` tant que le support par clé n'est pas défini. |

Comparaison demandée : conserver cloud-init limité à `growpart` + `resizefs`
resterait une **autre conception**, non testée ici. Il faudrait remplacer ses
listes de modules, imposer la datasource `None`, désactiver son réseau et éviter
de doubler la chaîne initramfs/systemd existante. Le gain n'est pas établi.
La proposition la plus courte pour cette base est de désactiver cloud-init et
de conserver la croissance upstream, puis de vérifier ce comportement sur SD.

## Compte et permissions : renommage ciblé possible

Le compte générique `pi` est UID/GID **1000:1000**, shell
`/usr/sbin/nologin`. `/home/pi` est 0700 et son inventaire ne contient que
`.bash_logout`, `.bashrc`, `.profile`, tous 1000:1000. Aucun marqueur
`/var/lib/userconf-pi/autologin`, drop-in getty d'autologin ni fichier
`010_pi-nopasswd`/`010_wiz-nopasswd` n'a été trouvé.

Renommer **pi → inky**, groupe primaire compris, et déplacer le home conserve
les IDs et évite une migration générale des propriétaires. Verrouiller le mot
de passe, conserver `nologin` et remplacer les groupes supplémentaires par
`spi,i2c,gpio` ; ajouter `inky-provisioning` lors de l'intégration du helper.
Cela retire notamment `sudo` et `netdev`. Ne pas supprimer la règle générique
`%sudo` pour tous les comptes : l'app doit simplement ne pas en bénéficier.

Deux restes ciblés : `/etc/subuid` et `/etc/subgid` contiennent une délégation
pour `pi`, à retirer si inutilisée ou adapter explicitement ;
`/etc/ssh/sshd_config.d/rename_user.conf` ne fait qu'afficher la bannière du wizard.
Ne pas appeler `userconf`/`cancel-rename` pour cette préparation : ces scripts
rétablissent Bash et peuvent activer/démarrer getty ou recharger SSH.
La future règle sudo limitée au service app reste distincte du sudo général.
`/usr/sbin/policy-rc.d` est absent de la base : une future installation de
paquets offline devra donc fournir explicitement son blocage temporaire des
services, puis vérifier qu'aucune identité ni activation runtime n'a été créée.

## Réseau, matériel et identité : delta proposé

| Sujet | État constaté | Adaptation minimale proposée |
|---|---|---|
| NetworkManager | Seul fichier sous `/var/lib/NetworkManager` : `NetworkManager.state`, avec `WirelessEnabled=false`. `system-connections` et `/etc/netplan` sont vides. | Aucun profil à fabriquer. Définir explicitement l'activation radio avec le futur contrat pays Wi-Fi ; l'effacement d'un state ne vaut pas choix de pays. |
| Bluetooth | `/var/lib/bluetooth` vide ; des états rfkill génériques sont présents. Politique D-Bus BlueZ autorise la destination `org.bluez` au contexte default. | Prévoir l'initialisation radio au boot ; ne pas donner `netdev` ou sudo global à l'app pour contourner le helper. |
| SPI/I²C | `dtparam=spi=on` et `dtparam=i2c_arm=on` commentés. Aucun module `i2c-dev` dans modules-load. | Activer les deux paramètres sous `[all]`, charger `i2c-dev`, ajouter `dtoverlay=spi0-0cs` conformément au contrat matériel retenu, sans annoncer le panneau qualifié. |
| Permissions | `/usr/lib/udev/rules.d/99-com.rules:1–9` donne `spi`, `i2c`, `gpio` en 0660. | Réutiliser ces groupes/règles ; vérifier les devices réels sur SD. Pas de `chmod 666`. |
| Hostname | `raspberrypi` dans `/etc/hostname` et `/etc/hosts`. | Futur service root idempotent : suffixe individuel persistant, sans identifiant matériel personnel, avant NetworkManager/Avahi/app ; aucune attente réseau. |

Ces adaptations restent une proposition système. L'heure TLS, le QR initial,
l'ownership et la récupération physique restent des contrats Inky Studio.
Ni le compte Linux ni le mécanisme de croissance SD ne doivent créer l'identité
applicative ou ouvrir une fenêtre d'adoption.
