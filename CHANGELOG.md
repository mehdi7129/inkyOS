# Changelog

## 2026.10.29-rc1 — 2026-10-29

Première image générique publiée pour le parcours inkyImager → Wi-Fi local → QR iPhone.

- Backend Inky Studio `716104b130d34d1973001e78f15e25989d4c2e76`, avec partage d’accès photo par invitation QR entre iPhone.
- Image vierge : aucun Wi-Fi, accès, photo, identité de cadre ou clé personnelle préinjectés.
- Wi-Fi renseigné depuis le Mac, importé au premier démarrage puis fichier transitoire retiré de la partition FAT.
- Runtime ARM64, Python 3.13.5, inky 2.5.0, profil `ac073-800x480-timed-wait`.
- Documentation alignée sur le parcours LAN actuel et séparation des prototypes BLE/SoftAP historiques.

Validation : contrôles offline des systèmes de fichiers et des unités, vérification du bundle fermé, imports ARM64 isolés, décompression XZ complète comparée au RAW, 14 tests du profil Imager. Le premier boot physique de **cet artefact** n’a pas été observé : statut release candidate maintenu. Le cadre existant et le partage QR ont été validés séparément par l’utilisateur.
