# Fixtures historiques

`preflight-fdf5a12.py.txt` est la copie exacte du preflight du commit
`05c92d01ad732310643ade9cbf06e40252a71851`, SHA-256
`fdf5a12b7b2c13dce3456531816d634e5bb235e37fdeff8d2efd4edcdb45209b`.
Le diagnostic d'observation existant reste lié à ce fichier présent dans
l'ancien rootfs d'enrôlement. Son test contrôle ce snapshot, tandis que les
nouveaux parents TEST et le runtime opérateur utilisent le preflight courant.
Cette fixture n'est pas installée dans les images et n'est pas exécutée par
le test de hash. Aucun pin du diagnostic historique n'est remplacé.
