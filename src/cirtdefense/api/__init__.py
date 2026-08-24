"""Interface applicative (EF-11, EF-12).

Les points d'entree suivent les roles redefinis par la v3.0 :

- **Analyste** : consulte, audite, declenche un rollback *a posteriori*. Il
  n'existe volontairement aucun point d'entree lui permettant de valider,
  modifier ou rejeter une action avant execution — ce serait retablir
  l'EF-13 anterieure par la porte de l'API.
- **Decideur** : consulte le portefeuille et les indicateurs.
- **Administrateur** : politique de reponse, catalogue de reversibilite,
  coupe-circuit.
"""
