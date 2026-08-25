"""Interface applicative (EF-11, EF-12).

Les points d'entrée suivent les rôles redefinis par la v3.0 :

- **Analyste** : consulte, audite, déclenche un rollback *a posteriori*. Il
  n'existe volontairement aucun point d'entrée lui permettant de valider,
  modifier ou rejeter une action avant exécution — ce serait rétablir
  l'EF-13 antérieure par la porte de l'API.
- **Décideur** : consulte le portefeuille et les indicateurs.
- **Administrateur** : politique de réponse, catalogue de réversibilité,
  coupe-circuit.
"""
