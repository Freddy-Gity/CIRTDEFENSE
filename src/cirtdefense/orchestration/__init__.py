"""Moteur d'orchestration : de l'evenement a l'action executee (EF-05 a EF-07,
EF-13 a EF-17, EF-25, EF-26).

C'est ici que se joue le pivot de la v3.0. En v2.1 ce module produisait des
recommandations soumises a l'analyste ; il produit desormais des ordres qu'il
execute lui-meme. Les garde-fous qui remplacent la validation humaine sont
tous implantes dans ce paquet et nulle part ailleurs :

- `reversibility` : seule une action annulable est executable en autonomie ;
- `policy_compiler` : la politique de l'administrateur devient contrainte ;
- `circuit_breaker` : arret d'urgence global (EF-26) ;
- `rollback`      : annulation autonome sur degradation (EF-25).
"""
