"""Persistance SQLite : schema, connexions, dépôts.

SQLite est retenu pour que la plateforme reste deployable sur un poste isole
(contrainte du mode dégrade, Axe 5). Les dépôts exposent une interface assez
etroite pour qu'un passage a PostgreSQL ne touche que ce paquet.
"""
