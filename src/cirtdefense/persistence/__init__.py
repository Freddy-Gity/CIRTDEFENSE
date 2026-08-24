"""Persistance SQLite : schema, connexions, depots.

SQLite est retenu pour que la plateforme reste deployable sur un poste isole
(contrainte du mode degrade, Axe 5). Les depots exposent une interface assez
etroite pour qu'un passage a PostgreSQL ne touche que ce paquet.
"""
