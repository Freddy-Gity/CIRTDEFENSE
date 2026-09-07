# Guide d'utilisation CIRTDEFENSE

Document destine aux exploitants de la plateforme : analystes, administrateurs
et decideurs du Centre.

## Compiler

```bash
cd guide
make            # -> guide.pdf
make clean      # efface les fichiers intermediaires
```

Trois passes de `pdflatex` sont necessaires : la premiere ecrit la table des
matieres, les suivantes la placent et resolvent les mini-tables de chapitre.

## Fichier maitre

`guide.tex`. Sur Overleaf, le designer explicitement par
**Menu -> Main document -> guide.tex** : sans fichier nomme `main.tex`,
Overleaf choisit parfois mal.

## Arborescence

```
guide.tex ................ fichier maitre, n'ordonne que les parties
preambule.tex ............ style (memoir) — copie de celui du rapport
glossaire.tex ............ acronymes
frontmatter/ ............. titre, avant-propos, conventions
chapitres/
  01-presentation/ ....... ce qu'est la plateforme, ce qu'elle ne fait pas
  02-installation/ ....... prerequis, installation, configuration
  03-prise-en-main/ ...... premiere mise en service, premier tour
  04-interface/ .......... les huit onglets, un par un
  05-scenarios/ .......... six situations d'exploitation, pas a pas
  06-administration/ ..... posture, politique, coupe-circuit, comptes
  07-rapports/ ........... edition, formats, template administratif
  08-technologies/ ....... socle, bibliotheques, algorithmes, nature de l'IA
  09-depannage/ .......... symptomes courants et limitations connues
  annexes/ ............... variables d'environnement, CLI, API
```

## Pourquoi le preambule est une copie

Le style est celui du rapport (`../rapport/preambule.tex`), duplique plutot que
partage. Les deux documents se livrent separement : un guide qui ne compilerait
qu'a cote de son rapport ne serait pas un livrable. La contrepartie est qu'une
retouche de style doit etre reportee dans les deux dossiers.

## Tenir le guide a jour

Les chapitres 2, 6 et les annexes citent des valeurs qui vivent dans le code :
variables d'environnement (`src/cirtdefense/config.py`), sous-commandes
(`src/cirtdefense/cli.py`), nombre de routes et de tests. Les reverifier avant
chaque revision plutot que de les recopier de memoire.

Le chapitre 9 porte les limitations connues. Elles sont enoncees volontairement :
un evaluateur qui les trouve avant vous est un mauvais moment.
