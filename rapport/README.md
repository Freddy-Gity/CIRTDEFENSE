# Rapport de stage — squelette LaTeX

Structure dérivée du modèle ENSPY / UY1 fourni (classe `memoir`), adaptée au
projet CIRTDEFENSE. Le préambule du modèle d'origine est conservé tel quel :
le rapport compile donc partout où le modèle compilait.

## Compilation

```bash
cd rapport
make            # chaîne complète
make vite       # une passe, pour relire une correction
make propre     # efface les fichiers intermédiaires
```

Sur Overleaf : téléverser le dossier `rapport/` et régler le document
principal sur `rapport.tex`, moteur pdfLaTeX.

Le modèle s'appuie sur des paquets d'ornements et de fontes historiques
(`pgfornament`, `fourier-orns`, `psvectorian`, `initials`, `calligra`). Une
distribution TeX Live complète est nécessaire — `texlive-full` sur
Debian/Ubuntu.

## Arborescence

| Fichier | Rôle |
|---|---|
| `rapport.tex` | fichier maître — ordonne les parties, ne contient aucun texte |
| `preambule.tex` | préambule du modèle d'origine, inchangé sauf une ligne (voir plus bas) |
| `uml.tex` | outillage de dessin UML en TikZ pur, écrit pour ce rapport |
| `glossaire.tex` | acronymes et entrées de glossaire du projet |
| `frontmatter/` | page de titre, dédicace, remerciements, abréviations, résumé, abstract |
| `chapitres/00-introduction/` | introduction générale |
| `chapitres/01-structure/` | présentation de la structure d'accueil |
| `chapitres/02-etat-de-l-art/` | état de l'art |
| `chapitres/03-analyse/` | analyse et spécification des besoins |
| `chapitres/04-conception/` | conception et modélisation — **rédigé** |
| `chapitres/05-implementation/` | implémentation, tests et résultats |
| `chapitres/06-conclusion/` | conclusion générale |
| `chapitres/annexes/` | annexes |
| `bibliographie.tex` | références, en `thebibliography` comme le modèle |

Chaque dossier de chapitre contient un sous-dossier `figNN/` pour ses images ;
elles s'incluent par leur chemin relatif, par exemple
`\includegraphics{fig05/vue-ensemble.png}`.

## Une modification au préambule du modèle

Le modèle chargeait `enumitem` (ligne 119) **puis** `enumerate` (ligne 363).
Le second écrase le premier et casse toute liste écrite
`\begin{enumerate}[...]`. La ligne 363 est donc neutralisée, avec un
commentaire à cet endroit.

## Ce qui reste à compléter

Les emplacements à remplir sont signalés dans les sources, soit par des
crochets `[à compléter]` dans le texte, soit par un commentaire
`% A COMPLETER` précisant les documents à réunir. Les repérer :

```bash
grep -rn "A COMPLETER\|à compléter\|XXX\|20XX" .
```

## Écrire un diagramme UML

Tout diagramme se trace dans l'environnement `diagramme`, jamais dans
`tikzpicture` directement :

```latex
\begin{diagramme}[node distance=6mm]
  \node (a) [umlclasse=3.5cm] {\umltitre{MaClasse} \nodepart{two} - champ \,: Type
    \nodepart{three} + methode()};
\end{diagramme}
```

`diagramme` suspend le temps du dessin les raccourcis typographiques que
`babel-french` pose sur `; : ! ?` — ces caractères servent aussi de
séparateurs dans la syntaxe de TikZ, et un diagramme tracé sans cette
précaution échoue de façon déroutante.

Styles disponibles dans `uml.tex` : `umlclasse`, `umlcompact`, `umlsimple`,
`cas`, `etat`, `action`, `decision`, `barre`, `composant`, `paquetage`,
`noeudmat`, `artefact`, `note`, `couloir` ; relations `generalisation`,
`realisation`, `composition`, `agregation`, `association`, `dependance`,
`flot` / `flotok` / `flotko`, `transition` ; commandes `\umlacteur`,
`\seqvie`, `\seqact`, `\seqmsg`, `\seqrep`, `\seqauto`, `\seqfrag`.

Une figure large passe par `\ajusterportrait{...}` ou, dans une
`sidewaysfigure`, par `\ajusterpaysage{...}` : ces commandes réduisent le
diagramme pour qu'il tienne dans la page, jamais ne l'agrandissent.
