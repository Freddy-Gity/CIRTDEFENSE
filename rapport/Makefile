# Compilation du rapport de stage.
#
#   make        -> rapport.pdf (chaine complete : index, glossaire, minitoc)
#   make vite   -> une seule passe, pour relire une correction de texte
#   make propre -> efface les fichiers intermediaires
#
# Prerequis : une distribution TeX Live complete (le modele utilise des
# paquets d'ornements et de fontes historiques : pgfornament, fourier-orns,
# psvectorian, initials). Sur Debian/Ubuntu : texlive-full.

MAITRE = rapport

all: $(MAITRE).pdf

$(MAITRE).pdf: $(MAITRE).tex preambule.tex uml.tex glossaire.tex \
               $(wildcard frontmatter/*.tex) $(wildcard chapitres/*/*.tex) \
               bibliographie.tex
	pdflatex -interaction=nonstopmode $(MAITRE).tex
	-makeindex $(MAITRE).idx
	-makeindex -s $(MAITRE).ist -t $(MAITRE).glg -o $(MAITRE).gls $(MAITRE).glo
	pdflatex -interaction=nonstopmode $(MAITRE).tex
	pdflatex -interaction=nonstopmode $(MAITRE).tex

vite:
	pdflatex -interaction=nonstopmode $(MAITRE).tex

propre:
	rm -f *.aux *.log *.toc *.lof *.lot *.out *.idx *.ilg *.ind *.glo \
	      *.gls *.glg *.ist *.maf *.mtc* *.fls *.fdb_latexmk *.synctex.gz \
	      chapitres/*/*.aux frontmatter/*.aux

tres-propre: propre
	rm -f $(MAITRE).pdf

.PHONY: all vite propre tres-propre
