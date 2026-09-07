# Compilation du guide d'utilisation.
#
#   make        -> main.pdf (chaine complete : minitoc)
#   make clean  -> efface les fichiers intermediaires
#
# Le style est celui du rapport (../rapport). Le preambule en est une copie :
# les deux documents se livrent separement.

MAITRE = main

all: $(MAITRE).pdf

$(MAITRE).pdf: $(MAITRE).tex preambule.tex glossaire.tex \
               $(wildcard frontmatter/*.tex) $(wildcard chapitres/*/*.tex)
	pdflatex -interaction=nonstopmode $(MAITRE).tex
	pdflatex -interaction=nonstopmode $(MAITRE).tex
	pdflatex -interaction=nonstopmode $(MAITRE).tex

clean:
	rm -f *.aux *.log *.out *.toc *.lof *.lot *.idx *.ilg *.ind \
	      *.gls *.glg *.ist *.maf *.mtc* *.fls *.fdb_latexmk *.synctex.gz \
	      chapitres/*/*.aux frontmatter/*.aux

distclean: clean
	rm -f $(MAITRE).pdf

.PHONY: all clean distclean
