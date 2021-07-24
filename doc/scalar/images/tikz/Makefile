#	Makefile
#	2020-02-24	Markku-Juhani O. Saarinen <mjos@pqshield.com>

PROJ		= tikpix
TEXFILES	= $(wildcard *.tex) $(wildcard *.tikz)

#	scalable vector graphics for asciidoctor from tikz

all:	es_state.svg es_dataflow.svg es_noisetest.svg 
	cp *.svg ..

#	alternative: xelatex

%.pdf : %.tex $(TEXFILES)
	pdflatex $<

#	alternative: svg2pdf

%.svg : %.pdf
	dvisvgm --pdf $<

#	clean. removes the result .svg files too (good ones in parent)

clean:
	rm -f	*.aux *.dvi *.bbl *.blg *.log *.toc *.lof \
			*.thm *.out *.pdf *.svg

