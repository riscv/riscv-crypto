
HEADER=riscv-crypto-spec-scalar.adoc
DOC_PDF=$(HEADER:%.adoc=%.pdf)

all: $(DOC_PDF)

# Contains current git commit for putting into the spec.
SPEC_COMMIT= git-commit.adoc

.PHONY: $(SPEC_COMMIT)
$(SPEC_COMMIT):
	@git rev-parse --abbrev-ref HEAD > ${@}
	@echo "@" >> ${@}
	@git log --pretty=format:'%H' -n 1 >> ${@}

%.pdf : %.adoc $(SPEC_COMMIT)
	asciidoctor-pdf -v \
        -r asciidoctor-bibtex \
        -r asciidoctor-diagram \
        -a toc \
        -a compress \
        -a pdf-style=resources/themes/risc-v_spec-pdf.yml \
        -a pdf-fontsdir=resources/fonts \
        -o $@ $<

clean:
	rm -f $(DOC_PDF)

