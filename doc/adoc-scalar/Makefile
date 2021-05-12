
HEADER=riscv-crypto-spec-scalar.adoc
DOC_PDF=$(HEADER:%.adoc=%.pdf)

# Contains current git commit for putting into the spec.
SPEC_COMMIT= git-commit.adoc

.PHONY: $(SPEC_COMMIT)
$(SPEC_COMMIT):
	@git rev-parse --abbrev-ref HEAD > ${@}
	@echo "@" >> ${@}
	@git log --pretty=format:'%H' -n 1 >> ${@}

%.pdf : %.adoc $(SPEC_COMMIT)
	asciidoctor-pdf \
        -a pdf-style=resources/themes/risc-v_spec-pdf.yml \
        -a pdf-fontsdir=resources/fonts \
        -o $@ $<

all: $(DOC_PDF)

clean:
	rm -f $(DOC_PDF)

