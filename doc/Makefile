
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

TEX = pdflatex 

BUILD_DIR = $(REPO_BUILD)/spec

OPCODES_SCALAR   = $(REPO_HOME)/doc/opcodes-crypto-scalar.tex
OPCODES_VECTOR   = $(REPO_HOME)/doc/opcodes-crypto-vector.tex

SPEC_SCALAR_OUT  = $(BUILD_DIR)/riscv-crypto-spec-scalar.pdf
SPEC_SCALAR_TOP  = riscv-crypto-spec-scalar.tex
SPEC_SCALAR_TEX  = $(SPEC_TOP) $(wildcard $(REPO_HOME)/doc/tex/*) $(OPCODES_SCALAR)

SPEC_VECTOR_OUT  = $(BUILD_DIR)/riscv-crypto-spec-vector.pdf
SPEC_VECTOR_TOP  = riscv-crypto-spec-vector.tex
SPEC_VECTOR_TEX  = $(SPEC_TOP) $(wildcard $(REPO_HOME)/doc/tex/*) $(OPCODES_VECTOR)

SPEC_EXTRA= riscv-crypto-spec.sty $(OPCODES)
SPEC_COMMIT= $(BUILD_DIR)/spec.commit

$(OPCODES_SCALAR) : $(REPO_HOME)/tools/opcodes-crypto-scalar
	@mkdir -p $(dir $(OPCODES_SCALAR))
	cat $^ | python3 $(REPO_HOME)/bin/parse_opcodes.py -tex > $@

$(OPCODES_VECTOR) : $(REPO_HOME)/tools/opcodes-crypto-vector
	@mkdir -p $(dir $(OPCODES_VECTOR))
	cat $^ | python3 $(REPO_HOME)/bin/parse_opcodes.py -tex > $@

.PHONY: $(SPEC_COMMIT)
$(SPEC_COMMIT):
	@mkdir -p $(BUILD_DIR)
	@git rev-parse --abbrev-ref HEAD > ${@}
	@echo "@" >> ${@}
	@git log --pretty=format:'%H' -n 1 >> ${@}

$(SPEC_SCALAR_OUT) : $(SPEC_SCALAR_TEX) $(SPEC_EXTRA) $(SPEC_COMMIT)
	@mkdir -p $(BUILD_DIR)
	$(TEX) $(basename $(SPEC_SCALAR_TOP))
	bibtex   $(basename $(SPEC_SCALAR_TOP))
	$(TEX) $(basename $(SPEC_SCALAR_TOP))
	$(TEX) $(basename $(SPEC_SCALAR_TOP))

$(SPEC_VECTOR_OUT) : $(SPEC_VECTOR_TEX) $(SPEC_EXTRA) $(SPEC_COMMIT)
	@mkdir -p $(BUILD_DIR)
	$(TEX) $(basename $(SPEC_VECTOR_TOP))
	bibtex   $(basename $(SPEC_VECTOR_TOP))
	$(TEX) $(basename $(SPEC_VECTOR_TOP))
	$(TEX) $(basename $(SPEC_VECTOR_TOP))

spec-scalar: $(SPEC_SCALAR_OUT)
spec-vector: $(SPEC_VECTOR_OUT)
specs: spec-scalar spec-vector

clean:
	rm -rf $(BUILD_DIR)/* $(OPCODES) \
		*.aux *.bbl *.blg *.log *.out *.pdf *.run.xml *-blx.bib *.toc
