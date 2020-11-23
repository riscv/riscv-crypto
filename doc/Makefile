
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

TEX = pdflatex 

BUILD_DIR = $(REPO_BUILD)/spec

BASE_RV32 = $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32a \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32b \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32d \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32f \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32h \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32i \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32m \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32q

BASE_RV64 = $(BASE_RV32)                                    \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64a \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64b \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64d \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64f \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64h \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64i \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64m \
            $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64q

OPCODES_SCALAR_RV32 = $(REPO_HOME)/tools/opcodes-crypto-scalar-rv32
OPCODES_SCALAR_RV64 = $(REPO_HOME)/tools/opcodes-crypto-scalar-rv64
OPCODES_SCALAR_BOTH = $(REPO_HOME)/tools/opcodes-crypto-scalar-both

OPCODES_SCALAR      = $(OPCODES_SCALAR_BOTH) $(OPCODES_SCALAR_RV32) \
                                             $(OPCODES_SCALAR_RV64)

TEX_SCALAR_CMD= $(REPO_HOME)/doc/opcodes-crypto-scalar-cmds.tex
TEX_SCALAR_TAB= $(REPO_HOME)/doc/opcodes-crypto-scalar-table.tex

TEX_VECTOR   = $(REPO_HOME)/doc/opcodes-crypto-vector.tex

SPEC_SCALAR_OUT  = $(BUILD_DIR)/riscv-crypto-spec-scalar.pdf
SPEC_SCALAR_TOP  = riscv-crypto-spec-scalar.tex
SPEC_SCALAR_TEX  = $(SPEC_TOP) $(wildcard $(REPO_HOME)/doc/tex/*) $(OPCODES_SCALAR)

SPEC_VECTOR_OUT  = $(BUILD_DIR)/riscv-crypto-spec-vector.pdf
SPEC_VECTOR_TOP  = riscv-crypto-spec-vector.tex
SPEC_VECTOR_TEX  = $(SPEC_TOP) $(wildcard $(REPO_HOME)/doc/tex/*) $(TEX_VECTOR)

SPEC_EXTRA= riscv-crypto-spec.sty $(TEX_SCALAR_TAB) $(TEX_SCALAR_CMD)
SPEC_COMMIT= $(BUILD_DIR)/spec.commit

check-rv32: $(BASE_RV32) $(OPCODES_SCALAR_RV32) $(OPCODES_SCALAR_BOTH)
	cat $^ | python3 $(REPO_HOME)/bin/parse_opcodes.py -check
	cat $(OPCODES_SCALAR_RV32) $(OPCODES_SCALAR_BOTH) \
        | python3 $(REPO_HOME)/bin/parse_opcodes.py -count

check-rv64: $(BASE_RV32) $(OPCODES_SCALAR_RV64) $(OPCODES_SCALAR_BOTH)
	cat $^ | python3 $(REPO_HOME)/bin/parse_opcodes.py -check
	cat $(OPCODES_SCALAR_RV64) $(OPCODES_SCALAR_BOTH) \
        | python3 $(REPO_HOME)/bin/parse_opcodes.py -count

check: check-rv32 check-rv64

$(TEX_SCALAR_TAB) : $(OPCODES_SCALAR)
	@mkdir -p $(dir $(TEX_SCALAR_TAB))
	cat $^ | python3 $(REPO_HOME)/bin/parse_opcodes.py -tex > $@

$(TEX_SCALAR_CMD) : $(OPCODES_SCALAR)
	@mkdir -p $(dir $(TEX_SCALAR_CMD))
	cat $^ | python3 $(REPO_HOME)/bin/parse_opcodes.py -texcmd > $@

$(TEX_VECTOR) : $(REPO_HOME)/tools/opcodes-crypto-vector
	@mkdir -p $(dir $(TEX_VECTOR))
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
