
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

TEX = pdflatex 

BUILD_DIR = $(REPO_BUILD)/spec

#
# Script for checking if opcodes collide and generating C/SAIL/Tex
PARSEOPCODES = python3 $(REPO_HOME)/bin/better_parse_opcodes.py

#
# Opcode Checking
# ------------------------------------------------------------

#
# Machine readable opcode descriptions for RV32
OPCODES_BASE_RV32 = \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32a \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32b \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32d \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32f \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32h \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32i \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32m \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv32q

#
# Machine readable opcode descriptions for RV64
OPCODES_BASE_RV64 = \
    $(OPCODES_BASE_RV32) \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64a \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64b \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64d \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64f \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64h \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64i \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64m \
    $(REPO_HOME)/extern/riscv-opcodes/opcodes-rv64q

#
# Machine readable opcode descriptions for scalar crypto

OPCODES_CRYPTO_SCALAR_RV32 = $(REPO_HOME)/tools/opcodes-crypto-scalar-rv32

OPCODES_CRYPTO_SCALAR_RV64 = $(REPO_HOME)/tools/opcodes-crypto-scalar-rv64

OPCODES_CRYPTO_SCALAR_BOTH = $(REPO_HOME)/tools/opcodes-crypto-scalar-both

OPCODES_CRYPTO_SCALAR_ALL  = \
    $(OPCODES_CRYPTO_SCALAR_BOTH) \
    $(OPCODES_CRYPTO_SCALAR_RV32) \
    $(OPCODES_CRYPTO_SCALAR_RV64)

#
# Machine readable opcode descriptions for vector crypto

OPCODES_CRYPTO_VECTOR      = $(REPO_HOME)/tools/opcodes-crypto-vector

#
# Check for RV32 / RV64 encoding collisions.

check-rv32: $(OPCODES_BASE_RV32) $(OPCODES_CRYPTO_SCALAR_RV32) $(OPCODES_CRYPTO_SCALAR_BOTH)
	$(PARSEOPCODES) check $^

check-rv64: $(OPCODES_BASE_RV64) $(OPCODES_CRYPTO_SCALAR_RV64) $(OPCODES_CRYPTO_SCALAR_BOTH)
	$(PARSEOPCODES) check $^

check: check-rv32 check-rv64

#
# Specification - General
# ------------------------------------------------------------

# Contains current git commit for putting into the spec.
SPEC_COMMIT= $(BUILD_DIR)/spec.commit

.PHONY: $(SPEC_COMMIT)
$(SPEC_COMMIT):
	@mkdir -p $(BUILD_DIR)
	@git rev-parse --abbrev-ref HEAD > ${@}
	@echo "@" >> ${@}
	@git log --pretty=format:'%H' -n 1 >> ${@}

#
# Extra sources that the specs are dependent on.
SPEC_EXTRA= riscv-crypto-spec.sty

#
# Scalar Specification
# ------------------------------------------------------------

#
# Opcode macros
TEX_SCALAR_CMD= $(REPO_HOME)/doc/opcodes-crypto-scalar-cmds.tex

$(TEX_SCALAR_CMD) : $(OPCODES_CRYPTO_SCALAR_ALL)
	@mkdir -p $(dir $(TEX_SCALAR_CMD))
	$(PARSEOPCODES) tex-cmds $^ > $@

#
# Encoding table.
TEX_SCALAR_TAB= $(REPO_HOME)/doc/opcodes-crypto-scalar-table.tex

$(TEX_SCALAR_TAB) : $(OPCODES_CRYPTO_SCALAR_ALL)
	@mkdir -p $(dir $(TEX_SCALAR_TAB))
	$(PARSEOPCODES) tex-table $^ > $@

# Output file for the scalar specification.
SPEC_SCALAR_OUT  = $(BUILD_DIR)/riscv-crypto-spec-scalar.pdf

# Top latex file for the scalar specification.
SPEC_SCALAR_TOP  = riscv-crypto-spec-scalar.tex

# All latex included in the scalar specification
SPEC_SCALAR_TEX  =                                      \
    $(SPEC_SCALAR_TOP)                                  \
    $(SPEC_COMMIT)                                      \
    $(SPEC_EXTRA)                                       \
    $(TEX_SCALAR_TAB)                                   \
    $(TEX_SCALAR_CMD)                                   \
    $(REPO_HOME)/doc/tex/appx-entropy.tex               \
    $(REPO_HOME)/doc/tex/appx-materials.tex             \
    $(REPO_HOME)/doc/tex/appx-scalar-encodings.tex      \
    $(REPO_HOME)/doc/tex/contributors.tex               \
    $(REPO_HOME)/doc/tex/sec-entropy-source.tex         \
    $(REPO_HOME)/doc/tex/sec-policies.tex               \
    $(REPO_HOME)/doc/tex/sec-scalar-aes.tex             \
    $(REPO_HOME)/doc/tex/sec-scalar-bitmanip.tex        \
    $(REPO_HOME)/doc/tex/sec-scalar-intro.tex           \
    $(REPO_HOME)/doc/tex/sec-scalar-profiles.tex        \
    $(REPO_HOME)/doc/tex/sec-scalar-sha2.tex            \
    $(REPO_HOME)/doc/tex/sec-scalar-sm3.tex             \
    $(REPO_HOME)/doc/tex/sec-scalar-sm4.tex             \
    $(REPO_HOME)/doc/tex/sec-scalar-timing.tex

$(SPEC_SCALAR_OUT) : $(SPEC_SCALAR_TEX)
	@mkdir -p $(BUILD_DIR)
	$(TEX) $(basename $(SPEC_SCALAR_TOP))
	bibtex   $(basename $(SPEC_SCALAR_TOP))
	$(TEX) $(basename $(SPEC_SCALAR_TOP))
	$(TEX) $(basename $(SPEC_SCALAR_TOP))

spec-scalar: $(SPEC_SCALAR_OUT)

#
# Vector Specification
# ------------------------------------------------------------

TEX_VECTOR_CMD   = $(REPO_HOME)/doc/opcodes-crypto-vector-cmds.tex

$(TEX_VECTOR_CMD) : $(OPCODES_CRYPTO_VECTOR)
	@mkdir -p $(dir $(TEX_VECTOR_CMD))
	$(PARSEOPCODES) tex-cmds $^ > $@

TEX_VECTOR_TAB   = $(REPO_HOME)/doc/opcodes-crypto-vector-table.tex

$(TEX_VECTOR_TAB) : $(OPCODES_CRYPTO_VECTOR)
	@mkdir -p $(dir $(TEX_VECTOR_TAB))
	$(PARSEOPCODES) tex-table $^ > $@

SPEC_VECTOR_OUT  = $(BUILD_DIR)/riscv-crypto-spec-vector.pdf

SPEC_VECTOR_TOP  = riscv-crypto-spec-vector.tex

SPEC_VECTOR_TEX  = \
    $(SPEC_VECTOR_TOP)                                  \
    $(SPEC_COMMIT)                                      \
    $(SPEC_EXTRA)                                       \
    $(TEX_VECTOR_TAB)                                   \
    $(TEX_VECTOR_CMD)                                   \
    $(REPO_HOME)/doc/tex/appx-materials.tex             \
    $(REPO_HOME)/doc/tex/appx-vector-encodings.tex      \
    $(REPO_HOME)/doc/tex/contributors.tex               \
    $(REPO_HOME)/doc/tex/sec-policies.tex               \
    $(REPO_HOME)/doc/tex/sec-vector-aes.tex             \
    $(REPO_HOME)/doc/tex/sec-vector-clmul.tex           \
    $(REPO_HOME)/doc/tex/sec-vector-grev.tex            \
    $(REPO_HOME)/doc/tex/sec-vector-intro.tex           \
    $(REPO_HOME)/doc/tex/sec-vector-profiles.tex        \
    $(REPO_HOME)/doc/tex/sec-vector-rotate.tex          \
    $(REPO_HOME)/doc/tex/sec-vector-sha2.tex            \
    $(REPO_HOME)/doc/tex/sec-vector.tex

$(SPEC_VECTOR_OUT) : $(SPEC_VECTOR_TEX)
	@mkdir -p $(BUILD_DIR)
	$(TEX) $(basename $(SPEC_VECTOR_TOP))
	bibtex   $(basename $(SPEC_VECTOR_TOP))
	$(TEX) $(basename $(SPEC_VECTOR_TOP))
	$(TEX) $(basename $(SPEC_VECTOR_TOP))

spec-vector: $(SPEC_VECTOR_OUT)

#
# General utility targets
# ------------------------------------------------------------

specs: spec-scalar spec-vector

all: specs

clean:
	rm -rf $(BUILD_DIR)/* \
		*.aux *.bbl *.blg *.log *.out *.pdf *.run.xml *-blx.bib *.toc

spotless: clean
	rm -rf *.pdf
