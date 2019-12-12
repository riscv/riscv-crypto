
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

BUILD_DIR = $(REPO_BUILD)/spec

SPEC_OUT  = $(BUILD_DIR)/riscv-crypto-spec.pdf
SPEC_TOP  = riscv-crypto-spec.tex
SPEC_TEX  = $(SPEC_TOP) $(wildcard $(REPO_HOME)/doc/tex/*)
SPEC_EXTRA= riscv-crypto-spec.sty

$(SPEC_OUT) : $(SPEC_TEX) $(SPEC_EXTRA)
	@mkdir -p $(BUILD_DIR)
	pdflatex  -output-directory $(BUILD_DIR) $(basename $(SPEC_TOP))
	biber    --output_directory $(BUILD_DIR) $(basename $(SPEC_TOP))
	pdflatex  -output-directory $(BUILD_DIR) $(basename $(SPEC_TOP))
	biber    --output_directory $(BUILD_DIR) $(basename $(SPEC_TOP))
	pdflatex  -output-directory $(BUILD_DIR) $(basename $(SPEC_TOP))

spec: $(SPEC_OUT)

clean:
	rm -r $(BUILD_DIR)/*
