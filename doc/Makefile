
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

BUILD_DIR = $(REPO_BUILD)/spec

SPEC_OUT  = $(BUILD_DIR)/riscv-crypto-spec.pdf
SPEC_TOP  = riscv-crypto-spec.tex
SPEC_TEX  = $(SPEC_TOP) $(wildcard $(REPO_HOME)/doc/tex/*)
SPEC_EXTRA= riscv-crypto-spec.sty
SPEC_COMMIT= $(BUILD_DIR)/spec.commit

.PHONY: $(SPEC_COMMIT)
$(SPEC_COMMIT):
	@git rev-parse --abbrev-ref HEAD > ${@}
	@echo "@" >> ${@}
	@git log --pretty=format:'%H' -n 1 >> ${@}
ifneq ("$(REPO_DIRTY)","")
	@echo "{\\\color{red}\\\bf -dirty}" >> ${@} ;
endif

$(SPEC_OUT) : $(SPEC_TEX) $(SPEC_EXTRA) $(SPEC_COMMIT)
	@mkdir -p $(BUILD_DIR)
	pdflatex  -output-directory $(BUILD_DIR) $(basename $(SPEC_TOP))
	biber    --output_directory $(BUILD_DIR) $(basename $(SPEC_TOP))
	pdflatex  -output-directory $(BUILD_DIR) $(basename $(SPEC_TOP))
	biber    --output_directory $(BUILD_DIR) $(basename $(SPEC_TOP))
	pdflatex  -output-directory $(BUILD_DIR) $(basename $(SPEC_TOP))

spec: $(SPEC_OUT)

clean:
	rm -r $(BUILD_DIR)/*
