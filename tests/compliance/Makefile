
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

COMPLIANCE_REPO=$(REPO_HOME)/extern/riscv-compliance
COMPLIANCE_PATCH=$(REPO_HOME)/tests/compliance/riscv-compliance.patch

compliance-revert-patch:
	cd $(COMPLIANCE_REPO) && git reset HEAD && git checkout . && git clean -dxf

compliance-apply-patch:
	cd $(COMPLIANCE_REPO) && git apply $(COMPLIANCE_PATCH)
	cd $(COMPLIANCE_REPO) && git add .

compliance-update-patch:
	cd $(COMPLIANCE_REPO) && git diff --cached > $(COMPLIANCE_PATCH)


compliance-run-spike:
	$(MAKE) -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf \
        RISCV_TARGET=spike

compliance-run-sail-csim:
	$(MAKE) -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf \
        RISCV_TARGET=sail-riscv-c

compliance-run-sail-ocaml:
	$(MAKE) -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf \
        RISCV_TARGET=sail-riscv-ocaml

compliance-run-all: compliance-run-spike        \
                    compliance-run-sail-csim    \
                    compliance-run-sail-ocaml
