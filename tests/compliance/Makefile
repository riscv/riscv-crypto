
ifndef REPO_HOME
    $(error "Please run 'source ./bin/conf.sh' to setup the project workspace")
endif

COMPLIANCE_REPO=$(REPO_HOME)/extern/riscv-compliance
COMPLIANCE_PATCH=$(REPO_HOME)/tests/compliance/riscv-compliance.patch

COMPLIANCE_DEST_RV32= $(COMPLIANCE_REPO)/riscv-test-suite/rv32ik/src
COMPLIANCE_DEST_RV64= $(COMPLIANCE_REPO)/riscv-test-suite/rv64ik/src
COMPLIANCE_GENERATE = $(REPO_HOME)/tests/compliance/generate_tests.py
COMPLIANCE_GEN_RV32 = $(REPO_HOME)/build/kat-gen/kat_gen_spike32.py
COMPLIANCE_GEN_RV64 = $(REPO_HOME)/build/kat-gen/kat_gen_spike64.py

COMPLIANCE_WORK_RV32= $(COMPLIANCE_REPO)/work/rv32ik
COMPLIANCE_WORK_RV64= $(COMPLIANCE_REPO)/work/rv64ik
COMPLIANCE_REF_RV32 = $(COMPLIANCE_REPO)/riscv-test-suite/rv32ik/references
COMPLIANCE_REF_RV64 = $(COMPLIANCE_REPO)/riscv-test-suite/rv64ik/references

#
# Patch Management.
# ------------------------------------------------------------

compliance-revert-patch:
	cd $(COMPLIANCE_REPO) && git reset HEAD && git checkout . && git clean -dxf

compliance-apply-patch:
	cd $(COMPLIANCE_REPO) && git apply $(COMPLIANCE_PATCH)
	cd $(COMPLIANCE_REPO) && git add .

compliance-update-patch:
	cd $(COMPLIANCE_REPO) && git diff --cached > $(COMPLIANCE_PATCH)

#
# Running Tests.
# ------------------------------------------------------------

compliance-run-spike-rv32:
	$(MAKE) -B -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf- \
        RISCV_TARGET=spike RISCV_ISA=rv32ik RISCV_DEVICE=rv32ik

compliance-run-sail-csim-rv32:
	$(MAKE) -B -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf- \
        RISCV_TARGET=sail-riscv-c RISCV_ISA=rv32ik RISCV_DEVICE=rv32ik

compliance-run-sail-ocaml-rv32:
	$(MAKE) -B -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf- \
        RISCV_TARGET=sail-riscv-ocaml RISCV_ISA=rv32ik RISCV_DEVICE=rv32ik

compliance-run-spike-rv64:
	$(MAKE) -B -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf- \
        RISCV_TARGET=spike RISCV_ISA=rv64ik RISCV_DEVICE=rv64ik

compliance-run-sail-csim-rv64:
	$(MAKE) -B -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf- \
        RISCV_TARGET=sail-riscv-c RISCV_ISA=rv64ik RISCV_DEVICE=rv64ik

compliance-run-sail-ocaml-rv64:
	$(MAKE) -B -C $(COMPLIANCE_REPO) RISCV_PREFIX=riscv64-unknown-elf- \
        RISCV_TARGET=sail-riscv-ocaml RISCV_ISA=rv64ik RISCV_DEVICE=rv64ik

compliance-run-all: compliance-run-spike-rv32       \
                    compliance-run-sail-csim-rv32   \
                    compliance-run-sail-ocaml-rv32  \
                    compliance-run-spike-rv64       \
                    compliance-run-sail-csim-rv64   \
                    compliance-run-sail-ocaml-rv64

#
# Generating new test sets.
# ------------------------------------------------------------

compliance-generate-rv32ik : $(COMPLIANCE_GEN_RV32)
	$(COMPLIANCE_GENERATE) $< $(COMPLIANCE_DEST_RV32)

compliance-generate-rv64ik : $(COMPLIANCE_GEN_RV64)
	$(COMPLIANCE_GENERATE) $< $(COMPLIANCE_DEST_RV64)

#
# Updating the reference outputs
# ------------------------------------------------------------

compliance-update-signatures-rv32ik : compliance-generate-rv32ik
	rm -f $(COMPLIANCE_REF_RV32)/*.reference_output
	cp $(COMPLIANCE_WORK_RV32)/*.signature.output \
       $(COMPLIANCE_REF_RV32)/.
	rename 's/signature\.output/reference_output/' $(COMPLIANCE_REF_RV32)/*.signature.output

compliance-update-signatures-rv64ik : compliance-generate-rv64ik
	rm -f $(COMPLIANCE_REF_RV64)/*.reference_output
	cp $(COMPLIANCE_WORK_RV64)/*.signature.output \
       $(COMPLIANCE_REF_RV64)/.
	rename 's/signature\.output/reference_output/' $(COMPLIANCE_REF_RV64)/*.signature.output

