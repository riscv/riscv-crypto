
BUILD_DIR   = $(REPO_BUILD)/tests/assembler

ALL_TARGETS = 

include $(REPO_HOME)/tests/common.mk

ifeq ($(RISCV_ARCH),riscv64-unknown-elf)
$(eval $(call add_assembler_target,test_archstr.S))
$(eval $(call add_assembler_target,test_assembly_rv64.S))
else
$(eval $(call add_assembler_target,test_archstr.S))
$(eval $(call add_assembler_target,test_assembly_rv32.S))
endif

all: $(ALL_TARGETS)

clean:
	rm -f $(ALL_TARGETS)

