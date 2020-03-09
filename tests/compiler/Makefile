
BUILD_DIR   = $(REPO_BUILD)/tests/compiler

ALL_TARGETS = 

include $(REPO_HOME)/tests/common.mk

ifeq ($(RISCV_ARCH),riscv64-unknown-elf)
$(eval $(call add_compiler_target,test_archstr_c.c))
$(eval $(call add_compiler_target,test_archstr_s.S))
else
$(eval $(call add_compiler_target,test_archstr_c.c))
$(eval $(call add_compiler_target,test_archstr_s.S))
endif

all: $(ALL_TARGETS)

clean:
	rm -f $(ALL_TARGETS)

