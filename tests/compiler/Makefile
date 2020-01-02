
BUILD_DIR   = $(REPO_BUILD)/tests/compiler

ALL_TARGETS = 

include $(REPO_HOME)/tests/common.mk

$(eval $(call add_compiler_target,test_archstr_c.c))
$(eval $(call add_compiler_target,test_archstr_s.S))

all: $(ALL_TARGETS)

clean:
	rm -f $(ALL_TARGETS)

