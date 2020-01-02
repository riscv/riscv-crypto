
BUILD_DIR   = $(REPO_BUILD)/tests/compiler

ALL_TARGETS = 

include $(REPO_HOME)/tests/common.mk

$(eval $(call add_compiler_target,test_archstr.c))

all: $(ALL_TARGETS)

clean:
	rm -f $(ALL_TARGETS)

