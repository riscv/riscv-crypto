
BUILD_DIR   = $(REPO_BUILD)/tests/assembler

ALL_TARGETS = 

include $(REPO_HOME)/tests/common.mk

$(eval $(call add_assembler_target,test_archstr.S))

all: $(ALL_TARGETS)

clean:
	rm -f $(ALL_TARGETS)

