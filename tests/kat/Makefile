
BUILD_DIR   = $(REPO_BUILD)/tests/kat

ALL_TARGETS = 

include $(REPO_HOME)/tests/common.mk

$(eval $(call add_elf_target,lut4.c))
$(eval $(call add_spike_target,lut4))

$(eval $(call add_elf_target,ssha256.c))
$(eval $(call add_spike_target,ssha256))

all: $(ALL_TARGETS)

clean:
	rm -f $(ALL_TARGETS)


