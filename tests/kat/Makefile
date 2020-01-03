
BUILD_DIR   = $(REPO_BUILD)/tests/kat

ALL_TARGETS = 

include $(REPO_HOME)/tests/common.mk

$(eval $(call add_elf_target,lut4.c))
$(eval $(call add_spike_target,lut4))

$(eval $(call add_elf_target,ssha256.c))
$(eval $(call add_spike_target,ssha256))

#
# Disable for now, since we don't build a 64-bit toolchain yet, and
# these instructions are 64-bit only.
#$(eval $(call add_elf_target,ssha512.c))
#$(eval $(call add_spike_target,ssha512))

$(eval $(call add_elf_target,ssha3.c))
$(eval $(call add_spike_target,ssha3))

all: $(ALL_TARGETS)

clean:
	rm -f $(ALL_TARGETS)


