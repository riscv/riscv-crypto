
BUILD_DIR   = $(REPO_BUILD)/tests/kat

ALL_TARGETS =

include $(REPO_HOME)/tests/common.mk

$(eval $(call add_elf_target,lut42.c))
$(eval $(call add_spike_target,lut42))

$(eval $(call add_elf_target,ssha256.c))
$(eval $(call add_spike_target,ssha256))

$(eval $(call add_elf_target,ssha3.c))
$(eval $(call add_spike_target,ssha3))

$(eval $(call add_elf_target,indexed_ld.c))
$(eval $(call add_spike_target,indexed_ld))

$(eval $(call add_elf_target,saes.c))
$(eval $(call add_spike_target,saes))

$(eval $(call add_elf_target,mmulu.c))
$(eval $(call add_spike_target,mmulu))

$(eval $(call add_elf_target,maccu.c))
$(eval $(call add_spike_target,maccu))

#
# Disable for now, since we don't build a 64-bit toolchain yet, and
# these instructions are 64-bit only.
#$(eval $(call add_elf_target,ssha512.c))
#$(eval $(call add_spike_target,ssha512))
#
#$(eval $(call add_elf_target,lut42.c))
#$(eval $(call add_spike_target,lut42))

all: $(ALL_TARGETS)

clean:
	rm -f $(ALL_TARGETS)


