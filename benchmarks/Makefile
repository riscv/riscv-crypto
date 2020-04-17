
HEADERS_IN = $(shell find ./ -name *.h )
HEADERS_OUT=

# All possible targets
TARGETS     =

# Compilation targets
BUILDTARGETS=

# Simulation targets
RUNTARGETS  = 

include common.mk

#
# Make sure the header files are coppied over.
$(foreach HEADER,$(HEADERS_IN),$(eval $(call add_header_target,$(HEADER))))

headers: $(HEADERS_OUT)


include aes/reference/Makefile.in
include aes/ttable/Makefile.in
include aes/zscrypto_rv32/Makefile.in
include aes/zscrypto_rv64/Makefile.in

include sha256/reference/Makefile.in
include sha256/zscrypto_rv32/Makefile.in

include sha512/reference/Makefile.in
include sha512/zscrypto_rv64/Makefile.in

include sha3/reference/Makefile.in

include test/Makefile.in

all: headers $(TARGETS)

run: $(RUNTARGETS)

print-configs:
	@echo $(VALID_CONFIGS) | sed "s/ /\n/g"

print-all-targets:
	@echo $(TARGETS) | sed "s/ /\n/g"

print-build-targets:
	@echo $(BUILDTARGETS) | sed "s/ /\n/g"

print-run-targets:
	@echo $(RUNTARGETS) | sed "s/ /\n/g"

clean:
	rm -f $(TARGETS)

spotless:
	rm -rf $(BUILD_DIR)

