
HEADERS_IN = $(shell find ./ -name *.h )
HEADERS_OUT=

TARGETS     = 
BUILDTARGETS=
RUNTARGETS  = 

include common.mk

#
# Make sure the header files are coppied over.
$(foreach HEADER,$(HEADERS_IN),$(eval $(call add_header_target,$(HEADER))))

include crypto_hash/sha256/ref/Makefile.in
include crypto_hash/sha256/zscrypto/Makefile.in

include crypto_hash/sha512/ref/Makefile.in
include crypto_hash/sha512/zscrypto/Makefile.in

include crypto_hash/sha3/ref/Makefile.in

include test/Makefile.in

headers: $(HEADERS_OUT)

all: headers $(TARGETS)

run: $(RUNTARGETS)

print-build-targets:
	@echo $(BUILDTARGETS)

print-run-targets:
	@echo $(RUNTARGETS)

clean:
	rm -f $(TARGETS)

spotless:
	rm -rf $(BUILD_DIR)

