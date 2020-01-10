
HEADERS_IN = $(shell find ./ -name *.h )
HEADERS_OUT=

TARGETS = 
RUNTARGETS = 

include common.mk

#
# Make sure the header files are coppied over.
$(foreach HEADER,$(HEADERS_IN),$(eval $(call add_header_target,$(HEADER))))

include crypto_hash/sha256/ref/Makefile.in
include crypto_hash/sha256/zscrypto/Makefile.in

include test/Makefile.in

headers: $(HEADERS_OUT)

all: headers $(TARGETS)

run: $(RUNTARGETS)

clean:
	rm -f $(TARGETS)

spotless:
	rm -rf $(BUILD_DIR)

