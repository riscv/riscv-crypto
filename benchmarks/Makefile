
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

$(TARGETS) : $(HEADERS_OUT)

include crypto_hash/Makefile.in

include test/Makefile.in

all: headers $(TARGETS)

run: $(RUNTARGETS)

print-all-targets:
	@echo "---"
	@echo $(TARGETS)

print-build-targets:
	@echo $(BUILDTARGETS)

print-run-targets:
	@echo $(RUNTARGETS)

clean:
	rm -f $(TARGETS)

spotless:
	rm -rf $(BUILD_DIR)

