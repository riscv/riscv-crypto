
VALID_CONFIGS = $(basename $(notdir $(shell find ./config/ -name *.conf)))

ifeq ($(CONFIG),)
    $(error Please specify a config using 'CONFIG=X' where X is one of $(VALID_CONFIGS))
endif

include config/$(CONFIG).conf

SPIKE   = $(RISCV)/bin/spike

BUILD_DIR = $(REPO_BUILD)/benchmarks/$(CONFIG)

CFLAGS  += -Wall -I$(BUILD_DIR)/include
CFLAGS  += $(CONF_CFLAGS)

TEST_SRC = $(REPO_HOME)/benchmarks/share/test.c

#
# 1. Relative header file path, as found by running "find"
define map_header
$(BUILD_DIR)/include/riscvcrypto/${1}
endef

#
# 1. Input file name
define map_obj
$(BUILD_DIR)/obj/${1:%.c=%.o}
endef

#
# 1. Input file name
# 2. Optional distinguisher
define map_elf
$(BUILD_DIR)/bin/${1:%.c=%-${2}.elf}
endef

#
# 1. Library name
define map_lib
$(BUILD_DIR)/lib/lib${1}.a
endef

#
# 1. Input file name
# 2. Optional distinguisher
define map_dis
$(BUILD_DIR)/dis/$(basename ${1})${2}.dis
endef

#
# 1. Input file name
define map_size
$(BUILD_DIR)/dis/$(basename ${1}).size
endef

#
# 1. Input file name
# 2. Optional distinguisher
define map_run_log
$(BUILD_DIR)/log/${1:%.c=%-${2}.log}
endef

#
# 1. Relative header file path, as found by running "find"
define add_header_target
$(call map_header,${1}) : ${1}
	@mkdir -p $(dir $(call map_header,${1}))
	@cp   $${<} $${@}

HEADERS_OUT += $(call map_header,${1})
endef


#
# 1. Input file
define add_obj_target

$(call map_obj,${1}) : ${1}
	@mkdir -p $(dir $(call map_obj,${1}))
	$(CC) $(CFLAGS) -c -o $${@} $${<}

$(call map_dis,${1}) : $(call map_obj,${1})
	@mkdir -p $(dir $(call map_dis,${1}))
	$(OBJDUMP) -D $${<} > $${@}

$(call map_size,${1}) : $(call map_obj,${1})
	@mkdir -p $(dir $(call map_size,${1}))
	$(SIZE) -d $${<} > $${@}

TARGETS += $(call map_obj,${1})
TARGETS += $(call map_dis,${1})
TARGETS += $(call map_size,${1})
endef


#
# 1. Library Name
# 2. Input files.
define add_lib_target

$(foreach INFILE,$(filter %.c %.S,${2}),$(call add_obj_target,${INFILE}))

$(call map_lib,${1}) : $(filter %.o,${2}) $(foreach INFILE,$(filter %.c %.S,${2}),$(call map_obj,${INFILE}))
	@mkdir -p $(dir $(call map_lib,${1}))
	$(AR) rcs $${@} $${^}

TARGETS      += $(call map_lib,${1})

build-lib-${1} : $(call map_lib,${1})

BUILDTARGETS += build-lib-${1}

endef


#
# 1. Source Files
# 2. Libraries and extra source files.
# 3. Test executable name.
define add_test_elf_target

$(call map_elf,${1},${3}) : ${1} $(TEST_SRC) $(foreach LIB,${2},$(call map_lib,${LIB}))
	@mkdir -p $(dir $(call map_elf,${1},${3}))
	$(CC) $(CFLAGS) -DTEST_NAME=${3} -o $${@} \
        ${1} \
        $(TEST_SRC) \
        $(foreach LIB,${2},$(call map_lib,${LIB}))

$(call map_dis,${1},${3}) : $(call map_elf,${1},${3})
	@mkdir -p $(dir $(call map_dis,${1},${3}))
	$(OBJDUMP) -D $${<} > $${@}

$(call map_run_log,${1},-${3}) : $(call map_elf,${1},${3})
	@mkdir -p $(dir $(call map_run_log,${1},${3}))
	$(SPIKE) --isa=$(CONF_ARCH_SPIKE) $(PK) $(call map_elf,${1},${3}) \
        | tee $${@}

TARGETS += $(call map_elf,${1},${3})
TARGETS += $(call map_dis,${1},${3})

run-test-${3}   : $(call map_run_log,${1},-${3})

RUNTARGETS += run-test-${3}

build-test-${3} : $(call map_dis,${1},${3}) $(call map_elf,${1},${3})

BUILDTARGETS += build-test-${3}

endef

