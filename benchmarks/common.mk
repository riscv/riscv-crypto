
CC      = $(RISCV)/bin/riscv32-unknown-elf-gcc
AR      = $(RISCV)/bin/riscv32-unknown-elf-ar
OBJDUMP = $(RISCV)/bin/riscv32-unknown-elf-objdump
SIZE    = $(RISCV)/bin/riscv32-unknown-elf-size
SPIKE   = $(RISCV)/bin/spike
PK      = $(RISCV)/riscv32-unknown-elf/bin/pk

CONFIG ?= rv32-baseline

include config/$(CONFIG).conf

BUILD_DIR = $(REPO_BUILD)/benchmarks/$(CONFIG)

CFLAGS  += -Wall -I$(BUILD_DIR)/include
CFLAGS  += $(CONF_CFLAGS)

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
define map_dis
$(BUILD_DIR)/dis/${1:%.c=%.dis}
endef

#
# 1. Input file name
define map_size
$(BUILD_DIR)/size/${1:%.c=%.size}
endef

#
# 1. Relative header file path, as found by running "find"
define add_header_target
$(call map_header,${1}) : ${1}
	@mkdir -p $(dir $(call map_header,${1}))
	cp   $${<} $${@}

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

$(foreach INFILE,${2},$(call add_obj_target,${INFILE}))

$(call map_lib,${1}) : $(foreach INFILE,${2},$(call map_obj,${INFILE}))
	@mkdir -p $(dir $(call map_lib,${1}))
	$(AR) rcs $${@} $${^}

lib-${1} : $(call map_lib,${1})

TARGETS += $(call map_lib,${1})
endef


#
# 1. Source Files
# 2. Libraries
# 3. Name
define add_test_elf_target

$(call map_elf,${1},${3}) : ${1} $(foreach LIB,${2},$(call map_lib,${LIB}))
	@mkdir -p $(dir $(call map_elf,${1},${3}))
	$(CC) $(CFLAGS) -o $${@} $${^}

$(call map_dis,${1}) : $(call map_elf,${1},${3})
	@mkdir -p $(dir $(call map_dis,${1}))
	$(OBJDUMP) -D $${<} > $${@}

run-${3} : $(call map_elf,${1},${3})
	$(SPIKE) --isa=$(CONF_ARCH_SPIKE) $(PK) $(call map_elf,${1},${3})

TARGETS += $(call map_elf,${1},${3})
TARGETS += $(call map_dis,${1})

endef

