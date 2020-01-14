
AS          = $(RISCV)/bin/riscv64-unknown-elf-as
CC          = $(RISCV)/bin/riscv64-unknown-elf-gcc
OBJDUMP     = $(RISCV)/bin/riscv64-unknown-elf-objdump

CFLAGS     += -O2 -Wall

ARCH_BASE   = rv64imafdcb
ARCH        = $(ARCH_BASE)_zscrypto
ABI         = lp64d

SPIKE       = $(RISCV)/bin/spike
PK          = $(RISCV)/riscv64-unknown-elf/bin/pk

define map_obj
$(BUILD_DIR)/$(basename ${1}).o
endef

define map_dis
$(BUILD_DIR)/$(basename ${1}).dis
endef

define map_elf
$(BUILD_DIR)/$(basename ${1}).elf
endef

define add_objdump_target
$(call map_dis,${1}) : ${2}
	$(OBJDUMP) -D $${^} > $${@}
endef

define add_assembler_target
$(call map_obj,${1}) : ${1}
	mkdir -p $(dir $(call map_obj,${1}))
	$(AS) -mabi=$(ABI) -march=$(ARCH) -o $${@} $${^}

$(call add_objdump_target,${1},$(call map_obj,${1}))

ALL_TARGETS +=$(call map_obj,${1})
ALL_TARGETS +=$(call map_dis,${1})
endef


define add_compiler_target
$(call map_obj,${1}) : ${1}
	mkdir -p $(dir $(call map_obj,${1}))
	$(CC) -c -mabi=$(ABI) -march=$(ARCH) -o $${@} $${^}

$(call add_objdump_target,${1},$(call map_obj,${1}))

ALL_TARGETS +=$(call map_obj,${1})
ALL_TARGETS +=$(call map_dis,${1})
endef


define add_elf_target
$(call map_elf,${1}) : ${1}
	mkdir -p $(dir $(call map_elf,${1}))
	$(CC) $(CFLAGS) -mabi=$(ABI) -march=$(ARCH) -o $${@} $${^}

$(call add_objdump_target,${1},$(call map_elf,${1}))

ALL_TARGETS +=$(call map_elf,${1})
ALL_TARGETS +=$(call map_dis,${1})
endef


define add_spike_target
run_${1} : $(call map_elf,${1})
	$(SPIKE) --isa=${ARCH_BASE} $(PK) $(call map_elf,${1})
ALL_TARGETS += run_${1}
endef
