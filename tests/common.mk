
AS          = $(RISCV)/bin/riscv32-unknown-elf-as
CC          = $(RISCV)/bin/riscv32-unknown-elf-gcc
OBJDUMP     = $(RISCV)/bin/riscv32-unknown-elf-objdump

ARCH        = rv32imacb_zscrypto
ABI         = ilp32

define map_obj
$(BUILD_DIR)/$(basename ${1}).o
endef

define map_dis
$(BUILD_DIR)/$(basename ${1}).dis
endef

define add_objdump_target
$(call map_dis,${1}) : $(call map_obj,${1})
	$(OBJDUMP) -D $${^} > $${@}
endef

define add_assembler_target
$(call map_obj,${1}) : ${1}
	mkdir -p $(dir $(call map_obj,${1}))
	$(AS) -mabi=$(ABI) -march=$(ARCH) -o $${@} $${^}

$(call add_objdump_target,${1})

ALL_TARGETS +=$(call map_obj,${1})
ALL_TARGETS +=$(call map_dis,${1})
endef


define add_compiler_target
$(call map_obj,${1}) : ${1}
	mkdir -p $(dir $(call map_obj,${1}))
	$(CC) -mabi=$(ABI) -march=$(ARCH) -o $${@} $${^}

$(call add_objdump_target,${1})

ALL_TARGETS +=$(call map_obj,${1})
ALL_TARGETS +=$(call map_dis,${1})
endef
