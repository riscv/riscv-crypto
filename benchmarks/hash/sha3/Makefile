
INPUT   = keccakp1600.c

TARGETS = 

CC      = $(RISCV)/bin/riscv64-unknown-elf-gcc
OBJDUMP = $(RISCV)/bin/riscv64-unknown-elf-objdump
SIZE    = $(RISCV)/bin/riscv64-unknown-elf-size

BUILD_DIR = $(REPO_BUILD)/benchmarks/hash/sha3

define map_obj
$(BUILD_DIR)/${2}-${1:%.c=%.o}
endef

define map_dis
$(BUILD_DIR)/${2}-${1:%.c=%.dis}
endef

define map_size
$(BUILD_DIR)/${2}-${1:%.c=%.size}
endef

CFLAGS  += -O3 -Wall

#
# 1. Input file.
# 2. Architecture string.
# 3. ABI string
#
define add_build_target

$(call map_obj,${1},${2}) : ${1}
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -mabi=${3} -march=${2} -c -o $${@} $${<}

$(call map_dis,${1},${2}) : $(call map_obj,${1},${2})
	@mkdir -p $(BUILD_DIR)
	$(OBJDUMP) -D $${<} > $${@}

$(call map_size,${1},${2}) : $(call map_obj,${1},${2})
	@mkdir -p $(BUILD_DIR)
	$(SIZE) -d $${<} > $${@}


TARGETS += $(call map_dis,${1},${2})
TARGETS += $(call map_obj,${1},${2})
TARGETS += $(call map_size,${1},${2})

endef

$(eval $(call add_build_target,$(INPUT),rv32imc,ilp32))
$(eval $(call add_build_target,$(INPUT),rv64imc,lp64))
$(eval $(call add_build_target,$(INPUT),rv32im,ilp32))
$(eval $(call add_build_target,$(INPUT),rv64im,lp64))

all: $(TARGETS)

clean:
	rm -f $(TARGETS)
