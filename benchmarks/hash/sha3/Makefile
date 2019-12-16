
INPUT   = keccakp1600.c

TARGETS = 

CC      = $(RISCV)/bin/riscv64-unknown-elf-gcc
OBJDUMP = $(RISCV)/bin/riscv64-unknown-elf-objdump
SIZE    = $(RISCV)/bin/riscv64-unknown-elf-size

BUILD_DIR = $(REPO_BUILD)/benchmarks/hash/sha3

#
# 1. Profile
# 2. Input file name
# 3. Arch variant.
define map_obj
$(BUILD_DIR)/${1}-${3}-${2:%.c=%.o}
endef

#
# 1. Profile
# 2. Input file name
# 3. Arch variant.
define map_dis
$(BUILD_DIR)/${1}-${3}-${2:%.c=%.dis}
endef

#
# 1. Profile
# 2. Input file name
# 3. Arch variant.
define map_size
$(BUILD_DIR)/${1}-${3}-${2:%.c=%.size}
endef

CFLAGS  += -Wall

FLAGS_FAST = -O3
FLAGS_SMALL= -O2

#
# 1. Profile
# 2. Input file.
# 3. Architecture string.
# 4. ABI string
# 5. Flags
#
define add_build_target

$(call map_obj,${1},${2},${3}) : ${2}
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) ${5} -mabi=${4} -march=${3} -c -o $${@} $${<}

$(call map_dis,${1},${2},${3}) : $(call map_obj,${1},${2},${3})
	@mkdir -p $(BUILD_DIR)
	$(OBJDUMP) -D $${<} > $${@}

$(call map_size,${1},${2},${3}) : $(call map_obj,${1},${2},${3})
	@mkdir -p $(BUILD_DIR)
	$(SIZE) -d $${<} > $${@}


TARGETS += $(call map_dis,${1},${2},${3})
TARGETS += $(call map_obj,${1},${2},${3})
TARGETS += $(call map_size,${1},${2},${3})

endef

$(eval $(call add_build_target,fast,$(INPUT),rv32imc,ilp32,$(FLAGS_FAST)))
$(eval $(call add_build_target,fast,$(INPUT),rv64imc,lp64,$(FLAGS_FAST)))
$(eval $(call add_build_target,fast,$(INPUT),rv32im,ilp32,$(FLAGS_FAST)))
$(eval $(call add_build_target,fast,$(INPUT),rv64im,lp64,$(FLAGS_FAST)))

$(eval $(call add_build_target,small,$(INPUT),rv32imc,ilp32,$(FLAGS_SMALL)))
$(eval $(call add_build_target,small,$(INPUT),rv64imc,lp64,$(FLAGS_SMALL)))
$(eval $(call add_build_target,small,$(INPUT),rv32im,ilp32,$(FLAGS_SMALL)))
$(eval $(call add_build_target,small,$(INPUT),rv64im,lp64,$(FLAGS_SMALL)))

all: $(TARGETS)

clean:
	rm -f $(TARGETS)
