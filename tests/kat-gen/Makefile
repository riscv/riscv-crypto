
CC      = $(RISCV)/bin/riscv64-unknown-elf-gcc
AR      = $(RISCV)/bin/riscv64-unknown-elf-ar
OBJDUMP = $(RISCV)/bin/riscv64-unknown-elf-objdump
SIZE    = $(RISCV)/bin/riscv64-unknown-elf-size
PK64    = $(RISCV)/riscv64-unknown-elf/bin/pk
PK32    = $(RISCV)/riscv32-unknown-elf/bin/pk
SPIKE   = $(RISCV)/bin/spike
SAIL32  = ~/riscv/sail-riscv/c_emulator/riscv_sim_RV32
SAIL64  = ~/riscv/sail-riscv/c_emulator/riscv_sim_RV64

KAT_BUILD       = $(REPO_BUILD)/kat-gen

KAT_SPIKE_ELF32 = $(KAT_BUILD)/kat_gen_spike32
KAT_SPIKE_ELF64 = $(KAT_BUILD)/kat_gen_spike64

KAT_SPIKE_LOG32 = $(KAT_BUILD)/kat_gen_spike32.py
KAT_SPIKE_LOG64 = $(KAT_BUILD)/kat_gen_spike64.py

KAT_SAIL_ELF32  = $(KAT_BUILD)/kat_gen_sail32
KAT_SAIL_ELF64  = $(KAT_BUILD)/kat_gen_sail64

KAT_SAIL_LOG32  = $(KAT_BUILD)/kat_gen_sail32.py
KAT_SAIL_LOG64  = $(KAT_BUILD)/kat_gen_sail64.py

KAT_GEN_SRC     = $(REPO_HOME)/tests/kat-gen/kat_gen.c
KAT_SPIKE_SRC   = $(REPO_HOME)/tests/kat-gen/main_spike.c
KAT_SAIL_SRC    = $(REPO_HOME)/tests/kat-gen/sail.S \
                  $(REPO_HOME)/tests/kat-gen/main_sail.c

# Use rather rich architecture subsets because newlib is only
# built for so many variants, and these are known to build well.
ARCH_32         = rv32imac
ARCH_64         = rv64imafdc
ABI_32          = ilp32
ABI_64          = lp64d

CFLAGS          = -Wall -O2 -D__ZSCRYPTO=1 -mcmodel=medany
CFLAGS         += -I $(REPO_HOME)/benchmarks/share
CFLAGS         += -I $(REPO_HOME)/tests/kat-gen
CFLAGS32        = -march=$(ARCH_32) -mabi=$(ABI_32)
CFLAGS64        = -march=$(ARCH_64) -mabi=$(ABI_64)

CFLAGS_SAIL     = -T$(REPO_HOME)/tests/kat-gen/sail.ld \
                  -static -nostdlib -nostartfiles

SEED            = 12345678
NUM_TESTS       = 1000

$(KAT_SPIKE_ELF32) : $(KAT_GEN_SRC) $(KAT_SPIKE_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAGS32) -o $@ $^
	$(OBJDUMP) -D $@ > $@.dis

$(KAT_SPIKE_ELF64) : $(KAT_GEN_SRC) $(KAT_SPIKE_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAGS64) -o $@ $^
	$(OBJDUMP) -D $@ > $@.dis

$(KAT_SPIKE_LOG32) : $(KAT_SPIKE_ELF32)
	$(SPIKE) --isa=$(ARCH_32) $(PK32) $< $(SEED) $(NUM_TESTS) > $@
	sed -i 's/bbl loader.*//' $@

$(KAT_SPIKE_LOG64) : $(KAT_SPIKE_ELF64)
	$(SPIKE) --isa=$(ARCH_64) $(PK64) $< $(SEED) $(NUM_TESTS) > $@
	sed -i 's/bbl loader.*//' $@


$(KAT_SAIL_ELF32) : $(KAT_GEN_SRC) $(KAT_SAIL_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAGS_SAIL)  $(CFLAGS32) -o $@ $^
	$(OBJDUMP) -D $@ > $@.dis

$(KAT_SAIL_ELF64) : $(KAT_GEN_SRC) $(KAT_SAIL_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CFLAGS_SAIL)  $(CFLAGS64) -o $@ $^
	$(OBJDUMP) -D $@ > $@.dis

$(KAT_SAIL_LOG32) : $(KAT_SAIL_ELF32)
	$(SAIL32) -V $< > $@

$(KAT_SAIL_LOG64) : $(KAT_SAIL_ELF64)
	$(SAIL64) -V $< > $@

sail32: $(KAT_SAIL_LOG32)
sail64: $(KAT_SAIL_LOG64)

build:    $(KAT_SPIKE_ELF32) $(KAT_SPIKE_ELF64) \
          $(KAT_SAIL_ELF32)

generate: $(KAT_SPIKE_LOG32) $(KAT_SPIKE_LOG64)

