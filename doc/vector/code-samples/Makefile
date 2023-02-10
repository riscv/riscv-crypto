# Copyright 2022 Rivos Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SDK_ROOT?=~/RISC-V
TARGET?=riscv64-linux-gnu
SPIKE?=spike
PK?=$(SDK_ROOT)/$(TARGET)/bin/pk
LDFLAGS?=

AS?=$(TARGET)-as
CC?=$(TARGET)-gcc
LD?=$(TARGET)-gcc

MARCH_EXT_FLAGS=_zvbb_zvbc_zvkned
CFLAGS?=-march=rv64gcv$(MARCH_EXT_FLAGS)
CFLAGS+=-Wall
LDFLAGS+=-static
# Note that each Spike invocation adds a --isa flag of the form
#    --varch=vlen:$(VLEN),elen:64
# with different values of VLEN.
COMMON_SPIKE_FLAGS?=--isa=rv64gcv$(MARCH_EXT_FLAGS)

TEST_VECTORS_DIR=test-vectors

CBC_VECTORS=\
	CBCGFSbox128.h    \
	CBCGFSbox256.h    \
	CBCKeySbox128.h   \
	CBCKeySbox256.h   \
	CBCMMT128.h       \
	CBCMMT256.h       \
	CBCVarKey128.h    \
	CBCVarKey256.h    \
	CBCVarTxt128.h    \
	CBCVarTxt256.h    \
	aes-cbc-vectors.h \

SUBDIR_CBC_VECTORS=$(CBC_VECTORS:%=$(TEST_VECTORS_DIR)/%)

C_OBJECTS=\
	aes-cbc-test.o \
	log.o \
	zvbb-test.o \
	zvbc-test.o \

ASM_OBJECTS=\
	vlen-bits.o \
	zvbb.o \
	zvbc.o \
	zvkned.o \

default: aes-cbc-test zvbb-test zvbc-test

.PHONY: test-vectors
test-vectors: $(SUBDIR_CBC_VECTORS)

$(SUBDIR_CBC_VECTORS):
	python3 gentests.py cbc

$(C_OBJECTS): %.o: %.c test-vectors
	$(CC) -c $(CFLAGS) -o $@ $<

$(ASM_OBJECTS): %.o: %.s
	$(AS) -c $(CFLAGS) -o $@ $^

aes-cbc-test: aes-cbc-test.o zvkned.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

zvbb-test: zvbb-test.o zvbb.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

zvbc-test: zvbc-test.o zvbc.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

# TODO: add VLEN=32, VLEN=64 runs.
.PHONY: run-aes-cbc
run-aes-cbc: aes-cbc-test
	for VLEN in 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

.PHONY: run-zvbb
run-zvbb: zvbb-test
	for VLEN in 64 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

.PHONY: run-zvbc
run-zvbc: zvbc-test
	for VLEN in 64 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

.PHONY: run-tests
run-tests: run-aes-cbc run-zvbb run-zvbc

.PHONY: clean
clean:
	rm -f $(SUBDIR_CBC_VECTORS)
	rm -f *.o
	rm -f aes-cbc-test
	rm -f zvbb-test
	rm -f zvbc-test
