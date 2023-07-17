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

MARCH_EXT_FLAGS=_zvbb_zvbc_zvkg_zvkned_zvknhb_zvksed_zvksh

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

GCM_VECTORS=\
        aes-gcm-vectors.h    \
        gcmDecrypt128.h      \
        gcmDecrypt256.h      \
        gcmEncryptExtIV128.h \
        gcmEncryptExtIV256.h \

SHA_VECTORS=\
        sha256-vectors.h \
        SHA256LongMsg.h  \
        SHA256ShortMsg.h \
        sha512-vectors.h \
        SHA512LongMsg.h  \
        SHA512ShortMsg.h

SM3_VECTORS=sm3-test-vectors.h

SM4_VECTORS=sm4-test-vectors.h

SUBDIR_CBC_VECTORS=$(CBC_VECTORS:%=$(TEST_VECTORS_DIR)/%)
SUBDIR_GCM_VECTORS=$(GCM_VECTORS:%=$(TEST_VECTORS_DIR)/%)
SUBDIR_SHA_VECTORS=$(SHA_VECTORS:%=$(TEST_VECTORS_DIR)/%)

C_OBJECTS=\
	aes-cbc-test.o \
	aes-gcm-test.o \
	log.o \
	sha-test.o \
	sm3-test.o \
	sm4-test.o \
	zkb-test.o \
	zvbb-test.o \
	zvbc-test.o \
	zvkg-test.o \

ASM_OBJECTS=\
	vlen-bits.o \
	zvb-ghash.o \
	zvbb.o \
	zvbc.o \
	zvkg.o \
	zvkned.o \
	zvknh.o \
        zvksed.o \
        zvksh.o \

default: aes-cbc-test aes-gcm-test sha-test sm3-test sm4-test zvbb-test zvbc-test zvkg-test

.PHONY: test-vectors
test-vectors: $(SUBDIR_CBC_VECTORS) $(SUBDIR_GCM_VECTORS) $(SUBDIR_SHA_VECTORS)

$(SUBDIR_CBC_VECTORS):
	python3 gentests.py cbc

$(SUBDIR_GCM_VECTORS):
	python3 gentests.py gcm

$(SUBDIR_SHA_VECTORS):
	python3 gentests.py sha256 sha512

$(C_OBJECTS): %.o: %.c test-vectors
	$(CC) -c $(CFLAGS) -o $@ $<

$(ASM_OBJECTS): %.o: %.s
	$(AS) -c $(CFLAGS) -o $@ $^

aes-cbc-test: aes-cbc-test.o zvkned.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

aes-gcm-test: aes-gcm-test.o zvb-ghash.o zvkg.o zvkned.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

sha-test: sha-test.o zvknh.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

sm3-test: sm3-test.o zvksh.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

sm4-test: sm4-test.o zvksed.o
	$(LD) $(LDFLAGS) -o $@ $^

zvbb-test: zvbb-test.o zvbb.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

zvbc-test: zvbc-test.o zvbc.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

zvkg-test: zvkg-test.o zvkg.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

# TODO: add VLEN=32, VLEN=64 runs.
.PHONY: run-aes-cbc
run-aes-cbc: aes-cbc-test
	for VLEN in 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

# TODO: add VLEN=64 runs.
.PHONY: run-aes-gcm
run-aes-gcm: aes-gcm-test
	for VLEN in 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

.PHONY: run-sha
run-sha: sha-test
	for VLEN in 64 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

.PHONY: run-sm3
run-sm3: sm3-test
	for VLEN in 64 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

.PHONY: run-sm4
run-sm4: sm4-test
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

.PHONY: run-zvkg
run-zvkg: zvkg-test
	for VLEN in 64 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

.PHONY: run-tests
run-tests: run-aes-cbc run-aes-gcm run-sha run-sm3 run-sm4 run-zvbb run-zvbc run-zvkg

.PHONY: clean
clean:
	rm -f $(SUBDIR_CBC_VECTORS)
	rm -f $(SUBDIR_GCM_VECTORS)
	rm -f $(SUBDIR_SHA_VECTORS)
	rm -f *.o
	rm -f aes-cbc-test
	rm -f aes-gcm-test
	rm -f sha-test
	rm -f sm3-test
	rm -f sm4-test
	rm -f zvbb-test
	rm -f zvbc-test
