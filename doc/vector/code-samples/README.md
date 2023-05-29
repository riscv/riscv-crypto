RISC-V Vector Crypto Proof of Concepts
======================================

This directory contains a set of examples designed to showcase the
functionality of RISC-V Vector Crypto ISA extensions.

Assembly (.s) files contain routines for algorithms utilizing instructions of a
given extension (denoted by the file name) directly while C (.c) files contain
all the support code required to verify them.

Specifically:

- aes-cbc-test.c - implements the AES-CBC with a 128 or 256 bit key using the
  Zvkns extension. The resulting program runs this implementation against NIST
  Known Answer Tests.
- aes-gcm-test.c - implements the AES-GCM with a 128 or 256 bit key using Zvkns,
  Zvkg, Zvbb, and Zvbc extensions. The resulting program runs
  this implementation against NIST Known Answer Tests.
- zvbb-test.c - shows proper usage of instructions in the Zvbb extension. The
  resulting program generates a set of random verification data and applies
  the Zvbb routines to that.
- zvbc-test.c - shows usage of the Zvbc extensions.
- sm3-test.c - implements the SM4 hashing using the Zvksh extension. The
  resulting program runs this implementation against test vectors defined in
  SM3 IETF draft (see [1]).
- sm4-test.c - implements the SM4 block cypher using the Zvksed extension. The
  resulting program runs this implementation against test vectors defined in
  SM4 IETF draft (see [2]).

Pre-requisites
--------------

To compile and run programs in this directory a several pre-requisites have to
be met:

1. `riscv64-linux-gnu` toolchain available in the `PATH`.
2. Vector Crypto compatible `binutils-gdb` available in the `PATH` overriding
   the above toolchain (see [3]).
3. Vector Crypto compatible Spike available in the `PATH` (see [4]).
4. The RISC-V Proxy kernel (`riscv-pk`) compiled and available in
   `~/RISC-V/riscv64-linux-gnu/bin/pk` (can be overridden with the `PK` make
   variable).

Build & run
-----------

The default `make` target (`default`) will compile the code for all examples.

To run all examples run the `run-tests` target.

### Example `make` invocations

```bash
# Build and run all examples with the default toolchain and riscv-pk location
make run-tests
# Build and run the aes-gcm-test example with the default toolchain and
# riscv-pk location.
make run-aes-gcm
# Override riscv-pk location
make run-tests PK=/opt/prefix/riscv64-linux-gnu/bin/pk
# Override target triplet and riscv-pk location
make run-tests TARGET=riscv64-unknown-linux-gnu \
               PK=/opt/prefix/riscv64-linux-gnu/bin/pk
```

### Make targets

- `default` - Build all examples.
- `clean` - Clean build artifacts.
- `aes-cbc-test` - Build the AES-CBC example.
- `aes-gcm-test` - Build the AES-GCM example.
- `sha-test` - Build the SHA example.
- `sm3-test` - Build the SM3 example.
- `sm4-test` - Build the SM4 example.
- `zvbb-test` - Build the Zvbb example.
- `run-tests` - Build and run all examples.
- `run-aes-cbc` - Build and run the AES-CBC example in Spike.
- `run-aes-gcm` - Build and run the AES-GCM example in Spike.
- `run-sha` - Build and run the SHA example in Spike.
- `run-sm3` - Build and run the SM3 example in Spike.
- `run-sm4` - Build and run the SM4 example in Spike.
- `run-zvbb` - Build and run the Zvbb example in Spike.

### Make variables

- `TARGET` - Target triplet to use. By default riscv64-linux-gnu.
- `PK` - Location of the riscv-pk binary. By default it's
  `~/RISC-V/$(TARGET)/bin/pk`.

See Makefile for more details.

References
----------

- [1] https://datatracker.ietf.org/doc/html/draft-oscca-cfrg-sm3-00
- [2] https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10
- [3] https://github.com/rivosinc/binutils-gdb/tree/zvk-vector-crypto
- [4] https://github.com/rivosinc/riscv-isa-sim/tree/zvk-vector-crypto
