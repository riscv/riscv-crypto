
# RISC-V Cryptography Extension

*RISC-V cryptography extensions standardisation work.*

---

- [About](#About)
- [Specification](#Specification)
- [Formal Model](#Formal-Model)
- [Toolchain](#Toolchain)
- [Spike](#Spike)
- [Architectural Tests](#Architectural-Tests)
- [Benchmarks](#Benchmarks)
- [Verilog RTL](#Verilog-RTL-Prototypes)

## About

This repository is used to develop standardisation proposals for
scalar and vector cryptographic instruction set extensions for the RISC-V
architecture.

For a general overview of the extension status and ratification progress,
please see 
[our page on the RISC-V Wiki](https://wiki.riscv.org/x/MVcF).

- **Note:** See the
   [dev/next-release](https://github.com/riscv/riscv-crypto/tree/dev/next-release)
   branch for the most up to date version.

- **Note:** These instructions are a work in progress. Their specifications
  will to change before being accepted as part of the RISC-V standard.  While
  there are *experimental* encodings assigned to the proposed instructions,
  they *should not* be depended upon.  They only exist to enable a toolchain
  and simulator flow.  They *will* change.

- The Scalar Cryptography extension proposals overlap significantly
  with the [Bitmanip extension](https://github.com/riscv/riscv-bitmanip).
  Hence, we are experimenting with *sharing* opcodes between extensions.
  
- The Vector Cryptography extension proposals is available as a sub-directory
  of this repository [vector](https://github.com/riscv/riscv-crypto/tree/master/doc/vector)

- See the [project board](https://github.com/riscv/riscv-crypto/projects/1)
  for a list of on-going  / open issues.
  ["How Can I Help?"](https://github.com/riscv/riscv-crypto/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)

- Some of the proposals in this repository are based on work done as part of
  the [XCrypto](https://github.com/scarv/xcrypto) project by the University
  of Bristol Cryptography Group on scalar cryptography extensions
  to RISC-V.

## Specification

To see the latest draft release of the proposals, look at the
[Releases](https://github.com/riscv/riscv-crypto/releases) tab of
the [Github Repository](https://github.com/riscv/riscv-crypto).

Source code and supplementary information is found in the
[doc/](doc/README.md) directory.

## Formal Model

There is a work-in-progress formal-model implementation of the crypto
instructions in the `sail/` directory.
See the [README](sail/README.md) file for information on how to build
and use it.

## Toolchain

See [tools/README.md](tools/README.md) for instructions on how to
build the experimental toolchain.

There is also a [task list](tools/gcc-patch-tasks.adoc) for
implementing an upstreamable patch.
If you can implement this patch, please get in touch.

## Spike

Spike is included as a submodule (`extern/riscv-isa-sim`), since
we have upstream Spike support which is periodically updated as the
specification progresses.
See [tools/README.md](tools/README.md) for instructions on how to
build Spike.

## Architectural Tests 

See [tests/compliance/README.md](tests/compliance/README.md) for
information on how to run the work-in-progress
[RISC-V Architectural Test suite](https://github.com/riscv/riscv-arch-test)
for the cryptography extension.
You will need to setup the toolchain, spike and SAIL before you can do
this.

There is also a work-in-progress 
[test plan](tests/compliance/test-plan-scalar.adoc)
for the Scalar cryptography extensions.

**Note:** This was formally known as the _riscv-compliance_ test suite.
Hence there are some references or directories to "compliance".
These have been left in some cases to preserve widely shared links,
especially to the test plan.

## Benchmarks

See [`benchmarks/README.md`](benchmarks/README.md) for how to
get started with the benchmarking flow and how to contribute new
benchmarks.

## Verilog RTL Prototypes

See the [`rtl/`](rtl/) directory for information on experimental
RTL implementations of the proposed instructions.

