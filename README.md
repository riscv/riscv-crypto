
# RISC-V Cryptography Extension

*RISC-V cryptography extensions standardisation work.*

---

- [About](#About)
- [Specification](#Specification)
- [Formal Model](#Formal-Model)
- [Toolchain](#Toolchain)
- [Benchmarks](#Benchmarks)
- [Verilog RTL](#Verilog-RTL-Prototypes)

## About

This repository is used to develop standardisation proposals for
scalar cryptographic instruction set extensions for the RISC-V
architecture.

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
  
- See the [project board](https://github.com/riscv/riscv-crypto/projects/1)
  for a list of on-going  / open issues.

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
Currently, only the scalar instructions are implemented, since the
vector instructions are blocked by the implementation of the base
vector extension in the formal model.

These files currently need to be manually added to the existing
[sail-riscv](https://github.com/rems-project/sail-riscv)
model. A proper integration will be done eventually.
See [issue #20](https://github.com/riscv/riscv-crypto/issues/20)
for what is left to be implemented.
A log of open questions about SAIL is being kept in
[issue #22](https://github.com/riscv/riscv-crypto/issues/22).

## Toolchain

See [tools/README.md](tools/README.md) for instructions on how to
build the experimental toolchain.

## Benchmarks

See [`benchmarks/README.md`](benchmarks/README.md) for how to
get started with the benchmarking flow and how to contribute new
benchmarks.

## Verilog RTL Prototypes

See the [`rtl/`](rtl/) directory for information on experimental
RTL implementations of the proposed instructions.

