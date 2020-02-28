
# RISC-V Crypto

*RISC-V cryptography extensions standardisation work.*

---

**Note:** This repository is in the very early stages of development.

**TL;DR:** To see the latest draft release of the proposals, look at the
[Releases](https://github.com/scarv/riscv-crypto/releases) tab of
the [Github Repository](https://github.com/scarv/riscv-crypto).

## About

- This repository is used to develop standardisation proposals for
  scalar cryptographic instruction set extensions for the RISC-V
  architecture.

  - The Scalar Cryptography extension proposals overlap significantly
    with the [Bitmanip extension](https://github.com/riscv/riscv-bitmanip).
    Hence, we are experimenting with *sharing* opcodes between extensions.

  - Some of the proposals in this repository are based on work done as part of
    the [XCrypto](https://github.com/scarv/xcrypto) project by the University
    of Bristol Cryptography Group on scalar cryptography extensions
    to RISC-V.

- **Note:** These instructions are a work in progress. Their specifications
  will to change before being accepted as part of the RISC-V standard.  While
  there are *experimental* encodings assigned to the proposed instructions,
  they *should not* be depended upon.  They only exist to enable a toolchain
  and simulator flow.  They *will* change.

## Getting Started

- Checkout the repository:
  ```sh
  $> git clone git@github.com:scarv/riscv-crypto.git
  $> cd riscv-crypto
  $> git submodule update --init
  $> source bin/conf.sh
  ```

- See [`tools/README.md`](tools/README.md) for information on installing
  the experimental toolchain.

- A *very rough* draft of the extension proposals can be found in the
  `doc/` folder.
  It can be built by running:
  ```sh
  $> make spec
  ```
  from the root of the project.
  This will write the compiled document to
  `$REPO_BUILD/spec/riscv-crypto-spec.pdf`

  - A draft version will eventually be kept inside this repository
    (as the [riscv-bitmanip](https://github/riscv/riscv-bitmanip) repo did)
    once it has stablised enough.

- See [`benchmarks/README.md`](benchmarks/README.md) for how to
  get started with the benchmarking flow and how to contribute new
  benchmarks.

- See [`rtl/README.md`](rtl/README.md) for information on experimental
  RTL implementations of the proposed instructions.
