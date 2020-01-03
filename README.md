
# RISC-V Crypto

*RISC-V cryptography extensions standardisation work.*

---

## About

- This repository is used to develop standardisation proposals for
  scalar cryptographic instruction set extensions for the RISC-V
  architecture.

  - The proposals in this repository are based on work done as part of the
    [XCrypto](https://github.com/scarv/xcrypto) project by the
    University of Bristol Cryptography Research Group on
    scalar cryptography extensions to RISC-V.

  - The Scalar Cryptography extension proposals overlap significantly
    with the **B**itmanip extension.
    Hence, we are experimenting with *sharing* opcodes between extensions.

- **Note:** These instructions are a work in progress. Their specifications
  are likely to change before being accepted as part of the RISC-V standard.

  - While there are *experimental* encodings assigned to the proposed
    instructions, they *should not* be depended upon.
    They only exist to enable a toolchain and simulator flow.
    They *will* change.

## Getting Started

- Checkout the repository:
  ```sh
  $> git clone git@github.com:scarv/riscv-crypto.git
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

  - No pre-compiled version of the spec is being kept yet (as was the
    case with Bitmanip) since everything is changing too quickly to
    make this managable.
    This will be done in future, when things are stable enough to
    discuss usefully.



