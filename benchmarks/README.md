
# RISC-V Crypto Benchmarking

*A description of how the RISC-V Crypto extension benchmarking suite works.*

---

## Purpose

The RISC-V Crypto benchmark suite is organised similarly to other
Crypto benchmarking efforts like
[SUPERCOP](https://bench.cr.yp.to/supercop.html).
However, it is somewhat *simplified* because it's aims are different.
Specifically, the primary aims are:

1. To evaluate a set of *popular* cryptographic algorithms on the *baseline*
   RISC-V architecture.
   These include:

   - The usual suspects from NIST:
     AES, SHA256, SHA512, SHA3/SHAKE/CSHAKE

   - Other standardised and widely used algorithms:
     ChaCha20, SM4

   - Primitive operations which are used *under the hood* in various
     cryptographic systems and protocols:
     Long Multiply, Modular Exponentiation etc.

2. To evaluate said algorithms on extended *variants* of the RISC-V
   architecture, and provide supporting evidence for proposed
   standard extensions to the ISA.
   Said variants include:

   - The
     [Bitmanip](https://github.com/riscv/riscv-bitmanip)
     `B` extension, which is currently nearing ratification.

   - The WIP `scalar` and `vector` cryptography extensions to RISC-V.

3. To provide a set of *secure and efficient* reference implementations
   of popular cryptographic algorithms for use with various
   RISC-V architectures.

4. To also provide optimised implementations for contributed cryptographic
   algorithms to assess the general usability of the RISC-V architecture
   from a cryptographic perspective.


## Organisation

```
├── README.md                       - You're reading it.
├── common.mk                       - Shared GNU Makefile macros / variables.
├── Makefile                        - Top level makefile for driving things.
├── config                          - Configs for different architcture variants.
│   ├── rv32-baseline-b.conf
│   ├── rv32-baseline.conf
│   └── rv32-zscrypto.conf
├── crypto_hash                     - The set of hash functions being analysed.
│   └── sha256
│       ├── api_sha256.h
│       ├── ref                     - Reference implementation.
│       └── zscrypto                - Scalar Proposal Evaluation.
├── share                           - Shared code.
│   ├── riscv-crypto-intrinsics.h   - Intrinsics for new instructions.
│   ├── test.h
│   └── util.h
└── test                            - Test code wrappers.
    ├── Makefile.in
    └── test_*.c
```

- Each algorithm belongs to a particular top-level catagory:
  hash functions, block ciphers etc.

- Each algorithm can have multiple implementations.
  For example, the SHA256 algorithm under `crypto_hash/`
  has (at the time of writing) two implementations.
  One is the reference / baseline taken from SUPERCOP, the
  other is optimised to use the proposed RISC-V scalar cryptography
  extensions.

  - Each implementation of each algorithm is compiled into it's own
    static library, as controlled by the `Makefile` in the implementation's
    directory.

  - All implementations of an algorithm have the same API, as defined
    in the `api_*.h` file for each algorithm.

  - A test program can then link against different implementations of the
    same algorithm to run a correctness test or benchmark.

## Getting Started

- Make sure you have setup a toolchain correctly.
  See [tools/README.md](../tools/README.md) for how to do this.

- Move into the benchmarking directory:
  ```sh
  $> cd $REPO_HOME/benchmarks
  ```
  This isn't strictly needed, but it reduced typing later on.

- You *must* select a particular architecture configuration from
  the `config/` folder before driving the benchmarking flow.
  Each config sets various architecture and optimisaiton flags.

  - By default, the `rv32-baseline` config is selected.

  - To pick another, add `CONFIG=[config name]` to the command line
    when running `make`, where `config/[config name].conf` is a file
    which exists.

**Building:**

- To build the various test libraries and executable for a given
  config, run:
  ```sh
  $> make CONFIG=rv32-baseline all
  ```

- For those without tab-completion, you can see which specific
  build targets are available with:
  ``` sh
  $> make CONFIG=rv32-baseline print-build-targets
  ```

- Results for each build are placed in
  `$REPO_BUILD/benchmarks/[CONFIG]/`.

  - `bin/` - Contains the test executables.

  - `lib/` - Contains the static libraries.

  - `dis/` - Contains disassembly and size information for each object file
             and exectuable.

  - `include/` - Contains the header files for each algorithm.

**Running:**

Currently, all benchmarks run using the patched version of the
Spike ISA simulator.

- To run all of the test and benchmark programs for a given config:
  ```sh
  $> make CONFIG=rv32-baseline run
  ```

- To run a specific test or benchmark:
  ```sh
  $> make CONFIG=rv32-baseline run-[test program]
  ```

- For those without tab-completion, you can see which specific
  run targets are available with:
  ``` sh
  $> make CONFIG=rv32-baseline print-run-targets
  ```


