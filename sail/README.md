
# RISC-V Crypto Sail Model

*A brief explanation of the RISC-V Cryptography extension sail model.*

---

# Relevent Github issues:

A dynamically updated list can be found 
[here](https://github.com/riscv/riscv-crypto/issues?q=is%3Aissue+is%3Aopen+label%3ASAIL).
At the time of writing, these are the most relevant:

- [#20](https://github.com/riscv/riscv-crypto/issues/20) - Sail Support: Scalar Instructions
- [#22](https://github.com/riscv/riscv-crypto/issues/22) - Sail Questions.
- [#23](https://github.com/riscv/riscv-crypto/issues/23) - Vector SHA2 Mock Sail code
- [#24](https://github.com/riscv/riscv-crypto/issues/24) - Vector AES Mock Sail code

Issue 
[#22](https://github.com/riscv/riscv-crypto/issues/22)
is used to track open questions about using Sail, and the RISC-V
implementation in Sail.

There is (at the time of writing) an open pull request against the
upstream Sail repository 
([#80](https://github.com/rems-project/sail-riscv/pull/80))
to merge in support for the scalar cryptography extension.

The current Sail submodule included in this repository (`extern/sail-riscv`)
currently points at a 
[public fork](https://github.com/ben-marshall/sail-riscv/tree/scalar-crypto)
where the development for Sail is being done.

## Reading guide for the Crypto Sail Model

All of the Sail model files are found in
`$REPO_HOME/extern/sail-riscv/model/*.sail`.

- `riscv_types_kext.sail`  - Common code/constants. Includes stub
  register access functions for the mocked vector extension.

- `riscv_insts_kext.sail` - Scalar instructions which are identical
  for RV32 and RV64.

- `riscv_insts_kext_rv32.sail` - RV32-only scalar instructions.

- `riscv_insts_kext_rv64.sail` - RV64-only scalar instructions.

The scalar ISE code is complete (small changes or fixes not withstanding).

## Building the Sail model.

First, you will need to build *the Sail compiler*, before you can play
with *the RISC-V model implemented using Sail*.
This process varys from platform to platform.
The `sail/setup-sail.sh` script can be used for Ubuntu/Debian systems.
See the
[guide](https://github.com/rems-project/sail/blob/sail2/BUILDING.md)
from the developers of Sail for more information.

The following commands should be executed from `$REPO_HOME`, having
run `source bin/conf.sh` from the top of the `riscv-crypto` repository.

- Make sure the `$REPO_HOME/extern/sail-riscv` git submodule is checked out.

  ```
  git submodule update --init extern/sail-riscv
  ```

- Build the Sail models:

  ```
  make -C sail/ sail-build-rv32-csim    # Build the RV32 C simulator
  make -C sail/ sail-build-rv64-csim    # Build the RV64 C simulator
  make -C sail/ sail-build-rv32-osim    # Build the RV32 OCaml simulator
  make -C sail/ sail-build-rv64-osim    # Build the RV64 OCaml simulator
  make -C sail/ sail-build-all          # Build all of the above.
  ```

## Experimental Vector extension code

These files live in `$REPO_HOME/sail`, as they are completely
experimental at the moment and not upstreamed.

- `riscv_insts_crypto_rvv_aes.sail` - Vector AES instructions.

- `riscv_insts_crypto_rvv_alu.sail` - Vector rotate, grev and carry-less
  multiply.

- `riscv_insts_crypto_rvv_sha.sail` - Vector SHA2 instructions.

- `riscv_crypto_tests.sail` - Some simple self-contained tests for
  the vector AES/SHA2 instructions. Very work in progress.

The vector ISE code is work in progress, as the base vector extension
is not yet implemented in Sail. We have tried to implement as much as
possible by using stub functions for vector register get/set accesses.

