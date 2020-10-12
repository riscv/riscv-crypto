
# RISC-V Crypto SAIL Model

*A brief explanation of the RISC-V Cryptography extension sail model, and
 how to patch the upstream version of SAIL with the model code in this
 repository.*

---

# Relevent Github issues:

A dynamically updated list can be found 
[here](https://github.com/riscv/riscv-crypto/issues?q=is%3Aissue+is%3Aopen+label%3ASAIL).
At the time of writing, these are the most relevant:

- [#20](https://github.com/riscv/riscv-crypto/issues/20) - SAIL Support: Scalar Instructions
- [#22](https://github.com/riscv/riscv-crypto/issues/22) - SAIL Questions.
- [#23](https://github.com/riscv/riscv-crypto/issues/23) - Vector SHA2 Mock SAIL code
- [#24](https://github.com/riscv/riscv-crypto/issues/24) - Vector AES Mock SAIL code

Issue 
[#22](https://github.com/riscv/riscv-crypto/issues/22)
is used to track open questions about using SAIL, and the RISC-V
implementation in SAIL.

## Reading guide for the Crypto SAIL Model

- All of the SAIL model files are found in `$REPO_HOME/sail/*.sail`.

  - `riscv_types_crypto.sail`  - Common code/constants. Includes stub
    register access functions for the mocked vector extension.

  - `riscv_insts_crypto.sail` - Scalar instructions which are identical
    for RV32 and RV64.

  - `riscv_insts_crypto_rv32.sail` - RV32-only scalar instructions.
  
  - `riscv_insts_crypto_rv64.sail` - RV64-only scalar instructions.

  - `riscv_insts_crypto_rvv_aes.sail` - Vector AES instructions.
  
  - `riscv_insts_crypto_rvv_alu.sail` - Vector rotate, grev and carry-less
    multiply.

  - `riscv_insts_crypto_rvv_sha.sail` - Vector SHA2 instructions.

  - `riscv_crypto_tests.sail` - Some simple self-contained tests for
    the vector AES/SHA2 instructions. Very work in progress.

- The scalar ISE code is complete (small changes or fixes not withstanding).

- The vector ISE code is work in progress, as the base vector extension
  is not yet implemented in SAIL. We have tried to implement as much as
  possible by using stub functions for vector register get/set accesses.

## Building the SAIL model.

First, you will need to build *the SAIL compiler*, before you can play
with *the RISC-V model implemented using SAIL*.
This process varys from platform to platform.
The `sail/setup-sail.sh` script can be used for Ubuntu/Debian systems.
See the
[guide](https://github.com/rems-project/sail/blob/sail2/BUILDING.md)
from the developers of SAIL for more information.

The following commands should be executed from `$REPO_HOME`, having
run `source bin/conf.sh` from the top of the `riscv-crypto` repository.

- Make sure the `$REPO_HOME/extern/sail-riscv` git submodule is checked out.

  ```
  git submodule update --init extern/sail-riscv
  ```

- Apply the patch to the SAIL makefile.
  
  ```
  make -C sail sail-apply-patch
  ```

  This applies the patch to the Makefile, and coppies the `*.sail` files
  from `$REPO_HOME/sail/` to `$REPO_HOME/extern/sail-riscv/model/`
  The `*.sail` sort files are *not* part of the patch to make it easier
  to manage the patch.

  Note that the SAIL model compilation process is *very* sensitive to
  file order, with non-obvious error messages or failures if something
  is missing, or in the wrong order.


- Build the SAIL models:

  ```
  make -C sail/ sail-build-rv32-csim    # Build the RV32 C simulator
  make -C sail/ sail-build-rv64-csim    # Build the RV64 C simulator
  make -C sail/ sail-build-rv32-osim    # Build the RV32 OCaml simulator
  make -C sail/ sail-build-rv64-osim    # Build the RV64 OCaml simulator
  make -C sail/ sail-build-all          # Build all of the above.
  ```

  Every time one of these commands is run, the `*.sail` files 
  from `$REPO_HOME/sail/` are coppied to `$REPO_HOME/extern/sail-riscv/model/`.
  Hence it is these files which should be edited to make changes.


- The SAIL repository can be put back to it's un-alterd state by running

  ```
  make -C sail sail-revert-patch
  ```

  This runs `git clean` under the hood.


- Look at `$REPO_HOME/tests/kat-gen` for an example of running ELF files
  on the SAIL simulator.

