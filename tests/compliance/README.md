
# RISC-V Crypto Compliance Tests

*Work in progress compliance test development framework.*

---

## Useful Links

- [RISC-V Compliance Github Repo](https://github.com/riscv/riscv-compliance)
  - [Documentation](https://github.com/riscv/riscv-compliance/tree/master/doc)


## Getting Started

- Make sure that you are in the root of the `riscv-crypto` repository, and
  run the workspace setup script:

  ```
  source bin/conf.sh
  ```

  This makes sure that the `spike` and `sail` simulators (if they are
  built) are in the `$PATH`, which is needed by the compliance framework.

- Ensure the riscv-compliance sub-module is checked out:

  ```
  git submodule update --init extern/riscv-compliance
  ```

- The compliance tests are currently maintained as a patch to a known-good
  commit of the riscv-compliance repository.
  Once the riscv-compliance repo submodule is checked out, the following
  commands can be used to manage the patch.

  - Apply the patch to the submodule:

    ```
    make -C tests/compliance compliance-apply-patch
    ```

    This applies the `tests/compliance/riscv-compliance.patch` to
    the submodule, and stages the modifications.

  - Revert the patch:
    
    ```
    make -C tests/compliance compliance-revert-patch
    ```
    
    This puts the riscv-compliance sub-module pack to an un-modified state.

  - Update the patch:
    
    ```
    make -C tests/compliance compliance-update-patch
    ```

    This takes all of the *staged* changes in the riscv-compliance
    submodule, and updates the patch file in the riscv-crypto
    repository.


## Running the compliance tests

- Run:

  ```make
  make -C extern/riscv-compliance RISCV_TARGET=<target> RISCV_DEVICE=<device> RISCV_PREFIX=riscv64-unknown-elf
  ```

  Where:

  - `target` is one of `spike`, `sail-riscv-c` or `sail-riscv-ocaml`

    and

  - `device` is `rv32ik` or `rv64ik`, indicating the base 32/64-bit integer
    ISA, with support for the Crypto extension.


- Alternativley, run these short commands:

  ```make
  make -C tests/compliance compliance-run-spike-rv32
  make -C tests/compliance compliance-run-sail-csim-rv32
  make -C tests/compliance compliance-run-sail-ocaml-rv32
  make -C tests/compliance compliance-run-spike-rv64
  make -C tests/compliance compliance-run-sail-csim-rv64
  make -C tests/compliance compliance-run-sail-ocaml-rv64
  make -C tests/compliance compliance-run-all
  ```

  Which just wrap up the above long-form commands and run all of the
  available compliance tests.

