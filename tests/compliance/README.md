
# RISC-V Crypto Compliance Tests

*Work in progress compliance test development framework.*

---

## Useful Links

- [RISC-V Compliance Github Repo](https://github.com/riscv/riscv-compliance)
  - [Documentation](https://github.com/riscv/riscv-compliance/tree/master/doc)


## Methodology:

This is the general methodology for generating the compliance tests for
the Scalar Crypto ISE.

1. Implement the ISE in Spike
2. Implement the ISE in SAIL
3. Create a simple host-agonistic test harness to generate input/output test
   vectors. This is found in `tests/kat-gen`.
4. Run the harness on Spike and SAIL, checking for diffs and fixing as
   appropriate. Again, see `tests/kat-gen/README.md` for an explanation
   of this.
5. Other TG members run the same harness on their implementations, and diff
   against the same output from SAIL/Spike. If everything matches, we can be
   confident that we have all implemented the same thing.
6. If we are all confident our implementations are correct, the compliance
   tests are generated from the test harness.
7. The generated compliance tests can then be re-run on all of our various
   implementations as a final check.

Once the first set of compliance test vectors are generated, we can all
use the existing riscv-compliance framework rather than the hacky
kat-generator tool. The kat-generator is just there to bootstrap the
process.

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


## Re-generating the reference outputs.

You will need `python3` and the [Jinja2](https://jinja.palletsprojects.com/en/2.11.x/) templating engine to run the test generation process.

- Run the KAT generator (see `tests/kat-generator` for instructions)
  to create a set of input/output vectors for every instruciton.

- Generate example outputs from your *trusted simulator*. We will use
  SAIL in this example.

  ```make
  make -C tests/compliance compliance-generate-rv32ik
  make -C tests/compliance compliance-run-sail-csim-rv32
  ```

- Ignore any reported test failures, and copy the generated test
  signatures into the *reference* signatures directory:

  ```
  make -C tests/compliance compliance-update-signatures-rv32ik
  ```

- Now, run a *different* simulator or target against the newly generated
  reference signatures to check they agree.
  Here, we run the SAIL OCaml simulator and Spike.

  ```make
  make -C tests/compliance compliance-run-sail-ocaml-rv32
  make -C tests/compliance compliance-run-spike-rv32
  ```

  If they don't agree, one (or both) of the simualtors is defintley wrong.

- The same process can be run, substituting `rv32` for `rv64` in all cases.

