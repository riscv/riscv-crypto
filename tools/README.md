
# RISC-V Crypto Tools

*Instructions and notes on building an experimental RISC-V Crypto enabled
toolchain and ISA simulator.*

---

## Quickstart

After first checking out the `riscv-crypto` repository:

- From the root of the project, run:
  ```sh
  $> source bin/conf.sh
  ```
  to setup the project workspace.

- Then, run the getting started script in `tools/`:
  ```sh
  $> $REPO_HOME/tools/get-started.sh
  ```
  This will clone the relevant toolchain repos, checkout a known-good
  commit, apply the necessary patches and compile them.

- The resulting toolchain installation will appear in
  `$REPO_BUILD/toolchain/install`.

The next section explains each step in more detail:


## Getting Started

1. Checkout the relevant repositories:
    ```sh
    $> $REPO_HOME/tools/clone-repos.sh
    ```
    This will clone GCC, Binutils, Newlib, the RISC-V Proxy kernel (PK)
    and the RISC-V ISA Simulator (Spike).

    It will then checkout known good commits on a new branch
    called `riscv-crypto`, where `$REPO_VERSION` is set
    by the riscv-crypto environment setup script in `bin/conf.sh`.


2. Apply the relevant patches to the checked out repositories:
    ```sh
    $> $REPO_HOME/tools/apply-patch-all.sh
    ```
    Or, apply them individually using the `tools/apply-patch-*.sh`
    scripts.



3. Build the repositories:
    ```sh
    $> $REPO_HOME/tools/rebuild-all.sh
    ```
    This will configure build `binutils`, `gcc`, `newlib`, `pk` and `spike`,
    and place the compiled results in `$REPO_HOME/build/toolchain/install`.

   - The architecture the compiler will target is specified
     in `$REPO_HOME/tools/common.sh` as
     `TARGET_ARCH, `ARCH_STRING` and `ABI_STRING`.

   - Individual repositories can be re-built incrementally using the
     following commands:
     ```sh
     $> $REPO_HOME/tools/build-binutils.sh
     $> $REPO_HOME/tools/build-gcc.sh
     $> $REPO_HOME/tools/build-newlib.sh
     $> $REPO_HOME/tools/build-pk.sh
     $> $REPO_HOME/tools/build-spike.sh
     ```

   - To re-build a repository from scratch, first run the relevant
     `$REPO_HOME/tools/conf-*.sh` script before running the corresponding
     `build` script.

4. Run some basic tests to make sure that everything works:

    - Assembler:
      ```sh
      $> make tests-assembler
      ```

    - Compiler:
      ```sh
      $> make tests-compiler
      ```

    - Simulator:
      ```sh
      $> make tests-kat
      ```
      These are the **K**nown **A**nswer **T**ests (KAT) tests for
      each instruction implementation.
      They act as a simple sanity check.

    - All known tests:
      ```sh
      $> make tests-all
      ```

## Development flow

This section describes the development flow for the `riscv-crypto`
toolchain and simulator patches.

**Note:** This flow is awkward and temporary until dedicated
development branches can be setup on the relevant repositories.

- Assuming a fresh checkout of the `riscv-crypto` repository,
  run the [quickstart](#quickstart) steps described above so that you
  have a working baseline toolchain installation.

  - Running these steps will apply the patches to `binutils`, `gcc` and
    `spike` from the corresponding `tools/patch-*.patch` file.

- To make a change to a patch, navigate to the appropriate source tree
  under `$REPO_BUILD`:

  - `binutils`: `$REPO_BUILD/toolchain/riscv-binutils`

  - `gcc`: `$REPO_BUILD/toolchain/riscv-gcc`

  - `spike`: `$REPO_BUILD/toolchain/riscv-isa-sim`

- Make any changes to the relevant source tree.

  - The component projects can be re-built using the corresponding
    `$REPO_HOME/tools/build-*.sh` scripts.

  - To re-build the projects from scratch (rather than incrementally as
    is the default) run the corresponding
    `$REPO_HOME/tools/conf-*.sh` script.

- When you have finished making changes to a project:

  - Navigate to the project source tree.

  - Add the changes you want recorded with `git add .`
    You don't need to commit anything to a patched repository.

  - Run `git diff --cached > $REPO_HOME/tools/patch-<project>.patch`
    to dump the diff into the relevant patch file.

  - With the patch changed in `$REPO_HOME/tools/`, commit your changes
    to the `riscv-crypto` repository, noting in the commit message that
    other people will need to re-apply the patches.

