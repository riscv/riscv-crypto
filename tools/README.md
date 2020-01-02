
# RISC-V Crypto Tools

*Instructions and notes on building an experimental RISC-V Crypto enabled
toolchain and ISA simulator.*

---

1. Checkout the relevant repositories:
    ```sh
    $> $REPO_HOME/tools/clone-repos.sh
    ```
    This will clone GCC, Binutils, Newlib, the RISC-V Proxy kernel (PK)
    and the RISC-V ISA Simulator (Spike).

    It will then checkout known good commits on a new branch
    called `riscv-crypto`, where `$REPO_VERSION` is set
    by the riscv-crypto environment setup script in `bin/conf.sh`.

2. Apply the relevent patches to the checked out repositories:
    ```sh
    $> $REPO_HOME/tools/apply-patch-all.sh
    ```
    Or, apply them individually using the `tools/apply-patch-*.sh`
    scripts.



3. Build the repositories:
    ```sh
    $> $REPO_HOME/tools/build-all.sh
    ```
    This will configure build `binutils`, `gcc`, `newlib`, `pk` and `spike`,
    and place the compiled results in `$REPO_HOME/build/toolchain/install`.

   - The architecture the compiler will target is specified
     in `$REPO_HOME/tools/common.sh` as
     `TARGET_ARCH, `ARCH_STRING` and `ABI_STRING`.

   - Individual repositories can be re-built using the following
     commands:
     ```sh
     $> $REPO_HOME/tools/build-binutils.sh
     $> $REPO_HOME/tools/build-gcc.sh
     $> $REPO_HOME/tools/build-newlib.sh
     $> $REPO_HOME/tools/build-pk.sh
     $> $REPO_HOME/tools/build-spike.sh
     ```

   - To re-build a repository from scratch, first run the relevent
     `$REPO_HOME/tools/conf-*.sh` script before running the corresponding
     `build` script.

4. Set your `RISCV` environment variable:
    ```sh
    export RISCV=$REPO_BUILD/toolchain/install
    ```

