
# RISC-V Crypto Tools

*Instructions and notes on building an experimental RISC-V Crypto enabled
toolchain and ISA simulator.*

---

**NOTE:** There is a task-list for creating an official GCC/Binutils patch
for the scalar cryptography extension [here](gcc-patch-tasks.adoc).

## Building the Toolchain

**TL;DR:**

```sh
$> export RISCV_ARCH=riscv64-unknown-elf
$> source bin/conf.sh
$> $REPO_HOME/tools/start-from-scratch.sh
```

You only need to clone the external repos once.

**Long Version:**

After first checking out the `riscv-crypto` repository:

- From the root of the project, run:
  ```sh
  source bin/conf.sh
  ```
  to setup the project workspace.

  - Note the value `RISCV`, This describes where the toolchain will be
    installed too.

- Checkout the relevant repositories:
    ```sh
    ${REPO_HOME}/tools/clone.sh
    ```
    This will clone GCC, Binutils, Newlib, the RISC-V Proxy kernel (PK)
    and the RISC-V ISA Simulator (Spike).

- For each component in the tool-chain, execute the associated
  patch application, 
  configuration, 
  and/or 
  compilation (plus installation)
  script in turn:

  - `binutils`

    ```sh
    ${REPO_HOME}/tools/binutils-apply.sh
    ```
    
  - `gcc`

    ```sh
    ${REPO_HOME}/tools/toolchain-conf.sh
    ${REPO_HOME}/tools/toolchain-build.sh
    ```

  - `pk` (the RISC-V proxy kernel):

    ```sh
    ${REPO_HOME}/tools/pk-conf.sh
    ${REPO_HOME}/tools/pk-build.sh
    ``` 

  - `spike`:

    ```sh
    ${REPO_HOME}/tools/spike-conf.sh
    ${REPO_HOME}/tools/spike-build.sh
    ``` 

   - This will build `binutils`, `gcc`, `pk` and `spike`,
     and place the compiled results in `${REPO_HOME}/build/toolchain/install`.

   - You can go and make some tea / coffee for this bit, it will take a while.

   - The architecture the compiler will target is specified
     in `${REPO_HOME}/tools/share.sh` as
     `TARGET_ARCH`, `ARCH_STRING` and `ABI_STRING`.

- To re-build a repository from scratch, first run the relevant
  `${REPO_HOME}/tools/conf-*.sh` script before running the corresponding
  `build` script.


## Development flow

This section describes the development flow for the `riscv-crypto`
toolchain and simulator patches.

- Assuming a fresh checkout of the `riscv-crypto` repository,
  run the steps described above so that you have a working baseline
  toolchain installation.

- There are three classes of tool script used to manage the patches:

  - The `tools/*-apply.sh` scripts are used to take the patches
    contained in the RISC-V Crypto repository and apply them to the cloned
    upstream repositories.

  - The `tools/*-revert.sh` scripts are used to put the cloned
    upstream repositories back to their known initial state.

  - The `tools/*-update.sh` scripts take the *staged* modifications
    to the relevant repository and updates the RISC-V Crypto diff.

- To modify a patch:

  - When the upstream repositores are first cloned, all relevant patches
    are automatically applied.

  - If a change is made to a cloned repository, you must run `git add` to
    make sure the changes are *staged* for commit.
    *Do Not* commit your changes to the cloned repository.

  - Then, run the appropriate `tools/*-update.sh` script and
    commit the change to the patch to the RISC-V Crypto repository.

## Relevant Files

These are the relevant files / locations which need editing when
adding or changing instructions.

### Binutils

- See `extern/riscv-gnu-toolchain/riscv-binutils`.
- `gas/config/tc-riscv.c` - Instruction assembly.
- `include/opcode/riscv-opc.h` - Instruction encoding masks.
- `include/opcode/riscv.h` - Instruction field masks.
- `opcodes/riscv-dis.c` - Disassembly.
- `opcodes/riscv-opc.c` - Instruction mnemonic and argument lists.

### Spike

- See `extern/riscv-isa-sim`.
- `riscv/decode.h` - Instruction encoding field access.
- `riscv/encoding.h` - Instruction encoding masks.
- `riscv/riscv.mk.in` - Makefile listing included instructions.
- `riscv/insns/*` - Instruction implementatons.

