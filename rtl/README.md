
# RISC-V Crypto RTL

*Notes on the experimental RTL for implementing proposed instructions.*

---

- [Experimental Results](#Experimental-Results)
  - [Component Modules](#Component-Modules)
  - [Top Level Modules](#Top-Level-Modules)
  - [SBoxes](#SBoxes)
- [Tool Flow](#Tool-Flow)

This directory contains *experimental* Verilog RTL implementing the proposed
RISC-V scalar crypto instructions.

## Experimental Results

These are the results of running each design through Yosys and ABC
to get repeatable synthesis results.

- Yosys has a "Simple CMOS" library, which targets only NAND, NOR, NOT
  cells. This is used to give a "NAND2 Equivalent" measurement.

- "Longest Topological Path Length" from input to output, measured after
  mapping to Yosys Abstract Cell representation.

Note that only the Cryptography Extension specific instructions are
implemented here.
For the shared Bitmanip instructions, see the draft
[Bitmanip specification](https://github.com/riscv/riscv-bitmanip).

### Component Modules

Each of these modules implements a single instruction group.
Some are parameterised by `XLEN`.

Module Name                       | NAND2 Cells | LTP
----------------------------------|-------------|-------------
`riscv_crypto_fu_lut4` (RV32)     |       566   |  6
`riscv_crypto_fu_lut4` (RV64)     |      1938   |  7
`riscv_crypto_fu_saes32`          |      1176   | 30
`riscv_crypto_fu_saes64` (8 Sbox) |      8663   | 28
`riscv_crypto_fu_saes64` (4 Sbox) |      6277   | 29
`riscv_crypto_fu_ssha256`         |       737   |  5
`riscv_crypto_fu_ssha512` (RV32)  |       701   |  6
`riscv_crypto_fu_ssha512` (RV64)  |      1986   |  4
`riscv_crypto_fu_ssm3`            |       474   |  3
`riscv_crypto_fu_ssm4`            |       724   | 25
`riscv_crypto_fu_saes32_ssm4`     |      1436   | 33

Notes:

- All modules compute their results in a single clock cycle and are
  completely combinatorial. I.e. they do not register their outputs.

- The `riscv_crypto_fu_saes64` module (64-bit scalar AES instructions)
  implements `8` Forward and Inverse SBoxes, and so is an upper bound
  on the expected size of the implementaiton.

- The `riscv_crypto_fu_saes32_ssm4` module implements both the scalar
  32-bit AES instructions, and the scalar SM4 instructions.
  These can be implemented such that they share a considerable amount of
  datapath logic.
  The combined module is smaller than the sum of the two individual
  modules (`riscv_crypto_fu_saes32` and `riscv_crypto_fu_ssm4`)
  at the cost of a longer critical path.

### Top Level Modules

Two modules are provided as "drop-in" functional units for
RV32 and RV64 CPUs.

- Both can be configured to support any combination of the
  scalar crypto instructions.

- They can also optionally drop support for AES decryption instructions.

- The RV32 core can also optionally use the combined AES+SM4 module,
  reducing it's size but increasing it's path length.

- The cores optionally allow gating of inputs to each sub-module.
  This prevents downstream toggling in logic we are not using for the current
  instruction and saves power.

Module Name            | Combined AES/SM4 | Gate Inputs | NAND2 Cells | LTP
-----------------------|------------------|-------------|-------------|------
`riscv_crypto_fu_rv32` |        No        |     No      |      4267   | 29
`riscv_crypto_fu_rv32` |       Yes        |     No      |      3845   | 34
`riscv_crypto_fu_rv32` |       Yes        |     Yes     |      3672   | 35
`riscv_crypto_fu_rv64` |       N/A        |     No      |     13678   | 29
`riscv_crypto_fu_rv64` |       N/A        |     Yes     |     14126   | 29
RocketCore RV32 MulDiv |       N/A        |     N/A     |      5167   | 43
RocketCore RV64 MulDiv |       N/A        |     N/A     |     12404   | 68

Notes:

- The numbers reported here are for all instructions being included.

- The RV64 core instances `8` sboxes for the 64-bit AES instructions.

- The results with(out) logic gating of the inputs are a little
  counter-intuitive.
  It is possible the synthesis tool is "being clever".
  I have no way of evaluating the effectivness of the logic
  gating at the moment, 3'rd party evaluations are very welcome.

- The RocketCore RV32 and RV64 mutliplier/divider units are included for
  comparison.
  These numbers are taken from the
  [Bitmanip Draft specification v0.92](https://github.com/riscv/riscv-bitmanip).


### SBoxes

The AES and (to a lesser extent) SM4 SBox implementations can dominate
the area and timing of the crypto cores.
The implementations used here are those found in
Markku's
[lwaes_isa](https://github.com/mjosaarinen/lwaes_isa/)
repository.
They use the Boyar-Peralta construction for the AES SBox, and
share the non-linear middle layer between the AES and SM4 SBoxes.

Module Name                 | NAND2 Cells | LTP
----------------------------|-------------|---------------
`riscv_crypto_aes_fwd_sbox` | 293         | 15
`riscv_crypto_aes_inv_sbox` | 306         | 15
`riscv_crypto_sm4_sbox`     | 307         | 17
`riscv_crypto_aes_sm4_sbox` | 742         | 19

Note: the `riscv_crypto_aes_sm4_sbox` module combines all three
SBox modules into one, using the shared middle non-linear layer.

## Tool Flow

You will need Yosys, SymbiYosys and Verilator installed for these flows
to work.

- Make sure you have run the project workspace setup script:

  ```sh
  $> bin/conf.sh
  $> cd $REPO_HOME/rtl
  ```

- To list the available synthesis targets:
  ```sh
  $> make print-synth-targets
  ```
  Or just use tab-completion for `make`.
  

- All of the synthesis jobs can be run in one go with:
  ```sh
  $> make synth-all
  ```

- Use verilator in linting mode:
  ```sh
  $> make lint-all
  ```

- The model checking targets can be run using:
  ```sh
  $> make prove-all
  ```

- The results of synthesis and simulation runs are placed in
 `$REPO_BUILD/rtl/*`.


