
# RISC-V Crypto RTL

*Notes on the experimental RTL for implementing proposed instructions.*

---

This directory contains *experimental* Verilog RTL implementing proposed
RISC-V scalar crypto instructions.

Each sub-directory implements a particular (class of) instruction(s).

The top level makefile contains macros useful for building simple
synthesis and simulation targets. Each sub-makefile it includes is
then responsible for adding the sensible targets for each instruction.

## Getting Started

You will need Yosys and Icarus Verilog installed for these flows to work.

- Make sure you have run the project workspace setup script:

  ```sh
  $> bin/conf.sh
  $> cd $REPO_HOME/rtl
  ```

- To list the available synthesis targets:
  ```sh
  $> make print-synth-targets
  ```
  
  All of which can be run in one go with:
  ```sh
  $> make synth-all
  ```

- To list the available simulation targets:
  ```sh
  $> make print-sim-targets
  ```

  Again, all of these can be run with:
  ```sh
  $> make sim-all
  ```

- The results of synthesis and simulation runs are placed in
 `$REPO_BUILD/rtl/*`.

## Preliminary Results

These are the results of running each design through Yosys and ABC
to get rough synthesis results.

Module Name    | Abstract Cells[1] | Simple CMOS Cells [2] | LTP[3]
---------------|-------------------|-----------------------|----------------
`lut4_rv32_v1` | 776               | 752                   | 8
`lut4_rv32_v2` | 813               | 839                   | 9
`lut4_rv32_v3` | 638               | 745                   | 8
`lut4_rv64`    | 2512              | 2496                  | 8
`ssha256`      | 439               | 928                   | 6
`ssha512`      | 951               | 1925                  | 6
`ssha3`        | TBD               | TBD                   | TBD

1. Abstract cells are Yosys's internal representation.

2. Yosys has a "Simple CMOS" library, which targets only NAND, NOR, NOT
   cells.

3. "Longest Topological Path Length" from input to output, measured after
   mapping to Yosys Abstract Cell representation.

