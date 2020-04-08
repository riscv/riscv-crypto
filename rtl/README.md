
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

You will need Yosys, SymbiYosys and Icarus Verilog installed for these flows
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

- The model checking targets can be run using:
  ```sh
  $> make prove-all
  ```

- The results of synthesis and simulation runs are placed in
 `$REPO_BUILD/rtl/*`.

## Preliminary Results

These are the results of running each design through Yosys and ABC
to get rough synthesis results.

Module Name    | NAND2 Cells[1] | LTP[2]
---------------|----------------|----------------
`lut4_rv32`    | 566            | 6 
`lut4_rv64`    | 1888           | 7 
`aes_rv32`     | 1176           | 30
`aes_rv64`     | 8462           | 28
`ssha256`      | 787            | 5 
`ssha512`      | 1534           | 6 

1. Yosys has a "Simple CMOS" library, which targets only NAND, NOR, NOT
   cells.

2. "Longest Topological Path Length" from input to output, measured after
   mapping to Yosys Abstract Cell representation.

