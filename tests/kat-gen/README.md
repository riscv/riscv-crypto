
# KAT-Gen

*Known Answer Test Generator - A tool to generate per-instruction known
answer tests for building confidence in different ISA simulators and models.*

---

## Motivation

This tool is used to build confidence in the functional correctness of
scalar crypto instructions between different implementations, be
they RTL, ISA simulators or formal models.
It also acts as a pre-cursor to building the RISC-V architectural
compliance tests.
If the same results are given across multiple different implementations,
then we can be confident each implementation is correct, and so use it
to generate known-good input/output test vectors for each instruction.

## Theory of Operation

- The entire program lives in the `kat_gen.c` file, with a single exposed
  function `kat_generate`.
  The `kat_generate` function takes two arguments:

  - `prng_seed` - An `XLEN`-bit integer which seeds the internal
    pseudo-random number generator.

  - `put_char` - A function pointer, which points at the equivalent of
    a `putc` function. All output of the generator goes through this
    function call. For the Spike example generator (`main_spike.c`), this
    just points at a wrapper for `printf`. This makes it very easy
    to re-target the output for any bare-metal SoC or simulator.

- Running the program will cause it to print out a *valid Python file*.
  This python file records several variables:

  - `xlen` and `prng_seed` record exactly what you expect them to.

  - The `kat_results` variable is a python list. Each list element is a
    tuple of two values: (`mnemonic`, `operands`).
    The `mnemonic` is a string representation of the mnemonic of the
    instruction.
    `operands` is dictionary mapping instruction operands and results
    (`rd`,`rs1`,`imm` etc) to values.

  - Hence walking this data structure gives you expected results for
    each instruction, given the recorded inputs.
    A little more scripting can be used to generate the required test
    formats for the RISC-V architectural compliance tests.

  - The initial seed is set to a compile time default, or may be
    specified as the first and only argument on the command line.
    It must be supplied as a decimal-number.

  - Note that the LFSR PRNG used to create 'random' values differs
    for RV32 and RV64, because it always uses and `XLEN`-bit state
    and differing tap points, taken from
    [here](https://www.xilinx.com/support/documentation/application_notes/xapp210.pdf).
    Also note that the PRNG is *updated before it is sampled*.

- Comparing the outputs of the program for different simulators
  (whether by walking the data structure, or just using a text diff)
  will tell you whether they match.

  - By default, the generate will run `1000` iterations per instruction.
    For instructions with small immediates, all immediate values are tested
    `1000` times to get complete coverage of the immediate values.

## Building and Running

Hopefully the `Makefile` is fairly self explanatory.
The main commands are:

```make
make build      # Build 32 and 64-bit versions of the KAT generator.
make generate   # Run the 32/64-bit generators on Spike.
```

All results and build artefacts are dumped to `$REPO_BUILD/kat-gen`.

The `prng_seed` may be set through the `Makefile` too using:

```make
make generate SEED=12345      # Use constant value "12345"
make generate SEED=`date +%s` # Use current unix time as seed
```


