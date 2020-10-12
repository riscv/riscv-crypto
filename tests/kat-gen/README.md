
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
  The `kat_generate` function takes three arguments:

  - `prng_seed` - An `XLEN`-bit integer which seeds the internal
    pseudo-random number generator.

  - `put_char` - A function pointer, which points at the equivalent of
    a `putc` function. All output of the generator goes through this
    function call. For the Spike example generator (`main_spike.c`), this
    just points at a wrapper for `printf`. This makes it very easy
    to re-target the output for any bare-metal SoC or simulator.

  - `num_tests` - How many operand/result pairs to generate per instruction.

- Running the program will cause it to print out a *valid Python file*.
  This python file records several variables:

  - `xlen` and `prng_seed` record exactly what you expect them to.

  - The `kat_results` variable is a python list. Each list element is a
    tuple of two values: (`mnemonic`, `operands`).
    The `mnemonic` is a string representation of the mnemonic of the
    instruction.
    `operands` is dictionary mapping instruction operands
    (`rd`,`rs1`,`imm` etc) to values.

  - Hence walking this data structure gives you expected results for
    each instruction, given the recorded inputs.
    A little more scripting can be used to generate the required test
    formats for the RISC-V architectural compliance tests.

  - Note that the LFSR PRNG used to create 'random' values differs
    for RV32 and RV64, because it always uses and `XLEN`-bit state
    and differing tap points, taken from
    [here](https://www.xilinx.com/support/documentation/application_notes/xapp210.pdf).
    Also note that the PRNG is *updated before it is sampled*.

- Comparing the outputs of the program for different simulators
  (whether by walking the data structure, or just using a text diff)
  will tell you whether they match.

  - For instructions with small immediates, all immediate values are tested
    `num_tests` times to get complete coverage of the immediate values.

## Building and Running

Consult `sail/README.md` for instructions on building the patched
version of the SAIL ISA simulator.

Hopefully the `Makefile` is fairly self explanatory.
You will need to run the project setup script (`source bin/conf.sh`)
before these commands work.
The main commands, assuming you are in `$REPO_HOME`, are:

```make
make -C tests/kat-gen build    # Build 32 and 64-bit versions of the KAT generator.
make -C tests/kat-gen generate # Run the 32/64-bit generators on Spike.
```

All results and build artefacts are dumped to `$REPO_BUILD/kat-gen`.

For the spike example,
the `prng_seed` and `num_tests` may be set through the `Makefile` too using:

```make
make -C tests/kat-gen generate SEED=12345      # Use constant value "12345"
make -C tests/kat-gen generate SEED=`date +%s` # Use current unix time as seed
make -C tests/kat-gen generate NUM_TESTS=10 SEED=1243656 # Run 10 tests per instr with seed.
```

To check for differences between Spike and SAIL on RV32 or RV64, run:

```
make -C tests/kat-gen check-rv32 NUM_TESTS=100 SEED=12345678
make -C tests/kat-gen check-rv64 NUM_TESTS=100 SEED=12345678
```

Note `NUM_TESTS` and `SEED  must be set to the shown values, as this is hard
coded into the SAIL test harness.

Also note that the SAIL model is *very slow* compared to Spike.




