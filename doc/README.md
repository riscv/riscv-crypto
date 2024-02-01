
# Documentation

*Information on the specification and supplementary information.*

---

This directory contains the official draft specification, in
[AsciiDoc](https://asciidoctor.org/) form.
The specification is split into two components: Scalar+Entropy Source and
Vector.

To install the relevant tools for building a PDF document from the
AsciiDoc source, follow the instructions 
[here](https://github.com/riscv/docs-templates)

- Both specifications can be built by running:
  
  ```sh
  source bin/conf.sh
  git submodule update --init extern/sail-riscv extern/riscv-opcodes
  make specs
  ```
  from the root project of the directory.

  Note the `git submodule` command is needed, because Sail code is pulled
  directly from the source into the specification, so the files need to be
  checked out.

  Individual versions can be built by running:

  ```sh
  make -C doc/scalar all
  make -C doc/vector all
  ```

- Alternatively, pre-built versions corresponding to draft releases
  can be found on the
  [releases](https://github.com/riscv/riscv-crypto/releases)
  page.


- [Supplementary information](supp/supplementary-info.adoc),
  in [AsciiDoc](https://asciidoctor.org/) format.
  This contains various recommendations, discussions and design
  rationale which we have developed in conjunction to the specification.

