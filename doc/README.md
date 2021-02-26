
# Documentation

*Information on the specification and supplementary information.*

---

This directory contains two types of information:

- The official draft specification, in LaTeX form.
  The specification is split into two components: Scalar+Entropy Source and
  Vector.

  Both can be build by running:
  
  ```sh
  source bin/conf.sh
  git submodule update --init extern/sail-riscv
  make specs
  ```
  from the root project of the directory.

  Note the `git submodule` command is needed, because Sail code is pulled
  directly from the source into the specification, so the files need to be
  checked out.

  Individual versions can be built by running:

  ```sh
  make -C doc/ spec-scalar
  make -C doc/ spec-vector
  ```

- Alternatively, pre-built versions corresponding to draft releases
  can be found on the
  [releases](https://github.com/riscv/riscv-crypto/releases)
  page.


- [Supplementary information](supp/supplementary-info.adoc),
  in [AsciiDoc](https://asciidoctor.org/) format.
  This contains various recommendations, discussions and design
  rationale which we have developed in conjunction to the specification.

