
# RISC-V Crypto Architectural Tests

*Notes on the Cryptography Architectural Tests*

---

## Useful Links

- [RISC-V Architectural Tests Github Repo](https://github.com/riscv/riscv-arch-test)
  - [Documentation](https://github.com/riscv/riscv-arch-test/tree/master/doc)
- [Scalar Instructions Architectural Test Plan](test-plan-scalar.adoc)


## Getting Started

- Make sure that you are in the root of the `riscv-crypto` repository, and
  run the workspace setup script:

  ```
  source bin/conf.sh
  ```

  This makes sure that the `spike` and `sail` simulators (if they are
  built) are in the `$PATH`, which is needed by the architectural test
  framework.

- Ensure the riscv-arch-test sub-module is checked out:

  ```
  git submodule update --init extern/riscv-arch-test
  ```

**TODO:**

- Spike and Sail build/run instructions.
  This will be added after some pull requests to upstream Sail/Spike
  repositories are merged.

