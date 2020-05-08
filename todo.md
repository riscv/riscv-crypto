
# Todo List

*Somwehere to publically keep track of tasks.*

---

## Software

Algorithm   | Baseline | RV32  | RV64
------------|----------|-------|--------------
AES         |    x     |  x    | x
SHA256      |    x     |  x    | x
SHA512      |    x     |       | x
SHA3        |    x     |       |
SM3         |          |       | 
SM4         |    x     |  x    | x

- For SM4 example code, see
  [mjosaarinen / lwaes_isa](https://github.com/mjosaarinen/lwaes_isa/).

- For SHA3 / RV32 SHA 512 and SM3 example code, see
  [mjosaarinen / lwsha_isa](https://github.com/mjosaarinen/lwsha_isa/).

## Hardware

**Individual Instructions / classes:**

- [x] [Lut4](rtl/lut4)
- [x] [AES RV32](rtl/aes/rv32)
- [x] [AES RV64](rtl/aes/rv64)
- [x] [SHA256](rtl/ssha256)
- [x] [SHA512](rtl/ssha512)
- [x] [SM3](rtl/ssm3)
- [x] [SM4](rtl/ssm4)

**Combined Instruction Classes:**

- [ ] AES RV32 + SM4.
- [x] All SHA instructions.
- [x] Complete Crypto ISE Core "drop-in".


## Public review checklist

This is still being compiled by others in the foundation, but will include:

- [ ] Compliance tests.
- [ ] Formal Spec.
- [ ] Human Spec.

