# RFC: Vector carry-less multiply instruction options.

Following the TG meeting on June 2'nd 2020, these options are put forward for
comparison. There are three broad categories of instructions to consider:
- Hi/Lo instructions.
- Widening instructions.
- Multiply-Accumulate instructions.

There are also the orthogonal question of which values of `SEW` should the crypto
extension *require* support for?

Note: Much of 
[Markku's Analysis](https://github.com/scarv/riscv-crypto/blob/master/doc/supp/gcm-mode-cmul.adoc)
for the scalar GCM implementation also applies here.
Some of the example code below is based (with many apologies) on
[Markku's scalar code](https://github.com/mjosaarinen/lwaes_isa/blob/master/gcm_rv64b_gfmul.c).

## Instructions to consider

### Hi/Lo instructions

```
vclmul.vv   vrd, vrs1, vrs2, vm  // vrd[i] = vrs1[i] * vrs2[i] (SEW*SEW -> low  SEW)
vclmulh.vv  vrd, vrs1, vrs2, vm  // vrd[i] = vrs1[i] * vrs2[i] (SEW*SEW -> high SEW)
vclmul.vs   vrd, vrs1,  rs2, vm  // vrd[i] = vrs1[i] *  rs2    (SEW*SEW -> low  SEW)
vclmulh.vs  vrd, vrs1,  rs2, vm  // vrd[i] = vrs1[i] *  rs2    (SEW*SEW -> high SEW)
```
- These instructions work analogously to the base vector spec
  [Single-Width Integer Multiply Instructions](https://github.com/riscv/riscv-v-spec/blob/master/v-spec.adoc#1210-vector-single-width-integer-multiply-instructions)
- The `vclmul.*` instructions compute the low `SEW` bits of the `SEW*SEW`-bit multiply
- The `vclmulh.*` instructions compute the high `SEW` bits.

### Widening Instructions, with lo

```
vwclmul.vv   vrd, vrs1, vrs2, vm  // vrd[i] = vrs1[i] * vrs2[i] (SEW*SEW -> 2*SEW)
vwclmul.vs   vrd, vrs1,  rs2, vm  // vrd[i] = vrs1[i] *  rs2    (SEW*SEW -> 2*SEW)
vclmul.vv    vrd, vrs1, vrs2, vm  // vrd[i] = vrs1[i] * vrs2[i] (SEW*SEW -> low SEW)
vclmul.vs    vrd, vrs1,  rs2, vm  // vrd[i] = vrs1[i] *  rs2    (SEW*SEW -> low SEW)
```

- These instructions work analogously to the base vector spec
  [Widening Integer Multiply Instructions](https://github.com/riscv/riscv-v-spec/blob/master/v-spec.adoc#1212-vector-widening-integer-multiply-instructions)
- The `vwclmul.*` instructions compute the `2*SEW`-bit result of the 
  `SEW*SEW`-bit multiplication.
  - `EEW=  SEW` for `vrs1`, `vrs2` and `rs2`
  - `EEW=2*SEW` for `vrd`
  - The widening instructions are used for the multiplication part of the
    GHASH operation.
- The `vclmul.*` instructions are identical to the Hi/Lo ones and are needed for 
  the reduction.
- Questions:
  - Does using the widening instructions for the multiplication and non-widening
    for the reduction require a change of `SEW` value at any point?
  - When mixing widening and non-widening, do the `2*SEW` result elements of the
    widening instructions end up in the right places to easily perform the reduction?


### Carry-less Multiply Accumulate

```
// Hi/Lo: SEW -> SEW
vclmacc.vv    vrd, vrs1, vrs2, vm  // vrd[i] += vrs1[i] * vrs2[i]
vclmacch.vv   vrd, vrs1, vrs2, vm  // vrd[i] += vrs1[i] * vrs2[i]
vclmacc.vs    vrd, vrs1,  rs2, vm  // vrd[i] += vrs1[i] *  rs2
vclmacch.vs   vrd, vrs1,  rs2, vm  // vrd[i] += vrs1[i] *  rs2
// Widening: SEW -> 2*SEW
vwclmacc.vv   vrd, vrs1, vrs2, vm  // vrd[i] += vrs1[i] * vrs2[i]
vwclmacc.vs   vrd, vrs1,  rs2, vm  // vrd[i] += vrs1[i] *  rs2

```
- These instructions work analogously to the base vector spec
  [Single-Width Integer Multiply-Add Instructions](https://github.com/riscv/riscv-v-spec/blob/master/v-spec.adoc#1213-vector-single-width-integer-multiply-add-instructions)
  and
  [Vector Widening Integer Multiply-Add Instructions](https://github.com/riscv/riscv-v-spec/blob/master/v-spec.adoc#1214-vector-widening-integer-multiply-add-instructions).
- Their inclusion removes the need for `vxor` instructions in both the multiplication
  and the reduction steps.
- `xor` is very cheap to fuse into a carry-less multiply (compared to integer FMA).

## Open questions:

### Which values of `SEW` to require?
- The critical case for the vector crypto extension is `SEW=128`.
- Requiring `SEW=128` may be burdensome and face resistance.
- An alternative would be to require support for `SEW=XLEN`
  - This would make the vector code extremely similar to the
    [scalar code](https://github.com/mjosaarinen/lwaes_isa/blob/master/gcm_rv64b_gfmul.c#L25)
  - Implementers would be free to support `SEW >= XLEN`.
- Options: `SEW=XLEN`, `SEW>=XLEN`, `SEW=64/32`, `SEW=128`

### Should we include carry-less multiply-add?

- For supported values of `SEW < 128`, the `vclmac*` instructions become
  particularly useful as they fuse summing `vxor` operations.
  
### What is the exact subset of instructions we should require?

- We don't want to add work onto the base vector spec with late
  instruction requests. Instead, we will specify the minimum set of
  instructions needed to efficiently express GCM using the vector
  crypto extensions, expecting that more generic variants of the
  instructions will be included in later versions of the base
  vector specification.
 
- With that in mind, we must decide the exact subset of instructions
  needed, hopefully guided by the example code below.
  
  - Particularly, we may not need vector-vector and vector-scalar
    variants of every instruction.

## Example code

**Note:** None of this code is tested. It is only here to illustrate the
differences between the different feature sets described above.
The code will not compile due to use of variable names rather than
register names. It may be incorrect, any/all corrections are welcome.

- Inputs: `x*`, `y*`.
- Temporaries: `t*`.
- Outputs `z*`.


### Multiplication

SEW     | Option    |   Carry-less Multiply-accumulate
--------|-----------|-----------------------------------
64      | Hi/Lo     |   No
```
vector_gcm_mul:
  setvli     a0, a0, e64
  vclmulh.vv z3, x1, y1
  vclmul.vv  z2, x1, y1
  vclmulh.vv t1, x0, y1
  vclmul.vv  z1, x0, y1
  vxor       z2, z2, t1
  vclmulh.vv t1, x1, y0
  vclmul.vv  t0, x1, y0
  vxor       z2, z2, t1
  vxor       z1, z1, t0
  vclmulh.vv t1, x0, y0
  vclmul.vv  z0, x0, y0
  vxor       z1, z1, t1
```

SEW     | Option    | Carry-less Multiply-accumulate
--------|-----------|---------------------------------
64      | Hi/Lo     | Yes
```
vector_gcm_mul:
  setvli      a0, a0, e64
  vclmulh.vv  z3, x1, y1   // z3  = x1 * y1
  vclmul.vv   z2, x1, y1   // z2  = x1 * y1
  vclmul.vv   z1, x0, y1   // z1  = x0 * y1
  vclmacch.vv z2, x0, y1   // z2 += x0 * y1
  vclmacch.vv z2, x1, y0   // z2 += x1 * y0
  vclmacc.vv  z1, x1, y0   // z1 += x1 * y0
  vclmul.vv   z0, x0, y0   // z0  = x0 * y0
  vclmacch.vv z1, x0, y0   // z1 += x0 * y0
```


SEW     | Option    | Carry-less Multiply-accumulate
--------|-----------|---------------------------------
64      | Widening  | No 
```
vector_gcm_mul:
  setvli     a0, a0, e64
  vwclmul.vv z0, x0, y0    // 2 * SEW z0[i] = SEW x0[i] * y0[i]
  vwclmul.vv z1, x0, y1    // 2 * SEW z1[i] = SEW x0[i] * y1[i]
  vwclmul.vv z2, x1, y0    // 2 * SEW z2[i] = SEW x1[i] * y0[i]
  vwclmul.vv z3, x1, y1    // 2 * SEW z3[i] = SEW x1[i] * y1[i]
  vxor       z0, z0, z1    
  vxor       z0, z0, z2
  vxor       z0, z0, z3    // z0[i] += z1[i] + z2[i] + z3[i]
```


SEW     | Option    | Carry-less Multiply-accumulate
--------|-----------|---------------------------------
64      | Widening  | Yes
```
vector_gcm_mul:
  setvli      a0, a0, e64
  vwclmul.vv  z0, x0, y0    // 2 * SEW z0[i]  = SEW x0[i] * y0[i]
  vwclmacc.vv z0, x0, y1    // 2 * SEW z0[i] += SEW x0[i] * y1[i]
  vwclmacc.vv z0, x1, y0    // 2 * SEW z0[i] += SEW x1[i] * y0[i]
  vwclmacc.vv z0, x1, y1    // 2 * SEW z0[i] += SEW x1[i] * y1[i]
```


SEW     | Option    | Carry-less Multiply-accumulate
--------|-----------|---------------------------------
128     | Hi/Lo     | Not Needed
```
vector_gcm_mul:
  setvli     a0, a0, e128
  vclmulh.vv z1, x0, y0
  vclmul.vv  z0, x0, y0
```

SEW     | Option    | Carry-less Multiply-accumulate
--------|-----------|---------------------------------
128     | Widening  | Not Needed
```
vector_gcm_mul:
  setvli     a0, a0, e128
  vwclmul.vv z0, x0, y0    // z0[i] = x0[i] * y0[i]
```


### Reduction


SEW     | Option    | Carry-less Multiply-accumulate    | Multiply Method
--------|-----------|-----------------------------------|------------------
64      | Hi/Lo     | No                                | Hi/Lo
```
vector_gcm_mul:
  setvli      a0, a0, e64
  li          t0, 0x87
  vclmul.vs   v1, z3, t0    // v1 = z3 * t0
  vclmulh.vs  v2, z3, t0    // v2 = z3 * t0
  vxor        z2, z2, v1    // z2 = z2 + v1
  vxor        z1, z1, v2    // z1 = z1 + v2
  vclmul.vs   v1, z2, t0    // v1 = z2 * t0
  vclmulh.vs  v2, z2, t0    // v2 = z2 * t0
  vxor        z1, z1, v1    // z1 = z1 + v1
  vxor        z0, z0, v2    // z0 = z0 + v2
```

SEW     | Option    | Carry-less Multiply-accumulate    | Multiply Method
--------|-----------|-----------------------------------|------------------
64      | Hi/Lo     | No                                | Widening
```
vector_gcm_mul:
  setvli      a0, a0, e64
  li          t0, 0x87
  // TBD
```

SEW     | Option    | Carry-less Multiply-accumulate    | Multiply Method
--------|-----------|-----------------------------------|------------------
64      | Hi/Lo     | Yes                               | Hi/Lo
```
vector_gcm_mul:
  setvli      a0, a0, e64
  li          t0, 0x87
  vclmacc.vs  z2, z3, t0    // z2 += z3 * t0
  vclmacch.vs z1, z3, t0    // z1 += z3 * t0
  vclmacc.vs  z1, z2, t0    // z1 += z2 * t0
  vclmacc.vs  z0, z2, t0    // z0 += z2 * t0
```

SEW     | Option    | Carry-less Multiply-accumulate    | Multiply Method
--------|-----------|-----------------------------------|------------------
128     | Hi/Lo     | Yes                               | Any
```
vector_gcm_mul:
  setvli      a0, a0, e128
  li          t0, 0x87
  vclmul.vs   z0, z0, t0
```


