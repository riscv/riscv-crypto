
/*
 * file: riscv_insts_crypto_rvv_alu.sail
 *
 * This file contains the vector specific cryptography extension
 * instructions.
 *
 * This file must be included in the model iff the vector crypto extension
 * is supported.
 *
 */


union   clause ast    =       VCLMUL_VV : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =       VCLMUL_VS : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =      VCLMULH_VV : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =      VCLMULH_VS : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =      VCLMACC_VV : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =      VCLMACC_VS : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =     VCLMACCH_VV : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =     VCLMACCH_VS : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =      VWCLMUL_VV : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =      VWCLMUL_VS : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =     VWCLMACC_VV : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =     VWCLMACC_VS : (vregidx,vregidx,vregidx,bits(1))

union   clause ast    =         VROT_VV : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =         VROT_VS : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =         VROT_VI : (vregidx,bits(5),vregidx,bits(1))
union   clause ast    =         VROT_VX : (vregidx,regidx,vregidx,bits(1))

union   clause ast    =        VGREV_VV : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =        VGREV_VS : (vregidx,vregidx,vregidx,bits(1))
union   clause ast    =        VGREV_VI : (vregidx,bits(5),vregidx,bits(1))
union   clause ast    =        VGREV_VX : (vregidx,regidx,vregidx,bits(1))

mapping clause assembly =       VCLMUL_VV (vd,vs1,vs2,vm) <-> "vclmul.vv" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =       VCLMUL_VS (vd,vs1,vs2,vm) <-> "vclmul.vs" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =      VCLMULH_VV (vd,vs1,vs2,vm) <-> "vclmulh.vv" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =      VCLMULH_VS (vd,vs1,vs2,vm) <-> "vclmulh.vs" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =      VCLMACC_VV (vd,vs1,vs2,vm) <-> "vclmacc.vv" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =      VCLMACC_VS (vd,vs1,vs2,vm) <-> "vclmacc.vs" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =     VCLMACCH_VV (vd,vs1,vs2,vm) <-> "vclmacch.vv" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =     VCLMACCH_VS (vd,vs1,vs2,vm) <-> "vclmacch.vs" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =      VWCLMUL_VV (vd,vs1,vs2,vm) <-> "vwclmul.vv" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =      VWCLMUL_VS (vd,vs1,vs2,vm) <-> "vwclmul.vs" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =     VWCLMACC_VV (vd,vs1,vs2,vm) <-> "vwclmacc.vv" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =     VWCLMACC_VS (vd,vs1,vs2,vm) <-> "vwclmacc.vs" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =         VROT_VV (vd,vs1,vs2,vm) <-> "vrot.vv" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =         VROT_VS (vd,vs1,vs2,vm) <-> "vrot.vs" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =         VROT_VI (vd,simm5,vs2,vm) <-> "vrot.vi" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ hex_bits_5(simm5) ^ sep() ^ vreg_name(vd)
mapping clause assembly =         VROT_VX (vd,rs1,vs2,vm) <-> "vrot.vx" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ reg_name(rs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =        VGREV_VV (vd,vs1,vs2,vm) <-> "vgrev.vv" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =        VGREV_VS (vd,vs1,vs2,vm) <-> "vgrev.vs" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =        VGREV_VI (vd,simm5,vs2,vm) <-> "vgrev.vi" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ hex_bits_5(simm5) ^ sep() ^ vreg_name(vd)
mapping clause assembly =        VGREV_VX (vd,rs1,vs2,vm) <-> "vgrev.vx" ^ spc() ^ vm_name(vm) ^ sep() ^ vreg_name(vs2) ^ sep() ^ reg_name(rs1) ^ sep() ^ vreg_name(vd)

mapping clause encdec =       VCLMUL_VV   (vd,vs1,vs2,vm) <-> 0b010000 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =       VCLMUL_VS   (vd,vs1,vs2,vm) <-> 0b010001 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =      VCLMULH_VV   (vd,vs1,vs2,vm) <-> 0b010010 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =      VCLMULH_VS   (vd,vs1,vs2,vm) <-> 0b010011 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =      VCLMACC_VV   (vd,vs1,vs2,vm) <-> 0b010100 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =      VCLMACC_VS   (vd,vs1,vs2,vm) <-> 0b010101 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =     VCLMACCH_VV   (vd,vs1,vs2,vm) <-> 0b010110 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =     VCLMACCH_VS   (vd,vs1,vs2,vm) <-> 0b010111 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =      VWCLMUL_VV   (vd,vs1,vs2,vm) <-> 0b011000 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =      VWCLMUL_VS   (vd,vs1,vs2,vm) <-> 0b011001 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =     VWCLMACC_VV   (vd,vs1,vs2,vm) <-> 0b011010 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =     VWCLMACC_VS   (vd,vs1,vs2,vm) <-> 0b011011 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =         VROT_VV   (vd,vs1,vs2,vm) <-> 0b100000 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =         VROT_VS   (vd,vs1,vs2,vm) <-> 0b100001 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =         VROT_VI   (vd,simm5,vs2,vm) <-> 0b100010 @ 0b011 @ vd @ simm5 @ vs2 @ vm @ 0b1011011
mapping clause encdec =         VROT_VX   (vd,rs1,vs2,vm) <-> 0b100011 @ 0b100 @ vd @ rs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =        VGREV_VV   (vd,vs1,vs2,vm) <-> 0b100100 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =        VGREV_VS   (vd,vs1,vs2,vm) <-> 0b100101 @ 0b000 @ vd @ vs1 @ vs2 @ vm @ 0b1011011
mapping clause encdec =        VGREV_VI   (vd,simm5,vs2,vm) <-> 0b100110 @ 0b011 @ vd @ simm5 @ vs2 @ vm @ 0b1011011
mapping clause encdec =        VGREV_VX   (vd,rs1,vs2,vm) <-> 0b100111 @ 0b100 @ vd @ rs1 @ vs2 @ vm @ 0b1011011


/*
 * Vector Carryless Multiplys
 * ------------------------------------------------------------
 */

/* A generic 64x64->128 bit carry-less multiply function.
 */
val      clmul64 : (bits(64), bits(64)) -> bits(128)
function clmul64   (x       , y       ) = {
    accumulator     : bits(128) = EXTZ(0x0);
    multiplicand    : bits(128) = EXTZ(  x);
    foreach(i from 0 to 63) {
        if(bit_to_bool(y[i])) then accumulator = accumulator ^ multiplicand;
        multiplicand = multiplicand << 1;
    };
    accumulator
}

/* Vector-Vector - RHS is i'th element of vs1 */
function clause execute (      VCLMUL_VV (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, i);
          let result  : bits(32) = clmul64(EXTZ(lhs), EXTZ(rhs))[31..0];
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, i);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[63..0];
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-Scalar - RHS is 0'th element of vs1 */
function clause execute (      VCLMUL_VS (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, 0);
          let result  : bits(32) = clmul64(EXTZ(lhs), EXTZ(rhs))[31..0];
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, 0);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[63..0];
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-vector. RHS is i'th element of vs1. High half of result. */
function clause execute (     VCLMULH_VV (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, i);
          let result  : bits(32) = clmul64(EXTZ(lhs), EXTZ(rhs))[63..32];
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, i);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[127..64];
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-Scalar. RHS is 0'th element of vs1. High half of result. */
function clause execute (     VCLMULH_VS (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, 0);
          let result  : bits(32) = clmul64(EXTZ(lhs), EXTZ(rhs))[63..32];
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, 0);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[127..64];
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-vector. RHS is i'th element of vs1. Accumulate with vd. */
function clause execute (     VCLMACC_VV (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, i);
          let result  : bits(32) = clmul64(EXTZ(lhs), EXTZ(rhs))[31.. 0] ^
                                   vGetElement32(vd , i);
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, i);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[63.. 0] ^
                                   vGetElement64(vd , i);
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-Scalar. RHS is 0'th element of vs1. Accumulate with vd. */
function clause execute (     VCLMACC_VS (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, 0);
          let result  : bits(32) = clmul64(EXTZ(lhs), EXTZ(rhs))[31.. 0] ^
                                   vGetElement32(vd , i);
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, 0);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[63.. 0] ^
                                   vGetElement64(vd , i);
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-vector. RHS is i'th element of vs1. Accumulate with vd. High half */
function clause execute (    VCLMACCH_VV (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, i);
          let result  : bits(32) = clmul64(EXTZ(lhs), EXTZ(rhs))[63..32] ^
                                   vGetElement32(vd , i);
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, i);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[127..64] ^
                                   vGetElement64(vd , i);
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-Scalar. RHS is 0'th element of vs1. Accumulate with vd. High half */
function clause execute (    VCLMACCH_VS (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, 0);
          let result  : bits(32) = clmul64(EXTZ(lhs), EXTZ(rhs))[63..32] ^
                                   vGetElement32(vd , i);
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, 0);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[127..64] ^
                                   vGetElement64(vd , i);
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-vector. RHS is i'th element of vs1. Accumulate with vd. Widening. */
function clause execute (     VWCLMUL_VV (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, i);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[63.. 0];
          vSetElement64(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, i);
          let result  : bits(128) = clmul64(EXTZ(lhs), EXTZ(rhs))[127..0];
          vSetElement128(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-Scalar. RHS is 0'th element of vs1. Accumulate with vd. Widening. */
function clause execute (     VWCLMUL_VS (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, 0);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[63.. 0];
          vSetElement64(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, 0);
          let result  : bits(128) = clmul64(EXTZ(lhs), EXTZ(rhs))[127..0];
          vSetElement128(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-Vector. RHS is i'th element of vs1. Accumulate with vd. Widening. accumulate */
function clause execute (    VWCLMACC_VV (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, i);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[63.. 0] ^
                                   vGetElement64(vd, i);
          vSetElement64(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, i);
          let result  : bits(128) = clmul64(EXTZ(lhs), EXTZ(rhs))[127..0] ^
                                   vGetElement128(vd, i);
          vSetElement128(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-Vector. RHS is 0'th element of vs1. Accumulate with vd. Widening. accumulate */
function clause execute (    VWCLMACC_VS (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let lhs     : bits(32) = vGetElement32(vs2, i);
          let rhs     : bits(32) = vGetElement32(vs1, 0);
          let result  : bits(64) = clmul64(EXTZ(lhs), EXTZ(rhs))[63.. 0] ^
                                   vGetElement64(vd, i);
          vSetElement64(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let lhs     : bits(64) = vGetElement64(vs2, i);
          let rhs     : bits(64) = vGetElement64(vs1, 0);
          let result  : bits(128) = clmul64(EXTZ(lhs), EXTZ(rhs))[127..0] ^
                                   vGetElement128(vd, i);
          vSetElement128(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/*
 * Vector Rotations
 * ------------------------------------------------------------
 */

/* Vector - Vector right rotate */
/* --- specification snippet begin --- */
function clause execute (        VROT_VV (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let eval    : bits(32) = vGetElement32(vs2, i);
          let ramt    : bits( 5) = vGetElement32(vs1, i)[4..0];
          let result  : bits(32) = ((eval @ eval) >> ramt)[31..0];
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let eval    : bits(64) = vGetElement64(vs2, i);
          let ramt    : bits( 6) = vGetElement64(vs1, i)[5..0];
          let result  : bits(64) = ((eval @ eval) >> ramt)[63..0];
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}
/* --- specification snippet begin --- */

/* Vector - Scalar right rotate */
function clause execute (        VROT_VS (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let eval    : bits(32) = vGetElement32(vs2, i);
          let ramt    : bits( 5) = vGetElement32(vs1, 0)[4..0];
          let result  : bits(32) = ((eval @ eval) >> ramt)[31..0];
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let eval    : bits(64) = vGetElement64(vs2, i);
          let ramt    : bits( 6) = vGetElement64(vs1, 0)[5..0];
          let result  : bits(64) = ((eval @ eval) >> ramt)[63..0];
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector - Immediate right rotate */
function clause execute (        VROT_VI (vd,simm5,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let eval    : bits(32) = vGetElement32(vs2, i);
          let ramt    : bits( 5) = simm5;
          let result  : bits(32) = ((eval @ eval) >> ramt)[31..0];
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let eval    : bits(64) = vGetElement64(vs2, i);
          let ramt    : bits( 6) = 0b0 @ simm5;
          let result  : bits(64) = ((eval @ eval) >> ramt)[63..0];
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector - X Register right rotate */
function clause execute (        VROT_VX (vd,rs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let eval    : bits(32) = vGetElement32(vs2, i);
          let ramt    : bits( 5) = X(rs1)[4..0];
          let result  : bits(32) = ((eval @ eval) >> ramt)[31..0];
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let eval    : bits(64) = vGetElement64(vs2, i);
          let ramt    : bits( 6) = X(rs1)[5..0];
          let result  : bits(64) = ((eval @ eval) >> ramt)[63..0];
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/*
 * Vector GREV
 * ------------------------------------------------------------
 */

/* --- specification snippet begin --- */
val      vgrev_32bit : (bits(32), bits(5)) -> bits(32) effect{escape}
function vgrev_32bit   (input   , mask   ) = {
  x : bits(32) = input;
  if(bit_to_bool(mask[0])) then x = ((x & 0x55555555) <<  1) | ((x & 0xAAAAAAAA) >>  1);
  if(bit_to_bool(mask[1])) then x = ((x & 0x33333333) <<  2) | ((x & 0xCCCCCCCC) >>  2);
  if(bit_to_bool(mask[2])) then x = ((x & 0x0F0F0F0F) <<  4) | ((x & 0xF0F0F0F0) >>  4);
  if(bit_to_bool(mask[3])) then x = ((x & 0x00FF00FF) <<  8) | ((x & 0xFF00FF00) >>  8);
  if(bit_to_bool(mask[4])) then x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16);
  x
}

val      vgrev_64bit : (bits(64), bits(6)) -> bits(64) effect{escape}
function vgrev_64bit   (input   , mask   ) = {
  x : bits(64) = input;
  if(bit_to_bool(mask[0])) then x = ((x & 0x5555555555555555) <<  1) | ((x & 0xAAAAAAAAAAAAAAAA) >>  1);
  if(bit_to_bool(mask[1])) then x = ((x & 0x3333333333333333) <<  2) | ((x & 0xCCCCCCCCCCCCCCCC) >>  2);
  if(bit_to_bool(mask[2])) then x = ((x & 0x0F0F0F0F0F0F0F0F) <<  4) | ((x & 0xF0F0F0F0F0F0F0F0) >>  4);
  if(bit_to_bool(mask[3])) then x = ((x & 0x00FF00FF00FF00FF) <<  8) | ((x & 0xFF00FF00FF00FF00) >>  8);
  if(bit_to_bool(mask[4])) then x = ((x & 0x0000FFFF0000FFFF) << 16) | ((x & 0xFFFF0000FFFF0000) >> 16);
  if(bit_to_bool(mask[5])) then x = ((x & 0x00000000FFFFFFFF) << 32) | ((x & 0xFFFFFFFF00000000) >> 32);
  x
}

/* Vector-Vector - Mask from i'th element of VS1 */
function clause execute (       VGREV_VV (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let input   : bits(32) = vGetElement32(vs2, i);
          let mask    : bits( 5) = vGetElement32(vs1, i)[4..0];
          let result  : bits(32) = vgrev_32bit(input, mask);
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let input   : bits(64) = vGetElement64(vs2, i);
          let mask    : bits( 6) = vGetElement64(vs1, i)[5..0];
          let result  : bits(64) = vgrev_64bit(input, mask);
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}
/* --- specification snippet begin --- */

/* Vector-Scalar - Mask from 0'th element of VS1 */
function clause execute (       VGREV_VS (vd,vs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let input   : bits(32) = vGetElement32(vs2, i);
          let mask    : bits( 5) = vGetElement32(vs1, 0)[4..0];
          let result  : bits(32) = vgrev_32bit(input, mask);
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let input   : bits(64) = vGetElement64(vs2, i);
          let mask    : bits( 6) = vGetElement64(vs1, 0)[5..0];
          let result  : bits(64) = vgrev_64bit(input, mask);
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-Immediate - Mask from simm5 */
function clause execute (       VGREV_VI (vd,simm5,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let input   : bits(32) = vGetElement32(vs2, i);
          let mask    : bits( 5) = simm5;
          let result  : bits(32) = vgrev_32bit(input, mask);
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let input   : bits(64) = vGetElement64(vs2, i);
          let mask    : bits( 6) = 0b0 @ simm5;
          let result  : bits(64) = vgrev_64bit(input, mask);
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}

/* Vector-XReg - Mask from X Register*/
function clause execute (       VGREV_VX (vd,rs1,vs2,vm)) = {
  if(vSupportedEEW([|32,64|])) then {
    foreach(i from 0 to vGetVL()) {
      if(vElemMasked(vm, i)) then {
        if(vGetEEW() == 32) then {
          let input   : bits(32) = vGetElement32(vs2, i);
          let mask    : bits( 5) = X(rs1)[4..0];
          let result  : bits(32) = vgrev_32bit(input, mask);
          vSetElement32(vd, i, result);
        } else if(vGetEEW() == 64) then {
          let input   : bits(64) = vGetElement64(vs2, i);
          let mask    : bits( 6) = X(rs1)[5..0];
          let result  : bits(64) = vgrev_64bit(input, mask);
          vSetElement64(vd, i, result);
        }
      }
    };
    RETIRE_SUCCESS
  } else {
    RETIRE_FAIL
  }
}
