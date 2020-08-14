
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


function clause execute (      VCLMUL_VV (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (      VCLMUL_VS (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (     VCLMULH_VV (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (     VCLMULH_VS (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (     VCLMACC_VV (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (     VCLMACC_VS (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VCLMACCH_VV (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VCLMACCH_VS (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (     VWCLMUL_VV (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (     VWCLMUL_VS (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VWCLMACC_VV (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VWCLMACC_VS (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (        VROT_VV (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (        VROT_VS (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (        VROT_VI (vd,simm5,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (        VROT_VX (vd,rs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (       VGREV_VV (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (       VGREV_VS (vd,vs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (       VGREV_VI (vd,simm5,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (       VGREV_VX (vd,rs1,vs2,vm)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
