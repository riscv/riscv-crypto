
/*
 * file: riscv_insts_crypto_rvv_sha.sail
 *
 * This file contains the vector specific cryptography extension
 * instructions.
 *
 * This file must be included in the model iff the vector crypto extension
 * is supported.
 *
 */


union   clause ast    =        VSHA2_WS : (vregidx,bits(4),vregidx)
union   clause ast    =        VSHA2_MS : (vregidx,vregidx)
union   clause ast    =        VSHA2_HS : (vregidx,vregidx)


mapping clause encdec =        VSHA2_WS   (vt,rnd,vs2) <-> 0b0000110 @ 0b0 @ 0b000 @ vt @ rnd @ vs2 @ 0b1011011
mapping clause encdec =        VSHA2_MS   (vd,vs1) <-> 0b000011100000 @ 0b000 @ vd @ vs1 @ 0b1011011
mapping clause encdec =        VSHA2_HS   (vt,vs1) <-> 0b000011100001 @ 0b000 @ vt @ vs1 @ 0b1011011


mapping clause assembly =        VSHA2_WS (vt,rnd,vs2) <-> "vsha2.ws" ^ spc() ^ vreg_name(vs2) ^ sep() ^ hex_bits_4(rnd) ^ sep() ^ vreg_name(vt)
mapping clause assembly =        VSHA2_MS (vd,vs1) <-> "vsha2.ms" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vd)
mapping clause assembly =        VSHA2_HS (vt,vs1) <-> "vsha2.hs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)


function clause execute (       VSHA2_WS (vt,rnd,vs2)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (       VSHA2_MS (vd,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (       VSHA2_HS (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
