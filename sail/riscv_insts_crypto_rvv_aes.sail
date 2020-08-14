
/*
 * file: riscv_insts_crypto_rvv_aes.sail
 *
 * This file contains the vector specific cryptography extension
 * instructions.
 *
 * This file must be included in the model iff the vector crypto extension
 * is supported.
 *
 */


union   clause ast    =        VAESE_VS : (vregidx,vregidx)
union   clause ast    =    VAESELAST_VS : (vregidx,vregidx)
union   clause ast    =        VAESD_VS : (vregidx,vregidx)
union   clause ast    =    VAESDLAST_VS : (vregidx,vregidx)
union   clause ast    =        VAESE_VV : (vregidx,vregidx)
union   clause ast    =    VAESELAST_VV : (vregidx,vregidx)
union   clause ast    =        VAESD_VV : (vregidx,vregidx)
union   clause ast    =    VAESDLAST_VV : (vregidx,vregidx)
union   clause ast    =     VAES128KEYI : (vregidx,bits(4))
union   clause ast    =  VAES128INVKEYI : (vregidx,bits(4))
union   clause ast    =     VAES192KEYI : (vregidx,bits(4),vregidx)
union   clause ast    =  VAES192INVKEYI : (vregidx,bits(4),vregidx)
union   clause ast    =     VAES256KEYI : (vregidx,bits(4),vregidx)
union   clause ast    =  VAES256INVKEYI : (vregidx,bits(4),vregidx)
union   clause ast    =     VAESE128_VS : (vregidx,vregidx)
union   clause ast    =     VAESE192_VS : (vregidx,vregidx)
union   clause ast    =     VAESE256_VS : (vregidx,vregidx)
union   clause ast    =     VAESD128_VS : (vregidx,vregidx)
union   clause ast    =     VAESD192_VS : (vregidx,vregidx)
union   clause ast    =     VAESD256_VS : (vregidx,vregidx)
union   clause ast    =     VAESE128_VV : (vregidx,vregidx)
union   clause ast    =     VAESE192_VV : (vregidx,vregidx)
union   clause ast    =     VAESE256_VV : (vregidx,vregidx)
union   clause ast    =     VAESD128_VV : (vregidx,vregidx)
union   clause ast    =     VAESD192_VV : (vregidx,vregidx)
union   clause ast    =     VAESD256_VV : (vregidx,vregidx)
union   clause ast    =     VAES128RKEY : (vregidx)
union   clause ast    =     VAES192RKEY : (vregidx)
union   clause ast    =     VAES256RKEY : (vregidx)

mapping clause encdec =        VAESE_VS   (vt,vs1) <-> 0b000000000000 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =    VAESELAST_VS   (vt,vs1) <-> 0b000000000001 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =        VAESD_VS   (vt,vs1) <-> 0b000000000010 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =    VAESDLAST_VS   (vt,vs1) <-> 0b000000000011 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =        VAESE_VV   (vt,vs1) <-> 0b000000000100 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =    VAESELAST_VV   (vt,vs1) <-> 0b000000000101 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =        VAESD_VV   (vt,vs1) <-> 0b000000000110 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =    VAESDLAST_VV   (vt,vs1) <-> 0b000000000111 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAES128KEYI   (vt,rnd) <-> 0b0000000010000 @ 0b000 @ vt @ rnd @ 0b1011011
mapping clause encdec =  VAES128INVKEYI   (vt,rnd) <-> 0b0000000010001 @ 0b000 @ vt @ rnd @ 0b1011011
mapping clause encdec =     VAES192KEYI   (vt,rnd,vs2) <-> 0b0000010 @ 0b0 @ 0b000 @ vt @ rnd @ vs2 @ 0b1011011
mapping clause encdec =  VAES192INVKEYI   (vt,rnd,vs2) <-> 0b0000010 @ 0b1 @ 0b000 @ vt @ rnd @ vs2 @ 0b1011011
mapping clause encdec =     VAES256KEYI   (vt,rnd,vs2) <-> 0b0000011 @ 0b0 @ 0b000 @ vt @ rnd @ vs2 @ 0b1011011
mapping clause encdec =  VAES256INVKEYI   (vt,rnd,vs2) <-> 0b0000011 @ 0b1 @ 0b000 @ vt @ rnd @ vs2 @ 0b1011011
mapping clause encdec =     VAESE128_VS   (vt,vs1) <-> 0b000010000000 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESE192_VS   (vt,vs1) <-> 0b000010000001 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESE256_VS   (vt,vs1) <-> 0b000010000010 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESD128_VS   (vt,vs1) <-> 0b000010000011 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESD192_VS   (vt,vs1) <-> 0b000010000100 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESD256_VS   (vt,vs1) <-> 0b000010000101 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESE128_VV   (vt,vs1) <-> 0b000010000110 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESE192_VV   (vt,vs1) <-> 0b000010000111 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESE256_VV   (vt,vs1) <-> 0b000010001000 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESD128_VV   (vt,vs1) <-> 0b000010001001 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESD192_VV   (vt,vs1) <-> 0b000010001010 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAESD256_VV   (vt,vs1) <-> 0b000010001011 @ 0b000 @ vt @ vs1 @ 0b1011011
mapping clause encdec =     VAES128RKEY   (vt) <-> 0b00001000110000000000 @ vt @ 0b1011011
mapping clause encdec =     VAES192RKEY   (vt) <-> 0b00001000110000001000 @ vt @ 0b1011011
mapping clause encdec =     VAES256RKEY   (vt) <-> 0b00001000110000010000 @ vt @ 0b1011011

mapping clause assembly =        VAESE_VS (vt,vs1) <-> "vaese.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =    VAESELAST_VS (vt,vs1) <-> "vaeselast.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =        VAESD_VS (vt,vs1) <-> "vaesd.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =    VAESDLAST_VS (vt,vs1) <-> "vaesdlast.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =        VAESE_VV (vt,vs1) <-> "vaese.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =    VAESELAST_VV (vt,vs1) <-> "vaeselast.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =        VAESD_VV (vt,vs1) <-> "vaesd.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =    VAESDLAST_VV (vt,vs1) <-> "vaesdlast.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAES128KEYI (vt,rnd) <-> "vaes128keyi" ^ spc() ^ hex_bits_4(rnd) ^ sep() ^ vreg_name(vt)
mapping clause assembly =  VAES128INVKEYI (vt,rnd) <-> "vaes128invkeyi" ^ spc() ^ hex_bits_4(rnd) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAES192KEYI (vt,rnd,vs2) <-> "vaes192keyi" ^ spc() ^ vreg_name(vs2) ^ sep() ^ hex_bits_4(rnd) ^ sep() ^ vreg_name(vt)
mapping clause assembly =  VAES192INVKEYI (vt,rnd,vs2) <-> "vaes192invkeyi" ^ spc() ^ vreg_name(vs2) ^ sep() ^ hex_bits_4(rnd) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAES256KEYI (vt,rnd,vs2) <-> "vaes256keyi" ^ spc() ^ vreg_name(vs2) ^ sep() ^ hex_bits_4(rnd) ^ sep() ^ vreg_name(vt)
mapping clause assembly =  VAES256INVKEYI (vt,rnd,vs2) <-> "vaes256invkeyi" ^ spc() ^ vreg_name(vs2) ^ sep() ^ hex_bits_4(rnd) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESE128_VS (vt,vs1) <-> "vaese128.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESE192_VS (vt,vs1) <-> "vaese192.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESE256_VS (vt,vs1) <-> "vaese256.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESD128_VS (vt,vs1) <-> "vaesd128.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESD192_VS (vt,vs1) <-> "vaesd192.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESD256_VS (vt,vs1) <-> "vaesd256.vs" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESE128_VV (vt,vs1) <-> "vaese128.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESE192_VV (vt,vs1) <-> "vaese192.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESE256_VV (vt,vs1) <-> "vaese256.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESD128_VV (vt,vs1) <-> "vaesd128.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESD192_VV (vt,vs1) <-> "vaesd192.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAESD256_VV (vt,vs1) <-> "vaesd256.vv" ^ spc() ^ vreg_name(vs1) ^ sep() ^ vreg_name(vt)
mapping clause assembly =     VAES128RKEY (vt) <-> "vaes128rkey" ^ spc() ^ vreg_name(vt)
mapping clause assembly =     VAES192RKEY (vt) <-> "vaes192rkey" ^ spc() ^ vreg_name(vt)
mapping clause assembly =     VAES256RKEY (vt) <-> "vaes256rkey" ^ spc() ^ vreg_name(vt)


/*
 * A single encryption round of the AES block function.
 */
val      vaes_round_fwd : (bool, bits(128), bits(128)) -> bits(128)
function vaes_round_fwd   (last, state    , rkey     ) = {
    let ark: bits(128) = state ^ rkey;
    let sr : bits(128) = aes_shift_rows_fwd(ark  );
    let sb : bits(128) = aes_subbytes_fwd  (sr   );
    if(last) then sb else aes_mixcolumns_fwd(sb)
}


/*
 * A single decryption round of the AES block function
 * Uses the Equivalent Inverse Cipher transform, hence the order of
 * shift rows, sub bytes, mix columns.
 */
val      vaes_round_inv : (bool, bits(128), bits(128)) -> bits(128)
function vaes_round_inv   (last, state    , rkey     ) = {
    let sr : bits(128) = aes_shift_rows_inv(state);
    let sb : bits(128) = aes_subbytes_inv  (sr   );
    let mc : bits(128) = if(last) then sb else aes_mixcolumns_inv(sb);
    mc ^ rkey /* Return Value */
}


/*
 *
 */
val      vaes128_keystep_fwd : (bits(128), bits(4)) -> bits(128)
function vaes128_keystep_fwd   (current  , rnd    ) = {
    current /* TODO */
}


/*
 *
 */
val      vaes192_keystep_fwd : (bits(128), bits(128), bits(4)) -> bits(128)
function vaes192_keystep_fwd   (prev     , current  , rnd    ) = {
    current /* TODO */
}


/*
 *
 */
val      vaes256_keystep_fwd : (bits(128), bits(128), bits(4)) -> bits(128)
function vaes256_keystep_fwd   (prev     , current  , rnd    ) = {
    current /* TODO */
}

/*
 *
 */
val      vaes128_keystep_inv : (bits(128), bits(4)) -> bits(128)
function vaes128_keystep_inv   (current  , rnd    ) = {
    current /* TODO */
}


/*
 *
 */
val      vaes192_keystep_inv : (bits(128), bits(128), bits(4)) -> bits(128)
function vaes192_keystep_inv   (prev     , current  , rnd    ) = {
    current /* TODO */
}


/*
 *
 */
val      vaes256_keystep_inv : (bits(128), bits(128), bits(4)) -> bits(128)
function vaes256_keystep_inv   (prev     , current  , rnd    ) = {
    current /* TODO */
}


/* Input checks for vector AES instructions. If fail, raise invalid opcode. */
val      vaes_asserts : unit -> bool
function vaes_asserts () = {
    valid_setup : bool  = true;
    if(vGetEEW() != 128) then valid_setup = false;
    valid_setup /* Return value */
}


/* AES Single Mid-Round Encrypt - Vector-Scalar */
function clause execute (       VAESE_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        let key   : bits(128) = vGetElement128(vs1, 0);
        foreach (i from 0 to vGetVL()) {
            let state : bits(128) = vGetElement128(vt , i);
            let result: bits(128) = vaes_round_fwd(false, state, key);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES Single Last-Round Encrypt - Vector-Scalar*/
function clause execute (   VAESELAST_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        let key   : bits(128) = vGetElement128(vs1, 0);
        foreach (i from 0 to vGetVL()) {
            let state : bits(128) = vGetElement128(vt , i);
            let result: bits(128) = vaes_round_fwd(true, state, key);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES Single Mid-Round Decrypt - Vector-Scalar */
function clause execute (       VAESD_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        let key   : bits(128) = vGetElement128(vs1, 0);
        foreach (i from 0 to vGetVL()) {
            let state : bits(128) = vGetElement128(vt , i);
            let result: bits(128) = vaes_round_inv(false, state, key);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES Single Last-Round Decrypt - Vector-Scalar */
function clause execute (   VAESDLAST_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        let key   : bits(128) = vGetElement128(vs1, 0);
        foreach (i from 0 to vGetVL()) {
            let state : bits(128) = vGetElement128(vt , i);
            let result: bits(128) = vaes_round_inv(true, state, key);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES Single Mid-Round Encrypt - Vector-Vector */
function clause execute (       VAESE_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let key   : bits(128) = vGetElement128(vs1, i);
            let state : bits(128) = vGetElement128(vt , i);
            let result: bits(128) = vaes_round_fwd(false, state, key);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES Single Last-Round Encrypt - Vector-Vector */
function clause execute (   VAESELAST_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let key   : bits(128) = vGetElement128(vs1, i);
            let state : bits(128) = vGetElement128(vt , i);
            let result: bits(128) = vaes_round_fwd(true, state, key);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES Single Mid-Round Decrypt - Vector-Vector */
function clause execute (       VAESD_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let key   : bits(128) = vGetElement128(vs1, i);
            let state : bits(128) = vGetElement128(vt , i);
            let result: bits(128) = vaes_round_inv(false, state, key);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES Single Last-Round Decrypt - Vector-Vector */
function clause execute (   VAESDLAST_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let key   : bits(128) = vGetElement128(vs1, i);
            let state : bits(128) = vGetElement128(vt , i);
            let result: bits(128) = vaes_round_inv(true, state, key);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


function clause execute (    VAES128KEYI (vt,rnd)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let current : bits(128) = vGetElement128(vt, i);
            let result  : bits(128) = vaes128_keystep_fwd(current, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

function clause execute ( VAES128INVKEYI (vt,rnd)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let current : bits(128) = vGetElement128(vt, i);
            let result  : bits(128) = vaes128_keystep_inv(current, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

function clause execute (    VAES192KEYI (vt,rnd,vs2)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let prev    : bits(128) = vGetElement128(vt , i);
            let current : bits(128) = vGetElement128(vs2, i);
            let result  : bits(128) = vaes192_keystep_fwd(prev, current, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

function clause execute ( VAES192INVKEYI (vt,rnd,vs2)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let prev    : bits(128) = vGetElement128(vt , i);
            let current : bits(128) = vGetElement128(vs2, i);
            let result  : bits(128) = vaes192_keystep_inv(prev, current, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

function clause execute (    VAES256KEYI (vt,rnd,vs2)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let prev    : bits(128) = vGetElement128(vt , i);
            let current : bits(128) = vGetElement128(vs2, i);
            let result  : bits(128) = vaes256_keystep_fwd(prev, current, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

function clause execute ( VAES256INVKEYI (vt,rnd,vs2)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let prev    : bits(128) = vGetElement128(vt , i);
            let current : bits(128) = vGetElement128(vs2, i);
            let result  : bits(128) = vaes256_keystep_inv(prev, current, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


function clause execute (    VAESE128_VS (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAESE192_VS (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAESE256_VS (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}

function clause execute (    VAESD128_VS (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAESD192_VS (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAESD256_VS (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}

function clause execute (    VAESE128_VV (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAESE192_VV (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAESE256_VV (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}

function clause execute (    VAESD128_VV (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAESD192_VV (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAESD256_VV (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}

function clause execute (    VAES128RKEY (vt)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAES192RKEY (vt)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (    VAES256RKEY (vt)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
