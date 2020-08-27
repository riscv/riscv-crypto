
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
    let sb : bits(128) = aes_subbytes_fwd  (state);
    let sr : bits(128) = aes_shift_rows_fwd(sb   );
    let mc : bits(128) = if(last) then sr else aes_mixcolumns_fwd(sr);
    mc ^ rkey
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
    let ak : bits(128) = sb ^ rkey; /* Return Value */
    if(last) then ak else aes_mixcolumns_inv(ak);
}


/*
 * Given the current 128-bit round key for AES-128, compute the next
 * 128-bit round key.
 */
val      vaes128_keystep_fwd : (bits(128), bits(4)) -> bits(128)
function vaes128_keystep_fwd   (current  , rnd    ) = {
  let wi0 : bits(32) = current[ 31.. 0]; /* Unpack current rnd key words */
  let wi1 : bits(32) = current[ 63..32];  
  let wi2 : bits(32) = current[ 95..64];
  let wi3 : bits(32) = current[127..96];
  let rcon: bits(32) = aes_decode_rcon(rnd);
  let temp: bits(32) = aes_subword_fwd(ror32(wi3,to_bits(8,24))) ^ rcon;
  let wo0 : bits(32) = wi0 ^ temp;
  let wo1 : bits(32) = wi1 ^ wo0;
  let wo2 : bits(32) = wi2 ^ wo1;
  let wo3 : bits(32) = wi3 ^ wo2;
  wo3 @ wo2 @ wo1 @ wo0 /* Return value */
}


/*
 *
 */
val      vaes192_keystep_fwd : (bits(192), bits(4)) -> bits(128)
function vaes192_keystep_fwd   (current  , rnd    ) = {
    current[127..0] /* TODO: vaes192_keystep_fwd */
}


/*
 * Given the previous two 128-bit round keys, compute the next
 * 128-bit round key.
 */
val      vaes256_keystep_fwd : (bits(128), bits(128), bits(4)) -> bits(128)
function vaes256_keystep_fwd   (prev     , current  , rnd    ) = {
  let wi0 : bits(32) = prev   [ 31..  0]; /* Unpack current rnd key words */
  let wi1 : bits(32) = prev   [ 63.. 32];  
  let wi2 : bits(32) = prev   [ 95.. 64];
  let wi3 : bits(32) = prev   [127.. 96];
  let wi4 : bits(32) = current[ 31..  0];
  let wi5 : bits(32) = current[ 63.. 32];
  let wi6 : bits(32) = current[ 95.. 64];
  let wi7 : bits(32) = current[127.. 96];
  let rcon: bits(32) = aes_decode_rcon(rnd>>1);
  let temp: bits(32) = aes_subword_fwd(ror32(wi7,to_bits(8,24))) ^ rcon;
  let wo0 : bits(32) = wi0 ^ temp;
  let wo1 : bits(32) = wi1 ^ wo0;
  let wo2 : bits(32) = wi2 ^ wo1;
  let wo3 : bits(32) = wi3 ^ wo2;
  if(bit_to_bool(rnd[0]) == false) then {
    wo3 @ wo2 @ wo1 @ wo0                   /* Return round key N */
  } else {
    let wo4 : bits(32) = wi4 ^ aes_subword_fwd(wo3);
    let wo5 : bits(32) = wi5 ^ wo4;
    let wo6 : bits(32) = wi6 ^ wo5;
    let wo7 : bits(32) = wi7 ^ wo6;
    wo7 @ wo6 @ wo5 @ wo4                   /* Return round key N+1 */
  }
}

/*
 *
 */
val      vaes128_keystep_inv : (bits(128), bits(4)) -> bits(128)
function vaes128_keystep_inv   (current  , rnd    ) = {
    current /* TODO: vaes128_keystep_inv */
}


/*
 *
 */
val      vaes192_keystep_inv : (bits(192), bits(4)) -> bits(128)
function vaes192_keystep_inv   (current  , rnd    ) = {
    current[127..0] /* TODO: vaes192_keystep_inv */
}


/*
 *
 */
val      vaes256_keystep_inv : (bits(256), bits(4)) -> bits(128)
function vaes256_keystep_inv   (current  , rnd    ) = {
    current[127..0] /* TODO: vaes256_keystep_inv */
}


/*
 * Given the initial cipher key for AES128, get the final round key.
 */
val      vaes128_get_last_round_key : bits(128)  -> bits(128)
function vaes128_get_last_round_key  (key      ) = {
  rkey    : bits(128) = key;
  foreach(i from 0 to 9) {
      rkey    = vaes128_keystep_fwd(rkey, to_bits(4,i));
  };
  rkey
}

/*
 * Given the initial cipher key for AES256, get the final two round keys.
 */
val      vaes256_get_last_round_key : bits(256)  -> bits(256)
function vaes256_get_last_round_key  (key      ) = {
  rkey0 : bits(128) = key[127..  0];
  rkey1 : bits(128) = key[255..128];
  foreach(i from 0 to 11 by 2) {
    rkey2 = vaes256_keystep_fwd(rkey0, rkey1, to_bits(4,i  ));
    rkey3 = vaes256_keystep_fwd(rkey0, rkey1, to_bits(4,i+1));  
    rkey0 = rkey2;
    rkey1 = rkey3;
  };
  rkey2 : bits(128) = vaes256_keystep_fwd(rkey0, rkey1, to_bits(4,12 ));
  rkey2 @ rkey1
}


/* 
 * Perform an AES-128 block encryption using the given key and message.
 */
val      vaes128_block_enc : (bits(128), bits(128)) -> bits(128)
function vaes128_block_enc   (msg      , key      ) = {
    rkey  : bits(128) = key;
    state : bits(128) = msg ^ rkey;
    foreach(i from 0 to 9) {
        rkey        : bits(128) = vaes128_keystep_fwd(rkey, to_bits(4,i));
        last_round  : bool      = i == 9;
        state       : bits(128) = vaes_round_fwd(last_round, state, rkey);
    };
    state
}


/* 
 * Perform an AES-256 block encryption using the given key and message.
 */
val      vaes256_block_enc : (bits(128), bits(256)) -> bits(128)
function vaes256_block_enc   (msg      , key      ) = {
    rkey0 : bits(128) = key[127..  0];
    rkey1 : bits(128) = key[255..128];
    state : bits(128) = msg ^ rkey0;
    state             = vaes_round_fwd(false     , state, rkey1);
    foreach(i from 0 to 11 by 2) {
      rkey2 : bits(128) = vaes256_keystep_fwd(rkey0, rkey1, to_bits(4,i  ));
      rkey3 : bits(128) = vaes256_keystep_fwd(rkey0, rkey1, to_bits(4,i+1));  
      state             = vaes_round_fwd(false     , state, rkey2);
      state             = vaes_round_fwd(false     , state, rkey3);  
      rkey0             = rkey2;
      rkey1             = rkey3;
    };
    rkey2 : bits(128) = vaes256_keystep_fwd(rkey0, rkey1, to_bits(4,12 ));
    state             = vaes_round_fwd(true      , state, rkey2);
    state
}


/* Input checks for vector AES instructions. If fail, raise invalid opcode. */
val      vaes_asserts : unit -> bool
function vaes_asserts () = {
    valid_setup : bool  = true;
    if(vGetEEW() != 128) then valid_setup = false;
    valid_setup /* Return value */
}


/*
 * Execute Clauses
 * ----------------------------------------------------------------------
 */


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


/* AES 128 Single round key schedule - forwards */
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

/* AES 128 Single round key schedule - inverse */
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


/* AES 192 Single round key schedule - forwards */
function clause execute (    VAES192KEYI (vt,rnd,vs2)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let words_54: bits( 64) = vGetElement128(vt , i)[63..0];
            let words_30: bits(128) = vGetElement128(vs2, i);
            let keys    : bits(192) = words_54 @ words_30;
            let result  : bits(128) = vaes192_keystep_fwd(keys, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

/* AES 192 Single round key schedule - inverse */
function clause execute ( VAES192INVKEYI (vt,rnd,vs2)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let words_30: bits(128) = vGetElement128(vs2, i);
            let words_54: bits( 64) = vGetElement128(vt , i)[63..0];
            let keys    : bits(192) = words_54 @ words_30;
            let result  : bits(128) = vaes192_keystep_inv(keys, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES 256 Single round key schedule - forwards */
function clause execute (    VAES256KEYI (vt,rnd,vs2)) = {
  if(vaes_asserts()) then {
    foreach (i from 0 to vGetVL()) {
      let prev    : bits(128) = vGetElement128(vt , i);
      let current : bits(128) = vGetElement128(vs2, i);
      let next    : bits(128) = vaes256_keystep_fwd(prev, current, rnd);
      vSetElement128(vt, i, next);
    };
    RETIRE_SUCCESS
  } else
      RETIRE_FAIL
}

/* AES 256 Single round key schedule - inverse */
function clause execute ( VAES256INVKEYI (vt,rnd,vs2)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            let prev    : bits(128) = vGetElement128(vt , i);
            let current : bits(128) = vGetElement128(vs2, i);
            let keys    : bits(256) = current @ prev;
            let result  : bits(128) = vaes256_keystep_inv(keys, rnd);
            vSetElement128(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/*
 * Vector-Scalar All Rounds AES Encrypt
 * ------------------------------------------------------------
 */


/* AES 128 All Rounds Encrypt - Vector-Scalar */
function clause execute (    VAESE128_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            rnd     : bits(4)   = 0x0;
            key     : bits(128) = vGetElement128(vs1, 0); /* Vector-Scalar */
            state   : bits(128) = vGetElement128(vt , i);
            state   = vaes128_block_enc(state, key);
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES 192 All Rounds Encrypt - Vector-Scalar */
function clause execute (    VAESE192_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            rnd     : bits(4)   = 0x0;
            ekey    : bits(192) = vGetElement256(vs1, 0)[191..0];
            state   : bits(128) = vGetElement128(vt , i);
            /* TODO: vaes192 all rounds encrypto vector scalar */
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES 256 All Rounds Encrypt - Vector-Scalar */
function clause execute (    VAESE256_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            ekey  : bits(256) = vGetElement256(vs1, 0);
            state : bits(128) = vGetElement128(vt , i);
            state = vaes256_block_enc(state, ekey);
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

/*
 * Vector-Scalar All Rounds AES Decrypt
 * ------------------------------------------------------------
 */


/* AES 128 All Rounds Decrypt - Vector-Scalar */
function clause execute (    VAESD128_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            rkey    : bits(128) = vGetElement128(vs1, 0); /* Vector-Scalar */
            state   : bits(128) = vGetElement128(vt , i);
            /* TODO: vaes128_block_decrypt vector scalar; */
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES 192 All Rounds Decrypt - Vector-Scalar */
function clause execute (    VAESD192_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            ekey    : bits(192) = vGetElement256(vs1, 0)[191..0];
            state   : bits(128) = vGetElement128(vt , i);
            /* TODO: vaes192_block_decrypt vector scalar; */
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

/* AES 256 All Rounds Decrypt - Vector-Scalar */
function clause execute (    VAESD256_VS (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            ekey    : bits(256) = vGetElement256(vs1, 0);
            state   : bits(128) = vGetElement128(vt , i);
            /* TODO: vaes256_block_decrypt vector scalar; */
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

/*
 * Vector-Vector All Rounds AES Encrypt
 * ------------------------------------------------------------
 */

/* AES 128 All Rounds Encrypt - Vector-Scalar */
function clause execute (    VAESE128_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            rkey    : bits(128) = vGetElement128(vs1, i); /* Vector-Vector */
            state   : bits(128) = vGetElement128(vt , i);
            state   = vaes128_block_enc(state, rkey);
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES 192 All Rounds Encrypt - Vector-Scalar */
function clause execute (    VAESE192_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            ekey    : bits(192) = vGetElement256(vs1, i)[191..0];
            state   : bits(128) = vGetElement128(vt , i);
            /* TODO: vaes192 all rounds encrypt vector-scalar; */
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES 256 All Rounds Encrypt - Vector-Scalar */
function clause execute (    VAESE256_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            ekey    : bits(256) = vGetElement256(vs1, i);
            state   : bits(128) = vGetElement128(vt , i);
            state = vaes256_block_enc(state, ekey);
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

/*
 * Vector-Vector All Rounds AES Decrypt
 * ------------------------------------------------------------
 */

/* AES 128 All Rounds Decrypt - Vector-Vector */
function clause execute (    VAESD128_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            rkey    : bits(128) = vGetElement128(vs1, i); /* Vector-Vector */
            state   : bits(128) = vGetElement128(vt , i);
            /* TODO: vaes128 all rounds decrypt vector-vector; */
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES 192 All Rounds Decrypt - Vector-Vector */
function clause execute (    VAESD192_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            ekey    : bits(192) = vGetElement256(vs1, i)[191..0];
            state   : bits(128) = vGetElement128(vt , i);
            /* TODO: vaes192 all rounds decrypt vector-vector; */
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

/* AES 256 All Rounds Decrypt - Vector-Vector */
function clause execute (    VAESD256_VV (vt,vs1)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            ekey    : bits(256) = vGetElement256(vs1, i);
            state   : bits(128) = vGetElement128(vt , i);
            /* TODO: vaes256 all rounds decrypt vector-vector; */
            vSetElement128(vt, i, state);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}

/*
 * Vector-Vector Get final round key from first round key.
 * ------------------------------------------------------------
 */


/* AES 128 Get final decryption key from encryption key. */
function clause execute (    VAES128RKEY (vt)) = {
    if(vaes_asserts()) then {
        foreach (i from 0 to vGetVL()) {
            ckey : bits(128) = vGetElement128(vt, i);
            fkey : bits(128) = vaes128_get_last_round_key(ckey);
            vSetElement128(vt, i, fkey);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}


/* AES 192 Get final decryption key from encryption key. */
function clause execute (    VAES192RKEY (vt)) = {
    /* TODO: vaes192 get decrypt key; */
    RETIRE_SUCCESS
}


/* AES 256 Get final decryption key from encryption key. */
function clause execute (    VAES256RKEY (vt)) = {
  if(vaes_asserts()) then {
    foreach (i from 0 to vGetVL()) {
      ckey : bits(256) = vGetElement256(vt, i);
      fkey : bits(256) = vaes256_get_last_round_key(ckey);
      vSetElement256(vt, i, fkey);
    };
    RETIRE_SUCCESS
  } else
      RETIRE_FAIL
}
