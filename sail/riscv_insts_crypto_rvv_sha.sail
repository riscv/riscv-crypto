
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

/*
 * Utility functions: SHA256
 * ------------------------------------------------------------
 */

val      sha256_ch   : (bits(32), bits(32), bits(32)) -> bits(32)
function sha256_ch     (x       , y       , z       ) = {
    (x & y) ^ ((not_vec(x)) & z)
}

val      sha256_maj  : (bits(32), bits(32), bits(32)) -> bits(32)
function sha256_maj    (x       , y       , z       ) = {
    (x & y) ^ (x & z) ^ (y & z)
}

val      sha256_sum0 : bits(32)                       -> bits(32)
function sha256_sum0   (x) = {
    ror32(x,  2) ^ ror32(x, 13) ^ ror32(x, 22)
}

val      sha256_sum1 : bits(32)                       -> bits(32)
function sha256_sum1   (x) = {
    ror32(x,  6) ^ ror32(x, 11) ^ ror32(x, 25)
}

val      sha256_sig0 : bits(32)                       -> bits(32)
function sha256_sig0   (x) = {
    ror32(x,  7) ^ ror32(x, 18) ^ (x >>  3)
}

val      sha256_sig1 : bits(32)                       -> bits(32)
function sha256_sig1   (x) = {
    ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10)
}


let sha256_rc_table : list(bits(32)) = [|
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
|]


/* Lookup function - takes an index and a list, and retrieves the
 * x'th element of that list.
 */
val      sha256_rc_lookup: (int, list(bits(32))) -> bits(32)
function sha256_rc_lookup(x, table) = {
    match (x, table) {
        (0, t0::tn) => t0,
        (y, t0::tn) => sha256_rc_lookup(x - 1,tn)
    }
}


/* Get the x'th round constant for SHA256. */
val      sha256_rc : int -> bits(32)
function sha256_rc   (x) = {
    sha256_rc_lookup(x, sha256_rc_table)
}


val      sha256_word : (bits(512), int) -> bits(32)
function sha256_word   (x        , i  ) = {
    (x >>(to_bits(9,32*i)))[31..0]
}


/*
 * Update the SHA256 message schedule. Compute the next 16 values of W_t.
 */
val      sha256_message_schedule : bits(512) -> bits(512)
function sha256_message_schedule(x) = {
  w0  : bits(32) = sha256_word(x,  0);
  w1  : bits(32) = sha256_word(x,  1);
  w2  : bits(32) = sha256_word(x,  2);
  w3  : bits(32) = sha256_word(x,  3);
  w4  : bits(32) = sha256_word(x,  4);
  w5  : bits(32) = sha256_word(x,  5);
  w6  : bits(32) = sha256_word(x,  6);
  w7  : bits(32) = sha256_word(x,  7);
  w8  : bits(32) = sha256_word(x,  8);
  w9  : bits(32) = sha256_word(x,  9);
  w10 : bits(32) = sha256_word(x, 10);
  w11 : bits(32) = sha256_word(x, 11);
  w12 : bits(32) = sha256_word(x, 12);
  w13 : bits(32) = sha256_word(x, 13);
  w14 : bits(32) = sha256_word(x, 14);
  w15 : bits(32) = sha256_word(x, 15);
  w16 : bits(32) = sha256_sig1(w14) + w9  + sha256_sig0(w1 ) + w0 ;
  w17 : bits(32) = sha256_sig1(w15) + w10 + sha256_sig0(w2 ) + w1 ;
  w18 : bits(32) = sha256_sig1(w16) + w11 + sha256_sig0(w3 ) + w2 ;
  w19 : bits(32) = sha256_sig1(w17) + w12 + sha256_sig0(w4 ) + w3 ;
  w20 : bits(32) = sha256_sig1(w18) + w13 + sha256_sig0(w5 ) + w4 ;
  w21 : bits(32) = sha256_sig1(w19) + w14 + sha256_sig0(w6 ) + w5 ;
  w22 : bits(32) = sha256_sig1(w20) + w15 + sha256_sig0(w7 ) + w6 ;
  w23 : bits(32) = sha256_sig1(w21) + w16 + sha256_sig0(w8 ) + w7 ;
  w24 : bits(32) = sha256_sig1(w22) + w17 + sha256_sig0(w9 ) + w8 ;
  w25 : bits(32) = sha256_sig1(w23) + w18 + sha256_sig0(w10) + w9 ;
  w26 : bits(32) = sha256_sig1(w24) + w19 + sha256_sig0(w11) + w10;
  w27 : bits(32) = sha256_sig1(w25) + w20 + sha256_sig0(w12) + w11;
  w28 : bits(32) = sha256_sig1(w26) + w21 + sha256_sig0(w13) + w12;
  w29 : bits(32) = sha256_sig1(w27) + w22 + sha256_sig0(w14) + w13;
  w30 : bits(32) = sha256_sig1(w28) + w23 + sha256_sig0(w15) + w14;
  w31 : bits(32) = sha256_sig1(w29) + w24 + sha256_sig0(w16) + w15;
  w31 @ w30 @ w29 @ w28 @ w27 @ w26 @ w25 @ w24 @
  w23 @ w22 @ w21 @ w20 @ w19 @ w18 @ w17 @ w16
}


/*
 * Compute a single round of the SHA256 hash function.
 */
val      sha256_round : (bits(256), bits(32), int) -> bits(256) effect{escape}
function sha256_round   (ws       , Wt      , rnd) = {
  assert(rnd >= 0);
  assert(rnd < 64);
  a  : bits(32) = (ws>>(to_bits(8,0*32)))[31..0];
  b  : bits(32) = (ws>>(to_bits(8,1*32)))[31..0];
  c  : bits(32) = (ws>>(to_bits(8,2*32)))[31..0];
  d  : bits(32) = (ws>>(to_bits(8,3*32)))[31..0];
  e  : bits(32) = (ws>>(to_bits(8,4*32)))[31..0];
  f  : bits(32) = (ws>>(to_bits(8,5*32)))[31..0];
  g  : bits(32) = (ws>>(to_bits(8,6*32)))[31..0];
  h  : bits(32) = (ws>>(to_bits(8,7*32)))[31..0];
  Kt : bits(32) = sha256_rc(rnd);
  t1 : bits(32) = h + sha256_sum1(e) + sha256_ch (e,f,g) + Kt + Wt;  
  t2 : bits(32) =     sha256_sum0(a) + sha256_maj(a,b,c)          ;
  h  = g;
  g  = f;
  f  = e;
  e  = d + t1;
  d  = c;
  c  = b;
  b  = a;
  a  = t1 + t2;
  (h @ g @ f @ e @ d @ c @ b @ a)
}


/*
 * Compute 16 rounds of the SHA256 hash function.
 * - ws : Current working state
 * - ms : Current message schedule
 * - rnd: Initial round number in {0,16,32,48}
 */
val      sha256_16_rounds : (bits(256), bits(512), int) -> bits(256) effect{escape}
function sha256_16_rounds   (ws       , ms       , rnd) = {
    assert((rnd == 0) | (rnd == 16) | (rnd == 32) | (rnd==48));
    state : bits(256) = ws;
    foreach(i from rnd to (rnd+16)) {
        Wt    = sha256_word(ms, i%16); /* Select word from message schedule */
        state = sha256_round(state, Wt, i);
    };
    state
}


/*
 * Utility functions: SHA512
 * ------------------------------------------------------------
 */

val      sha512_ch   : (bits(64), bits(64), bits(64)) -> bits(64)
function sha512_ch     (x       , y       , z       ) = {
    (x & y) ^ ((not_vec(x)) & z)
}

val      sha512_maj  : (bits(64), bits(64), bits(64)) -> bits(64)
function sha512_maj    (x       , y       , z       ) = {
    (x & y) ^ (x & z) ^ (y & z)
}

val      sha512_sum0 : bits(64)                       -> bits(64)
function sha512_sum0   (x) = {
    ror64(x, 28) ^ ror64(x, 34) ^ ror64(x, 39)
}

val      sha512_sum1 : bits(64)                       -> bits(64)
function sha512_sum1   (x) = {
    ror64(x, 14) ^ ror64(x, 18) ^ ror64(x, 41)
}

val      sha512_sig0 : bits(64)                       -> bits(64)
function sha512_sig0   (x) = {
    ror64(x,  1) ^ ror64(x,  8) ^ (x >>  7)
}

val      sha512_sig1 : bits(64)                       -> bits(64)
function sha512_sig1   (x) = {
    ror64(x, 19) ^ ror64(x, 61) ^ (x >>  6)
}


let sha512_rc_table : list(bits(64)) = [|
0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
|]


/* Lookup function - takes an index and a list, and retrieves the
 * x'th element of that list.
 */
val      sha512_rc_lookup: (int, list(bits(64))) -> bits(64)
function sha512_rc_lookup(x, table) = {
    match (x, table) {
        (0, t0::tn) => t0,
        (y, t0::tn) => sha512_rc_lookup(x - 1,tn)
    }
}


/* Get the x'th round constant for SHA512. */
val      sha512_rc : int -> bits(64)
function sha512_rc   (x) = {
    sha512_rc_lookup(x, sha512_rc_table)
}


/*
 * Compute 16 rounds of the SHA512 hash function.
 * - ws : Current working state
 * - ms : Current message schedule
 * - rnd: Initial round number in {0,16,32,48,64}
 * TODO: sha512_16_rounds
 */
val      sha512_16_rounds : (bits(512), bits(1024), int) -> bits(512) effect{escape}
function sha512_16_rounds   (ws       , ms       , rnd) = {
    assert((rnd == 0) | (rnd == 16) | (rnd == 32) | (rnd==48) | (rnd==64));
    ws
}

/*
 * Execute Clauses
 * ------------------------------------------------------------
 */

/* TOOD: VSHA2_WS raise invalid opcode if SEW=256 and rnd >= 64 */
function clause execute (       VSHA2_WS (vt,rnd,vs2)) = {
    let r : int = 0;
    if(vGetSEW() == 256) then {
        foreach (i from 0 to vGetVL()) {
            let ws    : bits(256) = vGetElement256(vt , i);
            let ms    : bits(512) = vGetElement512(vs2, i);
            let result: bits(256) = sha256_16_rounds(ws, ms, r);
            vSetElement256(vt, i, result);
        };
        RETIRE_SUCCESS
    } else if(vGetSEW() == 512) then {
        foreach (i from 0 to vGetVL()) {
            let ws    : bits( 512) = vGetElement512 (vt , i);
            let ms    : bits(1024) = vGetElement1024(vs2, i);
            let result: bits( 512) = sha512_16_rounds(ws, ms, r);
            vSetElement512(vt, i, result);
        };
        RETIRE_SUCCESS
    } else
        RETIRE_FAIL
}
function clause execute (       VSHA2_MS (vd,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
function clause execute (       VSHA2_HS (vt,vs1)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}
