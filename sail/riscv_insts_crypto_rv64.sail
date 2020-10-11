
/*
 * file: riscv_insts_crypto_rv64.sail
 *
 * This file contains the 64-bit specific cryptography extension
 * instructions.
 *
 * This file must be included in the model build if XLEN=64
 *
 */

/*
 * Scalar Cryptography Extension - Scalar 64-bit AES instructions
 * ----------------------------------------------------------------------
 */

union   clause ast    =AES64_KS1I : (bits(4),regidx,regidx)
union   clause ast    = AES64_KS2 : (regidx,regidx,regidx)
union   clause ast    =  AES64_IM : (regidx,regidx)
union   clause ast    = AES64_ESM : (regidx,regidx,regidx)
union   clause ast    =  AES64_ES : (regidx,regidx,regidx)
union   clause ast    = AES64_DSM : (regidx,regidx,regidx)
union   clause ast    =  AES64_DS : (regidx,regidx,regidx)


mapping clause encdec =   AES64_KS1I (rcon,rs1,rd) <->
    0b00001000 @ rcon @ rs1 @ 0b010 @ rd @ 0b0101011

mapping clause encdec =   AES64_KS2 (rs2,rs1,rd) <->
    0b0000101 @ rs2 @ rs1 @ 0b010 @ rd @ 0b0101011

mapping clause encdec =  AES64_IM (rs1,rd) <-> 
    0b000011000001 @ rs1 @ 0b010 @ rd @ 0b0101011

mapping clause encdec = AES64_ESM (rs2,rs1,rd) <->
    0b0000111 @ rs2 @ rs1 @ 0b010 @ rd @ 0b0101011

mapping clause encdec =  AES64_ES (rs2,rs1,rd) <->
    0b0001000 @ rs2 @ rs1 @ 0b010 @ rd @ 0b0101011

mapping clause encdec = AES64_DSM (rs2,rs1,rd) <->
    0b0001001 @ rs2 @ rs1 @ 0b010 @ rd @ 0b0101011

mapping clause encdec =  AES64_DS (rs2,rs1,rd) <->
    0b0001010 @ rs2 @ rs1 @ 0b010 @ rd @ 0b0101011


mapping clause assembly =   AES64_KS1I (rcon,rs1,rd) <->
    "aes64ks1i" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ hex_bits_4(rcon)

mapping clause assembly =   AES64_KS2 (rs2,rs1,rd) <->
    "aes64ks2" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly =  AES64_IM (rs1,rd) <->
    "aes64im" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)

mapping clause assembly = AES64_ESM (rs2,rs1,rd) <->
    "aes64esm" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly =  AES64_ES (rs2,rs1,rd) <->
    "aes64es" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = AES64_DSM (rs2,rs1,rd) <->
    "aes64dsm" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly =  AES64_DS (rs2,rs1,rd) <->
    "aes64ds" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)


val      crypto_aes64 : (regidx, regidx, regidx, bool, bool) -> Retired effect {escape, rreg, wreg}
/* --- specification snippet begin --- */
function crypto_aes64   (rd    , rs1   , rs2   , enc , mix )  = {
  let sr : bits( 64) = match enc {
    true  => aes_rv64_shiftrows_fwd(X(rs2)[63..0], X(rs1)[63..0]), /*Encrypt*/
    false => aes_rv64_shiftrows_inv(X(rs2)[63..0], X(rs1)[63..0])  /*Decrypt*/
  };
  let wd : bits( 64) = sr[63..0];
  let sb : bits( 64) = match enc {
    true  => aes_apply_fwd_sbox_to_each_byte(wd),               /* Encrypt */
    false => aes_apply_inv_sbox_to_each_byte(wd)                /* Decrypt */
  };
  X(rd)  = match (mix, enc) {
    (true,true ) => aes_mixcolumn_fwd(sb[63..32]) @ aes_mixcolumn_fwd(sb[31..0]),
    (true,false) => aes_mixcolumn_inv(sb[63..32]) @ aes_mixcolumn_inv(sb[31..0]),
    (false, _  ) => sb
  };
  RETIRE_SUCCESS
}

function clause execute (AES64_KS1I (rcon,rs1,rd)) = {
    let tmp1  : bits(32) = X(rs1)[63..32];
    let rc    : bits(32) = aes_decode_rcon(rcon);
    let tmp2  : bits(32) = if rcon==0xA then tmp1 else ror32(tmp1, 8);
    let tmp3  : bits(32) = aes_sbox_fwd(tmp2[31..24]) @ aes_sbox_fwd(tmp2[23..16]) @
                           aes_sbox_fwd(tmp2[15.. 8]) @ aes_sbox_fwd(tmp2[ 7.. 0]) ;
    let result : bits(64) = (tmp3 ^ rc) @ (tmp3 ^ rc);
    X(rd)      = EXTZ(result); RETIRE_SUCCESS
}

function clause execute (AES64_KS2 (rs2,rs1,rd)) = {
    let w0 : bits(32) = X(rs1)[63..32] ^ X(rs2)[31..0];
    let w1 : bits(32) = X(rs1)[63..32] ^ X(rs2)[31..0] ^ X(rs2)[63..32];
    X(rd)  = w1 @ w0; RETIRE_SUCCESS
}

function clause execute (AES64_IM (rs1,rd)) = {
    let w0 : bits(32) = aes_mixcolumn_inv(X(rs1)[31.. 0]);
    let w1 : bits(32) = aes_mixcolumn_inv(X(rs1)[63..32]);
    X(rd)  = w1 @ w0; RETIRE_SUCCESS
}
/* --- specification snippet begin --- */

function clause execute (AES64_ESM (rs2,rs1,rd)) = {
    crypto_aes64(rd, rs1, rs2, true, true);
}

function clause execute (AES64_ES (rs2,rs1,rd)) = {
    crypto_aes64(rd, rs1, rs2, true, false);
}

function clause execute (AES64_DSM (rs2,rs1,rd)) = {
    crypto_aes64(rd, rs1, rs2, false, true);
}

function clause execute (AES64_DS (rs2,rs1,rd)) = {
    crypto_aes64(rd, rs1, rs2, false, false);
}

/*
 * Scalar Cryptography Extension - Scalar 64-bit SHA512 instructions
 * ----------------------------------------------------------------------
 */

union   clause ast    =    SHA512_SIG0 : (regidx,regidx)
union   clause ast    =    SHA512_SIG1 : (regidx,regidx)
union   clause ast    =    SHA512_SUM0 : (regidx,regidx)
union   clause ast    =    SHA512_SUM1 : (regidx,regidx)

mapping clause encdec =    SHA512_SIG0   (rs1,rd) <-> 0b000011100100 @ rs1 @ 0b111 @ rd @ 0b0101011
mapping clause encdec =    SHA512_SIG1   (rs1,rd) <-> 0b000011100101 @ rs1 @ 0b111 @ rd @ 0b0101011
mapping clause encdec =    SHA512_SUM0   (rs1,rd) <-> 0b000011100110 @ rs1 @ 0b111 @ rd @ 0b0101011
mapping clause encdec =    SHA512_SUM1   (rs1,rd) <-> 0b000011100111 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause assembly =    SHA512_SIG0 (rs1,rd) <-> "sha512sig0" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly =    SHA512_SIG1 (rs1,rd) <-> "sha512sig1" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly =    SHA512_SUM0 (rs1,rd) <-> "sha512sum0" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly =    SHA512_SUM1 (rs1,rd) <-> "sha512sum1" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)


val      crypto_sha512_rv64 : (sha512_rv64_op, regidx, regidx) -> Retired effect {escape, rreg, wreg}
/* --- specification snippet begin --- */
function crypto_sha512_rv64   (op             , rd    , rs1   ) =  {
  let inb    : bits(64) = X(rs1)[63..0];
  let result : bits(64) = match op {
    OP_SHA512_SIG0 => ror64(inb,  1) ^ ror64(inb,  8) ^ (inb >> 7),
    OP_SHA512_SIG1 => ror64(inb, 19) ^ ror64(inb, 61) ^ (inb >> 6),
    OP_SHA512_SUM0 => ror64(inb, 28) ^ ror64(inb, 34) ^ ror64(inb ,39),
    OP_SHA512_SUM1 => ror64(inb, 14) ^ ror64(inb, 18) ^ ror64(inb ,41)
  };
  X(rd) = EXTZ(result);
  RETIRE_SUCCESS
}
/* --- specification snippet end --- */


function clause execute (   SHA512_SIG0 (rs1,rd)) = {
    crypto_sha512_rv64(OP_SHA512_SIG0, rd, rs1);
}

function clause execute (   SHA512_SIG1 (rs1,rd)) = {
    crypto_sha512_rv64(OP_SHA512_SIG1, rd, rs1);
}

function clause execute (   SHA512_SUM0 (rs1,rd)) = {
    crypto_sha512_rv64(OP_SHA512_SUM0, rd, rs1);
}

function clause execute (   SHA512_SUM1 (rs1,rd)) = {
    crypto_sha512_rv64(OP_SHA512_SUM1, rd, rs1);
}

