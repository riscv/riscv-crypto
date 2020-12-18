
/*
 * file: riscv_insts_crypto.sail
 *
 * This file contains instructions whos definitions do not change whether
 * XLEN is 32 or 64.
 *
 * This file must be included in the model build whatever the value of XLEN.
 *
 */

/*
 * Scalar Cryptography Extension - Scalar        SHA256 instructions
 * ----------------------------------------------------------------------
 */

/* AST clauses for the SHA256 instructions. */
union   clause ast    =    SHA256SIG0 : (regidx,regidx)
union   clause ast    =    SHA256SIG1 : (regidx,regidx)
union   clause ast    =    SHA256SUM0 : (regidx,regidx)
union   clause ast    =    SHA256SUM1 : (regidx,regidx)


/* Encode/decode mappings for the SHA256 instructions. */
mapping clause encdec =      SHA256SUM0   (rs1,rd) 
    <-> 0b00 @ 0b01000 @ 0b00000 @ rs1 @ 0b001 @ rd @ 0b0010011

mapping clause encdec =      SHA256SUM1   (rs1,rd) 
    <-> 0b00 @ 0b01000 @ 0b00001 @ rs1 @ 0b001 @ rd @ 0b0010011

mapping clause encdec =      SHA256SIG0   (rs1,rd) 
    <-> 0b00 @ 0b01000 @ 0b00010 @ rs1 @ 0b001 @ rd @ 0b0010011

mapping clause encdec =      SHA256SIG1   (rs1,rd) 
    <-> 0b00 @ 0b01000 @ 0b00011 @ rs1 @ 0b001 @ rd @ 0b0010011


/* Assembly string mappings for the SHA256 instructions. */
mapping clause assembly = SHA256SIG0 (rs1,rd) <-> "sha256sig0" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly = SHA256SIG1 (rs1,rd) <-> "sha256sig1" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly = SHA256SUM0 (rs1,rd) <-> "sha256sum0" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly = SHA256SUM1 (rs1,rd) <-> "sha256sum1" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)

val      crypto_sha256 : (sha256_op, regidx, regidx) -> Retired effect {escape,rreg,wreg}
/* --- specification snippet begin --- */
function crypto_sha256   (op        , rd    , rs1   ) =  {
  let inb    : bits(32) = X(rs1)[31..0];
  let result : bits(32) = match op {
    OP_SHA256_SIG0 => ror32(inb ,07) ^ ror32(inb ,18) ^ (inb >>  3),
    OP_SHA256_SIG1 => ror32(inb ,17) ^ ror32(inb ,19) ^ (inb >> 10),
    OP_SHA256_SUM0 => ror32(inb , 2) ^ ror32(inb, 13) ^ ror32(inb,22),
    OP_SHA256_SUM1 => ror32(inb , 6) ^ ror32(inb, 11) ^ ror32(inb,25)
  };
  X(rd) = EXTZ(result);
  RETIRE_SUCCESS
}
/* --- specification snippet end --- */

/* Execution clauses for the SHA256 instructions. */
function clause execute (SHA256SIG0 (rs1,rd)) = {
    crypto_sha256(OP_SHA256_SIG0, rd, rs1);
}

function clause execute (SHA256SIG1 (rs1,rd)) = {
    crypto_sha256(OP_SHA256_SIG1, rd, rs1);
}

function clause execute (SHA256SUM0 (rs1,rd)) = {
    crypto_sha256(OP_SHA256_SUM0, rd, rs1);
}

function clause execute (SHA256SUM1 (rs1,rd)) = {
    crypto_sha256(OP_SHA256_SUM1, rd, rs1);
}

/*
 * Scalar Cryptography Extension - Scalar        SM3 instructions
 * ----------------------------------------------------------------------
 */


/* AST Types for SM3.p0/1 */
union   clause ast      =  SM3P0 : (regidx,regidx)
union   clause ast      =  SM3P1 : (regidx,regidx)

/* Decode clause for sm3.p0 */
mapping clause encdec =           SM3P0   (rs1,rd) 
    <-> 0b00 @ 0b01000 @ 0b01000 @ rs1 @ 0b001 @ rd @ 0b0010011

/* Decode clause for sm3.p1 */
mapping clause encdec =           SM3P1   (rs1,rd) 
    <-> 0b00 @ 0b01000 @ 0b01001 @ rs1 @ 0b001 @ rd @ 0b0010011


/* Asssembly code mapping for sm3p0 */
mapping clause assembly =  SM3P0 (rs1,rd) <->
    "sm3.p0" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)

/* Asssembly code mapping for sm3p1 */
mapping clause assembly =  SM3P1 (rs1,rd) <->
    "sm3.p1" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)


val      crypto_sm3 : (sm3_op, regidx, regidx) -> Retired effect {escape,rreg,wreg}
/* --- specification snippet begin --- */
function crypto_sm3   (op     , rd    , rs1   ) =  {
  let r1    : bits(32) = X(rs1)[31..0];
  let result  : bits(32) = match op {
    P0  => r1 ^ rol32(r1 , 9) ^ rol32(r1 ,17),
    P1  => r1 ^ rol32(r1 ,15) ^ rol32(r1 ,23)
  };
  X(rd)       = EXTZ(result);
  RETIRE_SUCCESS
}
/* --- specification snippet end --- */


/* Execute clause for sm3.p0 */
function clause execute ( SM3P0 (rs1,rd)) = {
  crypto_sm3(P0, rd, rs1);
}

/* Execute clause for sm3.p1 */
function clause execute ( SM3P1 (rs1,rd)) = {
  crypto_sm3(P1, rd, rs1);
}


/*
 * Scalar Cryptography Extension - Scalar        SM4 instructions
 * ----------------------------------------------------------------------
 */


/* AST clauses for the SM4 instructions. */
union   clause ast      = SM4ED : (bits(2),regidx,regidx)
union   clause ast      = SM4KS : (bits(2),regidx,regidx)


/* Encode / decode mappings for the SM4 instructions. */
mapping clause encdec =           SM4ED   (bs,rs2,rt) 
    <-> bs @ 0b11000 @ rs2 @ rt @ 0b000 @ 0b00000 @ 0b0110011
mapping clause encdec =           SM4KS   (bs,rs2,rt) 
    <-> bs @ 0b11010 @ rs2 @ rt @ 0b000 @ 0b00000 @ 0b0110011

/* Assembly string mappings for the SM4 instructions. */
mapping clause assembly = SM4ED (bs,rs2,rt) <->
    "sm4.ed"     ^ spc() ^ 
    reg_name(rt)  ^ sep() ^
    reg_name(rs2) ^ sep() ^ hex_bits_2(bs)

mapping clause assembly = SM4KS (bs,rs2,rt) <->
    "sm4.ks"     ^ spc() ^
    reg_name(rt)  ^ sep() ^
    reg_name(rs2) ^ sep() ^ hex_bits_2(bs)


/* Execute clause for the sm4 instructions. */
/* --- specification snippet begin --- */
function clause execute (SM4ED (bs,rs2,rt)) = {
  let shamt : bits(6)  = (0b0 @ bs @ 0b000); /* shamt = bs*8 */
  let sb_in : bits(8)  = (X(rs2) >> shamt)[7..0];
  let x     : bits(32) = 0x000000 @ sm4_sbox(sb_in);
  let y     : bits(32) = x ^  (x               <<  8) ^ ( x               <<  2) ^
                              (x               << 18) ^ ((x & 0x0000003F) << 26) ^
                             ((x & 0x000000C0) << 10);
  let z     : bits(32) = (y << shamt) ^ (y >> (0b100000-shamt));
  let result: bits(32) = z ^ X(rt)[31..0];
  X(rt)                = EXTZ(result);
  RETIRE_SUCCESS
}

function clause execute (SM4KS (bs,rs2,rt)) = {
  let shamt : bits(6)  = (0b0 @ bs @ 0b000); /* shamt = bs*8 */
  let sb_in : bits(8)  = (X(rs2) >> shamt)[7..0];
  let x     : bits(32) = 0x000000 @ sm4_sbox(sb_in);
  let y     : bits(32) = x ^ ((x & 0x00000007) << 29) ^ ((x & 0x000000FE) <<  7) ^
                             ((x & 0x00000001) << 23) ^ ((x & 0x000000F8) << 13) ;
  let z     : bits(32) = (y << shamt) ^ (y >> (0b100000-shamt));
  let result: bits(32) = z ^ X(rt)[31..0];
  X(rt)                = EXTZ(result);
  RETIRE_SUCCESS
}
/* --- specification snippet end --- */

