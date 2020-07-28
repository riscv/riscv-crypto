
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
union   clause ast    =    SSHA256_SIG0 : (regidx,regidx)
union   clause ast    =    SSHA256_SIG1 : (regidx,regidx)
union   clause ast    =    SSHA256_SUM0 : (regidx,regidx)
union   clause ast    =    SSHA256_SUM1 : (regidx,regidx)


/* Encode/decode mappings for the SHA256 instructions. */
mapping clause encdec =    SSHA256_SIG0   (rs1,rd) <->
    0b000011100000 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause encdec =    SSHA256_SIG1   (rs1,rd) <->
    0b000011100001 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause encdec =    SSHA256_SUM0   (rs1,rd) <->
    0b000011100010 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause encdec =    SSHA256_SUM1   (rs1,rd) <->
    0b000011100011 @ rs1 @ 0b111 @ rd @ 0b0101011


/* Assembly string mappings for the SHA256 instructions. */
mapping clause assembly = SSHA256_SIG0 (rs1,rd) <-> "ssha256.sig0" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly = SSHA256_SIG1 (rs1,rd) <-> "ssha256.sig1" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly = SSHA256_SUM0 (rs1,rd) <-> "ssha256.sum0" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)
mapping clause assembly = SSHA256_SUM1 (rs1,rd) <-> "ssha256.sum1" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)


/* Execution clauses for the SHA256 instructions. */
function clause execute (SSHA256_SIG0 (rs1,rd)) = {
    let rs1v : bits(32) = X(rs1)[31..0];
    X(rd)    = EXTZ(ror32(rs1v ,0x07) ^ ror32(rs1v ,0x12) ^ (rs1v >> 0x03));
    RETIRE_SUCCESS
}

function clause execute (SSHA256_SIG1 (rs1,rd)) = {
    let rs1v : bits(32) = X(rs1)[31..0];
    X(rd)    = EXTZ(ror32(rs1v ,0x11) ^ ror32(rs1v ,0x13) ^ (rs1v >> 0x0A));
    RETIRE_SUCCESS
}

function clause execute (SSHA256_SUM0 (rs1,rd)) = {
    let rs1v : bits(32) = X(rs1)[31..0];
    X(rd)    = EXTZ(ror32(rs1v ,0x02) ^ ror32(rs1v,0x0D) ^ ror32(rs1v,0x16));
    RETIRE_SUCCESS
}

function clause execute (SSHA256_SUM1 (rs1,rd)) = {
    let rs1v : bits(32) = X(rs1)[31..0];
    X(rd)    = EXTZ(ror32(rs1v ,0x06) ^ ror32(rs1v,0x0B) ^ ror32(rs1v,0x19));
    RETIRE_SUCCESS
}

/*
 * Scalar Cryptography Extension - Scalar        SM3 instructions
 * ----------------------------------------------------------------------
 */


/* AST Types for SSM3.p0/1 */
union   clause ast      =  SSM3_P0 : (regidx,regidx)
union   clause ast      =  SSM3_P1 : (regidx,regidx)

/* Decode clause for ssm3.p0 */
mapping clause encdec   =  SSM3_P0   (rs1,rd) <->
    0b000011101000 @ rs1 @ 0b111 @ rd @ 0b0101011

/* Decode clause for ssm3.p1 */
mapping clause encdec   =  SSM3_P1   (rs1,rd) <->
    0b000011101001 @ rs1 @ 0b111 @ rd @ 0b0101011


/* Asssembly code mapping for ssm3.p0 */
mapping clause assembly =  SSM3_P0 (rs1,rd) <->
    "ssm3.p0" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)

/* Asssembly code mapping for ssm3.p1 */
mapping clause assembly =  SSM3_P1 (rs1,rd) <->
    "ssm3.p1" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1)


/* Execute clause for ssm3.p0 */
function clause execute ( SSM3_P0 (rs1,rd)) = {
  let rs1v    : bits(32) = X(rs1)[31..0];
  let result  : bits(32) = rs1v ^ rol32(rs1v ,0x09) ^ rol32(rs1v ,0x11);
  X(rd)       = EXTZ(result);
  RETIRE_SUCCESS
}

/* Execute clause for ssm3.p1 */
function clause execute ( SSM3_P1 (rs1,rd)) = {
  let rs1v    : bits(32) = X(rs1)[31..0];
  let result  : bits(32) = rs1v ^ rol32(rs1v ,0x0E) ^ rol32(rs1v ,0x17);
  X(rd)       = EXTZ(result);
  RETIRE_SUCCESS
}


/*
 * Scalar Cryptography Extension - Scalar        SM4 instructions
 * ----------------------------------------------------------------------
 */


/* AST clauses for the SM4 instructions. */
union   clause ast      = SSM4_ED : (bits(2),regidx,regidx,regidx)
union   clause ast      = SSM4_KS : (bits(2),regidx,regidx,regidx)


/* Encode / decode mappings for the SM4 instructions. */
mapping clause encdec   = SSM4_ED   (bs,rs2,rs1,rd) <->
    bs @ 0b00100 @ rs2 @ rs1 @ 0b011 @ rd @ 0b0101011

mapping clause encdec   = SSM4_KS   (bs,rs2,rs1,rd) <->
    bs @ 0b00101 @ rs2 @ rs1 @ 0b011 @ rd @ 0b0101011


/* Assembly string mappings for the SM4 instructions. */
mapping clause assembly = SSM4_ED (bs,rs2,rs1,rd) <->
    "ssm4.ed"     ^ spc() ^ 
    reg_name(rd)  ^ sep() ^
    reg_name(rs1) ^ sep() ^
    reg_name(rs2) ^ sep() ^ hex_bits_2(bs)

mapping clause assembly = SSM4_KS (bs,rs2,rs1,rd) <->
    "ssm4.ks"     ^ spc() ^
    reg_name(rd)  ^ sep() ^
    reg_name(rs1) ^ sep() ^
    reg_name(rs2) ^ sep() ^ hex_bits_2(bs)


/* Execute clause for the ssm4.ed (encrypt/decrypt) instruction. */
function clause execute (        SSM4_ED (bs,rs2,rs1,rd)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}

/* Execute clause for the ssm4.ks (key schedule) instruction. */
function clause execute (        SSM4_KS (bs,rs2,rs1,rd)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}


/*
 * Scalar Cryptography Extension - Scalar        pollentropy instruciton.
 * ----------------------------------------------------------------------
 */

/* AST type for pollentropy instruction */
union   clause ast      = POLLENTROPY : (bits(5),regidx)

/* Encode / decode mapping for pollentropy */
mapping clause encdec   = POLLENTROPY (shamtw,rd) <->
    0b0000111 @ shamtw @ 0b01010111 @ rd @ 0b0101011

/* Assembly string mapping for pollentropy */
mapping clause assembly = POLLENTROPY (shamtw,rd) <-> 
    "pollentropy" ^ spc() ^ reg_name(rd) ^ sep() ^ hex_bits_5(shamtw)

/* Execute clause for pollentropy */
function clause execute (    POLLENTROPY (shamtw,rd)) = {
    /* TBD, implemented as nop.*/
    RETIRE_SUCCESS
}

