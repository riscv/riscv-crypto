
/*
 * file: riscv_insts_crypto_rv32.sail
 *
 * This file contains the 32-bit specific cryptography extension
 * instructions.
 *
 * This file must be included in the model build if XLEN=32
 *
 */

/*
 * Scalar Cryptography Extension - Scalar 32-bit AES instructions
 * ----------------------------------------------------------------------
 */

/* Map between f5 encoding field and scalar round function instrucitons. */
mapping encdec_aes32_op : aes_op <-> bits(5) = {
    ENCSM   <-> 0b11011,
    ENCS    <-> 0b11001,
    DECSM   <-> 0b11111,
    DECS    <-> 0b11101
}

/* Map 32-bit operations to assembly mnemonics - for disassemly */
mapping aes32_op_to_mnemonic : aes_op <-> string = {
    ENCSM <-> "aes32esm"  ,
    ENCS  <-> "aes32es"   ,
    DECSM <-> "aes32dsm"  ,
    DECS  <-> "aes32ds"
}

/* Map byte shift amounts to strings - for disassemly */
val     aes32_bs_to_str   : aes_bs <-> string
mapping aes32_bs_to_str   : aes_bs <-> string = {
    0b00 <-> "0",
    0b01 <-> "1",
    0b10 <-> "2",
    0b11 <-> "3"
}

union    clause ast      = AES32 : (aes_bs, regidx, regidx, aes_op)


/* Encrypt/Decrypt mapping for 32-bit scalar AES instructions. */
mapping  clause encdec   = AES32   (aes_bs, rs2   , rt    , op     )
    <-> aes_bs @ encdec_aes32_op(op) @ rs2 @ rt  @ 0b010 @ 0b00000 @ 0b0101011


/* Map between an AST representation of AES32 and a disassembly string. */
mapping  clause assembly = AES32   (     bs, rs2   , rt    , op     )
<-> aes32_op_to_mnemonic(op)   ^   spc()   ^
    reg_name(rt)                ^   sep()   ^
    reg_name(rs2)               ^   sep()   ^
    aes32_bs_to_str(bs)


/* Execute the scalar 32-bit AES instructions.
 * - op : The exact instruciton variant to perform.
 * - rt : Source register 1 / Destination register address
 * - rs2: Source register 2 address
 * - bs : 2-bit byte shift.
 */ 
/* --- specification snippet begin --- */
function clause execute   (AES32 (bs, rs2, rt, op))={
  let rs1_val : xlenbits = X(rt );
  let rs2_val : xlenbits = X(rs2);
  let shamt   : bits(6)  = (0b0 @ bs @ 0b000); /* shamt = bs*8 */
  let si      : bits(8)  = (rs2_val >> shamt)[7..0]; /* SBox Input */
  let so      : bits(8)  = if (aes_op_fwd(op)) then aes_sbox_fwd(si)
                                                else aes_sbox_inv(si);
  let mixed   : xlenbits =
    if(aes_op_does_mix(op)) then
      if(aes_op_fwd(op)) then aes_mixcolumn_byte_fwd(so)
                          else aes_mixcolumn_byte_inv(so)
    else
        0x000000 @ so;
  let result  : xlenbits = rs1_val ^ (mixed << shamt) ^ (mixed >> (0b100000-shamt));
  X(rt)       = result;
  RETIRE_SUCCESS
}
/* --- specification snippet end --- */


/*
 * Scalar Cryptography Extension - Scalar 32-bit SHA512 instructions
 * ----------------------------------------------------------------------
 */


/* AST clauses for the RV32 SHA512 instructions. */
union   clause ast    = SHA512SIG0L : (regidx,regidx,regidx)
union   clause ast    = SHA512SIG0H : (regidx,regidx,regidx)
union   clause ast    = SHA512SIG1L : (regidx,regidx,regidx)
union   clause ast    = SHA512SIG1H : (regidx,regidx,regidx)
union   clause ast    = SHA512SUM0R : (regidx,regidx,regidx)
union   clause ast    = SHA512SUM1R : (regidx,regidx,regidx)

/* Encode / decode mappings for the RV32 SHA512 instructions. */
mapping clause encdec =     SHA512SUM0R   (rs2,rs1,rd) 
    <-> 0b01 @ 0b01000 @ rs2 @ rs1 @ 0b000 @ rd @ 0b0110011

mapping clause encdec =     SHA512SUM1R   (rs2,rs1,rd) 
    <-> 0b01 @ 0b01001 @ rs2 @ rs1 @ 0b000 @ rd @ 0b0110011

mapping clause encdec =     SHA512SIG0L   (rs2,rs1,rd) 
    <-> 0b01 @ 0b01010 @ rs2 @ rs1 @ 0b000 @ rd @ 0b0110011

mapping clause encdec =     SHA512SIG0H   (rs2,rs1,rd) 
    <-> 0b01 @ 0b01110 @ rs2 @ rs1 @ 0b000 @ rd @ 0b0110011

mapping clause encdec =     SHA512SIG1L   (rs2,rs1,rd) 
    <-> 0b01 @ 0b01011 @ rs2 @ rs1 @ 0b000 @ rd @ 0b0110011

mapping clause encdec =     SHA512SIG1H   (rs2,rs1,rd) 
    <-> 0b01 @ 0b01111 @ rs2 @ rs1 @ 0b000 @ rd @ 0b0110011


/* Assembly string mappings for the RV32 SHA512 instructions. */
mapping clause assembly = SHA512SIG0L (rs2,rs1,rd) <->
    "sha512sig0l" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SHA512SIG0H (rs2,rs1,rd) <->
    "sha512sig0h" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SHA512SIG1L (rs2,rs1,rd) <->
    "sha512sig1l" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SHA512SIG1H (rs2,rs1,rd) <->
    "sha512sig1h" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SHA512SUM0R (rs2,rs1,rd) <->
    "sha512sum0r" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SHA512SUM1R (rs2,rs1,rd) <->
    "sha512sum1r" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)


val      crypto_sha512_rv32 :(sha512_rv32_op, regidx, regidx, regidx) -> Retired effect {escape, rreg, wreg}
/* --- specification snippet begin --- */
function crypto_sha512_rv32  (op             , rd    , rs1   , rs2   ) = {
  let r1     : bits(32) = X(rs1)[31..0];
  let r2     : bits(32) = X(rs2)[31..0];
  let result : bits(32) = match op {
    OP_SHA512_SIG0L => (r1>> 1)^(r1>> 7)^(r1>> 8)^(r2<<31)^(r2<<25)^(r2<<24),
    OP_SHA512_SIG0H => (r1>> 1)^(r1>> 7)^(r1>> 8)^(r2<<31)         ^(r2<<24),
    OP_SHA512_SIG1L => (r1<< 3)^(r1>> 6)^(r1>>19)^(r2>>29)^(r2<<26)^(r2<<13),
    OP_SHA512_SIG1H => (r1<< 3)^(r1>> 6)^(r1>>19)^(r2>>29)         ^(r2<<13),
    OP_SHA512_SUM0R => (r1<<25)^(r1<<30)^(r1>>28)^(r2>> 7)^(r2>> 2)^(r2<< 4),
    OP_SHA512_SUM1R => (r1<<23)^(r1>>14)^(r1>>18)^(r2>> 9)^(r2<<18)^(r2<<14)
  };
  X(rd) = EXTZ(result);
  RETIRE_SUCCESS
}
/* --- specification snippet end --- */


/*
 * Execute clauses for the 32-bit SHA512 instructions.
 */

function clause execute (  SHA512SIG0L (rs2,rs1,rd)) = {
  crypto_sha512_rv32(OP_SHA512_SIG0L, rd, rs1, rs2);
}

function clause execute (  SHA512SIG0H (rs2,rs1,rd)) = {
  crypto_sha512_rv32(OP_SHA512_SIG0H, rd, rs1, rs2);
}

function clause execute (  SHA512SIG1L (rs2,rs1,rd)) = {
  crypto_sha512_rv32(OP_SHA512_SIG1L, rd, rs1, rs2);
}

function clause execute (  SHA512SIG1H (rs2,rs1,rd)) = {
  crypto_sha512_rv32(OP_SHA512_SIG1H, rd, rs1, rs2);
}

function clause execute (  SHA512SUM0R (rs2,rs1,rd)) = {
  crypto_sha512_rv32(OP_SHA512_SUM0R, rd, rs1, rs2);
}

function clause execute (  SHA512SUM1R (rs2,rs1,rd)) = {
  crypto_sha512_rv32(OP_SHA512_SUM1R, rd, rs1, rs2);
}


