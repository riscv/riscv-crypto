
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
mapping encdec_saes32_op : saes_op <-> bits(5) = {
    ENCSM   <-> 0b00000,
    ENCS    <-> 0b00001,
    DECSM   <-> 0b00010,
    DECS    <-> 0b00011
}

/* Map 32-bit operations to assembly mnemonics - for disassemly */
mapping saes32_op_to_mnemonic : saes_op <-> string = {
    ENCSM <-> "saes32.encsm"  ,
    ENCS  <-> "saes32.encs"   ,
    DECSM <-> "saes32.decsm"  ,
    DECS  <-> "saes32.decs"
}

/* Map byte shift amounts to strings - for disassemly */
val     saes32_bs_to_str   : saes_bs <-> string
mapping saes32_bs_to_str   : saes_bs <-> string = {
    0b00 <-> "0",
    0b01 <-> "1",
    0b10 <-> "2",
    0b11 <-> "3"
}

union    clause ast      = SAES32 : (saes_bs, regidx, regidx, regidx, saes_op)


/* Encrypt/Decrypt mapping for 32-bit scalar AES instructions. */
mapping  clause encdec   = SAES32   (saes_bs, rs2   , rs1   , rd    , op     )
    <-> saes_bs @ encdec_saes32_op(op) @ rs2 @ rs1 @ 0b010 @ rd @ 0b0101011


/* Map between an AST representation of SAES32 and a disassembly string. */
mapping  clause assembly = SAES32   (     bs, rs2   , rs1   , rd    , op     )
<-> saes32_op_to_mnemonic(op)   ^   spc()   ^
    reg_name(rd)                ^   sep()   ^
    reg_name(rs1)               ^   sep()   ^
    reg_name(rs2)               ^   sep()   ^
    saes32_bs_to_str(bs)


/* Execute the scalar 32-bit AES instructions.
 * - op : The exact instruciton variant to perform.
 * - rd : Destination register address
 * - rs1: Source register 1 address
 * - rs2: Source register 2 address
 * - bs : 2-bit byte shift.
 */ 
/* --- specification snippet begin --- */
function clause execute   (SAES32 (bs, rs2, rs1, rd, op))={
  let rs1_val : xlenbits = X(rs1);
  let rs2_val : xlenbits = X(rs2);
  let shamt   : bits(6)  = (0b0 @ bs @ 0b000); /* shamt = bs*8 */
  let si      : bits(8)  = (rs2_val >> shamt)[7..0]; /* SBox Input */
  let so      : bits(8)  = if (saes_op_fwd(op)) then aes_sbox_fwd(si)
                                                else aes_sbox_inv(si);
  let mixed   : xlenbits =
    if(saes_op_does_mix(op)) then
      if(saes_op_fwd(op)) then aes_mixcolumn_byte_fwd(so)
                          else aes_mixcolumn_byte_inv(so)
    else
        0x000000 @ so;
  let result  : xlenbits = rs1_val ^ (mixed << shamt) ^ (mixed >> (0b100000-shamt));
  X(rd)       = result;
  RETIRE_SUCCESS
}
/* --- specification snippet end --- */


/*
 * Scalar Cryptography Extension - Scalar 32-bit SHA512 instructions
 * ----------------------------------------------------------------------
 */


/* AST clauses for the RV32 SHA512 instructions. */
union   clause ast    = SSHA512_SIG0L : (regidx,regidx,regidx)
union   clause ast    = SSHA512_SIG0H : (regidx,regidx,regidx)
union   clause ast    = SSHA512_SIG1L : (regidx,regidx,regidx)
union   clause ast    = SSHA512_SIG1H : (regidx,regidx,regidx)
union   clause ast    = SSHA512_SUM0R : (regidx,regidx,regidx)
union   clause ast    = SSHA512_SUM1R : (regidx,regidx,regidx)

/* Encode / decode mappings for the RV32 SHA512 instructions. */
mapping clause encdec = SSHA512_SIG0L (rs2,rs1,rd) <->
    0b0001000 @ rs2 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause encdec = SSHA512_SIG0H (rs2,rs1,rd) <->
    0b0001001 @ rs2 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause encdec = SSHA512_SIG1L (rs2,rs1,rd) <->
    0b0001010 @ rs2 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause encdec = SSHA512_SIG1H (rs2,rs1,rd) <->
    0b0001011 @ rs2 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause encdec = SSHA512_SUM0R (rs2,rs1,rd) <->
    0b0001100 @ rs2 @ rs1 @ 0b111 @ rd @ 0b0101011

mapping clause encdec = SSHA512_SUM1R (rs2,rs1,rd) <->
    0b0001101 @ rs2 @ rs1 @ 0b111 @ rd @ 0b0101011


/* Assembly string mappings for the RV32 SHA512 instructions. */
mapping clause assembly = SSHA512_SIG0L (rs2,rs1,rd) <->
    "ssha512.sig0l" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SSHA512_SIG0H (rs2,rs1,rd) <->
    "ssha512.sig0h" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SSHA512_SIG1L (rs2,rs1,rd) <->
    "ssha512.sig1l" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SSHA512_SIG1H (rs2,rs1,rd) <->
    "ssha512.sig1h" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SSHA512_SUM0R (rs2,rs1,rd) <->
    "ssha512.sum0r" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)

mapping clause assembly = SSHA512_SUM1R (rs2,rs1,rd) <->
    "ssha512.sum1r" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ reg_name(rs2)


val      crypto_ssha512_rv32 :(ssha512_rv32_op, regidx, regidx, regidx) -> Retired effect {escape, rreg, wreg}
/* --- specification snippet begin --- */
function crypto_ssha512_rv32  (op             , rd    , rs1   , rs2   ) = {
  let r1     : bits(32) = X(rs1)[31..0];
  let r2     : bits(32) = X(rs2)[31..0];
  let result : bits(32) = match op {
    SHA512_SIG0L => (r1>> 1) ^ (r1>> 7) ^ (r1>> 8) ^ (r2<<31) ^(r2<<25) ^(r2<<24),
    SHA512_SIG0H => (r1>> 1) ^ (r1>> 7) ^ (r1>> 8) ^ (r2<<31)           ^(r2<<24),
    SHA512_SIG1L => (r1>> 3) ^ (r1>> 6) ^ (r1>>19) ^ (r2<<29) ^(r2<<26) ^(r2<<13),
    SHA512_SIG1H => (r1>> 3) ^ (r1>> 6) ^ (r1>>19) ^ (r2<<29)           ^(r2<<13),
    SHA512_SUM0R => (r1<<25) ^ (r1<<30) ^ (r1>>28) ^ (r2<< 7) ^(r2<< 2) ^(r2<<24),
    SHA512_SUM1R => (r1<<23) ^ (r1<<14) ^ (r1>>18) ^ (r2<< 9) ^(r2<<18) ^(r2<<14)
  };
  X(rd) = EXTZ(result);
  RETIRE_SUCCESS
}
/* --- specification snippet end --- */


/*
 * Execute clauses for the 32-bit SHA512 instructions.
 */

function clause execute (  SSHA512_SIG0L (rs2,rs1,rd)) = {
  crypto_ssha512_rv32(SHA512_SIG0L, rd, rs1, rs2);
}

function clause execute (  SSHA512_SIG0H (rs2,rs1,rd)) = {
  crypto_ssha512_rv32(SHA512_SIG0H, rd, rs1, rs2);
}

function clause execute (  SSHA512_SIG1L (rs2,rs1,rd)) = {
  crypto_ssha512_rv32(SHA512_SIG1L, rd, rs1, rs2);
}

function clause execute (  SSHA512_SIG1H (rs2,rs1,rd)) = {
  crypto_ssha512_rv32(SHA512_SIG1H, rd, rs1, rs2);
}

function clause execute (  SSHA512_SUM0R (rs2,rs1,rd)) = {
  crypto_ssha512_rv32(SHA512_SUM0R, rd, rs1, rs2);
}

function clause execute (  SSHA512_SUM1R (rs2,rs1,rd)) = {
  crypto_ssha512_rv32(SHA512_SUM1R, rd, rs1, rs2);
}


