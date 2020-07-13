
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


/* Map 32-bit operations to assembly mnemonics - for disassemly */
mapping ssha256_op_to_mnemonic : ssha256_op <-> string = {
  SIG0 <-> "ssha256.sig0",
  SIG1 <-> "ssha256.sig1",
  SUM0 <-> "ssha256.sum0",
  SUM1 <-> "ssha256.sum1"
}

union   clause  ast     = SSHA256 : (ssha256_op , regidx, regidx)

/* TODO - ssha256 encode / decode
 * mapping clause  encdec  = SSHA256   (op         , rs1   , rs2   )
 * <-> encdec_ssha256_op(op) @ 
 */

mapping clause  assembly= SSHA256 (op         , rs1   , rd    ) <->
  ssha256_op_to_mnemonic(op) ^ spc()  ^
  reg_name(rd )              ^ sep()  ^
  reg_name(rs1)


function clause execute (SSHA256 (op   , rs1, rd)) = {
  let rs1v    : bits(32) = X(rs1)[31..0];
  let result  : bits(32) = match (op) {
    SIG0 => ror32(rs1v ,0x07) ^ ror32(rs1v ,0x12) ^      (rs1v >> 0x03),
    SIG1 => ror32(rs1v ,0x11) ^ ror32(rs1v ,0x13) ^      (rs1v >> 0x0A),
    SUM0 => ror32(rs1v ,0x02) ^ ror32(rs1v ,0x0D) ^ ror32(rs1v ,  0x16),
    SUM1 => ror32(rs1v ,0x06) ^ ror32(rs1v ,0x0B) ^ ror32(rs1v ,  0x19)
  };
  X(rd)       = EXTZ(result);
  RETIRE_SUCCESS
}

/*
 * Scalar Cryptography Extension - Scalar        SM3 instructions
 * ----------------------------------------------------------------------
 */


/* Map 32-bit operations to assembly mnemonics - for disassemly */
mapping ssm3_op_to_mnemonic : ssm3_op <-> string = {
  P0 <-> "ssm3.p0",
  P1 <-> "ssm3.p1" 
}

union   clause  ast     = SSM3 : (ssm3_op , regidx, regidx)

/* TODO - ssm3 encode / decode
 * mapping clause  encdec  = SSM3 (op         , rs1   , rs2   )
 * <-> encdec_ssm3 (op) @ 
 */

mapping clause  assembly= SSM3 (op         , rs1   , rd    ) <->
  ssm3_op_to_mnemonic(op) ^ spc()  ^
  reg_name(rd )           ^ sep()  ^
  reg_name(rs1)


function clause execute (SSM3 (op   , rs1, rd)) = {
  let rs1v    : bits(32) = X(rs1)[31..0];
  let result  : bits(32) = match (op) {
    P0 => rs1v ^ rol32(rs1v ,0x09) ^ rol32(rs1v ,0x11),
    P1 => rs1v ^ rol32(rs1v ,0x0E) ^ rol32(rs1v ,0x17) 
  };
  X(rd)       = EXTZ(result);
  RETIRE_SUCCESS
}


/*
 * Scalar Cryptography Extension - Scalar        SM4 instructions
 * ----------------------------------------------------------------------
 */


/*                                    TBD                                */

