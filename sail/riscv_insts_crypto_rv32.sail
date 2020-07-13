
/*
 * file: riscv_insts_crypto_rv32.sail
 *
 * This file contains the 32-bit specific cryptography extension
 * instructions.
 *
 * This file *must not* be included in the model build if XLEN != 32
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
function clause execute   (SAES32   (     bs, rs2   , rs1   , rd    , op))={
    let rs1_val : xlenbits  = X(rs1);
    let rs2_val : xlenbits  = X(rs2);
    let shamt   : bits(6)   = aes_bs_to_shamt(bs);
    let sb_in   : bits(8)   = (rs2_val >>shamt)[7..0];
    let sb_out  : bits(8)   = 
        if (saes_op_to_enc(op)) then aes_sbox_fwd(sb_in)
                                else aes_sbox_inv(sb_in)
    ;
    let mixed   : xlenbits  =
        if(saes_op_to_mix(op)) then
            if(saes_op_to_enc(op)) then
                gfmul(sb_out, 0x03) @       sb_out        @
                      sb_out        @ gfmul(sb_out, 0x02)
            else
                gfmul(sb_out, 0x0b) @ gfmul(sb_out, 0x0d) @
                gfmul(sb_out, 0x09) @ gfmul(sb_out, 0x0e)
        else
            0x000000 @ sb_out
    ;
    let rotated: xlenbits  = (mixed << shamt) ^ (mixed >> (0b100000-shamt));
    X(rd) = rotated ^ rs1_val;
    RETIRE_SUCCESS
}

/*
 * Scalar Cryptography Extension - Scalar 32-bit SHA512 instructions
 * ----------------------------------------------------------------------
 */


/*                                    TBD                                */

