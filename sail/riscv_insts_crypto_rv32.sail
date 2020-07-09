
/*
 * file: riscv_insts_crypto_rv32.sail
 *
 * This file contains the 32-bit specific cryptography extension
 * instructions.
 *
 */

/*
 * Scalar Cryptography Extension - Scalar 32-bit AES instructions
 * ----------------------------------------------------------------------
 */

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
 * Scalar Cryptography Extension - Scalar 32-bit SHA2 instructions
 * ----------------------------------------------------------------------
 */


/*                                    TBD                                */


/*
 * Scalar Cryptography Extension - Scalar        SM3 instructions
 * ----------------------------------------------------------------------
 */


/*                                    TBD                                */


/*
 * Scalar Cryptography Extension - Scalar        SM4 instructions
 * ----------------------------------------------------------------------
 */


/*                                    TBD                                */

