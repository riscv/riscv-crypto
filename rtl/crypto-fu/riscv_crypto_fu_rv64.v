
// 
// Copyright (C) 2020 
//    SCARV Project  <info@scarv.org>
//    Ben Marshall   <ben.marshall@bristol.ac.uk>
// 
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
// IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

//
// module: riscv_crypto_fu_rv64
//
//  A wrapper which implements the 64-bit RISC-V cryptography
//  extension specific instructions.
//
//  The following table shows which instructions are implemented
//  based on the feature enable parameter name(s).
//
//  Instruction     | Feature Parameter 
//  ----------------|----------------------------------
//   lut4           | LUT4_EN           
//   saes64.ks1     | SAES_EN
//   saes64.ks2     | SAES_EN
//   saes64.imix    | SAES_DEC_EN
//   saes64.encs    | SAES_EN
//   saes64.encsm   | SAES_EN
//   saes64.decs    | SAES_DEC_EN
//   saes64.decsm   | SAES_DEC_EN
//   ssha256.sig0   | SSHA256_EN
//   ssha256.sig1   | SSHA256_EN
//   ssha256.sum0   | SSHA256_EN
//   ssha256.sum1   | SSHA256_EN
//   ssha512.sig0   | SSHA512_EN
//   ssha512.sig1   | SSHA512_EN
//   ssha512.sum0   | SSHA512_EN
//   ssha512.sum1   | SSHA512_EN
//   ssm3.p0        | SSM3_EN
//   ssm3.p1        | SSM3_EN
//   ssm4.ks        | SSM4_EN
//   ssm4.ed        | SSM4_EN
//
module riscv_crypto_fu_rv64 #(
parameter LUT4_EN       = 1 , // Enable the lut4 instructions.
parameter SAES_EN       = 1 , // Enable the saes32/64 instructions.
parameter SAES_DEC_EN   = 1 , // Enable the saes32/64 decrypt instructions.
parameter SAES64_SBOXES = 8 , // saes64 sbox instances. Valid values: 8
parameter SSHA256_EN    = 1 , // Enable the ssha256.* instructions.
parameter SSHA512_EN    = 1 , // Enable the ssha256.* instructions.
parameter SSM3_EN       = 1 , // Enable the ssm3.* instructions.
parameter SSM4_EN       = 1   // Enable the ssm4.* instructions.
)(

input  wire             g_clk           , // Global clock
input  wire             g_resetn        , // Synchronous active low reset.

input  wire             valid           , // Inputs valid.
input  wire [     63:0] rs1             , // Source register 1
input  wire [     63:0] rs2             , // Source register 2
input  wire [      3:0] imm             , // bs, enc_rcon for aes32/64.

input  wire             op_lut4         , // RV64 lut4    instruction
input  wire             op_saes64_ks1   , // RV64 AES Encrypt KeySchedule 1
input  wire             op_saes64_ks2   , // RV64 AES Encrypt KeySchedule 2
input  wire             op_saes64_imix  , // RV64 AES Decrypt KeySchedule Mix
input  wire             op_saes64_encs  , // RV64 AES Encrypt SBox
input  wire             op_saes64_encsm , // RV64 AES Encrypt SBox + MixCols
input  wire             op_saes64_decs  , // RV64 AES Decrypt SBox
input  wire             op_saes64_decsm , // RV64 AES Decrypt SBox + MixCols
input  wire             op_ssha256_sig0 , //      SHA256 Sigma 0
input  wire             op_ssha256_sig1 , //      SHA256 Sigma 1
input  wire             op_ssha256_sum0 , //      SHA256 Sum 0
input  wire             op_ssha256_sum1 , //      SHA256 Sum 1
input  wire             op_ssha512_sig0 , // RV64 SHA512 Sigma 0
input  wire             op_ssha512_sig1 , // RV64 SHA512 Sigma 1
input  wire             op_ssha512_sum0 , // RV64 SHA512 Sum 0
input  wire             op_ssha512_sum1 , // RV64 SHA512 Sum 1
input  wire             op_ssm3_p0      , //      SSM3 P0
input  wire             op_ssm3_p1      , //      SSM3 P1
input  wire             op_ssm4_ks      , //      SSM4 KeySchedule
input  wire             op_ssm4_ed      , //      SSM4 Encrypt/Decrypt

output wire             ready           , // Outputs ready.
output wire [     63:0] rd

);


riscv_crypto_fu #(
.XLEN         (64          ), // Must be one of: 32, 64.
.LUT4_EN      (LUT4_EN     ), // Enable the lut4 instructions.
.SAES_EN      (SAES_EN     ), // Enable the saes32/64 instructions.
.SAES_DEC_EN  (SAES_DEC_EN ), // Enable the saes32/64 decrypt instructions.
.SAES64_SBOXES(8           ), // saes64 sbox instances. Valid values: 8
.SSHA256_EN   (SSHA256_EN  ), // Enable the ssha256.* instructions.
.SSHA512_EN   (SSHA512_EN  ), // Enable the ssha256.* instructions.
.SSM3_EN      (SSM3_EN     ), // Enable the ssm3.* instructions.
.SSM4_EN      (SSM4_EN     )  // Enable the ssm4.* instructions.
) i_riscv_crypto_fu (
.g_clk           (g_clk           ), // Global clock
.g_resetn        (g_resetn        ), // Synchronous active low reset.
.valid           (valid           ), // Inputs valid.
.rs1             (rs1             ), // Source register 1
.rs2             (rs2             ), // Source register 2
.imm             (imm             ), // bs, enc_rcon for aes32/64.
.op_lut4lo       (1'b0            ), // RV32 lut4-lo instruction
.op_lut4hi       (1'b0            ), // RV32 lut4-hi instruction
.op_lut4         (op_lut4         ), // RV64 lut4    instruction
.op_saes32_encs  (1'b0            ), // RV32 AES Encrypt SBox
.op_saes32_encsm (1'b0            ), // RV32 AES Encrypt SBox + MixCols
.op_saes32_decs  (1'b0            ), // RV32 AES Decrypt SBox
.op_saes32_decsm (1'b0            ), // RV32 AES Decrypt SBox + MixCols
.op_saes64_ks1   (op_saes64_ks1   ), // RV64 AES Encrypt KeySchedule 1
.op_saes64_ks2   (op_saes64_ks2   ), // RV64 AES Encrypt KeySchedule 2
.op_saes64_imix  (op_saes64_imix  ), // RV64 AES Decrypt KeySchedule Mix
.op_saes64_encs  (op_saes64_encs  ), // RV64 AES Encrypt SBox
.op_saes64_encsm (op_saes64_encsm ), // RV64 AES Encrypt SBox + MixCols
.op_saes64_decs  (op_saes64_decs  ), // RV64 AES Decrypt SBox
.op_saes64_decsm (op_saes64_decsm ), // RV64 AES Decrypt SBox + MixCols
.op_ssha256_sig0 (op_ssha256_sig0 ), //      SHA256 Sigma 0
.op_ssha256_sig1 (op_ssha256_sig1 ), //      SHA256 Sigma 1
.op_ssha256_sum0 (op_ssha256_sum0 ), //      SHA256 Sum 0
.op_ssha256_sum1 (op_ssha256_sum1 ), //      SHA256 Sum 1
.op_ssha512_sum0r(1'b0            ), // RV32 SHA512 Sum 0
.op_ssha512_sum1r(1'b0            ), // RV32 SHA512 Sum 1
.op_ssha512_sig0l(1'b0            ), // RV32 SHA512 Sigma 0 low
.op_ssha512_sig0h(1'b0            ), // RV32 SHA512 Sigma 0 high
.op_ssha512_sig1l(1'b0            ), // RV32 SHA512 Sigma 1 low
.op_ssha512_sig1h(1'b0            ), // RV32 SHA512 Sigma 1 high
.op_ssha512_sig0 (op_ssha512_sig0 ), // RV64 SHA512 Sigma 0
.op_ssha512_sig1 (op_ssha512_sig1 ), // RV64 SHA512 Sigma 1
.op_ssha512_sum0 (op_ssha512_sum0 ), // RV64 SHA512 Sum 0
.op_ssha512_sum1 (op_ssha512_sum1 ), // RV64 SHA512 Sum 1
.op_ssm3_p0      (op_ssm3_p0      ), //      SSM3 P0
.op_ssm3_p1      (op_ssm3_p1      ), //      SSM3 P1
.op_ssm4_ks      (op_ssm4_ks      ), //      SSM4 KeySchedule
.op_ssm4_ed      (op_ssm4_ed      ), //      SSM4 Encrypt/Decrypt
.ready           (ready           ), // Outputs ready.
.rd              (rd              )
);


endmodule

