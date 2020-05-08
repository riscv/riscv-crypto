
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
// module: riscv_crypto_fu_ssm4
//
//  Implements the scalar SM4 instructions for the RISC-V
//  cryptography extension
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN, and the feature enable
//  parameter name(s).
//
//  Instruction     | XLEN=32 | XLEN=64 
//  ----------------|---------|---------
//   ssm4.ks        |   x     |    x
//   ssm4.ed        |   x     |    x
//
module riscv_crypto_fu_ssm4 (

input  wire         valid       , // Inputs valid?
input  wire [31:0]  rs1         , // Source register 1
input  wire [31:0]  rs2         , // Source register 2
input  wire [ 1:0]  bs          , // Byte select

input  wire         op_ssm4_ks  , // Do ssm4.ks instruction
input  wire         op_ssm4_ed  , // Do ssm4.ed instruction

output wire [31:0]  result      , // Writeback result
output wire         ready         //

);


// Always finish in a single cycle.
assign     ready            = valid ;

//
// SBOX Byte select
// ------------------------------------------------------------

wire [7:0] in_bytes [3:0];

assign in_bytes[0]  = rs2[ 7: 0];
assign in_bytes[1]  = rs2[15: 8];
assign in_bytes[2]  = rs2[23:16];
assign in_bytes[3]  = rs2[31:24];

wire [ 7:0] sbox_in = in_bytes[bs];
wire [ 7:0] sbox_out;

wire [31:0] l       = {24'b0, sbox_out};

//
// ED Instruction
// ------------------------------------------------------------

wire [31:0] l_ed1   = l     ^  (l << 8) ^ (l << 2) ^  (l << 18);
wire [31:0] l_ed2   = l_ed1 ^ ((l     & 32'h3F) << 26) ^
                              ((l     & 32'hC0) << 10) ;

//
// KS Instruction
// ------------------------------------------------------------

wire [31:0] l_ks1   = l     ^ ((l & 32'h7) << 29) ^ ((l & 32'hFE) << 7);
wire [31:0] l_ks2   = l_ks1 ^ ((l     & 32'h01) << 23) ^
                              ((l     & 32'hF8) << 13) ;

//
// Rotate and XOR result
// ------------------------------------------------------------

wire [31:0] rot_in  = op_ssm4_ks ? l_ks2 : l_ed2;

wire [31:0] rot_out     =
    {32{bs == 2'b00}} & {rot_in                      } |
    {32{bs == 2'b01}} & {rot_in[23:0], rot_in[31:24] } |
    {32{bs == 2'b10}} & {rot_in[15:0], rot_in[31:16] } |
    {32{bs == 2'b11}} & {rot_in[ 7:0], rot_in[31: 8] } ;

assign      result      = rot_out ^ rs1 ;

//
// Submodule - SBox
riscv_crypto_sm4_sbox i_sm4_sbox (
    .in (sbox_in ),
    .out(sbox_out)
);

endmodule
