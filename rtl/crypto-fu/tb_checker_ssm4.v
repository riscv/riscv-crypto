
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
// module: tb_checker_ssm4
//
//  Checker module for the SSM4 instructions.
//  Always gives results in a single cycle.
//
module tb_checker_ssm4 (

input  wire [31:0]  rs1         , // Source register 1
input  wire [31:0]  rs2         , // Source register 2
input  wire [ 1:0]  bs          , // Byte select

input  wire         op_ssm4_ks  , // Do ssm4.ks instruction
input  wire         op_ssm4_ed  , // Do ssm4.ed instruction

output wire [31:0]  result      , // Writeback result

);

//
// Shared instruction logic
// ------------------------------------------------------------

wire [31:0] rs2_shifted = rs2 >> (8*bs);
wire [ 7:0] rs2_byte    = rs2_shifted[7:0];

wire [ 7:0] sbox_out    ;
wire [31:0] t1          = {24'b0, sbox_out};

//
// KS instruction
// ------------------------------------------------------------

wire [31:0] ks_tmp      =     t1                    ^ 
                            ((t1 & 32'h07) << 29)   ^
                            ((t1 & 32'hFE) <<  7)   ^
                            ((t1 & 32'h01) << 23)   ^
                            ((t1 & 32'hF8) << 13)   ;

wire [31:0] ks_rot      = (ks_tmp << (   8*bs))     |
                          (ks_tmp >> (32-8*bs))     ;

wire [31:0] ks_result   =  ks_rot ^ rs1             ;

//
// ED instruction
// ------------------------------------------------------------

wire [31:0] ed_tmp      =     t1                    ^ 
                            ( t1           <<  8)   ^
                            ( t1           <<  2)   ^
                            ( t1           << 18)   ^
                            ((t1 & 32'h3F) << 26)   ^
                            ((t1 & 32'hC0) << 10)   ;

wire [31:0] ed_rot      = (ed_tmp << (   8*bs))     |
                          (ed_tmp >> (32-8*bs))     ;

wire [31:0] ed_result   =  ed_rot ^ rs1             ;

//
// Result select
// ------------------------------------------------------------

assign result =
    {32{op_ssm4_ks}} & ks_result    |
    {32{op_ssm4_ed}} & ed_result    ;

//
// SBox instance
// ------------------------------------------------------------

riscv_crypto_sm4_sbox i_sbox (
    .in (rs2_byte),
    .out(sbox_out)
);


endmodule
