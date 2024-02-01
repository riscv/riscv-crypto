
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
// module: riscv_crypto_fu_saes32_sm4
//
//  Implements the scalar 32-bit AES and SM4 instructions for the RISC-V
//  cryptography extension
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN, and the feature enable
//  parameter name(s).
//
//  Instruction     | XLEN=32 | Feature Parameter 
//  ----------------|---------|----------------------------------
//   saes32.encs    |   x     | SAES_EN
//   saes32.encsm   |   x     | SAES_EN     
//   saes32.decs    |   x     | SAES_DEC_EN     
//   saes32.decsm   |   x     | SAES_DEC_EN     
//   ssm4.ks        |   x     | 
//   ssm4.ed        |   x     | 
//
module riscv_crypto_fu_saes32_ssm4 #(
parameter SAES_DEC_EN = 1            // Enable saes32 decrypt instructions.
)(

input  wire         valid          , // Are the inputs valid?
input  wire [ 31:0] rs1            , // Source register 1
input  wire [ 31:0] rs2            , // Source register 2
input  wire [  1:0] bs             , // Byte select immediate

input  wire         op_saes32_encs , // Encrypt SubBytes
input  wire         op_saes32_encsm, // Encrypt SubBytes + MixColumn
input  wire         op_saes32_decs , // Decrypt SubBytes
input  wire         op_saes32_decsm, // Decrypt SubBytes + MixColumn
input  wire         op_ssm4_ks     , // Do ssm4.ks instruction
input  wire         op_ssm4_ed     , // Do ssm4.ed instruction

output wire [ 31:0] rd             , // output destination register value.
output wire         ready            // Compute finished?

);

wire sel_aes = op_saes32_encs || op_saes32_encsm ||
               op_saes32_decs || op_saes32_decsm ;

wire sel_sm4 = op_ssm4_ks     || op_ssm4_ed      ;

assign ready = valid;

//
// SBox byte select
// ------------------------------------------------------------

wire [7:0] in_bytes [3:0];

assign in_bytes[0]  = rs2[ 7: 0];
assign in_bytes[1]  = rs2[15: 8];
assign in_bytes[2]  = rs2[23:16];
assign in_bytes[3]  = rs2[31:24];

// SBox inverse only relevant for AES. SM4 has only forward SBox.
wire        sbox_dec= SAES_DEC_EN ? op_saes32_decs || op_saes32_decsm   :
                                    1'b0                                ;

wire [ 7:0] sbox_in = in_bytes[bs];
wire [ 7:0] sbox_out;

wire [31:0] l       = {24'b0, sbox_out};

//
// AES Instructions
// ------------------------------------------------------------

wire        dec         = op_saes32_decsm || op_saes32_decs   ;
wire        mix         = op_saes32_decsm || op_saes32_encsm  ;

//
// Multiply by 2 in GF(2^8) modulo 8'h1b
function [7:0] xtime2;
    input [7:0] a;

    xtime2  = {a[6:0],1'b0} ^ (a[7] ? 8'h1b : 8'b0 );

endfunction

//
// Paired down multiply by X in GF(2^8)
function [7:0] xtimeN;
    input[7:0] a;
    input[3:0] b;

    xtimeN = 
        (b[0] ?                         a   : 0) ^
        (b[1] ? xtime2(                 a)  : 0) ^
        (b[2] ? xtime2(xtime2(          a)) : 0) ^
        (b[3] ? xtime2(xtime2(xtime2(   a))): 0) ;

endfunction

wire [ 7:0] mix_b3 =       xtimeN(sbox_out, (dec ? 11  : 3))            ;
wire [ 7:0] mix_b2 = dec ? xtimeN(sbox_out, (           13)) : sbox_out ;
wire [ 7:0] mix_b1 = dec ? xtimeN(sbox_out, (            9)) : sbox_out ;
wire [ 7:0] mix_b0 =       xtimeN(sbox_out, (dec ? 14  : 2))            ;

wire [31:0] saes_mixed  = {mix_b3, mix_b2, mix_b1, mix_b0};

wire [31:0] saes_result = mix ? saes_mixed : {24'b0, sbox_out};

//
// SM4 Instructions
// ------------------------------------------------------------

wire [31:0] sm4_ed  =   l                  ^  
                      ( l           <<  8) ^ 
                      ( l           <<  2) ^
                      ( l           << 18) ^
                      ((l & 32'h3F) << 26) ^
                      ((l & 32'hC0) << 10) ;

wire [31:0] sm4_ks  =   l                  ^
                      ((l & 32'h07) << 29) ^
                      ((l & 32'hFE) <<  7) ^
                      ((l & 32'h01) << 23) ^
                      ((l & 32'hF8) << 13) ;

//
// Select, rotate and XOR
// ------------------------------------------------------------

wire [31:0] rot_in = sel_aes    ? saes_result   :
                     op_ssm4_ks ? sm4_ks        :
                                  sm4_ed        ;

wire [31:0] rot_out=
    {32{bs == 2'b00}} & {rot_in                      } |
    {32{bs == 2'b01}} & {rot_in[23:0], rot_in[31:24] } |
    {32{bs == 2'b10}} & {rot_in[15:0], rot_in[31:16] } |
    {32{bs == 2'b11}} & {rot_in[ 7:0], rot_in[31: 8] } ;

assign      rd      = rot_out ^ rs1;

//
// SBox instance
// ------------------------------------------------------------

riscv_crypto_aes_sm4_sbox i_riscv_crypto_aes_sm4_sbox(
.aes(sel_aes    ), // Perform AES SBox
.sm4(sel_sm4    ), // Perform SM4 SBox
.dec(sbox_dec   ), // Decrypt (AES Only)
.in (sbox_in    ), // Input byte
.out(sbox_out   )  // Output byte
);


endmodule
