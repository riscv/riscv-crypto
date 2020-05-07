
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
// AES instruction proposals: RV32
//
//  Models: 
//      - saes32.encs  : dec=0, mix=0
//      - saes32.encsm : dec=0, mix=1
//      - saes32.decs  : dec=1, mix=0
//      - saes32.decsm : dec=1, mix=1
//
module tb_checker_saes32 (

input  wire         valid   , // Are the inputs valid? Used for logic gating.
input  wire         op_encs , // Encrypt SubBytes
input  wire         op_encsm, // Encrypt SubBytes + MixColumn
input  wire         op_decs , // Decrypt SubBytes
input  wire         op_decsm, // Decrypt SubBytes + MixColumn

input  wire [ 31:0] rs1     , // Source register 1
input  wire [ 31:0] rs2     , // Source register 2
input  wire [  1:0] bs      , // Byte select immediate

output wire [ 31:0] rd      , // output destination register value.
output wire         ready     // Compute finished?

);

//
// Useful common stuff
`include "tb_checker_saes.vh"

//
// Constant assignments

assign ready        = valid                     ;

wire   dec          = op_decs  || op_decsm      ;
wire   mix          = op_encsm || op_decsm      ;

//
// SBOX signals for model
wire [ 7:0] sb_in   = bs == 2'b00 ? rs2[ 7: 0]  :
                      bs == 2'b01 ? rs2[15: 8]  :
                      bs == 2'b10 ? rs2[23:16]  :
                                    rs2[31:24]  ;

wire [ 7:0] sb_inv  = aes_sbox_inv(sb_in)       ;
wire [ 7:0] sb_fwd  = aes_sbox_fwd(sb_in)       ;
wire [ 7:0] sb_out  = dec ? sb_inv : sb_fwd     ;

//
// Mix columns outputs for model.

wire [31:0] mix_out_dec = 
    {xtN(sb_out,4'd11), xtN(sb_out,4'd13),xtN(sb_out,4'd9), xtN(sb_out,4'd14)};

wire [31:0] mix_out_enc = 
    {xtN(sb_out,4'd3 ),     sb_out       ,    sb_out      , xtN(sb_out,4'd2 )};

wire [31:0] mix_out     = dec  ? mix_out_dec : mix_out_enc;

//
// Final modelled output

wire [31:0] rot_in  =  mix ? mix_out : {24'b0, sb_out};

wire [31:0] rot_out = (rot_in << (8*bs)) | (rot_in >> (32-8*bs));

assign      rd      = rot_out ^ rs1;

endmodule

