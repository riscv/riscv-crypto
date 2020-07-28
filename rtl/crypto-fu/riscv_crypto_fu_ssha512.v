
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
// module: riscv_crypto_fu_ssha512
//
//  Implements the ssha512 instructions for the RISC-V cryptography extension.
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN.
//
//  Instruction     | XLEN=32 | XLEN=64 
//  ----------------|---------|---------
//   ssha512.sum0r  |   x     |
//   ssha512.sum1r  |   x     |
//   ssha512.sig0l  |   x     |
//   ssha512.sig0h  |   x     |
//   ssha512.sig1l  |   x     |
//   ssha512.sig1h  |   x     |
//   ssha512.sig0   |         |    x
//   ssha512.sig1   |         |    x
//   ssha512.sum0   |         |    x
//   ssha512.sum1   |         |    x
//
module riscv_crypto_fu_ssha512 #(
parameter XLEN          = 64  // Must be one of: 32, 64.
)(

input  wire             g_clk           , // Global clock
input  wire             g_resetn        , // Synchronous active low reset.

input  wire             valid           , // Inputs valid.
input  wire [ XLEN-1:0] rs1             , // Source register 1.
input  wire [ XLEN-1:0] rs2             , // Source register 1.

input  wire             op_ssha512_sum0r, // RV32 SHA512 Sum 0
input  wire             op_ssha512_sum1r, // RV32 SHA512 Sum 1
input  wire             op_ssha512_sig0l, // RV32 SHA512 Sigma 0 low
input  wire             op_ssha512_sig0h, // RV32 SHA512 Sigma 0 high
input  wire             op_ssha512_sig1l, // RV32 SHA512 Sigma 1 low
input  wire             op_ssha512_sig1h, // RV32 SHA512 Sigma 1 high
input  wire             op_ssha512_sig0 , // RV64 SHA512 Sigma 0
input  wire             op_ssha512_sig1 , // RV64 SHA512 Sigma 1
input  wire             op_ssha512_sum0 , // RV64 SHA512 Sum 0
input  wire             op_ssha512_sum1 , // RV64 SHA512 Sum 1

output wire             ready           , // Outputs ready.
output wire [ XLEN-1:0] rd                // Result.

);

//
// Local/internal parameters and useful defines:
// ------------------------------------------------------------

localparam XL   = XLEN -  1  ;
localparam RV32 = XLEN == 32 ;
localparam RV64 = XLEN == 64 ;

`define ROR32(a,b) ((a >> b) | (a << 32-b))
`define ROR64(a,b) ((a >> b) | (a << 64-b))
`define SRL32(a,b) ((a >> b)              )
`define SLL32(a,b) ((a << b)              )
`define SRL64(a,b) ((a >> b)              )

//
// Instruction logic
// ------------------------------------------------------------

// Single cycle instructions.
assign ready = valid;

if(RV64) begin  : rv64_ssha512

    wire [XL:0] ssha512_sig0 = `ROR64(rs1, 1) ^ `ROR64(rs1, 8) ^`SRL64(rs1, 7);

    wire [XL:0] ssha512_sig1 = `ROR64(rs1,19) ^ `ROR64(rs1,61) ^`SRL64(rs1, 6);

    wire [XL:0] ssha512_sum0 = `ROR64(rs1,28) ^ `ROR64(rs1,34) ^`ROR64(rs1,39);

    wire [XL:0] ssha512_sum1 = `ROR64(rs1,14) ^ `ROR64(rs1,18) ^`ROR64(rs1,41);

    assign rd =
        {XLEN{op_ssha512_sig0}} & ssha512_sig0    |
        {XLEN{op_ssha512_sig1}} & ssha512_sig1    |
        {XLEN{op_ssha512_sum0}} & ssha512_sum0    |
        {XLEN{op_ssha512_sum1}} & ssha512_sum1    ;

end else begin  : rv32_ssha512

    wire [XL:0] ssha512_sum0r = `SLL32(rs1,25)^`SLL32(rs1,30)^`SRL32(rs1,28)^
                                `SLL32(rs2, 7)^`SLL32(rs2, 2)^`SLL32(rs2, 4);
    
    wire [XL:0] ssha512_sum1r = `SLL32(rs1,23)^`SLL32(rs1,14)^`SRL32(rs1,18)^
                                `SLL32(rs2, 9)^`SLL32(rs2,18)^`SLL32(rs2,14);
    
    wire [XL:0] ssha512_sig0l = `SRL32(rs1, 1)^`SRL32(rs1, 7)^`SRL32(rs1, 8)^
                                `SLL32(rs2,31)^`SLL32(rs2,25)^`SLL32(rs2,24);
    
    wire [XL:0] ssha512_sig0h = `SRL32(rs1, 1)^`SRL32(rs1, 7)^`SRL32(rs1, 8)^
                                `SLL32(rs2,31)               ^`SLL32(rs2,24);
    
    wire [XL:0] ssha512_sig1l = `SRL32(rs1, 3)^`SRL32(rs1, 6)^`SRL32(rs1,19)^
                                `SLL32(rs2,29)^`SLL32(rs2,26)^`SLL32(rs2,13);
    
    wire [XL:0] ssha512_sig1h = `SRL32(rs1, 3)^`SRL32(rs1, 6)^`SRL32(rs1,19)^
                                `SLL32(rs2,29)               ^`SLL32(rs2,13);

    assign rd =
        {XLEN{op_ssha512_sig0l}} & ssha512_sig0l   |
        {XLEN{op_ssha512_sig0h}} & ssha512_sig0h   |
        {XLEN{op_ssha512_sig1l}} & ssha512_sig1l   |
        {XLEN{op_ssha512_sig1h}} & ssha512_sig1h   |
        {XLEN{op_ssha512_sum0r}} & ssha512_sum0r   |
        {XLEN{op_ssha512_sum1r}} & ssha512_sum1r   ;

end

//
// Clean up macro definitions
// ------------------------------------------------------------

`undef ROR32
`undef SRL32
`undef SLL32
`undef ROR64
`undef SRL64

endmodule
