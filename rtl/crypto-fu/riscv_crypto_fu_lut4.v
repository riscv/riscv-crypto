
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
// module: riscv_crypto_fu_lut4
//
//  Implements the LUT4 instructions for the RISC-V cryptography extension.
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN.
//
//  Instruction     | XLEN=32 | XLEN=64 
//  ----------------|---------|---------
//   lut4lo         |   x     |         
//   lut4hi         |   x     |         
//   lut4           |         |    x    
//
module riscv_crypto_fu_lut4 #(
parameter XLEN          = 64  // Must be one of: 32, 64.
)(

input  wire             g_clk           , // Global clock
input  wire             g_resetn        , // Synchronous active low reset.

input  wire             valid           , // Inputs valid.
input  wire [ XLEN-1:0] rs1             , // Source register 1
input  wire [ XLEN-1:0] rs2             , // Source register 2

input  wire             op_lut4lo       , // RV32 lut4-lo instruction
input  wire             op_lut4hi       , // RV32 lut4-hi instruction
input  wire             op_lut4         , // RV64 lut4    instruction

output wire             ready           , // Outputs ready.
output wire [ XLEN-1:0] rd                // Result.

);


//
// Local/internal parameters and useful defines:
// ------------------------------------------------------------

localparam XL   = XLEN -  1  ;
localparam RV32 = XLEN == 32 ;
localparam RV64 = XLEN == 64 ;

localparam NIBBLES = XLEN / 4;

//
// Instruction logic
// ------------------------------------------------------------

// Single cycle instructions.
assign ready = valid;

// Easily indexable access to the LUT.
wire [3:0] lut4_lut [NIBBLES-1:0];

// Unpack the LUT from RS2. Works for RV32 and RV64.
genvar n;
for(n = 0; n < NIBBLES; n = n + 1) begin
    
    // Pull out each nibble of rs2.
    assign lut4_lut[n] = rs2[4*n+:4];

    if         (RV32) begin : rv32_lut4      // RV32 LUT4

        wire [2:0] lut_in  = rs1[4*n+:3];
        
        wire       lut_hi  = rs1[4*n +3];
        
        wire       sel_hi  = lut_hi ^ op_lut4hi;

        wire [3:0] lut_out = lut4_lut[lut_in];

        assign rd[n*4+:4]  = sel_hi ? 4'b0000 : lut_out;

    end else if(RV64) begin : rv64_lut4      // RV64 LUT4
        
        wire [3:0] lut_in  = rs1[4*n+:4];
        
        assign rd[n*4+:4]  = lut4_lut[lut_in];

    end

end

endmodule
