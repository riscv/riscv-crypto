
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
// module: tb_checker_lut4_rv32
//
//  Re-usable checker for the 32-bit lut4 instructions
//
module tb_checker_lut4_rv32 (

input  wire [31:0] rs1,
input  wire [31:0] rs2,
input  wire        hi ,

output wire [31:0] rd

);

// Calculate the lut.
wire [3:0] lut [7:0];

genvar i;
generate for(i = 0; i < 8; i = i + 1) begin
    assign lut[i] = rs2[4*i+:4];
end endgenerate

// Calculate the nibble values for the output
assign rd[4*0+:4] = hi ^ rs1[4*0+3] ? 4'b0000 : lut[rs1[4*0+:3]];
assign rd[4*1+:4] = hi ^ rs1[4*1+3] ? 4'b0000 : lut[rs1[4*1+:3]];
assign rd[4*2+:4] = hi ^ rs1[4*2+3] ? 4'b0000 : lut[rs1[4*2+:3]];
assign rd[4*3+:4] = hi ^ rs1[4*3+3] ? 4'b0000 : lut[rs1[4*3+:3]];
assign rd[4*4+:4] = hi ^ rs1[4*4+3] ? 4'b0000 : lut[rs1[4*4+:3]];
assign rd[4*5+:4] = hi ^ rs1[4*5+3] ? 4'b0000 : lut[rs1[4*5+:3]];
assign rd[4*6+:4] = hi ^ rs1[4*6+3] ? 4'b0000 : lut[rs1[4*6+:3]];
assign rd[4*7+:4] = hi ^ rs1[4*7+3] ? 4'b0000 : lut[rs1[4*7+:3]];

endmodule
