
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
// module: tb_checker_lut4_rv64
//
//  Re-usable checker for the 64-bit lut4 instructions
//
module tb_checker_lut4_rv64 (

input  wire [63:0] rs1,
input  wire [63:0] rs2,

output wire [63:0] rd

);


wire[3:0] lut4_rv64_lut [15:0];

genvar i;

for(i=0; i < (64/4); i=i+1) begin
    assign lut4_rv64_lut[  i   ] =               rs2[4*i+:4] ;
    assign rd           [4*i+:4] = lut4_rv64_lut[rs1[4*i+:4]];
end

endmodule
