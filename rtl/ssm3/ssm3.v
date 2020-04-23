
//
// module: ssm3
//
//  Implements the lightweight SM3 instructions
//
module ssm3 (

input  wire [31:0] rs1   , // Input source register 1
input  wire        p1    , // If set, do ssm3.p1 instruction, else ssm3.p0

output wire [31:0] result

);

`define ROL32(a,b) ((a << b) | (a >> 32-b))

wire [31:0] p0_result = rs1 ^ `ROL32(rs1,  9) ^ `ROL32(rs1,17);
wire [31:0] p1_result = rs1 ^ `ROL32(rs1, 15) ^ `ROL32(rs1,23);

assign result = p1 ? p1_result : p0_result;

endmodule
