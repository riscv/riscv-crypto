
//
// module: ssha256
//
//  Implements the light-weight SHA256 instruction functions.
//
module ssha256 (

input  wire [31:0] rs1   , // Input source register 1
input  wire [ 1:0] ss    , // Exactly which transformation to perform?

output wire [31:0] result  // 

);

`define ROR32(a,b) ((a >> b) | (a << 32-b))
`define SRL32(a,b) ((a >> b)              )

//
// Which transformation to perform?
wire s0 = ss == 2'b00;
wire s1 = ss == 2'b01;
wire s2 = ss == 2'b10;
wire s3 = ss == 2'b11;

wire [31:0] s0_result = `ROR32(rs1, 7) ^ `ROR32(rs1,18) ^ `SRL32(rs1, 3) ;

wire [31:0] s1_result = `ROR32(rs1,17) ^ `ROR32(rs1,19) ^ `SRL32(rs1,10) ;

wire [31:0] s2_result = `ROR32(rs1, 2) ^ `ROR32(rs1,13) ^ `ROR32(rs1,22) ;

wire [31:0] s3_result = `ROR32(rs1, 6) ^ `ROR32(rs1,11) ^ `ROR32(rs1,25) ;

assign result =
    {32{s0}} & s0_result |
    {32{s1}} & s1_result |
    {32{s2}} & s2_result |
    {32{s3}} & s3_result ;

`undef ROR32
`undef SRL32

endmodule

