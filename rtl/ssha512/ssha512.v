
//
// module: ssha512
//
//  Implements the light-weight SHA512 instruction functions.
//
module ssha512 (

input  wire [63:0] rs1   , // Input source register 1
input  wire [ 1:0] ss    , // Exactly which transformation to perform?

output wire [63:0] result  // 

);

`define ROR64(a,b) ((a >> b) | (a << 64-b))
`define SRL64(a,b) ((a >> b)              )

//
// Which transformation to perform?
wire s0 = ss == 2'b00;
wire s1 = ss == 2'b01;
wire s2 = ss == 2'b10;
wire s3 = ss == 2'b11;

wire [63:0] s0_result = `ROR64(rs1, 1) ^ `ROR64(rs1, 8) ^ `SRL64(rs1, 7) ;

wire [63:0] s1_result = `ROR64(rs1,19) ^ `ROR64(rs1,61) ^ `SRL64(rs1, 6) ;

wire [63:0] s2_result = `ROR64(rs1,28) ^ `ROR64(rs1,34) ^ `ROR64(rs1,39) ;

wire [63:0] s3_result = `ROR64(rs1,14) ^ `ROR64(rs1,18) ^ `ROR64(rs1,41) ;

assign result =
    {64{s0}} & s0_result |
    {64{s1}} & s1_result |
    {64{s2}} & s2_result |
    {64{s3}} & s3_result ;

`undef ROR64
`undef SRL64

endmodule

