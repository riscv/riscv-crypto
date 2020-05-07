
//
// module: riscv_crypto_fu_ssm3
//
//  Implements the ssm3 instructions for the RISC-V cryptography extension.
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN.
//
//  Instruction     | XLEN=32 | XLEN=64 
//  ----------------|---------|---------
//   ssm3.p0        |   x     |    x
//   ssm3.p1        |   x     |    x
//
module riscv_crypto_fu_ssm3 #(
parameter XLEN          = 64  // Must be one of: 32, 64.
)(

input  wire             g_clk           , // Global clock
input  wire             g_resetn        , // Synchronous active low reset.

input  wire             valid           , // Inputs valid.
input  wire [     31:0] rs1             , // Source register 1. Low 32 bits.

input  wire             op_ssm3_p0      , //      SSM3 P0
input  wire             op_ssm3_p1      , //      SSM3 P1

output wire             ready           , // Outputs ready.
output wire [ XLEN-1:0] rd                // Result.

);


//
// Local/internal parameters and useful defines:
// ------------------------------------------------------------

localparam XL   = XLEN -  1  ;
localparam RV32 = XLEN == 32 ;
localparam RV64 = XLEN == 64 ;

`define ROL32(a,b) ((a << b) | (a >> 32-b))

//
// Instruction logic
// ------------------------------------------------------------

// Single cycle instructions.
assign      ready       = valid;

wire [31:0] ssm3_p0     = rs1 ^ `ROL32(rs1,  9) ^ `ROL32(rs1,17);

wire [31:0] ssm3_p1     = rs1 ^ `ROL32(rs1, 15) ^ `ROL32(rs1,23);

wire [31:0] ssm3_low32  =
    {32{op_ssm3_p0}} & ssm3_p0    |
    {32{op_ssm3_p1}} & ssm3_p1    ;

if(RV64) begin
    
    // Zero extend 32-bit result
    assign rd = {32'b0, ssm3_low32};

end else begin
    
    assign rd = {       ssm3_low32};

end

//
// Clean up macro definitions
// ------------------------------------------------------------

`undef ROL32

endmodule

