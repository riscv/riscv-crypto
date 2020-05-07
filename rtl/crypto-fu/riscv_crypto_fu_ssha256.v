
//
// module: riscv_crypto_fu_ssha256
//
//  Implements the ssha256 instructions for the RISC-V cryptography extension.
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN.
//
//  Instruction     | XLEN=32 | XLEN=64 
//  ----------------|---------|---------
//   ssha256.sig0   |   x     |    x
//   ssha256.sig1   |   x     |    x
//   ssha256.sum0   |   x     |    x
//   ssha256.sum1   |   x     |    x
//
module riscv_crypto_fu_ssha256 #(
parameter XLEN          = 64  // Must be one of: 32, 64.
)(

input  wire             g_clk           , // Global clock
input  wire             g_resetn        , // Synchronous active low reset.

input  wire             valid           , // Inputs valid.
input  wire [     31:0] rs1             , // Source register 1. Low 32 bits.

input  wire             op_ssha256_sig0 , //      SHA256 Sigma 0
input  wire             op_ssha256_sig1 , //      SHA256 Sigma 1
input  wire             op_ssha256_sum0 , //      SHA256 Sum 0
input  wire             op_ssha256_sum1 , //      SHA256 Sum 1

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
`define SRL32(a,b) ((a >> b)              )

//
// Instruction logic
// ------------------------------------------------------------

// Single cycle instructions.
assign ready = valid;

wire [31:0] ssha256_sig0 = `ROR32(rs1, 7) ^ `ROR32(rs1,18) ^ `SRL32(rs1, 3);

wire [31:0] ssha256_sig1 = `ROR32(rs1,17) ^ `ROR32(rs1,19) ^ `SRL32(rs1,10);

wire [31:0] ssha256_sum0 = `ROR32(rs1, 2) ^ `ROR32(rs1,13) ^ `ROR32(rs1,22);

wire [31:0] ssha256_sum1 = `ROR32(rs1, 6) ^ `ROR32(rs1,11) ^ `ROR32(rs1,25);

wire [31:0] ssha256_low32=
    {32{op_ssha256_sig0}} & ssha256_sig0    |
    {32{op_ssha256_sig1}} & ssha256_sig1    |
    {32{op_ssha256_sum0}} & ssha256_sum0    |
    {32{op_ssha256_sum1}} & ssha256_sum1    ;

if(RV64) begin
    
    // Zero extend 32-bit result
    assign rd = {32'b0, ssha256_low32};

end else begin
    
    assign rd = {       ssha256_low32};

end

//
// Clean up macro definitions
// ------------------------------------------------------------

`undef ROR32
`undef SRL32

endmodule
