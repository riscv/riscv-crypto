
//
// AES proposal: Variant 1
//
//  Optimised to execute in a minimum number of cycles: 1.
//  Instances four separate SBoxes.
//
module aes_v1 (
input   wire        g_clk   ,
input   wire        g_resetn,
input   wire        valid   , // Input data valid
input   wire        dec     , // Encrypt (0) or decrypt (1)
input   wire [31:0] rs1     , // Input source register

output  wire        ready   , // Finished computing?
output  wire [31:0] rd        // Output destination register value.
);

wire [7:0] rs1_0, rs1_1, rs1_2, rs1_3;
wire [7:0] rd_0 , rd_1 , rd_2 , rd_3 ;

assign ready                        = valid;

assign {rs1_3, rs1_2, rs1_1, rs1_0} = rs1;

assign rd = {rd_3, rd_2, rd_1, rd_0};

aes_sbox i_aes_sbox_0(.in (rs1_0), .inv(dec  ), .out( rd_0) );
aes_sbox i_aes_sbox_1(.in (rs1_1), .inv(dec  ), .out( rd_1) );
aes_sbox i_aes_sbox_2(.in (rs1_2), .inv(dec  ), .out( rd_2) );
aes_sbox i_aes_sbox_3(.in (rs1_3), .inv(dec  ), .out( rd_3) );

endmodule
