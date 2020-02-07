
//
// module: aes_v2_sub_latency
//
//  Implements the lightweight AES SubBytes instructions.
//  Optimised for low latency. Instances 4 sboxes. No register stages.
//
module aes_v2_sub_latency (

input  wire        g_clk    ,
input  wire        g_resetn ,

input  wire        valid    , // Are the inputs valid?
input  wire [31:0] rs1      , // Input source register 1
input  wire [31:0] rs2      , // Input source register 2
input  wire        enc      , // Perform encrypt (set) or decrypt (clear).
input  wire        rot      , // Perform encrypt (set) or decrypt (clear).
output wire        ready    , // Is the instruction complete?
output wire [31:0] rd         // 

);

// Single cycle implementation.
assign ready = valid;

wire [7:0] sb_in_0 = rs1[ 7: 0];
wire [7:0] sb_in_1 = rs2[15: 8];
wire [7:0] sb_in_2 = rs1[23:16];
wire [7:0] sb_in_3 = rs2[31:24];

wire [7:0] sb_out_0;
wire [7:0] sb_out_1;
wire [7:0] sb_out_2;
wire [7:0] sb_out_3;

assign rd     = rot ? {sb_out_2, sb_out_1, sb_out_0, sb_out_3} :
                      {sb_out_3, sb_out_2, sb_out_1, sb_out_0} ;

aes_sbox sbox_0(
.in  (sb_in_0 ), // Input byte
.inv (!enc    ), // Perform inverse (set) or forward lookup
.out (sb_out_0)  // Output byte
);

aes_sbox sbox_1(
.in  (sb_in_1 ), // Input byte
.inv (!enc    ), // Perform inverse (set) or forward lookup
.out (sb_out_1)  // Output byte
);

aes_sbox sbox_2(
.in  (sb_in_2 ), // Input byte
.inv (!enc    ), // Perform inverse (set) or forward lookup
.out (sb_out_2)  // Output byte
);

aes_sbox sbox_3(
.in  (sb_in_3 ), // Input byte
.inv (!enc    ), // Perform inverse (set) or forward lookup
.out (sb_out_3)  // Output byte
);

endmodule

