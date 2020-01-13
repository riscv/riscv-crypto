
// 
// for i in 0..8
//     rd.4[i] = rs2.2[rs1.4[i]]
// 
module lut4_rv32_v1 (

input  wire [31:0] rs1,
input  wire [31:0] rs2,

output wire [31:0] rd

);

localparam XLEN     = 32;
localparam NIBBLES  = XLEN / 4;
localparam PAIRS    = XLEN / 2;

wire [1:0] lut [PAIRS-1:0];

genvar i;
generate for(i = 0; i < PAIRS; i = i + 1) begin

    assign lut[i] = rs2[2*i+:2];

end endgenerate

genvar j;
generate for(j = 0; j < NIBBLES; j = j + 1) begin

    wire [3:0] l_in   = rs1[4*j+:4];

    wire [1:0] l_out  = lut[l_in];

    assign rd[4*j+:4] = {2'b00,l_out};

end endgenerate

endmodule
