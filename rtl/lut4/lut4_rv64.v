
module lut4_rv64 (

input  wire [63:0] rs1,
input  wire [63:0] rs2,

output wire [63:0] rd

);

localparam XLEN     = 64;
localparam NIBBLES  = XLEN / 4;

wire [3:0] lut [NIBBLES-1:0];

genvar i;
generate for(i = 0; i < NIBBLES; i = i + 1) begin

    assign lut[i] = rs2[4*i+:4];

    assign rd[4*i+:4] = lut[rs1[4*i+:4]];

end endgenerate

endmodule
