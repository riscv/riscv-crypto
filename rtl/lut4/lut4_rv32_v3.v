
// 
// for i in 0..8
//     idx     = rs1.4[i] & 0b0111
//     idx_hi  = rs1.4[i] & 0b1000
//     sel_zero= hi && !idx_hi || !hi && idx_hi
//     rd.4[i] = sel_zero ? 4'b0000 : rs2.4[idx]
// 
module lut4_rv32_v3 (

input  wire [31:0] rs1,
input  wire [31:0] rs2,
input  wire        hi ,

output wire [31:0] rd

);

localparam XLEN     = 32;
localparam NIBBLES  = XLEN / 4;
localparam PAIRS    = XLEN / 2;

wire [3:0] lut [NIBBLES-1:0];

genvar i;
generate for(i = 0; i < NIBBLES; i = i + 1) begin

    assign lut[i] = rs2[4*i+:4];

end endgenerate

genvar j;
generate for(j = 0; j < NIBBLES; j = j + 1) begin
    
    assign rd[j*4+:4] = hi ^ rs1[j*4+3] ? 4'b0000 : lut[rs1[j*4+:3]];

end endgenerate

endmodule
