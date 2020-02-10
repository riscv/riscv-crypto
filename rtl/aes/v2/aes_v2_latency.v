
//
// module: aes_v2
//
//  Latency (clock cycles) optimised.
//
module aes_v2 (

input  wire        g_clk    ,
input  wire        g_resetn ,

input  wire        valid    , // Are the inputs valid?
input  wire        sub      , // Sub if set, Mix if clear
input  wire        enc      , // Perform encrypt (set) or decrypt (clear).
input  wire [31:0] rs1      , // Input source register 1
input  wire [31:0] rs2      , // Input source register 2
output wire        ready    , // Is the instruction complete?
output wire [31:0] rd         // 

);

// Single cycle implementation
assign ready = valid;

//
// SBox Instruction
// ------------------------------------------------------------

// Output of SBox Computation
wire [31:0] sb_out;

aes_sbox i_aes_sbox_0(.in (rs1[ 7: 0]), .inv(!enc), .out(sb_out[ 7: 0]) );
aes_sbox i_aes_sbox_1(.in (rs2[15: 8]), .inv(!enc), .out(sb_out[15: 8]) );
aes_sbox i_aes_sbox_2(.in (rs1[23:16]), .inv(!enc), .out(sb_out[23:16]) );
aes_sbox i_aes_sbox_3(.in (rs2[31:24]), .inv(!enc), .out(sb_out[31:24]) );

//
// Mix Instruction
// ------------------------------------------------------------

//
// Multiply by 2 in GF(2^8) modulo 8'h1b
function [7:0] xt2;
    input [7:0] a;
    xt2 = (a << 1) ^ (a[7] ? 8'h1b : 8'b0) ;
endfunction

//
// Paired down multiply by X in GF(2^8)
function [7:0] xtN;
    input[7:0] a;
    input[3:0] b;
    xtN = (b[0] ?             a   : 0) ^
          (b[1] ? xt2(        a)  : 0) ^
          (b[2] ? xt2(xt2(    a)) : 0) ^
          (b[3] ? xt2(xt2(xt2(a))): 0) ;
endfunction

//
// Performs the mix column transformation on a single word.
function [7:0] mixcolumn_enc;
    input [7:0] b0, b1, b2, b3;
    mixcolumn_enc = xt2(b0) ^ (xt2(b1) ^ b1) ^ b2 ^ b3;
endfunction

//
// Performs the mix column transformation on a single word.
function [7:0] mixcolumn_dec;
    input [7:0] b0, b1, b2, b3;
    mixcolumn_dec = xtN(b0,4'he) ^ xtN(b1,4'hb) ^ xtN(b2,4'hd) ^ xtN(b3,4'h9);
endfunction

//
// Mix operation input selection
wire [ 7:0] mix_0    = rs1[ 7: 0];
wire [ 7:0] mix_1    = rs2[15: 8];
wire [ 7:0] mix_2    = rs1[23:16];
wire [ 7:0] mix_3    = rs2[31:24];

//
// Mix instruction - encrypt.
wire [ 7:0] mix_enc_0   = mixcolumn_enc(mix_0, mix_1, mix_2, mix_3);
wire [ 7:0] mix_enc_1   = mixcolumn_enc(mix_1, mix_2, mix_0, mix_3);
wire [ 7:0] mix_enc_2   = mixcolumn_enc(mix_2, mix_3, mix_0, mix_1);
wire [ 7:0] mix_enc_3   = mixcolumn_enc(mix_3, mix_0, mix_1, mix_2);

wire [31:0] mix_enc     = {mix_enc_3, mix_enc_2, mix_enc_1, mix_enc_0};

//
// Mix instruction - decrypt.
wire [ 7:0] mix_dec_0   = mixcolumn_dec(mix_0, mix_1, mix_2, mix_3);
wire [ 7:0] mix_dec_1   = mixcolumn_dec(mix_1, mix_2, mix_0, mix_3);
wire [ 7:0] mix_dec_2   = mixcolumn_dec(mix_2, mix_3, mix_0, mix_1);
wire [ 7:0] mix_dec_3   = mixcolumn_dec(mix_3, mix_0, mix_1, mix_2);

wire [31:0] mix_dec     = {mix_dec_3, mix_dec_2, mix_dec_1, mix_dec_0};

//
// Mix instruction - result

wire [31:0] mix_result  = enc ? mix_enc : mix_dec;

//
// Result Selection
// ------------------------------------------------------------

assign rd = sub ? sb_out : mix_result;

endmodule
