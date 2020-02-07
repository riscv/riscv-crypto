
//
// module: aes_v2_mix_latency
//
//  Implements the lightweight AES MixColumns instructions.
//
module aes_v2_mix_latency (

input  wire        g_clk ,
input  wire        g_resetn,

input  wire        valid , // Are the inputs valid?
input  wire [31:0] rs1   , // Input source register 1
input  wire [31:0] rs2   , // Input source register 2
input  wire        enc   , // Perform encrypt (set) or decrypt (clear).
output wire        ready , // Is the instruction complete?
output wire [31:0] rd  // 

);

//
// Multiply by 2 in GF(2^8) modulo 8'h1b
function [7:0] xtime2;
    input [7:0] a;

    xtime2  =|((a >> 7) & 8'b1) ? (a << 1) ^ 8'h1b :
                                 (a << 1)         ;
endfunction

//
// Multiply by 3 in GF(2^8)
function [7:0] xtime3;
    input [7:0] a;

    xtime3 = xtime2(a) ^ a;

endfunction

//
// Paired down multiply by X in GF(2^8)
function [7:0] xtimeN;
    input[7:0] a;
    input[3:0] b;

    xtimeN = 
        (b[0] ?                         a   : 0) ^
        (b[1] ? xtime2(                 a)  : 0) ^
        (b[2] ? xtime2(xtime2(          a)) : 0) ^
        (b[3] ? xtime2(xtime2(xtime2(   a))): 0) ;

endfunction

//
// Encrypt inputs
wire [7:0] e0 = rs1[ 7: 0];
wire [7:0] e1 = rs1[15: 8];
wire [7:0] e2 = rs2[23:16];
wire [7:0] e3 = rs2[31:24];

//
// Decrypt inputs
wire [7:0] d0 = rs1[ 7: 0];
wire [7:0] d1 = rs1[15: 8];
wire [7:0] d2 = rs2[23:16];
wire [7:0] d3 = rs2[31:24];

wire [31:0] result_enc;
wire [31:0] result_dec;

//
// Single Cycle Implementation
// ------------------------------------------------------------

//
// Always complete in a single cycle.
assign ready = valid;

//
// Mix Encrypt instruction logic
wire [7:0] mix_enc_0 = xtime2(e0) ^ xtime3(e1) ^ e2 ^ e3;
wire [7:0] mix_enc_1 = xtime2(e1) ^ xtime3(e2) ^ e0 ^ e3;
wire [7:0] mix_enc_2 = xtime2(e2) ^ xtime3(e3) ^ e0 ^ e1;
wire [7:0] mix_enc_3 = xtime2(e3) ^ xtime3(e0) ^ e1 ^ e2;

assign result_enc = {mix_enc_3, mix_enc_2, mix_enc_1, mix_enc_0};

//
// Mix Decrypt instruction logic
wire [7:0] mix_dec_0 = xtimeN(d0,4'he)^xtimeN(d1,4'hb)^xtimeN(d2,4'hd)^xtimeN(d3,4'h9);
wire [7:0] mix_dec_1 = xtimeN(d0,4'h9)^xtimeN(d1,4'he)^xtimeN(d2,4'hb)^xtimeN(d3,4'hd);
wire [7:0] mix_dec_2 = xtimeN(d0,4'hd)^xtimeN(d1,4'h9)^xtimeN(d2,4'he)^xtimeN(d3,4'hb);
wire [7:0] mix_dec_3 = xtimeN(d0,4'hb)^xtimeN(d1,4'hd)^xtimeN(d2,4'h9)^xtimeN(d3,4'he);

assign result_dec = {mix_dec_3, mix_dec_2, mix_dec_1, mix_dec_0};


//
// Create the final result.
assign     rd = enc ? result_enc : result_dec;

endmodule




