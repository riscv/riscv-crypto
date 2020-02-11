
//
// AES instruction V3 proposals, subset 1
//
//  Implements: 
//      - saes.v3.encs  : dec=0, mix=0
//      - saes.v3.encsm : dec=0, mix=1
//      - saes.v3.decs  : dec=1, mix=0
//      - saes.v3.decsm : dec=1, mix=1
//
//  More performant in terms of instructions / round, but puts the MixColumns
//  and SubBytes operations in sequence, leading to a longer timing path.
//
module aes_v3_1 (

input  wire         valid   , // Are the inputs valid? Used for logic gating.
input  wire         dec     , // Encrypt (clear) or decrypt (set)
input  wire         mix     , // Perform MixColumn transformation (if set)

input  wire [ 31:0] rs1     , // Source register 1
input  wire [ 31:0] rs2     , // Source register 2
input  wire [  1:0] bs      , // Byte select immediate

output wire [ 31:0] rd      , // output destination register value.
output wire         ready     // Compute finished?

);

wire [7:0] bytes_in [3:0]   ;

// Always finish in a single cycle.
assign     ready            = valid                     ;

assign     bytes_in [  0]   =  rs1[ 7: 0]               ;
assign     bytes_in [  1]   =  rs1[15: 8]               ;
assign     bytes_in [  2]   =  rs1[23:16]               ;
assign     bytes_in [  3]   =  rs1[31:24]               ;

wire [7:0] sel_byte         = bytes_in[bs]              ;

wire       sbox_inv         = dec                       ;
wire [7:0] sbox_out         ;

//
// Multiply by 2 in GF(2^8) modulo 8'h1b
function [7:0] xtime2;
    input [7:0] a;

    xtime2  = {a[6:0],1'b0} ^ (a[7] ? 8'h1b : 8'b0 );

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

wire [ 7:0] mix_b3 =       xtimeN(sbox_out, (dec ? 11  : 3))            ;
wire [ 7:0] mix_b2 = dec ? xtimeN(sbox_out, (           13)) : sbox_out ;
wire [ 7:0] mix_b1 = dec ? xtimeN(sbox_out, (            9)) : sbox_out ;
wire [ 7:0] mix_b0 =       xtimeN(sbox_out, (dec ? 14  : 2))            ;

wire [31:0] result_mix  = {mix_b3, mix_b2, mix_b1, mix_b0};

wire [31:0] result      = mix ? result_mix : {24'b0, sbox_out};

wire [31:0] rotated     =
    {32{bs == 2'b00}} & {result                      } |
    {32{bs == 2'b01}} & {result[23:0], result[31:24] } |
    {32{bs == 2'b10}} & {result[15:0], result[31:16] } |
    {32{bs == 2'b11}} & {result[ 7:0], result[31: 8] } ;

assign      rd          = rotated ^ rs2;

//
// Single SBOX instance
aes_sbox i_aes_sbox (
.inv(sbox_inv),
.in (sel_byte),
.out(sbox_out)
);

endmodule

