
//
// AES mix column byte module
//
// - Performs forward or Inverse MixColumn operation.
// - Outputs a single byte of the new column
//
module aes_mixcolumn_byte (
input   wire [31:0] col_in    ,
input   wire        dec       ,
output  wire [ 7:0] byte_out
);


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
    mixcolumn_enc = xtN(b0,4'd2) ^ xtN(b1,4'd3) ^ b2 ^ b3;
endfunction

//
// Performs the mix column transformation on a single word.
function [7:0] mixcolumn_dec;
    input [7:0] b0, b1, b2, b3;
    mixcolumn_dec = xtN(b0,4'he) ^ xtN(b1,4'hb) ^ xtN(b2,4'hd) ^ xtN(b3,4'h9);
endfunction

wire [7:0] b0 = col_in[ 7: 0];
wire [7:0] b1 = col_in[15: 8];
wire [7:0] b2 = col_in[23:16];
wire [7:0] b3 = col_in[31:24];

assign byte_out = dec ? mixcolumn_dec(b0, b1, b2, b3)   :
                        mixcolumn_enc(b0, b1, b2, b3)   ;

endmodule

//
// AES mix column module
//
// - Performs forward or Inverse MixColumn operation.
// - Outputs the entire new column.
//
module aes_mixcolumn (

input   wire [31:0] col_in    ,
input   wire        dec       ,
output  wire [31:0] col_out

);


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
    mixcolumn_enc = xtN(b0,4'd2) ^ xtN(b1,4'd3) ^ b2 ^ b3;
endfunction


//
// Performs the mix column transformation on a single word.
function [7:0] mixcolumn_dec;
    input [7:0] b0, b1, b2, b3;
    mixcolumn_dec = xtN(b0,4'he) ^ xtN(b1,4'hb) ^ xtN(b2,4'hd) ^ xtN(b3,4'h9);
endfunction

wire [7:0] b0 = col_in[ 7: 0];
wire [7:0] b1 = col_in[15: 8];
wire [7:0] b2 = col_in[23:16];
wire [7:0] b3 = col_in[31:24];

wire [31:0] col_enc = {
    mixcolumn_enc(b3, b0, b1, b2),
    mixcolumn_enc(b2, b3, b0, b1),
    mixcolumn_enc(b1, b2, b0, b3),
    mixcolumn_enc(b0, b1, b2, b3)
};

wire [31:0] col_dec = {
    mixcolumn_dec(b3, b0, b1, b2),
    mixcolumn_dec(b2, b3, b0, b1),
    mixcolumn_dec(b1, b2, b0, b3),
    mixcolumn_dec(b0, b1, b2, b3)
};

assign col_out = dec ? col_dec : col_enc;

endmodule

