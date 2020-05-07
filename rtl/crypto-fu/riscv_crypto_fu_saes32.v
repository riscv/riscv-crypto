
//
// module: riscv_crypto_fu_saes32
//
//  Implements the scalar 32-bit AES instructions for the RISC-V
//  cryptography extension
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN, and the feature enable
//  parameter name(s).
//
//  Instruction     | XLEN=32 | XLEN=64 | Feature Parameter 
//  ----------------|---------|---------|----------------------------------
//   saes32.encs    |   x     |         | SAES_EN
//   saes32.encsm   |   x     |         | SAES_EN     
//   saes32.decs    |   x     |         | SAES_DEC_EN     
//   saes32.decsm   |   x     |         | SAES_DEC_EN     
//
module riscv_crypto_fu_saes32 #(
parameter SAES_DEC_EN = 1            // Enable saes32 decrypt instructions.
)(

input  wire         valid          , // Are the inputs valid?
input  wire [ 31:0] rs1            , // Source register 1
input  wire [ 31:0] rs2            , // Source register 2
input  wire [  1:0] bs             , // Byte select immediate

input  wire         op_saes32_encs , // Encrypt SubBytes
input  wire         op_saes32_encsm, // Encrypt SubBytes + MixColumn
input  wire         op_saes32_decs , // Decrypt SubBytes
input  wire         op_saes32_decsm, // Decrypt SubBytes + MixColumn

output wire [ 31:0] rd             , // output destination register value.
output wire         ready            // Compute finished?

);

wire [7:0] bytes_in [3:0]   ;

// Always finish in a single cycle.
assign     ready        = valid                     ;

assign     bytes_in [0] =  rs2[ 7: 0]               ;
assign     bytes_in [1] =  rs2[15: 8]               ;
assign     bytes_in [2] =  rs2[23:16]               ;
assign     bytes_in [3] =  rs2[31:24]               ;

wire [7:0] sel_byte     = bytes_in[bs]              ;

wire       dec          = (op_saes32_decs  || op_saes32_decsm) && SAES_DEC_EN;
wire       mix          =  op_saes32_encsm || op_saes32_decsm      ;

wire [7:0] sbox_fwd_out     ;
wire [7:0] sbox_inv_out     ;
wire [7:0] sbox_out         = dec ? sbox_inv_out : sbox_fwd_out ;

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

assign      rd          = rotated ^ rs1;

//
// SBOX instances
// ------------------------------------------------------------

riscv_crypto_aes_fwd_sbox i_aes_sbox_fwd (
.in (sel_byte    ),
.fx (sbox_fwd_out)
);

generate if(SAES_DEC_EN) begin : saes32_dec_sbox_implemented

riscv_crypto_aes_inv_sbox i_aes_sbox_inv (
.in (sel_byte    ),
.fx (sbox_inv_out)
);

end else begin : saes32_dec_sbox_not_implemented

    assign sbox_inv_out = 8'b0;

end endgenerate // SAES_DEC_EN

endmodule

