
//
// AES instruction proposals: RV64
//
//  Models: 
//      - saes64.enc
//      - saes64.sub
//      - saes64.dec
//      - saes64.imix
//
module tb_checker_saes64 (

input  wire         valid   , // Are the inputs valid?
input  wire         mix     , // Mix enable for op_enc/op_dec
input  wire         op_enc  , // Encrypt
input  wire         op_dec  , // Decrypt
input  wire         op_imix , // Inverse MixColumn transformation (if set)
input  wire         op_ks1  , // KeySchedule 1
input  wire         op_ks2  , // KeySchedule 2

input  wire [ 63:0] rs1     , // Source register 1
input  wire [ 63:0] rs2     , // Source register 2
input  wire [  3:0] enc_rcon,

output wire [ 63:0] rd      , // output destination register value.
output wire         ready     // Compute finished?

);

//
// Useful common stuff
// ------------------------------------------------------------

`include "tb_checker_saes.vh"

`define BYTE(X,I) X[7+8*I:8*I]

//
// Utility Functions
// ------------------------------------------------------------

function [127:0] regs_to_state;
    input [63:0] rs1;
    input [63:0] rs2;
    regs_to_state = {
        rs2[63:32],
        rs2[31: 0],
        rs1[63:32],
        rs1[31: 0]
    };
endfunction


function [127:0] state_shift_rows;
    input [127:0] state;
    `BYTE(state_shift_rows, 0) = `BYTE(state, 0); // Column 0
    `BYTE(state_shift_rows, 1) = `BYTE(state, 5);
    `BYTE(state_shift_rows, 2) = `BYTE(state,10);
    `BYTE(state_shift_rows, 3) = `BYTE(state,15);
    `BYTE(state_shift_rows, 4) = `BYTE(state, 4); // Column 1
    `BYTE(state_shift_rows, 5) = `BYTE(state, 9);
    `BYTE(state_shift_rows, 6) = `BYTE(state,14);
    `BYTE(state_shift_rows, 7) = `BYTE(state, 3);
    `BYTE(state_shift_rows, 8) = `BYTE(state, 8); // Column 2
    `BYTE(state_shift_rows, 9) = `BYTE(state,13);
    `BYTE(state_shift_rows,10) = `BYTE(state, 2);
    `BYTE(state_shift_rows,11) = `BYTE(state, 7);
    `BYTE(state_shift_rows,12) = `BYTE(state,12); // Column 3
    `BYTE(state_shift_rows,13) = `BYTE(state, 1);
    `BYTE(state_shift_rows,14) = `BYTE(state, 6);
    `BYTE(state_shift_rows,15) = `BYTE(state,11);
endfunction


function [127:0] state_inv_shift_rows;
    input [127:0] state;
    `BYTE(state_inv_shift_rows, 0) = `BYTE(state, 0); // Column 0
    `BYTE(state_inv_shift_rows, 5) = `BYTE(state, 1);
    `BYTE(state_inv_shift_rows,10) = `BYTE(state, 2);
    `BYTE(state_inv_shift_rows,15) = `BYTE(state, 3);
    `BYTE(state_inv_shift_rows, 4) = `BYTE(state, 4); // Column 1
    `BYTE(state_inv_shift_rows, 9) = `BYTE(state, 5);
    `BYTE(state_inv_shift_rows,14) = `BYTE(state, 6);
    `BYTE(state_inv_shift_rows, 3) = `BYTE(state, 7);
    `BYTE(state_inv_shift_rows, 8) = `BYTE(state, 8); // Column 2
    `BYTE(state_inv_shift_rows,13) = `BYTE(state, 9);
    `BYTE(state_inv_shift_rows, 2) = `BYTE(state,10);
    `BYTE(state_inv_shift_rows, 7) = `BYTE(state,11);
    `BYTE(state_inv_shift_rows,12) = `BYTE(state,12); // Column 3
    `BYTE(state_inv_shift_rows, 1) = `BYTE(state,13);
    `BYTE(state_inv_shift_rows, 6) = `BYTE(state,14);
    `BYTE(state_inv_shift_rows,11) = `BYTE(state,15);
endfunction


function [63:0] subbytes_doubleword;
    input [63:0] dw;
    `BYTE(subbytes_doubleword,0) = aes_sbox_fwd(`BYTE(dw,0));
    `BYTE(subbytes_doubleword,1) = aes_sbox_fwd(`BYTE(dw,1));
    `BYTE(subbytes_doubleword,2) = aes_sbox_fwd(`BYTE(dw,2));
    `BYTE(subbytes_doubleword,3) = aes_sbox_fwd(`BYTE(dw,3));
    `BYTE(subbytes_doubleword,4) = aes_sbox_fwd(`BYTE(dw,4));
    `BYTE(subbytes_doubleword,5) = aes_sbox_fwd(`BYTE(dw,5));
    `BYTE(subbytes_doubleword,6) = aes_sbox_fwd(`BYTE(dw,6));
    `BYTE(subbytes_doubleword,7) = aes_sbox_fwd(`BYTE(dw,7));
endfunction


function [63:0] inv_subbytes_doubleword;
    input [63:0] dw;
    `BYTE(inv_subbytes_doubleword,0) = aes_sbox_inv(`BYTE(dw,0));
    `BYTE(inv_subbytes_doubleword,1) = aes_sbox_inv(`BYTE(dw,1));
    `BYTE(inv_subbytes_doubleword,2) = aes_sbox_inv(`BYTE(dw,2));
    `BYTE(inv_subbytes_doubleword,3) = aes_sbox_inv(`BYTE(dw,3));
    `BYTE(inv_subbytes_doubleword,4) = aes_sbox_inv(`BYTE(dw,4));
    `BYTE(inv_subbytes_doubleword,5) = aes_sbox_inv(`BYTE(dw,5));
    `BYTE(inv_subbytes_doubleword,6) = aes_sbox_inv(`BYTE(dw,6));
    `BYTE(inv_subbytes_doubleword,7) = aes_sbox_inv(`BYTE(dw,7));
endfunction

`undef BYTE

//
// AES Round Constants with some redundancy
// ------------------------------------------------------------
wire [ 7:0] rcon [0:15];
assign rcon[ 0] = 8'h01; assign rcon[ 8] = 8'h1b;
assign rcon[ 1] = 8'h02; assign rcon[ 9] = 8'h36;
assign rcon[ 2] = 8'h04; assign rcon[10] = 8'h00;
assign rcon[ 3] = 8'h08; assign rcon[11] = 8'h00;
assign rcon[ 4] = 8'h10; assign rcon[12] = 8'h00;
assign rcon[ 5] = 8'h20; assign rcon[13] = 8'h00;
assign rcon[ 6] = 8'h40; assign rcon[14] = 8'h00;
assign rcon[ 7] = 8'h80; assign rcon[15] = 8'h00;

//
// KeySchedule 1
// ------------------------------------------------------------

wire        ks1_dorcon = enc_rcon != 4'hA;
wire [31:0] ks1_temp = rs1[63:32];
wire [31:0] ks1_rot  = ks1_dorcon ? {ks1_temp[7:0],ks1_temp[31:8]} :
                                     ks1_temp                      ;
wire [31:0] ks1_sub    = {
    aes_sbox_fwd(ks1_rot[31:24]),
    aes_sbox_fwd(ks1_rot[23:16]),
    aes_sbox_fwd(ks1_rot[15: 8]),
    aes_sbox_fwd(ks1_rot[ 7: 0])
} ^ (ks1_dorcon ? {24'b0, rcon[enc_rcon]} : 32'b0) ;

wire [63:0] result_ks1 = {ks1_sub, ks1_sub};

//
// KeySchedule 2
// ------------------------------------------------------------

wire [63:0] result_ks2 = {
    rs1[63:32] ^ rs2[63:32] ^ rs2[31:0] ,
    rs1[63:32] ^ rs2[63:32]
};

//
// imix
// ------------------------------------------------------------

wire [63:0] result_imix ;
assign      result_imix[63:32] = mixcolumn_word_dec(rs1[63:32]);
assign      result_imix[31: 0] = mixcolumn_word_dec(rs1[31: 0]);

wire [127:0] grm_state      = regs_to_state(rs1, rs2);

//
// Encrypt
// ------------------------------------------------------------

wire [127:0] renc_shifted   = state_shift_rows(grm_state);
wire [ 63:0] renc_lo        = renc_shifted[ 63: 0] ;
wire [ 63:0] renc_sub       = subbytes_doubleword(renc_lo  );
wire [ 63:0] renc_mix       = {
    mixcolumn_word_enc(renc_sub[63:32]),
    mixcolumn_word_enc(renc_sub[31: 0])
};

wire[63:0]  result_enc      = mix ? renc_mix : renc_sub;

//
// Decrypt
// ------------------------------------------------------------

wire [127:0] rdec_shifted   = state_inv_shift_rows(grm_state);
wire [ 63:0] rdec_lo        = rdec_shifted[ 63: 0] ;
wire [ 63:0] rdec_sub       = inv_subbytes_doubleword(rdec_lo  );
wire [ 63:0] rdec_mix       = {
    mixcolumn_word_dec(rdec_sub[63:32]),
    mixcolumn_word_dec(rdec_sub[31: 0])
};

wire[63:0]  result_dec      = mix ? rdec_mix : rdec_sub;


//
// Result Multiplexing
// ------------------------------------------------------------

assign ready    = valid;

assign rd       =
    {64{op_enc }} & result_enc  |
    {64{op_dec }} & result_dec  |
    {64{op_imix}} & result_imix |
    {64{op_ks1 }} & result_ks1  |
    {64{op_ks2 }} & result_ks2  ;

endmodule


