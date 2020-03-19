
//
// AES instruction proposals: RV64
//
//  Implements: 
//      - saes64.enc
//      - saes64.sub
//      - saes64.dec
//      - saes64.imix
//
module aes64(

input  wire         valid   , // Are the inputs valid?
input  wire         hi      , // High (set) or low (clear) output?
input  wire         mix     , // Mix enable for op_enc/op_dec
input  wire         op_enc  , // Encrypt hi/lo
input  wire         op_dec  , // Decrypt hi/lo 
input  wire         op_imix , // Inverse MixColumn transformation (if set)
input  wire         op_sub  , // Perform only a sub-bytes operation

input  wire [ 63:0] rs1     , // Source register 1
input  wire [ 63:0] rs2     , // Source register 2

output wire [ 63:0] rd      , // output destination register value.
output wire         ready     // Compute finished?

);

`define BY(X,I) X[7+8*I:8*I]

// Always finish in a single cycle.
assign     ready            = valid              ;

//
// Shift Rows

wire [31:0] row_0   = {`BY(rs1,0),`BY(rs1,4),`BY(rs2,0),`BY(rs2,4)};
wire [31:0] row_1   = {`BY(rs1,1),`BY(rs1,5),`BY(rs2,1),`BY(rs2,5)};
wire [31:0] row_2   = {`BY(rs1,2),`BY(rs1,6),`BY(rs2,2),`BY(rs2,6)};
wire [31:0] row_3   = {`BY(rs1,3),`BY(rs1,7),`BY(rs2,3),`BY(rs2,7)};

// Forward shift rows
wire [31:0] fsh_0   =  row_0;                      
wire [31:0] fsh_1   = {row_1[23: 0], row_1[31:24]};
wire [31:0] fsh_2   = {row_2[15: 0], row_2[31:16]};
wire [31:0] fsh_3   = {row_3[ 7: 0], row_3[31: 8]};

// Inverse shift rows
wire [31:0] ish_0   =  row_0;
wire [31:0] ish_1   = {row_1[ 7: 0], row_1[31: 8]};
wire [31:0] ish_2   = {row_2[15: 0], row_2[31:16]};
wire [31:0] ish_3   = {row_3[23: 0], row_3[31:24]};

//
// Re-construct columns from rows
wire [31:0] f_col_3 = {`BY(fsh_3,0),`BY(fsh_2,0),`BY(fsh_1,0),`BY(fsh_0,0)};
wire [31:0] f_col_2 = {`BY(fsh_3,1),`BY(fsh_2,1),`BY(fsh_1,1),`BY(fsh_0,1)};
wire [31:0] f_col_1 = {`BY(fsh_3,2),`BY(fsh_2,2),`BY(fsh_1,2),`BY(fsh_0,2)};
wire [31:0] f_col_0 = {`BY(fsh_3,3),`BY(fsh_2,3),`BY(fsh_1,3),`BY(fsh_0,3)};

wire [31:0] i_col_3 = {`BY(ish_3,0),`BY(ish_2,0),`BY(ish_1,0),`BY(ish_0,0)};
wire [31:0] i_col_2 = {`BY(ish_3,1),`BY(ish_2,1),`BY(ish_1,1),`BY(ish_0,1)};
wire [31:0] i_col_1 = {`BY(ish_3,2),`BY(ish_2,2),`BY(ish_1,2),`BY(ish_0,2)};
wire [31:0] i_col_0 = {`BY(ish_3,3),`BY(ish_2,3),`BY(ish_1,3),`BY(ish_0,3)};

//
// Hi/Lo selection

wire [63:0] enc_sel = hi ? {f_col_3, f_col_2} : {f_col_1, f_col_0};
wire [63:0] dec_sel = hi ? {i_col_3, i_col_2} : {i_col_1, i_col_0};

//
// SBox input/output
wire [ 7:0] sb_fwd_out_0, sb_fwd_out_1, sb_fwd_out_2, sb_fwd_out_3;
wire [ 7:0] sb_fwd_out_4, sb_fwd_out_5, sb_fwd_out_6, sb_fwd_out_7;

wire [ 7:0] sb_inv_out_0, sb_inv_out_1, sb_inv_out_2, sb_inv_out_3;
wire [ 7:0] sb_inv_out_4, sb_inv_out_5, sb_inv_out_6, sb_inv_out_7;

// If just doing sub-bytes, sbox inputs direct from rs1.
wire [ 7:0] sb_fwd_in_0 = op_sub ? rs1[ 7: 0] : `BY(enc_sel, 0);
wire [ 7:0] sb_fwd_in_1 = op_sub ? rs1[15: 8] : `BY(enc_sel, 1);
wire [ 7:0] sb_fwd_in_2 = op_sub ? rs1[23:16] : `BY(enc_sel, 2);
wire [ 7:0] sb_fwd_in_3 = op_sub ? rs1[31:24] : `BY(enc_sel, 3);
wire [ 7:0] sb_fwd_in_4 =                       `BY(enc_sel, 4);
wire [ 7:0] sb_fwd_in_5 =                       `BY(enc_sel, 5);
wire [ 7:0] sb_fwd_in_6 =                       `BY(enc_sel, 6);
wire [ 7:0] sb_fwd_in_7 =                       `BY(enc_sel, 7);

wire [ 7:0] sb_inv_in_0 = `BY(dec_sel, 0);
wire [ 7:0] sb_inv_in_1 = `BY(dec_sel, 1);
wire [ 7:0] sb_inv_in_2 = `BY(dec_sel, 2);
wire [ 7:0] sb_inv_in_3 = `BY(dec_sel, 3);
wire [ 7:0] sb_inv_in_4 = `BY(dec_sel, 4);
wire [ 7:0] sb_inv_in_5 = `BY(dec_sel, 5);
wire [ 7:0] sb_inv_in_6 = `BY(dec_sel, 6);
wire [ 7:0] sb_inv_in_7 = `BY(dec_sel, 7);

// Decrypt sbox output
wire [63:0] d_sbout     = {
    sb_inv_out_7, sb_inv_out_6, sb_inv_out_5, sb_inv_out_4,
    sb_inv_out_3, sb_inv_out_2, sb_inv_out_1, sb_inv_out_0 
};

// Encrypt sbox output
wire [63:0] e_sbout     = {
    sb_fwd_out_7, sb_fwd_out_6, sb_fwd_out_5, sb_fwd_out_4,
    sb_fwd_out_3, sb_fwd_out_2, sb_fwd_out_1, sb_fwd_out_0 
};

// Forward MixColumns inputs.
wire [31:0] mce_i0      =                        e_sbout[31: 0];
wire [31:0] mce_i1      =                        e_sbout[63:32];

// Inverse MixColumns inputs.
wire [31:0] mcd_i0      = op_imix ? rs1[31: 0] : d_sbout[31: 0];
wire [31:0] mcd_i1      = op_imix ? rs1[63:32] : d_sbout[63:32];

// Forward MixColumns outputs.
wire [31:0] mce_o0      ;
wire [31:0] mce_o1      ;

// Inverse MixColumns outputs.
wire [31:0] mcd_o0      ;
wire [31:0] mcd_o1      ;


//
// Result gathering

wire [63:0] result_sub  = {rs1[63:32], e_sbout[31:0]};

wire [63:0] result_enc  = mix ? {mce_o1, mce_o0} : e_sbout;

wire [63:0] result_dec  = mix ? {mcd_o1, mcd_o0} : d_sbout;

wire [63:0] result_imix = {mcd_o1, mcd_o0};

assign rd = 
    {64{op_sub          }} & result_sub     |
    {64{op_enc          }} & result_enc     |
    {64{op_dec          }} & result_dec     |
    {64{op_imix         }} & result_imix    ;

//
// SBox instances
aes_fwd_sbox i_aes_fwd_sbox_0 (.in (sb_fwd_in_0),.fx(sb_fwd_out_0));
aes_fwd_sbox i_aes_fwd_sbox_1 (.in (sb_fwd_in_1),.fx(sb_fwd_out_1));
aes_fwd_sbox i_aes_fwd_sbox_2 (.in (sb_fwd_in_2),.fx(sb_fwd_out_2));
aes_fwd_sbox i_aes_fwd_sbox_3 (.in (sb_fwd_in_3),.fx(sb_fwd_out_3));
aes_fwd_sbox i_aes_fwd_sbox_4 (.in (sb_fwd_in_4),.fx(sb_fwd_out_4));
aes_fwd_sbox i_aes_fwd_sbox_5 (.in (sb_fwd_in_5),.fx(sb_fwd_out_5));
aes_fwd_sbox i_aes_fwd_sbox_6 (.in (sb_fwd_in_6),.fx(sb_fwd_out_6));
aes_fwd_sbox i_aes_fwd_sbox_7 (.in (sb_fwd_in_7),.fx(sb_fwd_out_7));

aes_inv_sbox i_aes_inv_sbox_0 (.in (sb_inv_in_0),.fx(sb_inv_out_0));
aes_inv_sbox i_aes_inv_sbox_1 (.in (sb_inv_in_1),.fx(sb_inv_out_1));
aes_inv_sbox i_aes_inv_sbox_2 (.in (sb_inv_in_2),.fx(sb_inv_out_2));
aes_inv_sbox i_aes_inv_sbox_3 (.in (sb_inv_in_3),.fx(sb_inv_out_3));
aes_inv_sbox i_aes_inv_sbox_4 (.in (sb_inv_in_4),.fx(sb_inv_out_4));
aes_inv_sbox i_aes_inv_sbox_5 (.in (sb_inv_in_5),.fx(sb_inv_out_5));
aes_inv_sbox i_aes_inv_sbox_6 (.in (sb_inv_in_6),.fx(sb_inv_out_6));
aes_inv_sbox i_aes_inv_sbox_7 (.in (sb_inv_in_7),.fx(sb_inv_out_7));

//
// Mix Column Instances
aes_mixcolumn_word_enc i_mix_e0(.col_in(mce_i0),.col_out(mce_o0));
aes_mixcolumn_word_enc i_mix_e1(.col_in(mce_i1),.col_out(mce_o1));

aes_mixcolumn_word_dec i_mix_d0(.col_in(mcd_i0),.col_out(mcd_o0));
aes_mixcolumn_word_dec i_mix_d1(.col_in(mcd_i1),.col_out(mcd_o1));

`undef BY

endmodule

