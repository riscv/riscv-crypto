
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
wire [ 7:0] sb_out_0, sb_out_1, sb_out_2, sb_out_3;
wire [ 7:0] sb_out_4, sb_out_5, sb_out_6, sb_out_7;

wire [63:0] ed_sbin  = op_enc ? enc_sel : dec_sel;

wire [ 7:0] sb_in_0  = op_sub ? rs1[ 7: 0] : `BY(ed_sbin, 0);
wire [ 7:0] sb_in_1  = op_sub ? rs1[15: 8] : `BY(ed_sbin, 1);
wire [ 7:0] sb_in_2  = op_sub ? rs1[23:16] : `BY(ed_sbin, 2);
wire [ 7:0] sb_in_3  = op_sub ? rs1[31:24] : `BY(ed_sbin, 3);
wire [ 7:0] sb_in_4  = op_sub ? 8'b0       : `BY(ed_sbin, 4);
wire [ 7:0] sb_in_5  = op_sub ? 8'b0       : `BY(ed_sbin, 5);
wire [ 7:0] sb_in_6  = op_sub ? 8'b0       : `BY(ed_sbin, 6);
wire [ 7:0] sb_in_7  = op_sub ? 8'b0       : `BY(ed_sbin, 7);

wire [63:0] ed_sbout = {
    sb_out_7, sb_out_6, sb_out_5, sb_out_4,
    sb_out_3, sb_out_2, sb_out_1, sb_out_0
};

wire [31:0] mix_in_1  = op_imix ? rs1[63:32] : ed_sbout[63:32];
wire [31:0] mix_in_0  = op_imix ? rs1[31: 0] : ed_sbout[31: 0];

wire [31:0] mix_out_1 ;
wire [31:0] mix_out_0 ;

//
// Result gathering

wire [63:0] result_sub = {rs1[63:32], sb_out_3, sb_out_2, sb_out_1, sb_out_0};

wire [63:0] result_encdec =
    mix ? {mix_out_1, mix_out_0} : ed_sbout;

wire [63:0] result_imix   = {mix_out_1, mix_out_0};

assign rd = 
    {64{op_sub          }} & result_sub     |
    {64{op_enc || op_dec}} & result_encdec  |
    {64{op_imix         }} & result_imix    ;

//
// SBox instances
aes_sbox i_aes_sbox_0 (.inv(op_dec),.in (sb_in_0),.out(sb_out_0));
aes_sbox i_aes_sbox_1 (.inv(op_dec),.in (sb_in_1),.out(sb_out_1));
aes_sbox i_aes_sbox_2 (.inv(op_dec),.in (sb_in_2),.out(sb_out_2));
aes_sbox i_aes_sbox_3 (.inv(op_dec),.in (sb_in_3),.out(sb_out_3));
aes_sbox i_aes_sbox_4 (.inv(op_dec),.in (sb_in_4),.out(sb_out_4));
aes_sbox i_aes_sbox_5 (.inv(op_dec),.in (sb_in_5),.out(sb_out_5));
aes_sbox i_aes_sbox_6 (.inv(op_dec),.in (sb_in_6),.out(sb_out_6));
aes_sbox i_aes_sbox_7 (.inv(op_dec),.in (sb_in_7),.out(sb_out_7));

aes_mixcolumn i_aes_mixcolumn_0(
    .col_in (mix_in_0           ),
    .dec    (op_dec || op_imix  ),
    .col_out(mix_out_0          )
);

aes_mixcolumn i_aes_mixcolumn_1(
    .col_in (mix_in_1           ),
    .dec    (op_dec || op_imix  ),
    .col_out(mix_out_1          )
);

`undef BYOF

endmodule

