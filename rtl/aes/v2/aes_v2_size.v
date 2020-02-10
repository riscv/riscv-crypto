
//
// module: aes_v2
//
//  Size optimised
//
module aes_v2(

input  wire        g_clk    ,
input  wire        g_resetn ,

input  wire        valid    , // Are the inputs valid?
input  wire        sub      , // Sub if set, Mix if clear
input  wire [31:0] rs1      , // Input source register 1
input  wire [31:0] rs2      , // Input source register 2
input  wire        enc      , // Perform encrypt (set) or decrypt (clear).
input  wire        rot      , // Perform encrypt (set) or decrypt (clear).
output wire        ready    , // Is the instruction complete?
output wire [31:0] rd         // 

);

//
// SBox Instruction
// ------------------------------------------------------------

wire [ 7:0] sb_in   =
    {8{fsm_idle}} & rs1[ 7: 0] |
    {8{fsm_s1  }} & rs2[15: 8] |
    {8{fsm_s2  }} & rs1[23:16] |
    {8{fsm_s3  }} & rs2[31:24] ;

wire [ 7:0] sb_out  ;

aes_sbox i_aes_sbox(.in (sb_in), .inv(!enc), .out(sb_out) );

//
// MixColumns Instruction
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

wire [ 7:0] mix_0    = rs1[ 7: 0];
wire [ 7:0] mix_1    = rs2[15: 8];
wire [ 7:0] mix_2    = rs1[23:16];
wire [ 7:0] mix_3    = rs2[31:24];

wire [ 7:0] mb0  = {8{fsm_idle}} & mix_0 |
                   {8{fsm_s1  }} & mix_1 |
                   {8{fsm_s2  }} & mix_2 |
                   {8{fsm_s3  }} & mix_3 ;

wire [ 7:0] mb1  = {8{fsm_idle}} & mix_1 |
                   {8{fsm_s1  }} & mix_2 |
                   {8{fsm_s2  }} & mix_3 |
                   {8{fsm_s3  }} & mix_0 ;

wire [ 7:0] mb2  = {8{fsm_idle}} & mix_2 |
                   {8{fsm_s1  }} & mix_0 |
                   {8{fsm_s2  }} & mix_0 |
                   {8{fsm_s3  }} & mix_1 ;

wire [ 7:0] mb3  = {8{fsm_idle}} & mix_3 |
                   {8{fsm_s1  }} & mix_3 |
                   {8{fsm_s2  }} & mix_1 |
                   {8{fsm_s3  }} & mix_2 ;

wire [ 7:0] mix_enc = xt2(mb0) ^ xt2(mb1) ^ mb1 ^ mb2 ^ mb3;

wire [ 7:0] mix_dec = xtN(mb0,4'he) ^ xtN(mb1,4'hb) ^
                      xtN(mb2,4'hd) ^ xtN(mb3,4'h9) ;

wire [ 7:0] mix_out = enc ? mix_enc : mix_dec;

//
// Temporary Storage
// ------------------------------------------------------------

reg  [  7:0] t0;
reg  [  7:0] t1;
reg  [  7:0] t2;

wire [  7:0] n_tmp = sub ? sb_out : mix_out;

always @(posedge g_clk) if(fsm_idle && valid) t0 <= n_tmp;
always @(posedge g_clk) if(fsm_s1           ) t1 <= n_tmp;
always @(posedge g_clk) if(fsm_s2           ) t2 <= n_tmp;


//
// Control FSM
// ------------------------------------------------------------

reg [  1:0]   fsm;
reg [  1:0] n_fsm;

localparam  FSM_IDLE    = 2'b00;
localparam  FSM_S1      = 2'b01;
localparam  FSM_S2      = 2'b10;
localparam  FSM_S3      = 2'b11;

wire        fsm_idle    = fsm == FSM_IDLE;
wire        fsm_s1      = fsm == FSM_S1  ;
wire        fsm_s2      = fsm == FSM_S2  ;
wire        fsm_s3      = fsm == FSM_S3  ;

assign      ready       = fsm_s3;
assign      rd          = {n_tmp, t2, t1, t0};

always @(*) case(fsm)
    FSM_IDLE : n_fsm = valid ? FSM_S1 : FSM_IDLE;
    FSM_S1   : n_fsm = FSM_S2;
    FSM_S2   : n_fsm = FSM_S3;
    FSM_S3   : n_fsm = FSM_IDLE;
endcase

always @(posedge g_clk) begin
    if(!g_resetn) begin
        fsm <= 2'b00;
    end else begin
        fsm <= n_fsm;
    end
end

endmodule

