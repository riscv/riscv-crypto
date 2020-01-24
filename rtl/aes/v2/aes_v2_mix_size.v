
//
// module: aes_v2_mix_size
//
//  Implements the lightweight AES MixColumns instructions.
//
module aes_v2_mix_size (

input  wire        clock ,
input  wire        reset ,

input  wire        flush , // Flush state ready for next set of inputs.
input  wire [31:0] flush_data, // Data flushed into the design.

input  wire        valid , // Are the inputs valid?
input  wire [31:0] rs1   , // Input source register 1
input  wire [31:0] rs2   , // Input source register 2
input  wire        enc   , // Perform encrypt (set) or decrypt (clear).
output wire        ready , // Is the instruction complete?
output wire [31:0] result  // 

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
wire [7:0] e0 = rs1[ 7: 0] & {8{valid && enc}};
wire [7:0] e1 = rs1[15: 8] & {8{valid && enc}};
wire [7:0] e2 = rs2[23:16] & {8{valid && enc}};
wire [7:0] e3 = rs2[31:24] & {8{valid && enc}};

//
// Decrypt inputs
wire [7:0] d0 = rs1[ 7: 0] & {8{valid && !enc}};
wire [7:0] d1 = rs1[15: 8] & {8{valid && !enc}};
wire [7:0] d2 = rs2[23:16] & {8{valid && !enc}};
wire [7:0] d3 = rs2[31:24] & {8{valid && !enc}};

wire [31:0] result_enc;
wire [31:0] result_dec;

//
// Multi-Cycle Implementation
// ------------------------------------------------------------

reg  [1:0] fsm     ;
wire [1:0] n_fsm   = fsm + 1 ;

wire       fsm_0   = fsm == 0;
wire       fsm_1   = fsm == 1;
wire       fsm_2   = fsm == 2;
wire       fsm_3   = fsm == 3;

assign     ready   = fsm_3;

reg [7:0]  b_0; // Per-byte results
reg [7:0]  b_1; // 
reg [7:0]  b_2; // 
wire[7:0]  b_3 = step_out;

//
// Encryption

wire [7:0] enc_x0_in    = {8{fsm_0 || fsm_1}} & e3  |
                          {8{fsm_2         }} & e1  |
                          {8{fsm_3         }} & e2  ;

wire [7:0] enc_x1_in    = {8{fsm_0         }} & e2  |
                          {8{fsm_1 || fsm_2}} & e0  |
                          {8{fsm_3         }} & e1  ;

wire [7:0] enc_x2_in    = {8{fsm_0         }} & e0  |
                          {8{fsm_1         }} & e1  |
                          {8{fsm_2         }} & e2  |
                          {8{fsm_3         }} & e3  ;

wire [7:0] enc_x3_in    = {8{fsm_0         }} & e1  |
                          {8{fsm_1         }} & e2  |
                          {8{fsm_2         }} & e3  |
                          {8{fsm_3         }} & e0  ;

wire [7:0] enc_x2_out   = xtime2(enc_x2_in);
wire [7:0] enc_x3_out   = xtime3(enc_x3_in);

wire [7:0] enc_byte     = enc_x3_out ^ enc_x2_out ^ enc_x1_in ^ enc_x0_in;

//
// Decryption

wire [7:0] dec_0_lhs    = {8{fsm_0}} & d0 |
                          {8{fsm_1}} & d1 |
                          {8{fsm_2}} & d2 |
                          {8{fsm_3}} & d3 ;

wire [7:0] dec_1_lhs    = {8{fsm_0}} & d1 |
                          {8{fsm_1}} & d2 |
                          {8{fsm_2}} & d3 |
                          {8{fsm_3}} & d0 ;

wire [7:0] dec_2_lhs    = {8{fsm_0}} & d2 |
                          {8{fsm_1}} & d3 |
                          {8{fsm_2}} & d0 |
                          {8{fsm_3}} & d1 ;

wire [7:0] dec_3_lhs    = {8{fsm_0}} & d3 |
                          {8{fsm_1}} & d0 |
                          {8{fsm_2}} & d1 |
                          {8{fsm_3}} & d2 ;

wire [7:0] dec_0_out    = xtimeN(dec_0_lhs, 4'he);
wire [7:0] dec_1_out    = xtimeN(dec_1_lhs, 4'hb);
wire [7:0] dec_2_out    = xtimeN(dec_2_lhs, 4'hd);
wire [7:0] dec_3_out    = xtimeN(dec_3_lhs, 4'h9);

wire [7:0] dec_byte     = dec_0_out ^ dec_1_out ^ dec_2_out ^ dec_3_out;

//
// Result collection

wire [7:0] step_out     = enc ? enc_byte : dec_byte;

assign     result_enc       = {b_3, b_2, b_1, b_0};
assign     result_dec       = {b_3, b_2, b_1, b_0};

always @(posedge clock) begin
    if(reset || flush) begin
        b_0 <= flush_data[7:0];
    end else if(fsm_0 && valid) begin
        b_0 <= step_out;
    end
end

always @(posedge clock) begin
    if(reset || flush) begin
        b_1 <= flush_data[15:8];
    end else if(fsm_1 && valid) begin
        b_1 <= step_out;
    end
end

always @(posedge clock) begin
    if(reset || flush) begin
        b_2 <= flush_data[23:16];
    end else if(fsm_2 && valid) begin
        b_2 <= step_out;
    end
end

always @(posedge clock) begin
    if(reset || flush) begin
        fsm <= 0;
    end else if(valid && !ready) begin
        fsm <= n_fsm;
    end
end

//
// Create the final result.
assign     result = result_enc | result_dec;

endmodule



