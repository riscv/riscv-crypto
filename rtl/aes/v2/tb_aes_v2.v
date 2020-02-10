
module tb_aes_v2 (
input   g_clk       ,
input   g_resetn
);

//
// DUT Inputs
reg         dut_valid   = $anyseq; // Output enable.
reg         dut_sub     = $anyseq; // Encrypt (0) or decrypt (1)
reg         dut_enc     = $anyseq; // Encrypt (0) or decrypt (1)
reg  [31:0] dut_rs1     = $anyseq; // Input source register
reg  [31:0] dut_rs2     = $anyseq; // Input source register

// DUT Outputs
wire        dut_ready   ; // Finished computing?
wire [31:0] dut_rd      ; // Output destination register value.

//
// SBOX outputs for model
wire [ 7:0] sbox_0;
wire [ 7:0] sbox_1;
wire [ 7:0] sbox_2;
wire [ 7:0] sbox_3;

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

wire [ 7:0] mix_0    = dut_rs1[ 7: 0];
wire [ 7:0] mix_1    = dut_rs2[15: 8];
wire [ 7:0] mix_2    = dut_rs1[23:16];
wire [ 7:0] mix_3    = dut_rs2[31:24];

//
// MixColumns outputs for model
wire [31:0] mix_enc_grm = {
    mixcolumn_enc(mix_3, mix_0, mix_1, mix_2),
    mixcolumn_enc(mix_2, mix_3, mix_0, mix_1),
    mixcolumn_enc(mix_1, mix_2, mix_0, mix_3),
    mixcolumn_enc(mix_0, mix_1, mix_2, mix_3)
};

wire [31:0] mix_dec_grm = {
    mixcolumn_dec(mix_3, mix_0, mix_1, mix_2),
    mixcolumn_dec(mix_2, mix_3, mix_0, mix_1),
    mixcolumn_dec(mix_1, mix_2, mix_0, mix_3),
    mixcolumn_dec(mix_0, mix_1, mix_2, mix_3)
};

// Assume we start in reset...
initial assume(!g_resetn);

//
// Formal Cover statements
always @(posedge g_clk) if(g_resetn) begin

    // Do we ever run anything?
    cover(dut_valid             );

    // Do we ever finish?
    cover(dut_valid && dut_ready);

end

//
// Formal assumptions
always @(posedge g_clk) begin

    //
    // Constraints
    if($past(dut_valid) && $past(!dut_ready)) begin
        // If the TB is waiting for the DUT to compute an output,
        // make sure that the inputs are stable.
        assume($stable(dut_valid));
        assume($stable(dut_enc  ));
        assume($stable(dut_sub  ));
        assume($stable(dut_rs1  ));
        assume($stable(dut_rs2  ));
    end

end

//
// Formal checks
always @(posedge g_clk) begin
    
    //
    // Should we check that the outputs are as expected?
    if(g_resetn && dut_valid && dut_ready) begin

        if         (dut_sub             ) begin
            
            assert(dut_rd == {sbox_3, sbox_2, sbox_1, sbox_0});

        end else if(!dut_sub &&  dut_enc) begin // Mix - Encrypt
            
            assert(dut_rd == mix_enc_grm);
        
        end else if(!dut_sub && !dut_enc) begin // Mix - Decrypt
            
            assert(dut_rd == mix_dec_grm);

        end

    end

end

//
// Instance the DUT
//
aes_v2 i_dut (
.g_clk    (g_clk        ),
.g_resetn (g_resetn     ),
.valid    (dut_valid    ), // Are the inputs valid?
.sub      (dut_sub      ), // Sub if set, Mix if clear
.enc      (dut_enc      ), // Perform encrypt (set) or decrypt (clear).
.rs1      (dut_rs1      ), // Input source register 1
.rs2      (dut_rs2      ), // Input source register 2
.ready    (dut_ready    ), // Is the instruction complete?
.rd       (dut_rd       )  // 
);


//
// SBox instances - we assume that the SBOX implementation is correct.
aes_sbox i_aes_sbox_0(.in (dut_rs1[ 7: 0]), .inv(!dut_enc), .out(sbox_0) );
aes_sbox i_aes_sbox_1(.in (dut_rs2[15: 8]), .inv(!dut_enc), .out(sbox_1) );
aes_sbox i_aes_sbox_2(.in (dut_rs1[23:16]), .inv(!dut_enc), .out(sbox_2) );
aes_sbox i_aes_sbox_3(.in (dut_rs2[31:24]), .inv(!dut_enc), .out(sbox_3) );

endmodule
