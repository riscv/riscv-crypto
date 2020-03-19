
//
//  Tests: 
//      - saes64.enc
//      - saes64.sub
//      - saes64.dec
//      - saes64.imix
//
module tb_aes64(
input   g_clk       ,
input   g_resetn
);

//
// Useful common stuff
// ------------------------------------------------------------

`include "aes_functions.vh"

`define BYTE(X,I) X[7+8*I:8*I]

//
// DUT Interface
// ------------------------------------------------------------

//
// DUT Inputs
reg          dut_valid   = $anyseq; // Are the inputs valid?
reg          dut_hi      = $anyseq; // High (set) or low (clear) output?
reg          dut_mix     = $anyseq; // Mix enable for op_enc/op_dec
reg          dut_op_enc  = $anyseq; // Encrypt hi/lo
reg          dut_op_dec  = $anyseq; // Decrypt hi/lo 
reg          dut_op_imix = $anyseq; // Inverse MixColumn transform (if set)
reg          dut_op_sub  = $anyseq; // Perform only a sub-bytes operation
reg  [ 63:0] dut_rs1     = $anyseq; // Source register 1
reg  [ 63:0] dut_rs2     = $anyseq; // Source register 2

wire [ 63:0] dut_rd      ; // output destination register value.
wire         dut_ready   ; // Compute finished?


//
// Golden Reference
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


wire [63:0] result_sub = {
                 dut_rs1[63:32] ,
    aes_sbox_fwd(dut_rs1[31:24]),
    aes_sbox_fwd(dut_rs1[23:16]),
    aes_sbox_fwd(dut_rs1[15: 8]),
    aes_sbox_fwd(dut_rs1[ 7: 0])
};

wire [63:0] result_imix ;
assign      result_imix[63:32] = mixcolumn_word_dec(dut_rs1[63:32]);
assign      result_imix[31: 0] = mixcolumn_word_dec(dut_rs1[31: 0]);

wire [127:0] grm_state      = regs_to_state(dut_rs1, dut_rs2);

wire [127:0] renc_shifted   = state_shift_rows(grm_state);
wire [ 63:0] renc_hilo      = dut_hi ? renc_shifted[127:64] :
                                       renc_shifted[ 63:0]  ;
wire [ 63:0] renc_sub       = subbytes_doubleword(renc_hilo);
wire [ 63:0] renc_mix       = {
    mixcolumn_word_enc(renc_sub[63:32]),
    mixcolumn_word_enc(renc_sub[31: 0])
};

wire[63:0]  result_enc      = dut_mix ? renc_mix : renc_sub;


wire [127:0] rdec_shifted   = state_inv_shift_rows(grm_state);
wire [ 63:0] rdec_hilo      = dut_hi ? rdec_shifted[127:64] :
                                       rdec_shifted[ 63: 0] ;
wire [ 63:0] rdec_sub       = inv_subbytes_doubleword(rdec_hilo);
wire [ 63:0] rdec_mix       = {
    mixcolumn_word_dec(rdec_sub[63:32]),
    mixcolumn_word_dec(rdec_sub[31: 0])
};

wire[63:0]  result_dec      = dut_mix ? rdec_mix : rdec_sub;

//
// Assertions and Assumptions
// ------------------------------------------------------------


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
        assume($stable(dut_valid  ));
        assume($stable(dut_hi     ));
        assume($stable(dut_mix    ));
        assume($stable(dut_op_enc ));
        assume($stable(dut_op_dec ));
        assume($stable(dut_op_imix));
        assume($stable(dut_op_sub ));
        assume($stable(dut_rs1    ));
        assume($stable(dut_rs2    ));
        
        // Atlease one op should be set!
        assume(|{dut_op_enc,dut_op_dec, dut_op_imix,dut_op_sub});

    end
        
    // Assume one-hotness of input op commands.
    assume(
        {dut_op_enc,dut_op_dec, dut_op_imix,dut_op_sub} == 4'b1000 ||
        {dut_op_enc,dut_op_dec, dut_op_imix,dut_op_sub} == 4'b0100 ||
        {dut_op_enc,dut_op_dec, dut_op_imix,dut_op_sub} == 4'b0010 ||
        {dut_op_enc,dut_op_dec, dut_op_imix,dut_op_sub} == 4'b0001
    );

    assume(dut_rs1 == 64'h2be2f4a0bee33d19);
    assume(dut_rs2 == 64'h0848f8e92a8dc69a);

end


//
// Formal checks
always @(posedge g_clk) begin

    if(g_resetn && dut_valid && dut_ready) begin

        if(dut_op_enc) begin
            
            assert(dut_rd == result_enc );

        end else if(dut_op_dec) begin
            
            assert(dut_rd == result_dec );

        end else if(dut_op_imix) begin
            
            assert(dut_rd == result_imix);

        end else if(dut_op_sub) begin
            
            assert(dut_rd == result_sub );

        end
    end
    

end

//
// Submodule Instances
// ------------------------------------------------------------

`undef BYTE

//
// Instance the DUT
//
aes64 i_dut (
.valid      (dut_valid  ), // Are the inputs valid? Used for logic gating.
.hi         (dut_hi     ), // High (set) or low (clear) output?
.mix        (dut_mix    ), // Enable mix for enc/dec operations.
.op_enc     (dut_op_enc ), //
.op_dec     (dut_op_dec ), // 
.op_imix    (dut_op_imix), // Inverse MixColumn transformation (if set)
.op_sub     (dut_op_sub ), // Perform only a sub-bytes operation
.rs1        (dut_rs1    ), // Source register 1
.rs2        (dut_rs2    ), // Source register 2
.rd         (dut_rd     ), // output destination register value.
.ready      (dut_ready  )  // Compute finished?
);


endmodule
