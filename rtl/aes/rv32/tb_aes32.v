
//
//  Tests: 
//      - saes32.encs  : dec=0, mix=0
//      - saes32.encsm : dec=0, mix=1
//      - saes32.decs  : dec=1, mix=0
//      - saes32.decsm : dec=1, mix=1
//
module tb_aes32(
input   g_clk       ,
input   g_resetn
);

//
// DUT Inputs
reg         dut_valid   = $anyseq; // Output enable.
reg         dut_dec     = $anyseq; // Encrypt (0) or decrypt (1)
reg         dut_mix     = $anyseq; // Encrypt (0) or decrypt (1)
reg  [31:0] dut_rs1     = $anyseq; // Input source register
reg  [31:0] dut_rs2     = $anyseq; // Input source register
reg  [ 1:0] dut_bs      = $anyseq; // Byte Select

// DUT Outputs
wire        dut_ready   ; // Finished computing?
wire [31:0] dut_rd      ; // Output destination register value.

//
// SBOX signals for model
wire [ 7:0] sb_in     = dut_bs == 2'b00 ? dut_rs2[ 7: 0] :
                        dut_bs == 2'b01 ? dut_rs2[15: 8] :
                        dut_bs == 2'b10 ? dut_rs2[23:16] :
                                          dut_rs2[31:24] ;
wire [ 7:0] sb_out    ;

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
// Mix columns outputs for model.

wire [31:0] mix_out_dec = 
    {xtN(sb_out,4'd11), xtN(sb_out,4'd13),xtN(sb_out,4'd9), xtN(sb_out,4'd14)};

wire [31:0] mix_out_enc = 
    {xtN(sb_out,4'd3 ),     sb_out       ,    sb_out      , xtN(sb_out,4'd2 )};

wire [31:0] mix_out     = dut_dec ? mix_out_dec : mix_out_enc;

//
// Final modelled output

wire [31:0] rot_in  =  dut_mix ? mix_out : {24'b0, sb_out};

wire [31:0] rot_out = (rot_in << (8*dut_bs)) | (rot_in >> (32-8*dut_bs));

wire [31:0] grm_out = rot_out ^ dut_rs1;


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
        assume($stable(dut_dec  ));
        assume($stable(dut_mix  ));
        assume($stable(dut_rs1  ));
        assume($stable(dut_rs2  ));
        assume($stable(dut_bs   ));
    end

end


//
// Formal checks
always @(posedge g_clk) begin
    
    //
    // Should we check that the outputs are as expected?
    if(g_resetn && dut_valid && dut_ready) begin

        if          ( dut_dec &&  dut_mix) begin // Decrypt, Sub & Mix

            assert(dut_rd == grm_out);

        end else if ( dut_dec && !dut_mix) begin // Decrypt, Sub

            assert(dut_rd == grm_out);
        
        end else if (!dut_dec &&  dut_mix) begin // Encrypt, Sub & Mix

            assert(dut_rd == grm_out);
        
        end else if (!dut_dec && !dut_mix) begin // Encrypt, Sub

            assert(dut_rd == grm_out);

        end

    end

end

//
// Instance the DUT
//
aes32 i_dut (
.valid  (dut_valid), // Are the inputs valid? Used for logic gating.
.dec    (dut_dec  ), // Encrypt (clear) or decrypt (set)
.mix    (dut_mix  ), // Perform MixColumn transformation (if set)
.rs1    (dut_rs1  ), // Source register 1
.rs2    (dut_rs2  ), // Source register 2
.bs     (dut_bs   ), // Byte select immediate
.rd     (dut_rd   ), // output destination register value.
.ready  (dut_ready)
);


//
// SBox instances - we assume that the SBOX implementation is correct.
aes_sbox i_aes_sbox_0(.in (sb_in), .inv(dut_dec), .out(sb_out) );

endmodule
