
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
reg          dut_op_ks1  = $anyseq; // KeySchedule1 instruction
reg          dut_op_ks2  = $anyseq; // "  "       2 instruction
reg  [ 63:0] dut_rs1     = $anyseq; // Source register 1
reg  [ 63:0] dut_rs2     = $anyseq; // Source register 2 / rcon immediate

wire [ 63:0] dut_rd      ; // Output destination register value.
wire         dut_ready   ; // Compute finished?

wire [ 63:0] grm_rd      ; // Output destination register value.
wire         grm_ready   ; // Compute finished?


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
        assume($stable(dut_op_ks1 ));
        assume($stable(dut_op_ks2 ));
        assume($stable(dut_rs1    ));
        assume($stable(dut_rs2    ));
        
        // Atlease one op should be set!
        assume(|{dut_op_enc,dut_op_dec, dut_op_imix,dut_op_ks1,dut_op_ks2});

    end

    if(dut_op_ks1) begin
        assume(dut_rs2[3:0] <= 4'hA);
    end
        
    // Assume one-hotness of input op commands.
    assume(
    {dut_op_enc,dut_op_dec,dut_op_imix,dut_op_ks1,dut_op_ks2} == 5'b10000 ||
    {dut_op_enc,dut_op_dec,dut_op_imix,dut_op_ks1,dut_op_ks2} == 5'b01000 ||
    {dut_op_enc,dut_op_dec,dut_op_imix,dut_op_ks1,dut_op_ks2} == 5'b00100 ||
    {dut_op_enc,dut_op_dec,dut_op_imix,dut_op_ks1,dut_op_ks2} == 5'b00010 ||
    {dut_op_enc,dut_op_dec,dut_op_imix,dut_op_ks1,dut_op_ks2} == 5'b00001
    );

    assume(dut_rs1 == 64'h2be2f4a0bee33d19);
    assume(dut_rs2 == 64'h0848f8e92a8dc69a);

end


//
// Formal checks
always @(posedge g_clk) begin

    if(g_resetn && dut_valid && dut_ready) begin

        assert(dut_rd == grm_rd);

    end

end

//
// Submodule Instances
// ------------------------------------------------------------

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
.op_ks1     (dut_op_ks1 ), // KeySchedule1
.op_ks2     (dut_op_ks2 ), // "  "       2
.rs1        (dut_rs1    ), // Source register 1
.rs2        (dut_rs2    ), // Source register 2
.rd         (dut_rd     ), // output destination register value.
.ready      (dut_ready  )  // Compute finished?
);


//
// Instance the GRM
//
aes64_checker i_grm (
.valid      (dut_valid  ), // Are the inputs valid? Used for logic gating.
.hi         (dut_hi     ), // High (set) or low (clear) output?
.mix        (dut_mix    ), // Enable mix for enc/dec operations.
.op_enc     (dut_op_enc ), //
.op_dec     (dut_op_dec ), // 
.op_imix    (dut_op_imix), // Inverse MixColumn transformation (if set)
.op_ks1     (dut_op_ks1 ), // KeySchedule1
.op_ks2     (dut_op_ks2 ), // "  "       2
.rs1        (dut_rs1    ), // Source register 1
.rs2        (dut_rs2    ), // Source register 2
.rd         (grm_rd     ), // output destination register value.
.ready      (grm_ready  )  // Compute finished?
);


endmodule
