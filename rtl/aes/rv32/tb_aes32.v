
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
// DUT Interface
// ------------------------------------------------------------

//
// DUT Inputs
reg         dut_valid   = $anyseq; // Output enable.
reg         dut_op_encs = $anyseq; // Encrypt SubBytes
reg         dut_op_encsm= $anyseq; // Encrypt SubBytes + MixColumn
reg         dut_op_decs = $anyseq; // Decrypt SubBytes
reg         dut_op_decsm= $anyseq; // Decrypt SubBytes + MixColumn
reg  [31:0] dut_rs1     = $anyseq; // Input source register
reg  [31:0] dut_rs2     = $anyseq; // Input source register
reg  [ 1:0] dut_bs      = $anyseq; // Byte Select

// DUT Outputs
wire        dut_ready   ; // Finished computing?
wire [31:0] dut_rd      ; // Output destination register value.

// GRM Outputs
wire        grm_ready   ; // Finished computing - always single cycle.
wire [31:0] grm_rd      ; // Golden model output


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
        assume($stable(dut_valid    ));
        assume($stable(dut_op_encs  ));
        assume($stable(dut_op_encsm ));
        assume($stable(dut_op_decs  ));
        assume($stable(dut_op_decsm ));
        assume($stable(dut_rs1      ));
        assume($stable(dut_rs2      ));
        assume($stable(dut_bs       ));
    end

end


//
// Formal checks
always @(posedge g_clk) begin
    
    //
    // Should we check that the outputs are as expected?
    if(g_resetn && dut_valid && dut_ready) begin

        assert(dut_rd == grm_rd);

    end

end

//
// Instance the DUT
//
aes32 i_dut (
.valid      (dut_valid      ), // Are the inputs valid? Used for logic gating.
.op_encs    (dut_op_encs    ), // Encrypt SubBytes
.op_encsm   (dut_op_encsm   ), // Encrypt SubBytes + MixColumn
.op_decs    (dut_op_decs    ), // Decrypt SubBytes
.op_decsm   (dut_op_decsm   ), // Decrypt SubBytes + MixColumn
.rs1        (dut_rs1        ), // Source register 1
.rs2        (dut_rs2        ), // Source register 2
.bs         (dut_bs         ), // Byte select immediate
.rd         (dut_rd         ), // output destination register value.
.ready      (dut_ready      )
);

//
// Instance the GRM
//
aes32_checker i_grm (
.valid      (dut_valid      ), // Are the inputs valid? Used for logic gating.
.op_encs    (dut_op_encs    ), // Encrypt SubBytes
.op_encsm   (dut_op_encsm   ), // Encrypt SubBytes + MixColumn
.op_decs    (dut_op_decs    ), // Decrypt SubBytes
.op_decsm   (dut_op_decsm   ), // Decrypt SubBytes + MixColumn
.rs1        (dut_rs1        ), // Source register 1
.rs2        (dut_rs2        ), // Source register 2
.bs         (dut_bs         ), // Byte select immediate
.rd         (grm_rd         ), // output destination register value.
.ready      (grm_ready      )
);

endmodule
