
module tb_aes_v1 (
input   g_clk       ,
input   g_resetn
);

//
// DUT Inputs
reg         dut_valid   = $anyseq; // Output enable.
reg         dut_dec     = $anyseq; // Encrypt (0) or decrypt (1)
reg  [31:0] dut_rs1     = $anyseq; // Input source register

// DUT Outputs
wire        dut_ready   ; // Finished computing?
wire [31:0] dut_rd      ; // Output destination register value.

// GRM outputs
wire [ 7:0] grm_0;
wire [ 7:0] grm_1;
wire [ 7:0] grm_2;
wire [ 7:0] grm_3;

wire [31:0] grm_out = {grm_3,grm_2,grm_1,grm_0};

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
        assume($stable(dut_rs1  ));
    end

end

//
// Formal checks
always @(posedge g_clk) begin
    
    //
    // Should we check that the outputs are as expected?
    if(g_resetn && dut_valid && dut_ready) begin
        assert(dut_rd[ 7: 0] == grm_0);
        assert(dut_rd[15: 8] == grm_1);
        assert(dut_rd[23:16] == grm_2);
        assert(dut_rd[31:24] == grm_3);
        assert(dut_rd        == grm_out);
    end

end

//
// Instance the DUT
//
aes_v1 i_dut (
.g_clk   (g_clk         ),
.g_resetn(g_resetn      ),
.valid   (dut_valid     ), // Output enable (logic gating SBox inputs).
.dec     (dut_dec       ), // Encrypt (0) or decrypt (1)
.rs1     (dut_rs1       ), // Input source register
.ready   (dut_ready     ), // Finished computing?
.rd      (dut_rd        )  // Output destination register value.
);


//
// SBox instances - we assume that the SBOX implementation is correct.
aes_sbox i_aes_sbox_0(.in (dut_rs1[ 7: 0]), .inv(dut_dec  ), .out(grm_0) );
aes_sbox i_aes_sbox_1(.in (dut_rs1[15: 8]), .inv(dut_dec  ), .out(grm_1) );
aes_sbox i_aes_sbox_2(.in (dut_rs1[23:16]), .inv(dut_dec  ), .out(grm_2) );
aes_sbox i_aes_sbox_3(.in (dut_rs1[31:24]), .inv(dut_dec  ), .out(grm_3) );

endmodule
