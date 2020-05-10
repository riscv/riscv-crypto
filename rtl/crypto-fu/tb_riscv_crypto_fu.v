
// 
// Copyright (C) 2020 
//    SCARV Project  <info@scarv.org>
//    Ben Marshall   <ben.marshall@bristol.ac.uk>
// 
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
// IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

//
// module: tb_riscv_crypto_fu
//
//  Formal testbench for the riscv crypto functional unit.
//
module tb_riscv_crypto_fu (

input dut_g_clk     ,
input dut_g_resetn

);

//
// DUT Parameters
// ------------------------------------------------------------

// `XLEN set by verify.sby depending on job type.
parameter XLEN          = `XLEN ; // Must be one of: 32, 64.
parameter LUT4_EN       = 1     ; // Enable the lut4 instructions.
parameter SAES_EN       = 1     ; // Enable the saes32/64 instructions.
parameter SAES_DEC_EN   = 1     ; // Enable the saes32/64 decrypt instructions.
parameter SAES64_SBOXES =`SBOXES; // saes64 sbox instances. Valid values: 8
parameter SSHA256_EN    = 1     ; // Enable the ssha256.* instructions.
parameter SSHA512_EN    = 1     ; // Enable the ssha256.* instructions.
parameter SSM3_EN       = 1     ; // Enable the ssm3.* instructions.
parameter SSM4_EN       = 1     ; // Enable the ssm4.* instructions.

localparam XL   = XLEN -  1 ;
localparam RV32 = XLEN == 32;
localparam RV64 = XLEN == 64;

//
// DUT Inputs
// ------------------------------------------------------------


reg             dut_valid           = $anyseq; // Inputs valid.
reg [ XLEN-1:0] dut_rs1             = $anyseq; // Source register 1
reg [ XLEN-1:0] dut_rs2             = $anyseq; // Source register 2
reg [      3:0] dut_imm             = $anyseq; // bs, enc_rcon for aes32/64.

reg             dut_op_lut4lo       = RV32 && LUT4_EN     ? $anyseq : 1'b0;
reg             dut_op_lut4hi       = RV32 && LUT4_EN     ? $anyseq : 1'b0;
reg             dut_op_lut4         = RV64 && LUT4_EN     ? $anyseq : 1'b0;
reg             dut_op_saes32_encs  = RV32 && SAES_EN     ? $anyseq : 1'b0;
reg             dut_op_saes32_encsm = RV32 && SAES_EN     ? $anyseq : 1'b0;
reg             dut_op_saes32_decs  = RV32 && SAES_DEC_EN ? $anyseq : 1'b0;
reg             dut_op_saes32_decsm = RV32 && SAES_DEC_EN ? $anyseq : 1'b0;
reg             dut_op_saes64_ks1   = RV64 && SAES_EN     ? $anyseq : 1'b0;
reg             dut_op_saes64_ks2   = RV64 && SAES_EN     ? $anyseq : 1'b0;
reg             dut_op_saes64_imix  = RV64 && SAES_DEC_EN ? $anyseq : 1'b0;
reg             dut_op_saes64_encs  = RV64 && SAES_EN     ? $anyseq : 1'b0;
reg             dut_op_saes64_encsm = RV64 && SAES_EN     ? $anyseq : 1'b0;
reg             dut_op_saes64_decs  = RV64 && SAES_DEC_EN ? $anyseq : 1'b0;
reg             dut_op_saes64_decsm = RV64 && SAES_DEC_EN ? $anyseq : 1'b0;
reg             dut_op_ssha256_sig0 =         SSHA256_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha256_sig1 =         SSHA256_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha256_sum0 =         SSHA256_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha256_sum1 =         SSHA256_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sum0r= RV32 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sum1r= RV32 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sig0l= RV32 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sig0h= RV32 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sig1l= RV32 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sig1h= RV32 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sig0 = RV64 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sig1 = RV64 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sum0 = RV64 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssha512_sum1 = RV64 && SSHA512_EN  ? $anyseq : 1'b0;
reg             dut_op_ssm3_p0      =         SSM3_EN     ? $anyseq : 1'b0;
reg             dut_op_ssm3_p1      =         SSM3_EN     ? $anyseq : 1'b0;
reg             dut_op_ssm4_ks      =         SSM4_EN     ? $anyseq : 1'b0;
reg             dut_op_ssm4_ed      =         SSM4_EN     ? $anyseq : 1'b0;

wire            dut_ready           ; // Outputs ready.
wire[ XLEN-1:0] dut_rd              ;

//
// Modelling
// ------------------------------------------------------------

wire             grm_saes_valid ;
wire             grm_saes_ready ;

generate if(RV32 && SAES_EN) begin
    assign grm_saes_valid = dut_valid && (
        dut_op_saes32_encs  || dut_op_saes32_encsm ||
        dut_op_saes32_decs  || dut_op_saes32_decsm
    );
end else if(RV64 && SAES_EN) begin
    assign grm_saes_valid = dut_valid && (
        dut_op_saes64_ks1   || dut_op_saes64_ks2   ||
        dut_op_saes64_imix  ||
        dut_op_saes64_encs  || dut_op_saes64_encsm ||
        dut_op_saes64_decs  || dut_op_saes64_decsm
    );
end else begin
    assign grm_saes_valid = 1'b0;
end endgenerate

wire             grm_lut4_valid = RV64 ? dut_op_lut4                    :
                                         dut_op_lut4lo || dut_op_lut4hi ;
wire             grm_lut4_ready = grm_lut4_valid ;

wire             grm_ssm4_valid = dut_op_ssm4_ks || dut_op_ssm4_ed      ;

wire [XLEN-1:0]  grm_saes_rd    ;
wire [XLEN-1:0]  grm_lut4_rd    ;
wire [    31:0]  grm_ssm4_rd    ;

reg  [XLEN-1:0]  grm_rd         ;

//
// Formal environment assumptions
// ------------------------------------------------------------

// Assume we start in reset.
initial assume(dut_g_resetn ==1'b0 );

//
// Formal Cover statements
always @(posedge dut_g_clk) if(dut_g_resetn) begin

    // Do we ever run anything?
    cover(dut_valid             );

    // Do we ever finish?
    cover(dut_valid && dut_ready);

end

//
// Make sure that the op_* inputs are one-hot.
// There must be a better way??

wire [31:0] op_inputs = {
    dut_op_lut4lo       , dut_op_lut4hi       , dut_op_lut4         ,
    dut_op_saes32_encs  , dut_op_saes32_encsm , dut_op_saes32_decs  ,
    dut_op_saes32_decsm , dut_op_saes64_ks1   , dut_op_saes64_ks2   ,
    dut_op_saes64_imix  , dut_op_saes64_encs  , dut_op_saes64_encsm ,
    dut_op_saes64_decs  , dut_op_saes64_decsm , dut_op_ssha256_sig0 ,
    dut_op_ssha256_sig1 , dut_op_ssha256_sum0 , dut_op_ssha256_sum1 ,
    dut_op_ssha512_sum0r, dut_op_ssha512_sum1r, dut_op_ssha512_sig0l,
    dut_op_ssha512_sig0h, dut_op_ssha512_sig1l, dut_op_ssha512_sig1h,
    dut_op_ssha512_sig0 , dut_op_ssha512_sig1 , dut_op_ssha512_sum0 ,
    dut_op_ssha512_sum1 , dut_op_ssm3_p0      , dut_op_ssm3_p1      ,
    dut_op_ssm4_ks      , dut_op_ssm4_ed      
};

reg [4:0] ops_active;
integer idx;

always @(posedge dut_g_clk) begin
    // Assume only one reset event
    if($past(dut_g_resetn)) assume(dut_g_resetn);
end

//
// DUT input stability
always @(posedge dut_g_clk) begin
  
    ops_active= 0;
    for( idx = 0; idx<32; idx = idx + 1) begin
        ops_active= ops_active + op_inputs[idx];
    end
    
    // Always one op active.
    if(dut_valid) begin
        assume(ops_active == 1);
    end
    
    //
    // Constraints
    if($past(dut_valid) && $past(!dut_ready)) begin
        // If the TB is waiting for the DUT to compute an output,
        // make sure that the inputs are stable.
        assume(        dut_valid            );
        assume($stable(dut_rs1             ));
        assume($stable(dut_rs2             ));
        assume($stable(dut_imm             ));
        assume($stable(dut_op_lut4lo       ));
        assume($stable(dut_op_lut4hi       ));
        assume($stable(dut_op_lut4         ));
        assume($stable(dut_op_saes32_encs  ));
        assume($stable(dut_op_saes32_encsm ));
        assume($stable(dut_op_saes32_decs  ));
        assume($stable(dut_op_saes32_decsm ));
        assume($stable(dut_op_saes64_ks1   ));
        assume($stable(dut_op_saes64_ks2   ));
        assume($stable(dut_op_saes64_imix  ));
        assume($stable(dut_op_saes64_encs  ));
        assume($stable(dut_op_saes64_encsm ));
        assume($stable(dut_op_saes64_decs  ));
        assume($stable(dut_op_saes64_decsm ));
        assume($stable(dut_op_ssha256_sig0 ));
        assume($stable(dut_op_ssha256_sig1 ));
        assume($stable(dut_op_ssha256_sum0 ));
        assume($stable(dut_op_ssha256_sum1 ));
        assume($stable(dut_op_ssha512_sum0r));
        assume($stable(dut_op_ssha512_sum1r));
        assume($stable(dut_op_ssha512_sig0l));
        assume($stable(dut_op_ssha512_sig0h));
        assume($stable(dut_op_ssha512_sig1l));
        assume($stable(dut_op_ssha512_sig1h));
        assume($stable(dut_op_ssha512_sig0 ));
        assume($stable(dut_op_ssha512_sig1 ));
        assume($stable(dut_op_ssha512_sum0 ));
        assume($stable(dut_op_ssha512_sum1 ));
        assume($stable(dut_op_ssm3_p0      ));
        assume($stable(dut_op_ssm3_p1      ));
        assume($stable(dut_op_ssm4_ks      ));
        assume($stable(dut_op_ssm4_ed      ));
    end
    
    // Valid values for saes64_ks1
    if(dut_op_saes64_ks1) begin
        assume(dut_imm[3:0] <= 4'hA);
    end
    
    // Tame the problem space for now.
    if(RV64) begin

        assume(dut_rs1 == 64'h0102030405060708);
        assume(dut_rs2 == 64'h090a0b0c0d0e0f00);

    end else if(RV32) begin

        assume(dut_rs1 == 32'h01020304);
        assume(dut_rs2 == 32'h090a0b0c);

    end

    //
    // Formal checks
                

    if(dut_g_resetn && dut_valid && dut_ready) begin
            
        if(grm_saes_valid) begin    : check_saes

            assert(dut_rd == grm_saes_rd);
            cover (dut_rd == grm_saes_rd);

            if(RV32) begin
                cover(dut_op_saes32_encs );
                cover(dut_op_saes32_decs );
                cover(dut_op_saes32_encsm);
                cover(dut_op_saes32_decsm);
            end else if(RV64) begin
                cover(dut_op_saes64_ks1  );
                cover(dut_op_saes64_ks2  );
                cover(dut_op_saes64_imix );
                cover(dut_op_saes64_encs );
                cover(dut_op_saes64_encsm);
                cover(dut_op_saes64_decs );
                cover(dut_op_saes64_decsm);
            end

        end else if(grm_lut4_valid) begin : check_lut4

            assert(dut_rd == grm_lut4_rd);
            cover (dut_rd == grm_lut4_rd);
            
            if(RV32) begin
                
                cover(dut_op_lut4lo);
                cover(dut_op_lut4hi);

            end else if(RV64) begin
                
                cover(dut_op_lut4  );

            end

        end else if(grm_ssm4_valid) begin: check_ssm4

            if(RV64) begin
                assert(dut_rd == {32'b0,grm_ssm4_rd});
                cover (dut_rd == {32'b0,grm_ssm4_rd});
            end else if(RV32) begin
                assert(dut_rd ==        grm_ssm4_rd );
                cover (dut_rd ==        grm_ssm4_rd );
            end
            cover (dut_op_ssm4_ks       );
            cover (dut_op_ssm4_ed       );

        end

    end

end


//
// DUT Instance
// ------------------------------------------------------------

riscv_crypto_fu #(
.XLEN         (XLEN         ), // Must be one of: 32, 64.
.LUT4_EN      (LUT4_EN      ), // Enable the lut4 instructions.
.SAES_EN      (SAES_EN      ), // Enable the saes32/64 instructions.
.SAES_DEC_EN  (SAES_DEC_EN  ), // Enable the saes32/64 decrypt instructions.
.SAES64_SBOXES(SAES64_SBOXES), // saes64 sbox instances. Valid values: 8
.SSHA256_EN   (SSHA256_EN   ), // Enable the ssha256.* instructions.
.SSHA512_EN   (SSHA512_EN   ), // Enable the ssha256.* instructions.
.SSM3_EN      (SSM3_EN      ), // Enable the ssm3.* instructions.
.SSM4_EN      (SSM4_EN      )  // Enable the ssm4.* instructions.
) i_dut (
.g_clk           (dut_g_clk           ), // Global clock
.g_resetn        (dut_g_resetn        ), // Synchronous active low reset.
.valid           (dut_valid           ), // Inputs valid.
.rs1             (dut_rs1             ), // Source register 1
.rs2             (dut_rs2             ), // Source register 2
.imm             (dut_imm             ), // bs, enc_rcon for aes32/64.
.op_lut4lo       (dut_op_lut4lo       ), // RV32 lut4-lo instruction
.op_lut4hi       (dut_op_lut4hi       ), // RV32 lut4-hi instruction
.op_lut4         (dut_op_lut4         ), // RV64 lut4    instruction
.op_saes32_encs  (dut_op_saes32_encs  ), // RV32 AES Encrypt SBox
.op_saes32_encsm (dut_op_saes32_encsm ), // RV32 AES Encrypt SBox + MixCols
.op_saes32_decs  (dut_op_saes32_decs  ), // RV32 AES Decrypt SBox
.op_saes32_decsm (dut_op_saes32_decsm ), // RV32 AES Decrypt SBox + MixCols
.op_saes64_ks1   (dut_op_saes64_ks1   ), // RV64 AES Encrypt KeySchedule 1
.op_saes64_ks2   (dut_op_saes64_ks2   ), // RV64 AES Encrypt KeySchedule 2
.op_saes64_imix  (dut_op_saes64_imix  ), // RV64 AES Decrypt KeySchedule Mix
.op_saes64_encs  (dut_op_saes64_encs  ), // RV64 AES Encrypt SBox
.op_saes64_encsm (dut_op_saes64_encsm ), // RV64 AES Encrypt SBox + MixCols
.op_saes64_decs  (dut_op_saes64_decs  ), // RV64 AES Decrypt SBox
.op_saes64_decsm (dut_op_saes64_decsm ), // RV64 AES Decrypt SBox + MixCols
.op_ssha256_sig0 (dut_op_ssha256_sig0 ), //      SHA256 Sigma 0
.op_ssha256_sig1 (dut_op_ssha256_sig1 ), //      SHA256 Sigma 1
.op_ssha256_sum0 (dut_op_ssha256_sum0 ), //      SHA256 Sum 0
.op_ssha256_sum1 (dut_op_ssha256_sum1 ), //      SHA256 Sum 1
.op_ssha512_sum0r(dut_op_ssha512_sum0r), // RV32 SHA512 Sum 0
.op_ssha512_sum1r(dut_op_ssha512_sum1r), // RV32 SHA512 Sum 1
.op_ssha512_sig0l(dut_op_ssha512_sig0l), // RV32 SHA512 Sigma 0 low
.op_ssha512_sig0h(dut_op_ssha512_sig0h), // RV32 SHA512 Sigma 0 high
.op_ssha512_sig1l(dut_op_ssha512_sig1l), // RV32 SHA512 Sigma 1 low
.op_ssha512_sig1h(dut_op_ssha512_sig1h), // RV32 SHA512 Sigma 1 high
.op_ssha512_sig0 (dut_op_ssha512_sig0 ), // RV64 SHA512 Sigma 0
.op_ssha512_sig1 (dut_op_ssha512_sig1 ), // RV64 SHA512 Sigma 1
.op_ssha512_sum0 (dut_op_ssha512_sum0 ), // RV64 SHA512 Sum 0
.op_ssha512_sum1 (dut_op_ssha512_sum1 ), // RV64 SHA512 Sum 1
.op_ssm3_p0      (dut_op_ssm3_p0      ), //      SSM3 P0
.op_ssm3_p1      (dut_op_ssm3_p1      ), //      SSM3 P1
.op_ssm4_ks      (dut_op_ssm4_ks      ), //      SSM4 KeySchedule
.op_ssm4_ed      (dut_op_ssm4_ed      ), //      SSM4 Encrypt/Decrypt
.ready           (dut_ready           ), // Outputs ready.
.rd              (dut_rd              )
);


//
// Model checker instances.
// ------------------------------------------------------------

generate if(RV32) begin : checker_model_aes32

tb_checker_saes32 i_tb_checker_saes32 (
.valid   (grm_saes_valid     ), // Are inputs valid?
.op_encs (dut_op_saes32_encs ), // Encrypt SubBytes
.op_encsm(dut_op_saes32_encsm), // Encrypt SubBytes + MixColumn
.op_decs (dut_op_saes32_decs ), // Decrypt SubBytes
.op_decsm(dut_op_saes32_decsm), // Decrypt SubBytes + MixColumn
.rs1     (dut_rs1            ), // Source register 1
.rs2     (dut_rs2            ), // Source register 2
.bs      (dut_imm[1:0]       ), // Byte select immediate
.rd      (grm_saes_rd      ), // output destination register value.
.ready   (grm_saes_ready   )  // Compute finished?
);


end else begin : checker_model_aes64

wire dut_saes64_mix = dut_op_saes64_encsm || dut_op_saes64_decsm;
wire dut_saes64_enc = dut_op_saes64_encsm || dut_op_saes64_encs ;
wire dut_saes64_dec = dut_op_saes64_decsm || dut_op_saes64_decs ;

tb_checker_saes64 i_tb_checker_saes64 (
.valid   (grm_saes_valid     ), // Are the inputs valid?
.mix     (dut_saes64_mix     ), // Mix enable for op_enc/op_dec
.op_enc  (dut_saes64_enc     ), // Encrypt
.op_dec  (dut_saes64_dec     ), // Decrypt
.op_imix (dut_op_saes64_imix ), // Inverse MixColumn transformation (if set)
.op_ks1  (dut_op_saes64_ks1  ), // KeySchedule 1
.op_ks2  (dut_op_saes64_ks2  ), // KeySchedule 2
.rs1     (dut_rs1            ), // Source register 1
.rs2     (dut_rs2            ), // Source register 2
.enc_rcon(dut_imm            ),
.rd      (grm_saes_rd      ), // output destination register value.
.ready   (grm_saes_ready   )  // Compute finished?
);

end endgenerate

generate if(RV32) begin : checker_model_lut4_rv32

tb_checker_lut4_rv32 i_checker_lut4_rv32 (
.rs1(dut_rs1        ),
.rs2(dut_rs2        ),
.hi (dut_op_lut4hi  ),
.rd (grm_lut4_rd    )
);

end else if(RV64) begin : checker_model_lut4_rv64

tb_checker_lut4_rv64 i_checker_lut4_rv64 (
.rs1(dut_rs1        ),
.rs2(dut_rs2        ),
.rd (grm_lut4_rd    )
);

end endgenerate


tb_checker_ssm4 i_tb_checker_ssm4 (
.rs1         (dut_rs1[31:0]   ), // Source register 1
.rs2         (dut_rs2[31:0]   ), // Source register 2
.bs          (dut_imm[1:0]    ), // Byte select
.op_ssm4_ks  (dut_op_ssm4_ks  ), // Do ssm4.ks instruction
.op_ssm4_ed  (dut_op_ssm4_ed  ), // Do ssm4.ed instruction
.result      (grm_ssm4_rd     ), // Writeback result
);


endmodule

