
//
// module: riscv_crypto_fu
//
//  A configurable block which implements the RISC-V cryptography
//  extension specific instructions. That is, all instructions specified
//  by the crypto extension, without the shared bitmanip instructions.
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN, and the feature enable
//  parameter name(s).
//
//  Instruction     | XLEN=32 | XLEN=64 | Feature Parameter 
//  ----------------|---------|---------|----------------------------------
//   lut4lo         |   x     |         | LUT4_EN           
//   lut4hi         |   x     |         | LUT4_EN           
//   lut4           |         |    x    | LUT4_EN           
//   saes32.encs    |   x     |         | SAES_EN
//   saes32.encsm   |   x     |         | SAES_EN     
//   saes32.decs    |   x     |         | SAES_DEC_EN     
//   saes32.decsm   |   x     |         | SAES_DEC_EN     
//   saes64.ks1     |         |    x    | SAES_EN
//   saes64.ks2     |         |    x    | SAES_EN
//   saes64.imix    |         |    x    | SAES_DEC_EN
//   saes64.encs    |         |    x    | SAES_EN
//   saes64.encsm   |         |    x    | SAES_EN
//   saes64.decs    |         |    x    | SAES_DEC_EN
//   saes64.decsm   |         |    x    | SAES_DEC_EN
//   ssha256.sig0   |   x     |    x    | SSHA256_EN
//   ssha256.sig1   |   x     |    x    | SSHA256_EN
//   ssha256.sum0   |   x     |    x    | SSHA256_EN
//   ssha256.sum1   |   x     |    x    | SSHA256_EN
//   ssha512.sum0r  |   x     |         | SSHA512_EN
//   ssha512.sum1r  |   x     |         | SSHA512_EN
//   ssha512.sig0l  |   x     |         | SSHA512_EN
//   ssha512.sig0h  |   x     |         | SSHA512_EN
//   ssha512.sig1l  |   x     |         | SSHA512_EN
//   ssha512.sig1h  |   x     |         | SSHA512_EN
//   ssha512.sig0   |         |    x    | SSHA512_EN
//   ssha512.sig1   |         |    x    | SSHA512_EN
//   ssha512.sum0   |         |    x    | SSHA512_EN
//   ssha512.sum1   |         |    x    | SSHA512_EN
//   ssm3.p0        |   x     |    x    | SSM3_EN
//   ssm3.p1        |   x     |    x    | SSM3_EN
//   ssm4.ks        |   x     |    x    | SSM4_EN
//   ssm4.ed        |   x     |    x    | SSM4_EN
//
//  Interface:
//
//  - The module works on a simple valid/ready signal interface.
//
//  - The op_* signals are one-hot, and indicate which instruction to
//    perform when valid is set.
//
//  - rs1, rs2, imm and op_* must be stable while valid is asserted and
//    ready is clear.
//
//  - When the instruction is complete, ready is asserted and rd may be
//    sampled.
//
//  - rs1, rs2, imm and op_* may change when valid and ready are asserted.
//
//  - The rd output is *not* registered. It's value may not be stable if
//    valid is de-asserted.
//
module riscv_crypto_fu #(
parameter XLEN          = 64, // Must be one of: 32, 64.
parameter LUT4_EN       = 1 , // Enable the lut4 instructions.
parameter SAES_EN       = 1 , // Enable the saes32/64 instructions.
parameter SAES_DEC_EN   = 1 , // Enable the saes32/64 decrypt instructions.
parameter SAES64_SBOXES = 8 , // saes64 sbox instances. Valid values: 8
parameter SSHA256_EN    = 1 , // Enable the ssha256.* instructions.
parameter SSHA512_EN    = 1 , // Enable the ssha256.* instructions.
parameter SSM3_EN       = 1 , // Enable the ssm3.* instructions.
parameter SSM4_EN       = 1   // Enable the ssm4.* instructions.
)(

input  wire             g_clk           , // Global clock
input  wire             g_resetn        , // Synchronous active low reset.

input  wire             valid           , // Inputs valid.
input  wire [ XLEN-1:0] rs1             , // Source register 1
input  wire [ XLEN-1:0] rs2             , // Source register 2
input  wire [      3:0] imm             , // bs, enc_rcon for aes32/64.

input  wire             op_lut4lo       , // RV32 lut4-lo instruction
input  wire             op_lut4hi       , // RV32 lut4-hi instruction
input  wire             op_lut4         , // RV64 lut4    instruction
input  wire             op_saes32_encs  , // RV32 AES Encrypt SBox
input  wire             op_saes32_encsm , // RV32 AES Encrypt SBox + MixCols
input  wire             op_saes32_decs  , // RV32 AES Decrypt SBox
input  wire             op_saes32_decsm , // RV32 AES Decrypt SBox + MixCols
input  wire             op_saes64_ks1   , // RV64 AES Encrypt KeySchedule 1
input  wire             op_saes64_ks2   , // RV64 AES Encrypt KeySchedule 2
input  wire             op_saes64_imix  , // RV64 AES Decrypt KeySchedule Mix
input  wire             op_saes64_encs  , // RV64 AES Encrypt SBox
input  wire             op_saes64_encsm , // RV64 AES Encrypt SBox + MixCols
input  wire             op_saes64_decs  , // RV64 AES Decrypt SBox
input  wire             op_saes64_decsm , // RV64 AES Decrypt SBox + MixCols
input  wire             op_ssha256_sig0 , //      SHA256 Sigma 0
input  wire             op_ssha256_sig1 , //      SHA256 Sigma 1
input  wire             op_ssha256_sum0 , //      SHA256 Sum 0
input  wire             op_ssha256_sum1 , //      SHA256 Sum 1
input  wire             op_ssha512_sum0r, // RV32 SHA512 Sum 0
input  wire             op_ssha512_sum1r, // RV32 SHA512 Sum 1
input  wire             op_ssha512_sig0l, // RV32 SHA512 Sigma 0 low
input  wire             op_ssha512_sig0h, // RV32 SHA512 Sigma 0 high
input  wire             op_ssha512_sig1l, // RV32 SHA512 Sigma 1 low
input  wire             op_ssha512_sig1h, // RV32 SHA512 Sigma 1 high
input  wire             op_ssha512_sig0 , // RV64 SHA512 Sigma 0
input  wire             op_ssha512_sig1 , // RV64 SHA512 Sigma 1
input  wire             op_ssha512_sum0 , // RV64 SHA512 Sum 0
input  wire             op_ssha512_sum1 , // RV64 SHA512 Sum 1
input  wire             op_ssm3_p0      , //      SSM3 P0
input  wire             op_ssm3_p1      , //      SSM3 P1
input  wire             op_ssm4_ks      , //      SSM4 KeySchedule
input  wire             op_ssm4_ed      , //      SSM4 Encrypt/Decrypt

output wire             ready           , // Outputs ready.
output wire [ XLEN-1:0] rd

);

//
// Local/internal parameters and useful defines:
// ------------------------------------------------------------

localparam XL   = XLEN -  1  ;
localparam RV32 = XLEN == 32 ;
localparam RV64 = XLEN == 64 ;

//
// LUT4 instructions:
// ------------------------------------------------------------

wire        lut4_valid  ;

wire [XL:0] lut4_rs1    = rs1   ;
wire [XL:0] lut4_rs2    = rs2   ;

wire        lut4_ready  ;
wire [XL:0] lut4_result ;

generate if(LUT4_EN) begin : lut4_implemented

    if(RV32) begin

        assign lut4_valid = op_lut4lo || op_lut4hi;

    end else begin
        
        assign lut4_valid = op_lut4               ;

    end

    riscv_crypto_fu_lut4 #(
        .XLEN   (XLEN)
    ) i_riscv_crypto_fu_lut4 (
        .g_clk     (g_clk       ), // Global clock
        .g_resetn  (g_resetn    ), // Synchronous active low reset.
        .valid     (lut4_valid  ), // Inputs valid.
        .rs1       (lut4_rs1    ), // Source register 1
        .rs2       (lut4_rs2    ), // Source register 2
        .op_lut4lo (op_lut4lo   ), // RV32 lut4-lo instruction
        .op_lut4hi (op_lut4hi   ), // RV32 lut4-hi instruction
        .op_lut4   (op_lut4     ), // RV64 lut4    instruction
        .ready     (lut4_ready  ), // Outputs ready.
        .rd        (lut4_result )  // Result
    );

end else begin : lut4_not_implemented

    assign lut4_result  = {XLEN{1'b0}};
    assign lut4_ready   = 1'b0;
    assign lut4_valid   = 1'b0;

end endgenerate


//
// SHA256 Instructions
// ------------------------------------------------------------

wire        ssha256_valid   ;
wire [31:0] ssha256_rs1     = rs1[31:0];
wire        ssha256_ready   ;
wire [XL:0] ssha256_result  ;

generate if(SSHA256_EN) begin : ssha256_implemented

    assign ssha256_valid = op_ssha256_sig0 || op_ssha256_sig1 ||
                           op_ssha256_sum0 || op_ssha256_sum1 ;

    riscv_crypto_fu_ssha256 #(
        .XLEN   (XLEN)
    ) i_riscv_crypto_fu_ssha256(
        .g_clk          (g_clk           ), // Global clock
        .g_resetn       (g_resetn        ), // Synchronous active low reset.
        .valid          (ssha256_valid   ), // Inputs valid.
        .rs1            (ssha256_rs1     ), // Source register 1. 32-bits.
        .op_ssha256_sig0(op_ssha256_sig0 ), //      SHA256 Sigma 0
        .op_ssha256_sig1(op_ssha256_sig1 ), //      SHA256 Sigma 1
        .op_ssha256_sum0(op_ssha256_sum0 ), //      SHA256 Sum 0
        .op_ssha256_sum1(op_ssha256_sum1 ), //      SHA256 Sum 1
        .ready          (ssha256_ready   ), // Outputs ready.
        .rd             (ssha256_result  )  // Result
    );

end else begin : ssha256_not_implemented

    assign ssha256_result = {XLEN{1'b0}};
    assign ssha256_ready  = 1'b0;
    assign ssha256_valid  = 1'b0;

end endgenerate // SSHA256_EN


//
// SHA512 Instructions
// ------------------------------------------------------------

wire        ssha512_valid   ;
wire [XL:0] ssha512_rs1     = rs1 ;
wire [XL:0] ssha512_rs2     = rs2 ;
wire        ssha512_ready   ;
wire [XL:0] ssha512_result  ;

generate if(SSHA512_EN) begin : ssha512_implemented

    if(RV32) begin

        assign ssha512_valid = op_ssha512_sum0r || op_ssha512_sum1r ||
                               op_ssha512_sig0l || op_ssha512_sig0h ||
                               op_ssha512_sig1l || op_ssha512_sig1h ;

    end else begin

        assign ssha512_valid = op_ssha512_sum0  || op_ssha512_sum1  ||
                               op_ssha512_sig0  || op_ssha512_sig1  ;

    end

    riscv_crypto_fu_ssha512 #(
        .XLEN   (XLEN)
    ) i_riscv_crypto_fu_ssha512 (
        .g_clk           (g_clk           ), // Global clock
        .g_resetn        (g_resetn        ), // Synchronous active low reset.
        .valid           (ssha512_valid   ), // Inputs valid.
        .rs1             (ssha512_rs1     ), // Source register 1. 32-bits.
        .rs2             (ssha512_rs2     ), // Source register 2. 32-bits.
        .op_ssha512_sum0r(op_ssha512_sum0r), // RV32 SHA512 Sum 0
        .op_ssha512_sum1r(op_ssha512_sum1r), // RV32 SHA512 Sum 1
        .op_ssha512_sig0l(op_ssha512_sig0l), // RV32 SHA512 Sigma 0 low
        .op_ssha512_sig0h(op_ssha512_sig0h), // RV32 SHA512 Sigma 0 high
        .op_ssha512_sig1l(op_ssha512_sig1l), // RV32 SHA512 Sigma 1 low
        .op_ssha512_sig1h(op_ssha512_sig1h), // RV32 SHA512 Sigma 1 high
        .op_ssha512_sig0 (op_ssha512_sig0 ), // RV64 SHA512 Sigma 0
        .op_ssha512_sig1 (op_ssha512_sig1 ), // RV64 SHA512 Sigma 1
        .op_ssha512_sum0 (op_ssha512_sum0 ), // RV64 SHA512 Sum 0
        .op_ssha512_sum1 (op_ssha512_sum1 ), // RV64 SHA512 Sum 1
        .ready           (ssha512_ready   ), // Outputs ready.
        .rd              (ssha512_result  )  // Result
    );

end else begin : ssha512_not_implemented

    assign ssha512_result   = {XLEN{1'b0}};
    assign ssha512_ready    = 1'b0;
    assign ssha512_valid    = 1'b0;

end endgenerate // SSHA512_EN


//
// SM3 instructions:
// ------------------------------------------------------------

wire        ssm3_valid   ;
wire [31:0] ssm3_rs1     = rs1[31:0];
wire        ssm3_ready   ;
wire [XL:0] ssm3_result  ;

generate if(SSHA256_EN) begin : ssm3_implemented

    assign ssm3_valid   = op_ssm3_p0 || op_ssm3_p1 ;

    riscv_crypto_fu_ssm3 #(
        .XLEN   (XLEN)
    ) i_riscv_crypto_fu_ssm3(
        .g_clk      (g_clk        ), // Global clock
        .g_resetn   (g_resetn     ), // Synchronous active low reset.
        .valid      (ssm3_valid   ), // Inputs valid.
        .rs1        (ssm3_rs1     ), // Source register 1. 32-bits.
        .op_ssm3_p0 (op_ssm3_p0   ), //      SSM3 P0
        .op_ssm3_p1 (op_ssm3_p1   ), //      SSM3 P1
        .ready      (ssm3_ready   ), // Outputs ready.
        .rd         (ssm3_result  )  // Result
    );

end else begin : ssm3_not_implemented

    assign ssm3_result  = {XLEN{1'b0}};
    assign ssm3_ready   = 1'b0;
    assign ssm3_valid   = 1'b0;

end endgenerate // SSHA256_EN

//
// AES 64-bit instructions
// ------------------------------------------------------------

wire        saes64_valid    ;

wire [XL:0] saes64_rs1      = rs1;
wire [XL:0] saes64_rs2      = rs2;
wire [ 3:0] saes64_enc_rcon = imm;
wire        saes64_ready    ;
wire [XL:0] saes64_result   ;

generate if(SAES_EN && RV64) begin  : saes64_implemented

    if(SAES_DEC_EN) begin

        assign saes64_valid = op_saes64_ks1   || op_saes64_ks2   ||
                              op_saes64_imix  || op_saes64_encs  ||
                              op_saes64_encsm || op_saes64_decs  ||
                              op_saes64_decsm ;

    end else begin

        assign saes64_valid = op_saes64_ks1   || op_saes64_ks2   ||
                              op_saes64_encs  || op_saes64_encsm ;

    end

    riscv_crypto_fu_saes64 #(
        .SAES_DEC_EN  (SAES_DEC_EN  ), // Enable saes64 decrypt instructions.
        .SAES64_SBOXES(SAES64_SBOXES)  // sbox instances. Valid values: 8
    ) i_riscv_crypto_fu_saes64 (
        .g_clk          (g_clk          ), // Global clock
        .g_resetn       (g_resetn       ), // Synchronous active low reset.
        .valid          (saes64_valid   ), // Are the inputs valid?
        .rs1            (saes64_rs1     ), // Source register 1
        .rs2            (saes64_rs2     ), // Source register 2
        .enc_rcon       (saes64_enc_rcon), // rcon immediate for ks1
        .op_saes64_ks1  (op_saes64_ks1  ), // RV64 AES Encrypt KeySchedule 1
        .op_saes64_ks2  (op_saes64_ks2  ), // RV64 AES Encrypt KeySchedule 2
        .op_saes64_imix (op_saes64_imix ), // RV64 AES Decrypt KeySchedule Mix
        .op_saes64_encs (op_saes64_encs ), // RV64 AES Encrypt SBox
        .op_saes64_encsm(op_saes64_encsm), // RV64 AES Encrypt SBox + MixCols
        .op_saes64_decs (op_saes64_decs ), // RV64 AES Decrypt SBox
        .op_saes64_decsm(op_saes64_decsm), // RV64 AES Decrypt SBox + MixCols
        .rd             (saes64_result  ), // output register value.
        .ready          (saes64_ready   )  // Compute finished?
    );

end else begin : saes64_not_implemented

    assign saes64_ready     = 1'b0;
    assign saes64_result    = {XLEN{1'b0}};
    assign saes64_valid     = 1'b0;

end endgenerate


//
// AES 32-bit instructions
// ------------------------------------------------------------

wire        saes32_valid    ;
wire [XL:0] saes32_rs1      = rs1       ;
wire [XL:0] saes32_rs2      = rs2       ;
wire [ 1:0] saes32_bs       = imm[1:0]  ;
wire        saes32_ready    ;
wire [XL:0] saes32_result   ;

generate if(SAES_EN && RV32) begin: saes32_implemented
        
    if(SAES_DEC_EN) begin

        assign saes32_valid = op_saes32_encs  || op_saes32_encsm ||
                              op_saes32_decs  || op_saes32_decsm ;

    end else begin

        assign saes32_valid = op_saes32_encs  || op_saes32_encsm ;

    end

    riscv_crypto_fu_saes32 #(
        .SAES_DEC_EN(SAES_DEC_EN)  // Enable the saes32 decrypt instructions.
    ) i_riscv_crypto_fu_aes32 (
        .valid          (saes32_valid   ), // Are the inputs valid?
        .rs1            (saes32_rs1     ), // Source register 1
        .rs2            (saes32_rs2     ), // Source register 2
        .bs             (saes32_bs      ), // Byte select immediate
        .op_saes32_encs (op_saes32_encs ), // Encrypt SubBytes
        .op_saes32_encsm(op_saes32_encsm), // Encrypt SubBytes + MixColumn
        .op_saes32_decs (op_saes32_decs ), // Decrypt SubBytes
        .op_saes32_decsm(op_saes32_decsm), // Decrypt SubBytes + MixColumn
        .rd             (saes32_result  ), // output register value.
        .ready          (saes32_ready   )  // Compute finished?
    );

end else begin : saes32_not_implemented

    assign saes32_ready     = 1'b0;
    assign saes32_result    = {XLEN{1'b0}};
    assign saes32_valid     = 1'b1;

end endgenerate

//
// SSM4 Instructions
// ------------------------------------------------------------

wire        ssm4_valid    ;
wire [31:0] ssm4_rs1      = rs1[31:0];
wire [31:0] ssm4_rs2      = rs2[31:0];
wire [ 1:0] ssm4_bs       = imm[ 1:0];
wire        ssm4_ready    ;
wire [XL:0] ssm4_result   ;

generate if(SSM4_EN) begin: ssm4_implemented

    wire [31:0] ssm4_rd32  ;

    assign      ssm4_valid = op_ssm4_ks || op_ssm4_ed;

    riscv_crypto_fu_ssm4 i_riscv_crypto_fu_ssm4 (
        .valid     (ssm4_valid  ), // Inputs valid?
        .rs1       (ssm4_rs1    ), // Source register 1
        .rs2       (ssm4_rs2    ), // Source register 2
        .bs        (ssm4_bs     ), // Byte select
        .op_ssm4_ks(op_ssm4_ks  ), // Do ssm4.ks instruction
        .op_ssm4_ed(op_ssm4_ed  ), // Do ssm4.ed instruction
        .result    (ssm4_rd32   ), // Writeback result
        .ready     (ssm4_ready  )  //
    );

    if(RV64) begin
        
        assign ssm4_result = {32'b0, ssm4_rd32};

    end else begin
        
        assign ssm4_result = {       ssm4_rd32};

    end

end else begin : ssm4_not_implemented

    assign ssm4_ready   = 1'b0;
    assign ssm4_result  = {XLEN{1'b0}};
    assign ssm4_valid   = 1'b0;

end endgenerate


//
// Result multiplexing.
// ------------------------------------------------------------

assign ready =
    lut4_ready      ||
    ssha256_ready   ||
    ssha512_ready   ||
    saes32_ready    ||
    saes64_ready    ||
    ssm3_ready      ||
    ssm4_ready      ;

assign rd   =
    {XLEN{lut4_valid   }} & lut4_result     |
    {XLEN{ssha256_valid}} & ssha256_result  |
    {XLEN{ssha512_valid}} & ssha512_result  |
    {XLEN{saes32_valid }} & saes32_result   |
    {XLEN{saes64_valid }} & saes64_result   |
    {XLEN{ssm3_valid   }} & ssm3_result     |
    {XLEN{ssm4_valid   }} & ssm4_result     ;

endmodule // riscv_crypto_fu

