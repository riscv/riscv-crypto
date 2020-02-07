
//
// module: aes_v2_sub_size
//
//  Implements the lightweight AES SubBytes instructions.
//  Optimised for small size, instances 1 sbox and saves intermediate values.
//
module aes_v2_sub_size (

input  wire        g_clk    ,
input  wire        g_resetn ,

input  wire        valid    , // Are the inputs valid?
input  wire [31:0] rs1      , // Input source register 1
input  wire [31:0] rs2      , // Input source register 2
input  wire        enc      , // Perform encrypt (set) or decrypt (clear).
input  wire        rot      , // Perform encrypt (set) or decrypt (clear).
output wire        ready    , // Is the instruction complete?
output wire [31:0] rd         // 

);


reg  [1:0] fsm     ;
wire [1:0] n_fsm   = fsm + 1 ;

wire       fsm_0   = fsm == 0;
wire       fsm_1   = fsm == 1;
wire       fsm_2   = fsm == 2;
wire       fsm_3   = fsm == 3;

wire [7:0] sbox_in = 
    {8{fsm_0}} & rs1[ 7: 0] |
    {8{fsm_1}} & rs2[15: 8] |
    {8{fsm_2}} & rs1[23:16] |
    {8{fsm_3}} & rs2[31:24] ;

wire [7:0] sbox_out;

assign     ready   = fsm_3;

reg [7:0]  b_0;
reg [7:0]  b_1;
reg [7:0]  b_2;

assign     rd      = rot ? {b_2, b_1, b_0, sbox_out} :
                           {sbox_out, b_2, b_1, b_0} ;

always @(posedge g_clk ) begin
    if(g_resetn) begin
        b_0 <= 8'b0;
    end else if(fsm_0 && valid) begin
        b_0 <= sbox_out;
    end
end

always @(posedge g_clk ) begin
    if(g_resetn) begin
        b_1 <= 8'b0;
    end else if(fsm_1 && valid) begin
        b_1 <= sbox_out;
    end
end

always @(posedge g_clk ) begin
    if(g_resetn) begin
        b_2 <= 8'b0;
    end else if(fsm_2 && valid) begin
        b_2 <= sbox_out;
    end
end

always @(posedge g_clk ) begin
    if(g_resetn) begin
        fsm <= 2'b0;
    end else if(valid && !ready) begin
        fsm <= n_fsm;
    end
end

aes_sbox sbox_0(
.in  (sbox_in ), // Input byte
.inv (!enc    ), // Perform inverse (set) or forward lookup
.out (sbox_out)  // Output byte
);

endmodule

