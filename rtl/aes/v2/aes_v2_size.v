
//
// module: aes_v2_size
//
module aes_v2_size(

input  wire        g_clk    ,
input  wire        g_resetn ,

input  wire        valid    , // Are the inputs valid?
input  wire        sub      , // Sub if set, Mix if clear
input  wire [31:0] rs1      , // Input source register 1
input  wire [31:0] rs2      , // Input source register 2
input  wire        enc      , // Perform encrypt (set) or decrypt (clear).
input  wire        rot      , // Perform encrypt (set) or decrypt (clear).
output wire        ready    , // Is the instruction complete?
output wire [31:0] rd         // 

);

wire        ready_sub   ;
wire        ready_mix   ;
wire [31:0] rd_sub      ;
wire [31:0] rd_mix      ;

assign ready = sub ? ready_sub : ready_mix;
assign rd    = sub ? rd_sub    : rd_mix   ;

aes_v2_sub_size i_sub (
.g_clk    (g_clk    ),
.g_resetn (g_resetn ),
.valid    (valid    ), // Are the inputs valid?
.rs1      (rs1      ), // Input source register 1
.rs2      (rs2      ), // Input source register 2
.enc      (enc      ), // Perform encrypt (set) or decrypt (clear).
.rot      (rot      ), // Perform encrypt (set) or decrypt (clear).
.ready    (ready_sub), // Is the instruction complete?
.rd       (rd_sub   )  // 
);

aes_v2_mix_size i_mix (
.g_clk    (g_clk    ),
.g_resetn (g_resetn ),
.valid    (valid    ), // Are the inputs valid?
.rs1      (rs1      ), // Input source register 1
.rs2      (rs2      ), // Input source register 2
.enc      (enc      ), // Perform encrypt (set) or decrypt (clear).
.ready    (ready_mix), // Is the instruction complete?
.rd       (rd_mix   )  // 
);

endmodule

