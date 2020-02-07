
//
// module: ssha3
//
//  Implements the specialised sha3 indexing functions.
//  - All of the f_* inputs must be 1-hot.
//
module ssha3 (

input  wire [31:0] rs1      , // Input source register 1
input  wire [31:0] rs2      , // Input source register 2

// One hot function select wires
input  wire        f_xy     , // ssha3.xy instruction function
input  wire        f_x1     , // ssha3.x1 instruction function
input  wire        f_x2     , // ssha3.x2 instruction function
input  wire        f_x4     , // ssha3.x4 instruction function
input  wire        f_yx     , // ssha3.yx instruction function

output wire [31:0] result     //

);
/* verilator lint_off WIDTH */

wire [2:0] in_x         = rs1[2:0];
wire [2:0] in_y         = rs2[2:0];

wire [3:0] in_x_plus    = in_x + {f_x4,f_x2,f_x1};
wire [4:0] in_y_plus    = {in_x, 1'b0} + {{2'b00,in_y,1'b0} + in_y};

wire [3:0] lut_in_lhs   = in_x_plus ;
wire [4:0] lut_in_rhs   = in_y_plus ;

wire [2:0] lut_out_lhs  = 
    {3{lut_in_lhs == 0}} & 3'd0 |
    {3{lut_in_lhs == 1}} & 3'd1 |
    {3{lut_in_lhs == 2}} & 3'd2 |
    {3{lut_in_lhs == 3}} & 3'd3 |
    {3{lut_in_lhs == 4}} & 3'd4 |
    {3{lut_in_lhs == 5}} & 3'd0 |
    {3{lut_in_lhs == 6}} & 3'd1 |
    {3{lut_in_lhs == 7}} & 3'd2 |
    {3{lut_in_lhs == 8}} & 3'd3 ;

wire [2:0] lut_out_rhs  = 
    {3{lut_in_rhs == 0}} & 3'd0 |
    {3{lut_in_rhs == 1}} & 3'd1 |
    {3{lut_in_rhs == 2}} & 3'd2 |
    {3{lut_in_rhs == 3}} & 3'd3 |
    {3{lut_in_rhs == 4}} & 3'd4 |
    {3{lut_in_rhs == 5}} & 3'd0 |
    {3{lut_in_rhs == 6}} & 3'd1 |
    {3{lut_in_rhs == 7}} & 3'd2 |
    {3{lut_in_rhs == 8}} & 3'd3 |
    {3{lut_in_rhs == 9}} & 3'd4 |
    {3{lut_in_rhs ==10}} & 3'd0 |
    {3{lut_in_rhs ==11}} & 3'd1 |
    {3{lut_in_rhs ==12}} & 3'd2 |
    {3{lut_in_rhs ==13}} & 3'd3 |
    {3{lut_in_rhs ==14}} & 3'd4 |
    {3{lut_in_rhs ==15}} & 3'd0 |
    {3{lut_in_rhs ==16}} & 3'd1 |
    {3{lut_in_rhs ==17}} & 3'd2 |
    {3{lut_in_rhs ==18}} & 3'd3 |
    {3{lut_in_rhs ==19}} & 3'd4 |
    {3{lut_in_rhs ==20}} & 3'd0 ;

wire [4:0] sum_rhs      = {lut_out_rhs,2'b00} + (f_yx ? lut_out_rhs : in_y);

wire [4:0] result_sum   = (f_yx ? in_y : lut_out_lhs) + sum_rhs;

assign result           = {24'b0,result_sum,2'b00};

/* verilator lint_on WIDTH */

endmodule
