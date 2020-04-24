
//  sboxes.v
//  2020-01-29  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

/*

    Non-hardened combinatorial logic for AES, inverse AES, and SM4 S-Boxes.

    Each S-Box has a nonlinear middle layer sandwitched between linear
    top and bottom layers. In this version the top ("inner") layer expands
    8 bits to 21 bits while the bottom layer compresses 18 bits back to 8.

    Overall structure and AES and AES^-1 slightly modified from [BoPe12].
    SM4 top and bottom layers by Markku-Juhani O. Saarinen, January 2020.

    The middle layer is common between all; the beneficiality of muxing it
    depends on target. Currently we are not doing it.

    How? Because all of these are "Nyberg S-boxes" [Ny93]; built from a
    multiplicative inverse in GF(256) and are therefore affine isomorphic.

    [BoPe12] Boyar J., Peralta R. "A Small Depth-16 Circuit for the AES
    S-Box." Proc.SEC 2012. IFIP AICT 376. Springer, pp. 287-298 (2012)
    DOI: https://doi.org/10.1007/978-3-642-30436-1_24
    Preprint: https://eprint.iacr.org/2011/332.pdf

    [Ny93] Nyberg K., "Differentially Uniform Mappings for Cryptography",
    Proc. EUROCRYPT '93, LNCS 765, Springer, pp. 55-64 (1993)
    DOI: https://doi.org/10.1007/3-540-48285-7_6

*/

//  The shared non-linear middle part for AES, AES^-1, and SM4.

module sbox_inv_mid( output [17:0] y, input [20:0] x );

    /* verilator lint_off UNOPTFLAT */
    wire [45:0] t;
    /* verilator lint_on UNOPTFLAT */

    assign  t[ 0] = x[ 3] ^  x[12];
    assign  t[ 1] = x[ 9] &  x[ 5];
    assign  t[ 2] = x[17] &  x[ 6];
    assign  t[ 3] = x[10] ^  t[ 1];
    assign  t[ 4] = x[14] &  x[ 0];
    assign  t[ 5] = t[ 4] ^  t[ 1];
    assign  t[ 6] = x[ 3] &  x[12];
    assign  t[ 7] = x[16] &  x[ 7];
    assign  t[ 8] = t[ 0] ^  t[ 6];
    assign  t[ 9] = x[15] &  x[13];
    assign  t[10] = t[ 9] ^  t[ 6];
    assign  t[11] = x[ 1] &  x[11];
    assign  t[12] = x[ 4] &  x[20];
    assign  t[13] = t[12] ^  t[11];
    assign  t[14] = x[ 2] &  x[ 8];
    assign  t[15] = t[14] ^  t[11];
    assign  t[16] = t[ 3] ^  t[ 2];
    assign  t[17] = t[ 5] ^  x[18];
    assign  t[18] = t[ 8] ^  t[ 7];
    assign  t[19] = t[10] ^  t[15];
    assign  t[20] = t[16] ^  t[13];
    assign  t[21] = t[17] ^  t[15];
    assign  t[22] = t[18] ^  t[13];
    assign  t[23] = t[19] ^  x[19];
    assign  t[24] = t[22] ^  t[23];
    assign  t[25] = t[22] &  t[20];
    assign  t[26] = t[21] ^  t[25];
    assign  t[27] = t[20] ^  t[21];
    assign  t[28] = t[23] ^  t[25];
    assign  t[29] = t[28] &  t[27];
    assign  t[30] = t[26] &  t[24];
    assign  t[31] = t[20] &  t[23];
    assign  t[32] = t[27] &  t[31];
    assign  t[33] = t[27] ^  t[25];
    assign  t[34] = t[21] &  t[22];
    assign  t[35] = t[24] &  t[34];
    assign  t[36] = t[24] ^  t[25];
    assign  t[37] = t[21] ^  t[29];
    assign  t[38] = t[32] ^  t[33];
    assign  t[39] = t[23] ^  t[30];
    assign  t[40] = t[35] ^  t[36];
    assign  t[41] = t[38] ^  t[40];
    assign  t[42] = t[37] ^  t[39];
    assign  t[43] = t[37] ^  t[38];
    assign  t[44] = t[39] ^  t[40];
    assign  t[45] = t[42] ^  t[41];
    assign  y[ 0] = t[38] &  x[ 7];
    assign  y[ 1] = t[37] &  x[13];
    assign  y[ 2] = t[42] &  x[11];
    assign  y[ 3] = t[45] &  x[20];
    assign  y[ 4] = t[41] &  x[ 8];
    assign  y[ 5] = t[44] &  x[ 9];
    assign  y[ 6] = t[40] &  x[17];
    assign  y[ 7] = t[39] &  x[14];
    assign  y[ 8] = t[43] &  x[ 3];
    assign  y[ 9] = t[38] &  x[16];
    assign  y[10] = t[37] &  x[15];
    assign  y[11] = t[42] &  x[ 1];
    assign  y[12] = t[45] &  x[ 4];
    assign  y[13] = t[41] &  x[ 2];
    assign  y[14] = t[44] &  x[ 5];
    assign  y[15] = t[40] &  x[ 6];
    assign  y[16] = t[39] &  x[ 0];
    assign  y[17] = t[43] &  x[12];

endmodule

//  top (inner) linear layer for SM4


module sbox_sm4_top( output [20:0] y, input [7:0] x);

    /* verilator lint_off UNOPTFLAT */
    wire [6:0] t;
    /* verilator lint_on UNOPTFLAT */

    assign  y[18] = x[ 2] ^  x[ 6];
    assign  t[ 0] = x[ 3] ^  x[ 4];
    assign  t[ 1] = x[ 2] ^  x[ 7];
    assign  t[ 2] = x[ 7] ^  y[18];
    assign  t[ 3] = x[ 1] ^  t[ 1];
    assign  t[ 4] = x[ 6] ^  x[ 7];
    assign  t[ 5] = x[ 0] ^  y[18];
    assign  t[ 6] = x[ 3] ^  x[ 6];
    assign  y[10] = x[ 1] ^  y[18];
    assign  y[ 0] = x[ 5] ^~ y[10];
    assign  y[ 1] = t[ 0] ^  t[ 3];
    assign  y[ 2] = x[ 0] ^  t[ 0];
    assign  y[ 4] = x[ 0] ^  t[ 3];
    assign  y[ 3] = x[ 3] ^  y[ 4];
    assign  y[ 5] = x[ 5] ^  t[ 5];
    assign  y[ 6] = x[ 0] ^~ x[ 1];
    assign  y[ 7] = t[ 0] ^~ y[10];
    assign  y[ 8] = t[ 0] ^  t[ 5];
    assign  y[ 9] = x[ 3];
    assign  y[11] = t[ 0] ^  t[ 4];
    assign  y[12] = x[ 5] ^  t[ 4];
    assign  y[13] = x[ 5] ^~ y[ 1];
    assign  y[14] = x[ 4] ^~ t[ 2];
    assign  y[15] = x[ 1] ^~ t[ 6];
    assign  y[16] = x[ 0] ^~ t[ 2];
    assign  y[17] = t[ 0] ^~ t[ 2];
    assign  y[19] = x[ 5] ^~ y[14];
    assign  y[20] = x[ 0] ^  t[ 1];

endmodule

//  bottom (outer) linear layer for SM4

module sbox_sm4_out( output [7:0] y, input [17:0] x);

    /* verilator lint_off UNOPTFLAT */
    wire [29:0] t;
    /* verilator lint_on UNOPTFLAT */

    assign  t[ 0] = x[ 4] ^  x[ 7];
    assign  t[ 1] = x[13] ^  x[15];
    assign  t[ 2] = x[ 2] ^  x[16];
    assign  t[ 3] = x[ 6] ^  t[ 0];
    assign  t[ 4] = x[12] ^  t[ 1];
    assign  t[ 5] = x[ 9] ^  x[10];
    assign  t[ 6] = x[11] ^  t[ 2];
    assign  t[ 7] = x[ 1] ^  t[ 4];
    assign  t[ 8] = x[ 0] ^  x[17];
    assign  t[ 9] = x[ 3] ^  x[17];
    assign  t[10] = x[ 8] ^  t[ 3];
    assign  t[11] = t[ 2] ^  t[ 5];
    assign  t[12] = x[14] ^  t[ 6];
    assign  t[13] = t[ 7] ^  t[ 9];
    assign  t[14] = x[ 0] ^  x[ 6];
    assign  t[15] = x[ 7] ^  x[16];
    assign  t[16] = x[ 5] ^  x[13];
    assign  t[17] = x[ 3] ^  x[15];
    assign  t[18] = x[10] ^  x[12];
    assign  t[19] = x[ 9] ^  t[ 1];
    assign  t[20] = x[ 4] ^  t[ 4];
    assign  t[21] = x[14] ^  t[ 3];
    assign  t[22] = x[16] ^  t[ 5];
    assign  t[23] = t[ 7] ^  t[14];
    assign  t[24] = t[ 8] ^  t[11];
    assign  t[25] = t[ 0] ^  t[12];
    assign  t[26] = t[17] ^  t[ 3];
    assign  t[27] = t[18] ^  t[10];
    assign  t[28] = t[19] ^  t[ 6];
    assign  t[29] = t[ 8] ^  t[10];
    assign  y[ 0] = t[11] ^~ t[13];
    assign  y[ 1] = t[15] ^~ t[23];
    assign  y[ 2] = t[20] ^  t[24];
    assign  y[ 3] = t[16] ^  t[25];
    assign  y[ 4] = t[26] ^~ t[22];
    assign  y[ 5] = t[21] ^  t[13];
    assign  y[ 6] = t[27] ^~ t[12];
    assign  y[ 7] = t[28] ^~ t[29];

endmodule

//  SM4 S-box (there is no need for inverse)

module sm4_sbox( output [7:0] out, input [7:0] in );

    /* verilator lint_off UNOPTFLAT */
    wire [20:0] t1;
    wire [17:0] t2;
    /* verilator lint_on UNOPTFLAT */

    sbox_sm4_top top ( t1 , in );
    sbox_inv_mid mid ( t2 , t1 );
    sbox_sm4_out bot ( out, t2 );

endmodule

