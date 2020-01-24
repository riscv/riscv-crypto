
//
// Implement a single 1-byte lookup for the AES SBox or inverse SBox
module aes_sbox(
    input  wire [7:0] in    ,   // Input byte
    input  wire       inv   ,   // Perform inverse (set) or forward lookup
    output wire [7:0] out       // Output byte
);

wire [7:0] out_fwd;
wire [7:0] out_inv;

assign out = inv ? out_inv : out_fwd;

aes_sbox_fwd i_sbox_fwd(
.in (in     ),
.out(out_fwd)
);

aes_sbox_inv i_sbox_inv (
.in (in     ),
.out(out_inv)
);

endmodule


//
// Adapted from:
// http://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
// http://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/AESDEPTH16SIZE125G
module aes_sbox_fwd (
    input  wire [7:0] in    ,   // Input byte
    output wire [7:0] out       // Output byte
);

wire u7, u6, u5, u4, u3, u2, u1, u0;
wire s7, s6, s5, s4, s3, s2, s1, s0;

assign out = {s0, s1, s2, s3, s4, s5, s6, s7};

assign {u0, u1, u2, u3, u4, u5, u6, u7}= in;

wire y14 = u3 ^ u5;
wire y13 = u0 ^ u6;
wire y9 = u0 ^ u3;
wire y8 = u0 ^ u5;
wire t0 = u1 ^ u2;
wire y1 = t0 ^ u7;
wire y4 = y1 ^ u3;
wire y12 = y13 ^ y14;
wire y2 = y1 ^ u0;
wire y5 = y1 ^ u6;
wire y3 = y5 ^ y8;
wire t1 = u4 ^ y12;
wire y15 = t1 ^ u5;
wire y20 = t1 ^ u1;
wire y6 = y15 ^ u7;
wire y10 = y15 ^ t0;
wire y11 = y20 ^ y9;
wire y7 = u7 ^ y11;
wire y17 = y10 ^ y11;
wire y19 = y10 ^ y8;
wire y16 = t0 ^ y11;
wire y21 = y13 ^ y16;
wire y18 = u0 ^ y16;
wire t2 = y12 && y15;
wire t3 = y3 && y6;
wire t4 = t3 ^ t2;
wire t5 = y4 && u7;
wire t6 = t5 ^ t2;
wire t7 = y13 && y16;
wire t8 = y5 && y1;
wire t9 = t8 ^ t7;
wire t10 = y2 && y7;
wire t11 = t10 ^ t7;
wire t12 = y9 && y11;
wire t13 = y14 && y17;
wire t14 = t13 ^ t12;
wire t15 = y8 && y10;
wire t16 = t15 ^ t12;
wire t17 = t4 ^ y20;
wire t18 = t6 ^ t16;
wire t19 = t9 ^ t14;
wire t20 = t11 ^ t16;
wire t21 = t17 ^ t14;
wire t22 = t18 ^ y19;
wire t23 = t19 ^ y21;
wire t24 = t20 ^ y18;
wire t25 = t21 ^ t22;
wire t26 = t21 && t23;
wire t27 = t24 ^ t26;
wire t28 = t25 && t27;
wire t29 = t28 ^ t22;
wire t30 = t23 ^ t24;
wire t31 = t22 ^ t26;
wire t32 = t31 && t30;
wire t33 = t32 ^ t24;
wire t34 = t23 ^ t33;
wire t35 = t27 ^ t33;
wire t36 = t24 && t35;
wire t37 = t36 ^ t34;
wire t38 = t27 ^ t36;
wire t39 = t29 && t38;
wire t40 = t25 ^ t39;
wire t41 = t40 ^ t37;
wire t42 = t29 ^ t33;
wire t43 = t29 ^ t40;
wire t44 = t33 ^ t37;
wire t45 = t42 ^ t41;
wire z0 = t44 && y15;
wire z1 = t37 && y6;
wire z2 = t33 && u7;
wire z3 = t43 && y16;
wire z4 = t40 && y1;
wire z5 = t29 && y7;
wire z6 = t42 && y11;
wire z7 = t45 && y17;
wire z8 = t41 && y10;
wire z9 = t44 && y12;
wire z10 = t37 && y3;
wire z11 = t33 && y4;
wire z12 = t43 && y13;
wire z13 = t40 && y5;
wire z14 = t29 && y2;
wire z15 = t42 && y9;
wire z16 = t45 && y14;
wire z17 = t41 && y8;
wire tc1 = z15 ^ z16;
wire tc2 = z10 ^ tc1;
wire tc3 = z9 ^ tc2;
wire tc4 = z0 ^ z2;
wire tc5 = z1 ^ z0;
wire tc6 = z3 ^ z4;
wire tc7 = z12 ^ tc4;
wire tc8 = z7 ^ tc6;
wire tc9 = z8 ^ tc7;
wire tc10 = tc8 ^ tc9;
wire tc11 = tc6 ^ tc5;
wire tc12 = z3 ^ z5;
wire tc13 = z13 ^ tc1;
wire tc14 = tc4 ^ tc12;
assign s3 = tc3 ^ tc11;
wire tc16 = z6 ^ tc8;
wire tc17 = z14 ^ tc10;
wire tc18 = tc13 ^ tc14;
assign s7 = z12 ~^ tc18;
wire tc20 = z15 ^ tc16;
wire tc21 = tc2 ^ z11;
assign s0 = tc3 ^ tc16;
assign s6 = tc10 ~^ tc18;
assign s4 = tc14 ^ s3;
assign s1 = s3 ~^ tc16;
wire tc26 = tc17 ^ tc20;
assign s2 = tc26 ~^ z17;
assign s5 = tc21 ^ tc17;

endmodule

//
// Adapted from:
// http://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
// http://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/AESReverseDepth.txt
module aes_sbox_inv (
    input  wire [7:0] in    ,   // Input byte
    output wire [7:0] out       // Output byte
);

wire u7, u6, u5, u4, u3, u2, u1, u0;
wire s7, s6, s5, s4, s3, s2, s1, s0;

assign out = {s0, s1, s2, s3, s4, s5, s6, s7};

assign {u0, u1, u2, u3, u4, u5, u6, u7}= in;

wire y0 = u0 ^ u3;
wire y2 = u1 ~^ u3;
wire y4 = u0 ^ y2;
wire rtl0 = u6 ^ u7;
wire y1 = y2 ^ rtl0;
wire y7 = u2 ~^ y1;
wire rtl1 = u3 ^ u4;
wire y6 = u7 ~^ rtl1;
wire y3 = y1 ^ rtl1;
wire rtl2 = u0 ~^ u2;
wire y5 = u5 ^ rtl2;
wire sa1 = y0 ^ y2;
wire sa0 = y1 ^ y3;
wire sb1 = y4 ^ y6;
wire sb0 = y5 ^ y7;
wire ah = y0 ^ y1;
wire al = y2 ^ y3;
wire aa = sa0 ^ sa1;
wire bh = y4 ^ y5;
wire bl = y6 ^ y7;
wire bb = sb0 ^ sb1;
wire ab20 = sa0 ^ sb0;
wire ab22 = al ^ bl;
wire ab23 = y3 ^ y7;
wire ab21 = sa1 ^ sb1;
wire abcd1 = ah && bh;
wire rr1 = y0 && y4;
wire ph11 = ab20 ^ abcd1;
wire t01 = y1 && y5;
wire ph01 = t01 ^ abcd1;
wire abcd2 = al && bl;
wire r1 = y2 && y6;
wire pl11 = ab22 ^ abcd2;
wire r2 = y3 && y7;
wire pl01 = r2 ^ abcd2;
wire r3 = sa0 && sb0;
wire vr1 = aa && bb;
wire pr1 = vr1 ^ r3;
wire wr1 = sa1 && sb1;
wire qr1 = wr1 ^ r3;
wire ab0 = ph11 ^ rr1;
wire ab1 = ph01 ^ ab21;
wire ab2 = pl11 ^ r1;
wire ab3 = pl01 ^ qr1;
wire cp1 = ab0 ^ pr1;
wire cp2 = ab1 ^ qr1;
wire cp3 = ab2 ^ pr1;
wire cp4 = ab3 ^ ab23;
wire tinv1 = cp3 ^ cp4;
wire tinv2 = cp3 && cp1;
wire tinv3 = cp2 ^ tinv2;
wire tinv4 = cp1 ^ cp2;
wire tinv5 = cp4 ^ tinv2;
wire tinv6 = tinv5 && tinv4;
wire tinv7 = tinv3 && tinv1;
wire d2 = cp4 ^ tinv7;
wire d0 = cp2 ^ tinv6;
wire tinv8 = cp1 && cp4;
wire tinv9 = tinv4 && tinv8;
wire tinv10 = tinv4 ^ tinv2;
wire d1 = tinv9 ^ tinv10;
wire tinv11 = cp2 && cp3;
wire tinv12 = tinv1 && tinv11;
wire tinv13 = tinv1 ^ tinv2;
wire d3 = tinv12 ^ tinv13;
wire sd1 = d1 ^ d3;
wire sd0 = d0 ^ d2;
wire dl = d0 ^ d1;
wire dh = d2 ^ d3;
wire dd = sd0 ^ sd1;
wire abcd3 = dh && bh;
wire rr2 = d3 && y4;
wire t02 = d2 && y5;
wire abcd4 = dl && bl;
wire r4 = d1 && y6;
wire r5 = d0 && y7;
wire r6 = sd0 && sb0;
wire vr2 = dd && bb;
wire wr2 = sd1 && sb1;
wire abcd5 = dh && ah;
wire r7 = d3 && y0;
wire r8 = d2 && y1;
wire abcd6 = dl && al;
wire r9 = d1 && y2;
wire r10 = d0 && y3;
wire r11 = sd0 && sa0;
wire vr3 = dd && aa;
wire wr3 = sd1 && sa1;
wire ph12 = rr2 ^ abcd3;
wire ph02 = t02 ^ abcd3;
wire pl12 = r4 ^ abcd4;
wire pl02 = r5 ^ abcd4;
wire pr2 = vr2 ^ r6;
wire qr2 = wr2 ^ r6;
wire p0 = ph12 ^ pr2;
wire p1 = ph02 ^ qr2;
wire p2 = pl12 ^ pr2;
wire p3 = pl02 ^ qr2;
wire ph13 = r7 ^ abcd5;
wire ph03 = r8 ^ abcd5;
wire pl13 = r9 ^ abcd6;
wire pl03 = r10 ^ abcd6;
wire pr3 = vr3 ^ r11;
wire qr3 = wr3 ^ r11;
wire p4 = ph13 ^ pr3;
assign s7 = ph03 ^ qr3;
wire p6 = pl13 ^ pr3;
wire p7 = pl03 ^ qr3;
assign s3 = p1 ^ p6;
assign s6 = p2 ^ p6;
assign s0 = p3 ^ p6;
wire x11 = p0 ^ p2;
assign s5 = s0 ^ x11;
wire x13 = p4 ^ p7;
wire x14 = x11 ^ x13;
assign s1 = s3 ^ x14;
wire x16 = p1 ^ s7;
assign s2 = x14 ^ x16;
wire x18 = p0 ^ p4;
wire x19 = s5 ^ x16;
assign s4 = x18 ^ x19;

endmodule
