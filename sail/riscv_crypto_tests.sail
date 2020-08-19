
/*
 * A collection of very small unit tests to check that internal
 * functions used by multiple crypto extension instructions give the correct
 * results given known inputs.
 */


/*
 * Simple KAT test for the AES 128 forward keystep function.
 * Values taken from FIPS 197 A.1 Expansion of a 128-bit Cipher key.
 */
val      crypto_test_vaes_128_keystep_fwd : unit -> bool effect{escape}
function crypto_test_vaes_128_keystep_fwd () = {
  let input   : bits(128) = 0x09cf4f3cabf7158828aed2a62b7e1516;
  let grm_out1: bits(128) = 0x2A6C760523A3393988542CB1A0FAFE17;
  let dut_out1: bits(128) = vaes128_keystep_fwd(input, 0x0);
  assert(dut_out1 == grm_out1);
  let grm_out2: bits(128) = 0x7359f67f5935807a7a96b943f2c295f2;
  let dut_out2: bits(128) = vaes128_keystep_fwd(dut_out1, 0x1);
  assert(dut_out2 == grm_out2);
  true
}

/*
 * Simple KAT test for the AES 256 forward keystep function.
 * Values taken from FIPS 197 A.3 Expansion of a 256-bit Cipher key.
 */
val      crypto_test_vaes_256_keystep_fwd : unit -> bool effect{escape}
function crypto_test_vaes_256_keystep_fwd () = {
  let dut_rk_0 : bits(128) = 0x857d77812b73aef015ca71be603deb10;
  let dut_rk_1 : bits(128) = 0x0914dff42d9810a33b6108d71f352c07;
  
  let dut_rk_2 : bits(128) = vaes256_keystep_fwd(dut_rk_0, dut_rk_1, 0x0);
  let grm_rk_2 : bits(128) = 0x2067fcdea51a8b5f8e6925af9ba35411;
  assert(dut_rk_2 == grm_rk_2);
  
  let dut_rk_3 : bits(128) = vaes256_keystep_fwd(dut_rk_0, dut_rk_1, 0x1);
  let grm_rk_3 : bits(128) = 0xb75d5b9abe49846e93d194cda8b09c1a;
  assert(dut_rk_3 == grm_rk_3);
  
  let dut_rk_4 : bits(128) = vaes256_keystep_fwd(dut_rk_2, dut_rk_3, 0x2);
  let grm_rk_4 : bits(128) = 0xde8ebe96fee942485bf3c917d59aecb8;
  assert(dut_rk_4 == grm_rk_4);
  
  let dut_rk_5 : bits(128) = vaes256_keystep_fwd(dut_rk_2, dut_rk_3, 0x3);
  let grm_rk_5 : bits(128) = 0x2f6c79b3983122292678a647b5a9328a;
  assert(dut_rk_5 == grm_rk_5);

  true
}

/*
0x3243f6a8 0x885a308d 0x313198a2 0xe0370734
0xe0370734 0x313198a2 0x885a308d 0x3243f6a8 
0xe0370734313198a2885a308d3243f6a8 
*/

