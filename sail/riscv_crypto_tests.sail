
/*
 * A collection of very small unit tests to check that internal
 * functions used by multiple crypto extension instructions give the correct
 * results given known inputs.
 */


val      crypto_test_vaes_128_keystep_fwd : unit -> bool
function crypto_test_vaes_128_keystep_fwd () = {
  let input   : bits(128) = 0x09cf4f3cabf7158828aed2a62b7e1516;
  let grm_out1: bits(128) = 0x2A6C760523A3393988542CB1A0FAFE17;
  let dut_out1: bits(128) = vaes128_keystep_fwd(input, 0x0);
  if(dut_out1 != grm_out1) then false else {
  let grm_out2: bits(128) = 0x7359f67f5935807a7a96b943f2c295f2;
  let dut_out2: bits(128) = vaes128_keystep_fwd(dut_out1, 0x1);
  if(dut_out2 != grm_out2) then false else true
  }
}
