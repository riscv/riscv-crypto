
/*
 * A collection of very small unit tests to check that internal
 * functions used by multiple crypto extension instructions give the correct
 * results given known inputs.
 */
/*                                        |      ||      ||      ||      |  */
let crypto_test_aes128_key: bits(128) = 0x09cf4f3cabf7158828aed2a62b7e1516
let crypto_test_aes128_pt : bits(128) = 0xe0370734313198a2885a308d3243f6a8
let crypto_test_aes128_ct : bits(128) = 0x196A0B32DC11859702DC09FB3925841D

let crypto_test_aes256_key: bits(256) = 0x1c1d1e1f18191a1b1415161710111213
                                      @ 0x0c0d0e0f08090a0b0405060700010203
let crypto_test_aes256_pt : bits(128) = 0xccddeeff8899aabb4455667700112233
let crypto_test_aes256_ct : bits(128) = 0x4b496089eafc4990516745bf8ea2b7ca

/*
 * Simple KAT test for the AES 128 forward keystep function.
 * Values taken from FIPS 197 A.1 Expansion of a 128-bit Cipher key.
 */
val      crypto_test_vaes_128_keystep_fwd : unit -> bool effect{escape}
function crypto_test_vaes_128_keystep_fwd () = {
  let input   : bits(128) = crypto_test_aes128_key;
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
 * Make sure we can calculate the correct final round key for AES 128
 */
val      crypto_test_vaes_128_get_final_round_key : unit -> bool effect{escape}
function crypto_test_vaes_128_get_final_round_key() = {
    let ck : bits(128) = crypto_test_aes128_key;
    let rk : bits(128) = vaes128_get_last_round_key(ck);
    assert(rk == 0xb6630ca6e13f0cc8c9ee2589d014f9a8);
    true
}

/* 
 * Make sure we can calculate the correct final round key for AES 256
 */
val      crypto_test_vaes_256_get_final_round_key : unit -> bool effect{escape}
function crypto_test_vaes_256_get_final_round_key() = {
    let ck : bits(256) = crypto_test_aes256_key;
    let rk : bits(256) = vaes256_get_last_round_key(ck);
    assert(rk ==0x6D68DE36371AC23CBF0979E924FC79CCCDF8CDEA7E572BAAA9F24FE04E5A6699);
    true
}


/*
 * Are shift rows and inv shift rows the inverse of one another?
 */
val      crypto_test_aes_shiftrows_complement : unit -> bool effect{escape}
function crypto_test_aes_shiftrows_complement () = {
    let input : bits(128) = 0x857d77812b73aef015ca71be603deb10;
    let fwd   : bits(128) = aes_shift_rows_fwd(input);
    let inv   : bits(128) = aes_shift_rows_inv(fwd);
    assert(inv == input);
    true
}

/*
 * Are subbytes and inv subbytes the inverse of one another?
 */
val      crypto_test_aes_subbytes_complement : unit -> bool effect{escape}
function crypto_test_aes_subbytes_complement () = {
    let input : bits(128) = 0x857d77812b73aef015ca71be603deb10;
    let fwd   : bits(128) = aes_subbytes_fwd(input);
    let inv   : bits(128) = aes_subbytes_inv(fwd);
    assert(inv == input);
    true
}

/*
 * Are MixCols and inv MixCols the inverse of one another?
 */
val      crypto_test_aes_mixcolumns_complement : unit -> bool effect{escape}
function crypto_test_aes_mixcolumns_complement () = {
    let input : bits(128) = 0x857d77812b73aef015ca71be603deb10;
    let fwd   : bits(128) = aes_mixcolumns_fwd(input);
    let inv   : bits(128) = aes_mixcolumns_inv(fwd  );
    assert(inv == input);
    true
}

/*
 * Is vaes_round_fwd correct for a non-final round transform?
 */
val      crypto_test_aes_enc_round_fwd: unit -> bool effect{escape}
function crypto_test_aes_enc_round_fwd() = {
    let pt : bits(128) = 0xe9f848089ac68d2aa0f4e22b193de3be;
    let key: bits(128) = 0x2a6c760523a3393988542cb1a0fafe17;
    let e1 : bits(128) = vaes_round_fwd(false, pt, key);
    assert(e1 == 0x026a50496b5bea43689f352ba49c7ff2);
    true
}

/*
 * Is vaes_round_inv correct for a non-final round transform?
 * TODO: crypto_test_aes_enc_round_inv
 */
val      crypto_test_aes_enc_round_inv: unit -> bool effect{escape}
function crypto_test_aes_enc_round_inv() = {
    let pt : bits(128) = 0x026a50496b5bea43689f352ba49c7ff2;
    let key: bits(128) = 0x2a6c760523a3393988542cb1a0fafe17;
    let e1 : bits(128) = vaes_round_inv(false, pt, key);
    assert(e1 == 0xe9f848089ac68d2aa0f4e22b193de3be);
    true
}


/*
 * Does the AES 128 block encrypt function work properly for a single KAT test?
 * Test values taken from FIPS 197, Appendix B, Page 33
 */
val      crypto_test_aes128_enc_block : unit -> bool effect{escape}
function crypto_test_aes128_enc_block () = {
    let pt : bits(128) = crypto_test_aes128_pt;
    let key: bits(128) = crypto_test_aes128_key;
    let ct : bits(128) = vaes128_block_enc(pt, key);
    assert(ct == crypto_test_aes128_ct);
    true
}


/*
 * Does the AES 256 block encrypt function work properly for a single KAT test?
 * Test values taken from FIPS 197, Appendix C.3
 */
val      crypto_test_aes256_enc_block : unit -> bool effect{escape}
function crypto_test_aes256_enc_block () = {
    let pt : bits(128) = crypto_test_aes256_pt;
    let key: bits(256) = crypto_test_aes256_key;
    let ct : bits(128) = vaes256_block_enc(pt, key);
    assert(ct == crypto_test_aes256_ct);
    true
}



/*
 * Run all of the crypto smoke tests.
 */
val      crypto_smoke_tests   : unit -> bool effect {escape}
function crypto_smoke_tests() = {
    ret: bool = crypto_test_aes_shiftrows_complement();
    ret: bool = crypto_test_aes_subbytes_complement();
    ret: bool = crypto_test_aes_mixcolumns_complement();
    ret: bool = crypto_test_vaes_128_keystep_fwd();
    ret: bool = crypto_test_vaes_256_keystep_fwd();
    ret: bool = crypto_test_vaes_128_get_final_round_key();
    ret: bool = crypto_test_vaes_256_get_final_round_key();
    ret: bool = crypto_test_aes_enc_round_fwd();
    ret: bool = crypto_test_aes128_enc_block();
    ret: bool = crypto_test_aes256_enc_block();
    ret
}


