
/*
 * file: riscv_crypto_entropy_source.sail
 *
 * Contains a basic model for the RISC-V cryptography extension entropy
 * source.
 *
 */

/*
 * The mnoise CSR
 * ------------------------------------------------------------
 */

register mnoise : xlenbits

/* mnoise is defined in machine mode only */
function clause ext_is_CSR_defined (0x7A9, Machine) = {
    true
}

function clause ext_read_CSR(0x7A9) = {
    Some(mnoise)
}

function clause ext_write_CSR(0x7A9, value) = {
    mnoise[31] = value[31];
    Some(mnoise)
}

val      in_noise_capture_mode : unit -> bool
function in_noise_capture_mode() = {
    if(bit_to_bool(mnoise[31])) then true else false
}

/*
 * The mentropy CSR
 * ------------------------------------------------------------
 */

enum mentropy_opst = {
    BIST,
    ES16,
    WAIT,
    DEAD
}

mapping opst_code : mentropy_opst <-> bits(2) = {
    BIST <-> 0b00,
    ES16 <-> 0b01,
    WAIT <-> 0b10,
    DEAD <-> 0b11
}

/* 
 * Dummy function representing an entropy samping.
 */
val      get_random_bits : unit -> bits(16)
function get_random_bits () = {
    0x0000
}

/* mentropy is defined in machine mode only */
function clause ext_is_CSR_defined (0xF15, Machine) = {
    true
}

function clause ext_read_CSR(0xF15) = {
    let reserved_bits   : bits( 6) = 0b000000;
    let custom_bits     : bits( 8) = 0x00;
    if(in_noise_capture_mode()) then {
        let seed            : bits(16) = 0x0000;
        Some(EXTZ(opst_code(BIST) @ reserved_bits @ custom_bits @ seed))
    } else {
        let seed            : bits(16) = get_random_bits();
        Some(EXTZ(opst_code(ES16) @ reserved_bits @ custom_bits @ seed))
    }
}

/* Always ignore writes to mentropy */
function clause ext_write_CSR(0xF15, value) = {
    Some(EXTZ(0x0))
}

