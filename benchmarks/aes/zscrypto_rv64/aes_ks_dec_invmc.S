
.text

.global aes_ks_dec_invmc
.func   aes_ks_dec_invmc
aes_ks_dec_invmc:           // a0 - uint64_t * ks
                            // a1 - uint64_t * end_ptr

    .l0:
        ld          a2, 0(a0)
        ld          a3, 8(a0)
        
        saes64.imix a2, a2
        saes64.imix a3, a3

        sd          a2, 0(a0)
        sd          a3, 8(a0)

        addi        a0, a0, 16
        bne         a0, a1, .l0

    ret

.endfunc
