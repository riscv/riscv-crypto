
#
# This test tries to assemble a single version of every instruction.
#

.text

main:

#
# ------------------------------------------------------------

    lut4lo      a1, a1, a2
    lut4hi      a1, a1, a2
    lut4        a1, a1, a2

#
# ------------------------------------------------------------

    mmulu       (a1,a0), a1, a2, a3

#
# Version 1 with over-write semantics for a1p
    maccu       (a1,a0), a1, a2, a3

#
# ------------------------------------------------------------
        
    saes32.encsm       a0, a1, a2, 0
    saes32.encs        a0, a1, a2, 0
    saes32.decsm       a0, a1, a2, 0
    saes32.decs        a0, a1, a2, 0
    
    saes64.ks1         a0, a1, 0
    saes64.ks2         a0, a1, a2
    saes64.imix        a0, a1
    
    saes64.encsm.lo    a0, a1, a2
    saes64.encsm.hi    a0, a1, a2
    saes64.encs.lo     a0, a1, a2
    saes64.encs.hi     a0, a1, a2
    
    saes64.decsm.lo    a0, a1, a2
    saes64.decsm.hi    a0, a1, a2
    saes64.decs.lo     a0, a1, a2
    saes64.decs.hi     a0, a1, a2

#
# ------------------------------------------------------------

    ssha256.s0  a0, a1
    ssha256.s1  a0, a1
    ssha256.s2  a0, a1
    ssha256.s3  a0, a1

    ssha512.s0  a0, a1
    ssha512.s1  a0, a1
    ssha512.s2  a0, a1
    ssha512.s3  a0, a1

#
# ------------------------------------------------------------

    lbx         a0, a1(a2)
    lhx         a0, a1(a2)
    lwx         a0, a1(a2)
    ldx         a0, a1(a2)
    lbux        a0, a1(a2)
    lhux        a0, a1(a2)
    lwux        a0, a1(a2)

    sbx         a0, a1(a2)
    shx         a0, a1(a2)
    swx         a0, a1(a2)
    sdx         a0, a1(a2)


