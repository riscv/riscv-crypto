
#
# This test tries to assemble a single version of every instruction.
#

.text

main:

#
# ------------------------------------------------------------

    lut4        a1, a1, a2

#
# ------------------------------------------------------------

    mmulu       (a1,a0), a1, a2, a3

#
# Version 1 with over-write semantics for a1p
    maccu       (a1,a0), a1, a2, a3

#
# ------------------------------------------------------------
        
    saes.sbenc  a0, a1
    saes.sbdec  a0, a1

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

    ssha3.xy    a0, a1, a2
    ssha3.x1    a0, a1, a2
    ssha3.x2    a0, a1, a2
    ssha3.x4    a0, a1, a2
    ssha3.yx    a0, a1, a2

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

