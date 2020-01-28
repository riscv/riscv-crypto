
#
# This test tries to assemble a single version of every instruction.
#

.text

main:

#
# ------------------------------------------------------------

    lut4lo      a1, a1, a2
    lut4hi      a1, a1, a2
  ##lut44       a1, a1, a2 // Disabled since it is RV64

#
# ------------------------------------------------------------

    mmulu       (a1,a0), a1, a2, a3

#
# Version 1 with over-write semantics for a1p
    maccu       (a1,a0), a1, a2, a3

#
# ------------------------------------------------------------
        
    saes.v1.enc         a0, a1
    saes.v1.dec         a0, a1
    
    saes.v2.sub.enc     a0, a1, a2
    saes.v2.sub.encrot  a0, a1, a2
    saes.v2.sub.dec     a0, a1, a2
    saes.v2.sub.decrot  a0, a1, a2
    saes.v2.mix.enc     a0, a1, a2
    saes.v2.mix.enc     a0, a1, a2
    
    saes.v3.ks          a0, a1, a2, 0, 0
    saes.v3.enc         a0, a1, a2, 0, 0
    saes.v3.dec         a0, a1, a2, 0, 0
    saes.v3.ks          a0, a1, a2, 3, 0
    saes.v3.enc         a0, a1, a2, 3, 1
    saes.v3.dec         a0, a1, a2, 3, 1

#
# ------------------------------------------------------------

    ssha256.s0  a0, a1
    ssha256.s1  a0, a1
    ssha256.s2  a0, a1
    ssha256.s3  a0, a1

  ##ssha512.s0  a0, a1
  ##ssha512.s1  a0, a1
  ##ssha512.s2  a0, a1
  ##ssha512.s3  a0, a1

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

