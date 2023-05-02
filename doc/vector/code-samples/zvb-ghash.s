# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# This code was developed to validate the design of the Zvbb/Zvbc extensions,
# and to understand and demonstrate expected usage patterns.
#
# DISCLAIMER OF WARRANTY:
#  This code is not intended for use in real cryptographic applications,
#  has not been reviewed, even less audited by cryptography or security
#  experts, etc.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY EXPRESS
#  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
#  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
#  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

.text

# zvb_ghash_init
#
# Pre-process the H value in order to have it in the optimal form
# for the hotpath logic:
#  1. Swap the endianness.
#  2. Multiply by 2, so that we won't have to shift the 256 bits
#     product in the main loop.
#
#   zvb_ghash_init(
#       uint64_t X[2],     // a0
#   );
#
.balign 4
.global zvb_ghash_init
zvb_ghash_init:
    # Load/store data in reverse order.
    # This is needed as a part of endianness swap.
    add a0, a0, 8
    li t0, -8
    li t1, 63
    la t2, polymod

    vsetivli x0, 2, e64, m1, ta, ma

    vlse64.v v1, (a0), t0
    vle64.v v2, (t2)

    # Byte order swap
    vrev8.v v1, v1

    # Shift one left and get the carry bits.
    vsrl.vx v3, v1, t1
    vsll.vi v1, v1, 1

    # Use the fact that the polynomial degree is no more than 128,
    # i.e. only the LSB of the upper half could be set.
    # Thanks to we don't need to do the full reduction here.
    # Instead simply subtract the reduction polynomial.
    # This idea was taken from x86 ghash implementation in OpenSSL.
    vslideup.vi v4, v3, 1
    vslidedown.vi v3, v3, 1

    vmv.v.i v0, 2
    vor.vv v1, v1, v4, v0.t

    # Need to set the mask to 3, if the carry bit is set.
    # Not sure if there is a better way of doing this.
    vmv.v.v v0, v3
    vmv.v.i v3, 0
    vmerge.vim v3, v3, 3, v0
    vmv.v.v v0, v3

    vxor.vv v1, v1, v2, v0.t

    add a0, a0, -8
    vse64.v v1, (a0)
    ret

# zvb_ghash
#
# Performs one step of GHASH function as described in NIST GCM publication.
# It uses vclmul* instruction from Zvbc extension.
#
#   zvb_ghash(
#       uint64_t X[2],     // a0
#       uint64_t H[2]      // a1
#   );
#
.balign 4
.global zvb_ghash
zvb_ghash:
    ld t0, (a1)
    ld t1, 8(a1)
    li t2, 63
    la t3, polymod
    ld t3, 8(t3)

    # Load/store data in reverse order.
    # This is needed as a part of endianness swap.
    add a0, a0, 8
    li t4, -8

    vsetivli x0, 2, e64, m1, ta, ma

    vlse64.v v5, (a0), t4
    vrev8.v v5, v5

    # Multiplication

    # Do two 64x64 multiplications in one go to save some time
    # and simplify things.

    # A = a1a0 (t1, t0)
    # B = b1b0 (v5)
    # C = c1c0 (256 bit)
    # c1 = a1b1 + (a0b1)h + (a1b0)h
    # c0 = a0b0 + (a0b1)l + (a1b0)h

    # v1 = (a0b1)l,(a0b0)l
    vclmul.vx v1, v5, t0
    # v3 = (a0b1)h,(a0b0)h
    vclmulh.vx v3, v5, t0

    # v4 = (a1b1)l,(a1b0)l
    vclmul.vx v4, v5, t1
    # v2 = (a1b1)h,(a1b0)h
    vclmulh.vx v2, v5, t1

    # Is there a better way to do this?
    # Would need to swap the order of elements within a vector register.
    vslideup.vi v5, v3, 1
    vslideup.vi v6, v4, 1
    vslidedown.vi v3, v3, 1
    vslidedown.vi v4, v4, 1

    vmv.v.i v0, 1
    # v2 += (a0b1)h
    vxor.vv v2, v2, v3, v0.t
    # v2 += (a1b1)l
    vxor.vv v2, v2, v4, v0.t

    vmv.v.i v0, 2
    # v1 += (a0b0)h,0
    vxor.vv v1, v1, v5, v0.t
    # v1 += (a1b0)l,0
    vxor.vv v1, v1, v6, v0.t

    # Now the 256bit product should be stored in (v2,v1)
    # v1 = (a0b1)l + (a0b0)h + (a1b0)l, (a0b0)l
    # v2 = (a1b1)h, (a1b0)h + (a0b1)h + (a1b1)l

    # Reduction
    # Let C := A*B = c3,c2,c1,c0 = v2[1],v2[0],v1[1],v1[0]
    # This is a slight variation of the Gueron's Montgomery reduction.
    # The difference being the order of some operations has been changed,
    # to make a better use of vclmul(h) instructions.

    # First step:
    # c1 += (c0 * P)l
    # vmv.v.i v0, 2
    vslideup.vi v3, v1, 1, v0.t
    vclmul.vx v3, v3, t3, v0.t
    vxor.vv v1, v1, v3, v0.t

    # Second step:
    # D = d1,d0 is final result
    # We want:
    # m1 = c1 + (c1 * P)h
    # m0 = (c1 * P)l + (c0 * P)h + c0
    # d1 = c3 + m1
    # d0 = c2 + m0

    #v3 = (c1 * P)l, 0
    vclmul.vx v3, v1, t3, v0.t
    #v4 = (c1 * P)h, (c0 * P)h
    vclmulh.vx v4, v1, t3

    vmv.v.i v0, 1
    vslidedown.vi v3, v3, 1

    vxor.vv v1, v1, v4
    vxor.vv v1, v1, v3, v0.t

    # XOR in the upper upper part of the product
    vxor.vv v2, v2, v1

    vrev8.v v2, v2
    vsse64.v v2, (a0), t4
    ret

.align  16
polymod:
        .dword 0x0000000000000001
        .dword 0xc200000000000000
