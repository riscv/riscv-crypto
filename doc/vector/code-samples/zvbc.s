# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# The Zvbc extension contains vectorized carryless multiply (vclmul, vclmulh).
#
# Those routines are vector-length (VLEN) agnostic, only requiring
# that VLEN is a multiple of 64. Smaller VLENs should work when using
# LMUL>1, but this is not exercised here.
#
# This code was developed to validate the design of the Zvbc extension, and to
# understand and demonstrate expected usage patterns.
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

######################################################################
# Vector Carryless Multiply routines
######################################################################

# zvbc_vclmul_vv
#
# Takes two vectors of uint64_t elements vs2, vs1 as input,
# a number of (64 bit) elements 'n', sets destination vector
# to clmul(vs2, vs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbc_vclmul_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       const uint64_t* vs1,  // a2
#       size_t n              // a3
#  );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvbc_vclmul_vv
zvbc_vclmul_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1)  # get vs2
    vle64.v v1, (a2)  # get vs1
    vclmul.vv v0, v2, v1  # vd, vs2, vs1
    vse64.v v0, (a0)
    sub a3, a3, t0
    slli t0, t0, 3  # t0 <- #bytes processed in this iteration.
    add a0, a0, t0
    add a1, a1, t0
    add a2, a2, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvbc_vclmul_vx
#
# Takes a vector of uint64_t elements vs2, a uint64_t scalar rs1,
# and a number of (64 bit) elements 'n' as inputs, sets the destination
# vector to vclmul(vs2, rs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbc_vclmul_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#  );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvbc_vclmul_vx
zvbc_vclmul_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vclmul.vx v0, v2, a2  # vd, vs2, rs1
    vse64.v v0, (a0)
    sub a3, a3, t0
    slli t0, t0, 3  # t0 <- #bytes processed in this iteration.
    add a0, a0, t0
    add a1, a1, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvbc_vclmulh_vv
#
# Takes two vectors of uint64_t elements vs2, vs1 as input,
# a number of (64 bit) elements 'n', sets destination vector
# to clmulh(vs2, vs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbc_vclmulh_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       const uint64_t* vs1,  // a2
#       size_t n              // a3
#  );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvbc_vclmulh_vv
zvbc_vclmulh_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1)  # get vs2
    vle64.v v1, (a2)  # get vs1
    vclmulh.vv v0, v2, v1  # vd, vs2, vs1
    vse64.v v0, (a0)
    sub a3, a3, t0
    slli t0, t0, 3  # t0 <- #bytes processed in this iteration.
    add a0, a0, t0
    add a1, a1, t0
    add a2, a2, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvbc_vclmulh_vx
#
# Takes a vector of uint64_t elements vs2, a uint64_t scalar rs1,
# and a number of (64 bit) elements 'n' as inputs, sets the destination
# vector to vclmulh(vs2, rs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvbc_vclmulh_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#  );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvbc_vclmulh_vx
zvbc_vclmulh_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vclmulh.vx v0, v2, a2  # vd, vs2, rs1
    vse64.v v0, (a0)
    sub a3, a3, t0
    slli t0, t0, 3  # t0 <- #bytes processed in this iteration.
    add a0, a0, t0
    add a1, a1, t0
    bnez a3, 1b

    mv a0, t1
    ret
