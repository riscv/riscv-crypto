# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Vector Carryless Multiply Accumulate over GHASH Galois-Field routine using
# the proposed Zvkg instructions (vghmac.vv).
#
# This code was developed to validate the design of the Zvkg extension,
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

# zvkg_vghsh
#
# Performs one step of GHASH function as described in NIST GCM publication.
# It is a thin wrapper around the vghsh instruction from the Zvkg extension.
#
#   void zvkg_vghsh(
#       uint64_t Y[2],  // a0
#       uint64_t X[2],  // a1
#       uint64_t H[2]   // a2
#   );
#
.balign 4
.global zvkg_vghsh
zvkg_vghsh:
    # 4 * 32b = 128b
    # We use LMUL=4 to enable runs with VLEN=32, as a proof of concept.
    # Once VLEN>=128, we can simply use LMUL=1.
    vsetivli x0, 4, e32, m4, ta, ma

    vle32.v v0, (a0)
    vle32.v v4, (a1)
    vle32.v v8, (a2)

    vghsh.vv v0, v8, v4
    vse32.v v0, (a0)
    ret


# zvkg_vghsh_vv
#
# Performs vector add-multiply over GHASH Galois-Field for multiple
# 128 bit elements groups. 'n' is the number of 128b groups.
# The input arrays should be 32b aligned on processors that do not
# support unaligned 32b vector loads/stores.
#     Y[i]_out = ((Y[i]_in ^ X[i]) o H[i])
#
#   void zvkg_vghsh_vv(
#       uint32_t* Y,   // a0
#       uint32_t* X,   // a1
#       uint32_t* H,   // a2
#       size_t    n    // a3
#   );
#
.balign 4
.global zvkg_vghsh_vv
zvkg_vghsh_vv:
    beqz a3, 2f  # Early exit in the "0 bytes to process" case
    # a3 on input is number of 128b groups in the input arrays. We multiply
    # by 4 as the Zvkg instructions expect VSEW=32. a3 becomes the number
    # of 32b elements to process, which is a multiple of 4.
    slli a3, a3, 2
1:
    # We use LMUL=4 to enable runs with VLEN=32, as a proof of concept.
    # Once VLEN>=128, we can simply use LMUL=1.
    vsetvli t0, a3, e32, m4, ta, ma

    vle32.v v0, (a0)
    vle32.v v4, (a1)
    vle32.v v8, (a2)
    vghsh.vv v0, v8, v4  # Y(v0) = Y(v0) ^ X(v4)) o H(v8)
    vse32.v v0, (a0)

    sub a3, a3, t0       # Decrement number of remaining 32b elements
    slli t0, t0, 2       # t0 (#bytes consumed) <- t0 (#4B) * 4
    add a0, a0, t0
    add a1, a1, t0
    add a2, a2, t0
    bnez a3, 1b          # More elements to process?

2:
    ret

# zvkg_vgmul_vv
#
# Performs vector multiply over GHASH Galois-Field for multiple
# 128 bit elements groups.
# 'n' is the number of 128b element groups, n operations will be performed.
# The input arrays should be 32b aligned on processors that do not
# support unaligned 32b vector loads/stores.
#
#     Y[i]_out = (Y[i]_in o H[i])
#
#   void zvkg_vgmul_vv(
#       uint32_t* Y,   // a0
#       uint32_t* H,   // a1
#       size_t    n    // a2
#   );
#
.balign 4
.global zvkg_vgmul_vv
zvkg_vgmul_vv:
    beqz a2, 2f  # Early exit in the "0 bytes to process" case
    # a3 on input is number of 128b groups in the input arrays. We multiply
    # by 4 as the Zvkg instructions expect VSEW=32. a3 becomes the number
    # of 32b elements to process, which is a multiple of 4.
    slli a2, a2, 2
1:
    # We use LMUL=4 to enable runs with VLEN=32, as a proof of concept.
    # Once VLEN>=128, we can simply use LMUL=1.
    vsetvli t0, a2, e32, m4, ta, ma

    vle32.v v0, (a0)
    vle32.v v4, (a1)
    vgmul.vv v0, v4
    vse32.v v0, (a0)

    sub a2, a2, t0
    slli t0, t0, 2       # t0 (#bytes consumes) <- t0 (#4B) * 4
    add a0, a0, t0
    add a1, a1, t0
    bnez a2, 1b          # More elements to process?

2:
    ret

