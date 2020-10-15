# RISC-V Compliance Test {{MNEMONIC}}-{{TEST_NUM}}
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of the Imperas Software Ltd. nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Imperas Software Ltd. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Specification: {{ARCH}} Base Integer Instruction Set, Version 2.1
# Description: Testing instruction '{{MNEMONIC}}'.

#include "riscv_test_macros.h"
#include "compliance_test.h"
#include "compliance_io.h"

RV_COMPLIANCE_RV32M

RV_COMPLIANCE_CODE_BEGIN


	RVTEST_IO_INIT
	RVTEST_IO_ASSERT_GPR_EQ(x31, x0, 0x00000000)
	RVTEST_IO_WRITE_STR(x31, "Test Begin\n")
	
{% for tid in range(0, NUM_TEST_SECTIONS) %}
    # ---------------------------------------------------------------------
    # Test {{tid}}.

    la x5, test_{{tid}}_res
    {% for sid in range(0, TEST_SECTION_SIZE) %}
    {% if OTYPE=="rr" -%}
    TEST_R_OP({{MNEMONIC}}, x1, x2,
    {{-RD_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-RS1_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-SWREG}},
    {{-WORDSIZE*sid}},
    {{-TESTREG}})
    {%- elif OTYPE=="rrr" -%}
    TEST_RR_OP({{MNEMONIC}}, x1, x2, x3,
    {{-RD_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-RS1_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-RS2_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-SWREG}},
    {{-WORDSIZE*sid}},
    {{-TESTREG}})
    {%- elif OTYPE=="rrri" -%}
    TEST_RRI_OP({{MNEMONIC}}, x1, x2, x3,
    {{-IMM_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-RD_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-RS1_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-RS2_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-SWREG}},
    {{-WORDSIZE*sid}},
    {{-TESTREG}})
    {%- elif OTYPE=="rri" -%}
    TEST_IMM_OP({{MNEMONIC}}, x1, x2, 
    {{-RD_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-RS1_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-IMM_VALS[tid*TEST_SECTION_SIZE+sid]}},
    {{-SWREG}},
    {{-WORDSIZE*sid}},
    {{-TESTREG}})
    {%- else -%}
    #error Compliance test generator error. Unknown instruction type: {{OTYPE}}
    {%- endif %} # {{sid}}
    {%- endfor %}
{% endfor %}

	# ---------------------------------------------------------------------
	
	RVTEST_IO_WRITE_STR(x31, "Test End\n")

	# ---------------------------------------------------------------------

	RV_COMPLIANCE_HALT

RV_COMPLIANCE_CODE_END

# Input data section.
	.data

# Output data section.
RV_COMPLIANCE_DATA_BEGIN

{% for tid in range(0, NUM_TEST_SECTIONS) -%}
test_{{tid}}_res:
    .fill {{TEST_SECTION_SIZE}},{{WORDSIZE}},-1
{% endfor %}

RV_COMPLIANCE_DATA_END


