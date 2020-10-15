#!/usr/bin/python3

import sys
import importlib
import math

import os
import argparse
import jinja2


default_test_template = os.path.expandvars(os.path.join(
    "$REPO_HOME","tests","compliance","test_template.S"
))


def build_argparser(args):
    """
    Constructs the argument parser for the script.

    args - input - Python list of command line arguments to the script.
                   Will usually be sys.argv.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("--template",type=str, default=default_test_template,
        help="The test template file.")

    parser.add_argument("kat_gen_output",type=str,
        help="Filepath to output of the KAT generator program")

    parser.add_argument("test_dest_dir",type=str,
        help="Directory path to dump generated tests too.")

    return parser

def get_operand_type(value_list):
    """
    - value_list - a list of dicts, where each key-value pair is an
                    operand/output and it's value. e.g. {'rs1':0xabc}
    """
    tr = ""
    if("rd" in value_list[0]):
        tr += "r"
    if("rs1" in value_list[0]):
        tr += "r"
    if("rs2" in value_list[0]):
        tr += "r"
    if("imm" in value_list[0]):
        tr += "i"
    return tr


def generate_test(
    xlen,
    mnemonic,
    value_list,
    output_dir,
    template,
    max_tests = 512):
    """
    Generate a test for the supplied instruction.

    - mnemonic - input - the assembler mnemonic of the instruciton.
    - value_list - a list of dicts, where each key-value pair is an
                    operand/output and it's value. e.g. {'rs1':0xabc}
    - output_dir - where to put the test file once generated.
    - template - Jinja template object.
    - max_tests - The maximum number of tests to generate per instruction.
    """

    arch        = "rv%dik" % xlen
    num         = "01"
    filepath    = os.path.join(output_dir,"K-%s-%s.S" % (mnemonic.upper(),num))

    otype       = get_operand_type(value_list)

    test_section_size   = 10
    num_test_sections   = int(math.ceil(len(value_list)/test_section_size))

    rd_vals  = []
    rs1_vals = []
    rs2_vals = []
    imm_vals = []

    for v in value_list:
        rd_vals .append(hex(v.get("rd" , 0x0)))
        rs1_vals.append(hex(v.get("rs1", 0x0)))
        rs2_vals.append(hex(v.get("rs2", 0x0)))
        imm_vals.append(hex(v.get("imm", 0x0)))

    text        = template.render(
        XLEN        = xlen,
        ARCH        = arch,
        MNEMONIC    = mnemonic,
        TEST_NUM    = num,
        OTYPE       = otype,
        WORDSIZE    = int(xlen/8),
        TEST_SECTION_SIZE = test_section_size,
        NUM_TEST_SECTIONS = num_test_sections,
        RD_VALS     = rd_vals ,
        RS1_VALS    = rs1_vals,
        RS2_VALS    = rs2_vals,
        IMM_VALS    = imm_vals,
        SWREG       = "x5",
        TESTREG     = "x6"
    )

    with open(filepath,"w") as fh:
        fh.write(text)
    
    print("Generated test for %20s - %s" % (mnemonic, filepath))

def main():
    """
    Main function for the script.
    """
    argparser = build_argparser(sys.argv)

    args = argparser.parse_args()

    kat_out = None

    # WARNING: Only load trusted python files using this method!
    # Load the python file created by the KAT generator
    with open(args.kat_gen_output,"r") as fh:
        contents = fh.read()
        modname  = "kat_out"
        spec     = importlib.util.spec_from_loader(modname,loader=None)
        kat_out  = importlib.util.module_from_spec(spec)
        sys.modules[modname] = kat_out
        exec(contents, kat_out.__dict__)

    xlen        = kat_out.xlen
    prng_seed   = kat_out.prng_seed
    num_tests   = kat_out.num_tests
    kat_results = kat_out.kat_results
    
    print("xlen        = %d" % xlen             )
    print("prng_seed   = %s" % hex(prng_seed)   )
    print("num_tests   = %d" % num_tests        )

    #
    # Setup the Jinja template
    template_dir = os.path.dirname(args.template)
    jinja_env = jinja2.Environment (
        loader=jinja2.FileSystemLoader(template_dir)
    )
    jinja_template = jinja_env.get_template(os.path.basename(args.template))

    #
    # Re-arrange the list of tuples into a dictionary, keyed by the
    # instruction mnemonic, mapping to a list of dicts. Each dict contains
    # the operands / results for a single execution of the instruciton.

    result_set  = {}

    for r in kat_results:
        mnemonic, operands_dict = r
        if(not mnemonic in result_set):
            result_set[mnemonic] = []
        result_set[mnemonic].append(operands_dict)

    for mnemonic in result_set:
        generate_test(
            xlen,
            mnemonic,
            result_set[mnemonic],
            args.test_dest_dir,
            jinja_template
        )

    print("Finished.")

    return 0

if(__name__=="__main__"):
    sys.exit(main())

