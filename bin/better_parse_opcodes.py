#!/usr/bin/env python3

import os
import sys
import argparse

from pysmt.shortcuts import Symbol, BV, LE, GE, Int, And, Equals, Plus, Solver
from pysmt.shortcuts import BVAnd, BVOr,BVXor,BVExtract,BVUGT,BVULE,BVUGE
from pysmt.shortcuts import BVNeg,BVComp, BVType, is_sat
from pysmt.shortcuts import    Equals as EQ
from pysmt.shortcuts import NotEquals as NE
from pysmt.typing import INT

class Bitfield(object):

    def __init__(self, hi,lo):
        self.hi     = int(hi)
        self.lo     = int(lo)
        assert(self.hi >= self.lo)

def BitfieldLo(b):
    return b.lo

class Operand(Bitfield):
    """
    Describes a single operand. Could be an immediate or register address.
    """
    def __init__(self, name, hi,lo,binutilscode,sailtype):
        Bitfield.__init__(self,hi,lo)
        self.name   = name
        self.binutilscode = binutilscode
        self.sailtype       = sailtype

    @property
    def is_register(self):
        return self.name in [
            "rs1", "rs2", "rs3", "rd", "rt"
        ]

    def __repr__(self):
        return self.name

    def __len__(self):
        return 1+self.hi-self.lo

class OperandConstraint(object):
    """
    describes a constraint on the value of an operand field.
    """
    def __init__(self, lhs,cond,rhs):
        assert(isinstance(lhs,Operand))
        assert(isinstance(rhs,Operand) or isinstance(rhs,int))
        self.lhs = lhs
        self.cond= cond
        self.rhs = rhs

    @property
    def cond_str(self):
        if(self.cond == EQ):
            return "=="
        elif(self.cond ==NE):
            return "!="
        elif(self.cond ==LE):
            return "<="
        else:
            assert False

    def __repr__(self):
        return "%s%s%s" % (self.lhs,str(self.cond_str),self.rhs)

class Field(Bitfield):
    """
    Describes a single immutable opcode encoding field.
    """

    def __init__(self,hi,lo,val):
        Bitfield.__init__(self,hi,lo)
        if(val.startswith("0x")):
            self.val = int(val[2:],16)
        elif(val.startswith("0b")):
            self.val = int(val[2:],2)
        else:
            self.val = int(val)

    def __repr__(self):
        return "%s..%s=%s"%(self.hi,self.lo,self.val)

    def __len__(self):
        return 1+self.hi-self.lo

    def match(self):
        return self.val << self.lo

    def mask(self):
        return ((2**len(self))-1) << self.lo
    
    @property
    def hex(self):
        return hex(self.val)

class Instruction(object):
    """
    Describes a single instruciton in terms of its operands and fields.
    """
    
    def __init__(self, mnemonic, operands, encoding_fields, constraints):

        self.pseudo     = mnemonic[0] == "@"
        self.mnemonic   = mnemonic[1:]if self.pseudo else mnemonic

        self._operands  = operands
        self._fields    = encoding_fields
        self._constraints = constraints
        
        # TODO - make these useful.
        self.rv32 = True
        self.rv64 = True

        assert(len(encoding_fields)>0)

    def getConstraintsForField(self, fname):
        tr = []
        for c in self.constraints:
            if(c.lhs.name == fname):
                tr.append(c)
        return tr

    @property
    def operands(self):
        return self._operands
    
    @property
    def fields(self):
        return self._fields
    
    @property
    def constraints(self):
        return self._constraints

    def __str__(self):
        return "%s %s %s %s" % (
            self.mnemonic,
            self._operands,
            self._constraints,
            self._fields
        )
        
    @property
    def as_normal_parse_opcodes(self):
        return "%s%s %s %s" % (
            "@" if self.pseudo else "",
            self.mnemonic,
            " ".join([str(o) for o in self._operands]),
            " ".join([str(o) for o in self._fields])
        )

    def match(self):
        tr = 0
        for f in self._fields:
            tr |= f.match()
        return tr

    def mask(self):
        tr = 0
        for f in self._fields:
            tr |= f.mask()
        return tr

    def match_hex(self):
        return hex(self.match())
    def mask_hex(self):
        return hex(self.mask())

    def wavedrom(self):
        print("Encoding `%s`::"%self.mnemonic)
        print("[wavedrom, , svg]")
        print("....")
        print("{reg:[")
        l = self.operands + self.fields
        l.sort(key=BitfieldLo)
        for f in l:
            if(isinstance(f,Operand)):
                print("{bits: %d, name: '%s'}," % (len(f),f.name))
            else:
                print("{bits: %d, name: %s}," % (len(f),f.hex))
        print("]}")
        print("....")

class EncodingParser(object):
    """
    Responsible for parseing the instruction opcode definition files.
    """

    known_operands = {
        # name             name       , hi, lo, b   , sail
        "bs"      : Operand("bs"      , 31, 30,"w"  , "bits(2)"  ),
        "rcon"    : Operand("rcon"    , 23, 20,"W"  , "bits(4)"  ),
        "rd"      : Operand("rd"      , 11,  7,"d"  , "regidx"   ),
        "rs1"     : Operand("rs1"     , 19, 15,"s"  , "regidx"   ),
        "rt"      : Operand("rt"      , 19, 15,"s"  , "regidx"   ),
        "rs2"     : Operand("rs2"     , 24, 20,"t"  , "regidx"   ),
        "rs3"     : Operand("rs3"     , 31, 27,"r"  , "regidx"   ),
        "shamt"   : Operand("shamt"   , 25, 20,">"  , "bits(5)"  ),
        "shamtw"  : Operand("shamtw"  , 24, 20,">"  , "bits(5)"  ),
        "aqrl"    : Operand("aqrl"    , 26, 25,"?"  , "?"        ),
        "rm"      : Operand("rm"      , 14, 12,"?"  , "?"        ),
        "fm"      : Operand("fm"      , 31, 28,"?"  , "?"        ),
        "pred"    : Operand("pred"    , 27, 24,"?"  , "?"        ),
        "succ"    : Operand("succ"    , 23, 20,"?"  , "?"        ),
        "imm20"   : Operand("imm20"   , 31, 12, None, None       ),
        "jimm20"  : Operand("jimm20"  , 31, 12, None, None       ),
        "imm12"   : Operand("imm12"   , 31, 20, None, None       ),
        "imm12hi" : Operand("imm12hi" , 31, 25, None, None       ),
        "bimm12hi": Operand("bimm12hi", 31, 25, None, None       ),
        "imm12lo" : Operand("imm12lo" , 11, 7 , None, None       ),
        "bimm12lo": Operand("bimm12lo", 11, 7 , None, None       ),
        "zimm"    : Operand("zimm"    , 19, 15, None, None       ),
        "rnd"     : Operand("rnd"     , 00, 00,"?"  , "bits(4)"  ),
        "vt"      : Operand("vt"      , 11,  7, None, None       ),
        "vd"      : Operand("vd"      , 11,  7, None, None       ),
        "vs3"     : Operand("vs3"     , 11,  7, None, None       ),
        "vs1"     : Operand("vs1"     , 19, 15, None, None       ),
        "vs2"     : Operand("vs2"     , 24, 20, None, None       ),
        "vm"      : Operand("vm"      , 25, 25, None, None       ),
        "simm5"   : Operand("rs1"     , 19, 15,"?"  , "bits(5)"  )
    }
    
    def parseLine(l):
        tokens = [x for x in l.split(" ") if x!=""]

        mnemonic    = tokens.pop(0)
        operands    = []
        fields      = []
        constraints = []

        while(len(tokens) > 0):
            if(tokens[0] in EncodingParser.known_operands):
                operands.append(EncodingParser.known_operands[tokens.pop(0)])
            elif(":" in tokens[0]):
                lhs,constr = tokens.pop(0).split(":")
                cond       = None
                rhs        = None
                if(constr.startswith("==")):
                    cond = EQ
                elif(constr.startswith("!=")):
                    cond = NE
                elif(constr.startswith("<=")):
                    cond = LE
                else:
                    raise Exception("Unknown field constraint '%s'")
                rhs  = constr[2:]
                if(rhs in EncodingParser.known_operands):
                    rhs = EncodingParser.known_operands[rhs]
                else:
                    rhs = int(rhs)
                constraints.append(OperandConstraint(
                    EncodingParser.known_operands[lhs],
                    cond,
                    rhs
                ))
            elif("=" in tokens[0]):
                hilo,val = tokens.pop(0).split("=")
                hi       = None
                lo       = None
                if(".." in hilo):
                    hi, lo = hilo.split("..")
                else:
                    hi, lo = hilo, hilo
                fields.append(Field(hi,lo,val))
            else:
                print(l)
                print(tokens)
                assert(0)

        tr = Instruction(mnemonic, operands, fields,constraints)
        return tr


def parse_encoding_files(input_files):
    """
    Takes a list of input files and returns a list of parsed opcodes.
    """
    tr = []

    for f in input_files:
        content = f.read()
        lines   = content.split("\n")
        lines   = [l for l in lines if l != "" and l[0] !="#"]
        for l in lines:
            instr   = EncodingParser.parseLine(l)
            if(instr != None):
                tr.append(instr)
    return tr

def overlaps(i,j):
    """
    Returns True if two instructions i,j overlap in their encoding.

    TODO: Add operand constraints into the solver formula.
    """
    if(i.pseudo or j.pseudo):
        return False
    ILEN=32

    instr   = Symbol("instr"    , BVType(width=ILEN))
    imask   = Symbol("imask"    , BVType(width=ILEN))
    imatch  = Symbol("imatch"   , BVType(width=ILEN))
    jmask   = Symbol("jmask"    , BVType(width=ILEN))
    jmatch  = Symbol("jmatch"   , BVType(width=ILEN))

    domains = And([
        EQ(imask , BV(i.mask() ,width=ILEN)),
        EQ(imatch, BV(i.match(),width=ILEN)),
        EQ(jmask , BV(j.mask() ,width=ILEN)),
        EQ(jmatch, BV(j.match(),width=ILEN))
    ])

    problem = And([
        EQ(instr & imask, imatch),
        EQ(instr & jmask, jmatch)
    ])

    formula = And(domains, problem)

    return is_sat(formula)

def cmd_check_encodings(instrs):
    """
    Check if any of the encodings collide.
    Returns true if the checks pass, False otherwise.
    """
    print("Instrucitons parsed: %d" % len(instrs))
    collisions = []

    checked = set([])
    stop    = False

    fi = None
    fj = None

    for i in instrs:
        print("Checking: %s" % i.mnemonic)
        for j in instrs:
            if(i != j and not (j,i) in checked):
                if(overlaps(i,j)):
                    collisions.append((i,j))
                    stop = True
                    fi = i
                    fj = j
                    break
                checked.add((i,j))
        if(stop):
            break

    if(stop):
        print(format(fi.mask() , "032b"))
        print(format(fj.mask() , "032b"))
        print(format(fi.match(), "032b"))
        print(format(fj.match(), "032b"))

    for (i,j) in collisions:
        print("%s collides with %s"%(i.mnemonic,j.mnemonic))

    return len(collisions) == 0

def latex_safename(n):
    n = n.replace(".","")
    n = n.replace("0","zero")
    n = n.replace("1","one")
    n = n.replace("2","two")
    n = n.replace("3","three")
    n = n.replace("4","four")
    n = n.replace("5","five")
    n = n.replace("6","six")
    n = n.replace("8","eight")
    n = n.replace("9","nine")
    return n

def c_safename(n):
    return n.replace(".","_")

def verilog_safename(n):
    return n.replace(".","_")

def cmd_tex_cmds(instrs):
    """
    Print latex commands which when invoked, show the encoding of
    the instruction in question.
    """
    for i in instrs:
        print("\\newcommand{\enc%s}{"%latex_safename(i.mnemonic))
        tp = []
        for f in i.fields:
            tp.append((f.hi, f.lo, format(f.val,"0%db"%len(f))))
        for o in i.operands:
            txt = o.name
            constraints = i.getConstraintsForField(o.name)
            if(len(constraints)==1):
                txt = str(constraints[0])
            if(len(constraints)>1):
                txt = ",".join([str(c) for c in constraints])
            tp.append((o.hi,o.lo,txt))
        tp.sort(key=lambda tp:tp[0],reverse=True)
        for hi,lo,val in tp:
            width = 1 + hi - lo
            print( r'\bitbox{%d}{\tt %s}' % (width,val))
        print( r'\bitbox{%d}{\bf\tt %s}\\' % ( 9,  i.mnemonic))
        print("}")
    return True


def cmd_tex_table(instrs):
    print(r"""\begin{bytefield}[bitwidth={1.05em},endianness={big}]{32}\bitheader{0-31} \\""")
    for i in instrs:
        print("\\enc%s" % latex_safename(i.mnemonic))
    print(r"""\end{bytefield}""")
    return True

def print_match_mask_defines(instrs):
    for i in instrs:
        mname = c_safename(i.mnemonic).upper()
        print("#define MASK_%s  %s" %(mname,i.mask_hex()))
        print("#define MATCH_%s %s" %(mname,i.match_hex()))

def cmd_wavedrom(instrs):
    for i in instrs:
        i.wavedrom()

def cmd_spike(instrs):
    """
    Print code useful for generating the spike patch.
    """
    print_match_mask_defines(instrs)
    for i in instrs:
        mname = c_safename(i.mnemonic).upper()
        print("DECLARE_INSN(%s,MATCH_%s,MASK_%s)"%(
            mname.lower(),mname,mname
        ))
    return True

def cmd_binutils(instrs):
    """
    Print code useful for generating the binutils patch.
    """
    print_match_mask_defines(instrs)

    for i in instrs:
        mname = c_safename(i.mnemonic).upper()

        opargs = [o.binutilscode for o in i.operands]
        argstring = ",".join([str(o) for o in opargs])

        line = "{%-15s, 0, INSN_CLASS_K, %10s, %s, %s, match_opcode, 0}," % (
          "\"%s\""%i.mnemonic,
          "\"%s\""%argstring,
          "MATCH_%s" % mname,
          "MASK_%s" % mname
        )
        print(line)
    return True


def make_sail_encdec_pattern(i):
    """
    Returns a list of strings, represnting the SAIL encdec clause
    pattern which will decode to the supplied instruciton.
    """
    tp = []
    for f in i.fields:
        tp.append((f.hi, f.lo, "0b"+format(f.val,"0%db"%len(f))))
    for o in i.operands:
        txt = o.name
        constraints = i.getConstraintsForField(o.name)
        tp.append((o.hi,o.lo,txt))
    tp.sort(key=lambda tp:tp[0],reverse=True)

    return [t[2] for t in tp]

def cmd_sail(instrs):
    encdec_clauses = []
    ast_clauses    = []
    asm_clauses    = []
    exec_clauses   = []

    for i in instrs:
        iname = i.mnemonic.upper().replace(".","_")

        iargs =  i.operands.copy()
        iargs.reverse()

        iarg_types = [a.sailtype for a in iargs]

        encdec_str = make_sail_encdec_pattern(i)

        clause_encdec = "mapping clause encdec = %15s   (%s) \n    <-> %s" % (
            iname, ",".join([i.name for i in iargs]), " @ ".join(encdec_str)
        )

        clause_ast    = "union   clause ast    = %15s : (%s)" % (
            iname, ",".join(iarg_types)
        )
        
        asm_tokens = i.operands.copy()

        for j in range(0,len(asm_tokens)):
            if(asm_tokens[j].is_register):
                asm_tokens[j] = "reg_name(%s)" % asm_tokens[j].name
            else:
                asm_tokens[j] = asm_tokens[j].name

        asm_str = "\"%s\" ^ spc() ^ %s" % (
            i.mnemonic, " ^ sep() ^ ".join(asm_tokens)
        )

        clause_asm    = "mapping clause assembly = %15s (%s) <-> %s" % (
            iname, ",".join([i.name for i in iargs]), asm_str
        )

        clause_exec   = "function clause execute (%15s (%s)) = {%s}" % (
            iname, 
            ",".join([i.name for i in iargs]),
            "\n    /* TBD, implemented as nop.*/\n    RETIRE_SUCCESS\n"
        )

        encdec_clauses.append(clause_encdec)
        ast_clauses.append(clause_ast)
        asm_clauses.append(clause_asm)
        exec_clauses.append(clause_exec)

    print("\n".join(ast_clauses))
    print("\n".join(asm_clauses))
    print("\n".join(exec_clauses))
    print("\n".join(encdec_clauses))
    return True



def cmd_normal_parse_opcodes(instrs):
    for i in instrs:
        print(i.as_normal_parse_opcodes)
    return True


def cmd_verilog(instrs):
    for i in instrs:
        print("wire dec_%-20s = (d_data & 32'h%s) == 32'h%s;" % (
           verilog_safename(i.mnemonic),
           hex(i.mask())[2:],
           hex(i.match())[2:]
        ))
    return True


def build_arg_parser():
    parser  = argparse.ArgumentParser()
    subs    = parser.add_subparsers()

    sub_check = subs.add_parser("check",help="Check opcodes for collisions")
    sub_check.set_defaults(func=cmd_check_encodings)
    sub_check.add_argument("input_files",nargs="+",type=argparse.FileType("r"))
    
    sub_textable = subs.add_parser("tex-table",help="Print the latex for the instruction encodings table.")
    sub_textable.set_defaults(func=cmd_tex_table)
    sub_textable.add_argument("input_files",nargs="+",type=argparse.FileType("r"))
    
    sub_texcmds = subs.add_parser("tex-cmds",help="Print the latex for the encoding table row of each instruciton, wrapped up as a single command.")
    sub_texcmds.set_defaults(func=cmd_tex_cmds)
    sub_texcmds.add_argument("input_files",nargs="+",type=argparse.FileType("r"))
    
    sub_wavedrom = subs.add_parser("wavedrom",help="Print the instruction encodings as wavedrom reg descriptions for inclusion in the asciidoc spec.")
    sub_wavedrom.set_defaults(func=cmd_wavedrom)
    sub_wavedrom.add_argument("input_files",nargs="+",type=argparse.FileType("r"))

    sub_spike= subs.add_parser("spike",help="Print Useful C code for the Spike patch")
    sub_spike.set_defaults(func=cmd_spike)
    sub_spike.add_argument("input_files",nargs="+",type=argparse.FileType("r"))

    sub_binutils= subs.add_parser("binutils",help="Print Useful C code for the Binutils patch")
    sub_binutils.set_defaults(func=cmd_binutils)
    sub_binutils.add_argument("input_files",nargs="+",type=argparse.FileType("r"))
    
    sub_binutils= subs.add_parser("sail",help="Print Useful SAIL code for the SAIL Formal Model patch")
    sub_binutils.set_defaults(func=cmd_sail)
    sub_binutils.add_argument("input_files",nargs="+",type=argparse.FileType("r"))
    
    sub_binutils= subs.add_parser("normal-parse-opcodes",help="Print the instructions in the format used by the vanilla parse_opcodes.py script")
    sub_binutils.set_defaults(func=cmd_normal_parse_opcodes)
    sub_binutils.add_argument("input_files",nargs="+",type=argparse.FileType("r"))

    sub_verilog = subs.add_parser("verilog", help="Print a simple verilog decoder per instruction")
    sub_verilog.set_defaults(func=cmd_verilog)
    sub_verilog.add_argument("input_files",nargs="+",type=argparse.FileType("r"))

    return parser

def main():
    parser  = build_arg_parser()
    args    = parser.parse_args()
    
    instrs  = parse_encoding_files(args.input_files)

    retval  = args.func(instrs)

    if(retval):
        sys.exit(0)
    else:
        sys.exit(1)

if(__name__ == "__main__"):
    main()
