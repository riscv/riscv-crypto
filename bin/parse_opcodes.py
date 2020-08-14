#!/usr/bin/env python

from __future__ import print_function
from builtins import hex
from builtins import range
import math
import sys
import tokenize

namelist = []
match = {}
mask = {}
pseudos = {}
arguments = {}
opcodebits ={}

sail_args_types = {
    "rs1"   : "regidx",
    "rs2"   : "regidx",
    "rd"    : "regidx",
    "bs"    : "bits(2)",
    "shamtw": "bits(5)",
    "rcon"  : "bits(4)",
    "vs1"   : "vregidx",
    "vs2"   : "vregidx",
    "vt"    : "vregidx",
    "vd"    : "vregidx",
    "rnd"   : "bits(4)",
    "vm"    : "bits(1)",
    "simm5" : "bits(5)"
}

reg_names = ["rd", "rs1", "rs2", "rs3"]

#
# Binutils argument codes
acodes = {}
acodes['bs'     ] = "w"
acodes['rcon'   ] = "W"
acodes['rd'     ] = "d"
acodes['rdp'    ] = "(N,M)"
acodes['rs1'    ] = "s"
acodes['rs2'    ] = "t"
acodes['rs3'    ] = "r"
acodes['shamtw' ] = ">"
acodes['vs1'    ] = "?" # Where ? appears, need to go look in binutils for
acodes['vs2'    ] = "?" # the right code.
acodes['vt'     ] = "?"
acodes['vd'     ] = "?"
acodes['rnd'    ] = "?"
acodes['vm'     ] = "?"
acodes['simm5'  ] = "?"

arglut = {}
arglut['bs']   = (31,30)
arglut['rcon'] = (23,20)

arglut['rd'] = (11,7)
arglut['rdp'] = (11,8)
arglut['rs1'] = (19,15)
arglut['rs2'] = (24,20)
arglut['rs3'] = (31,27)
arglut['aqrl'] = (26,25)
arglut['fm'] = (31,28)
arglut['pred'] = (27,24)
arglut['succ'] = (23,20)
arglut['rm'] = (14,12)
arglut['funct3'] = (14,12)
arglut['imm20'] = (31,12)
arglut['jimm20'] = (31,12)
arglut['imm12'] = (31,20)
arglut['imm12hi'] = (31,25)
arglut['bimm12hi'] = (31,25)
arglut['imm12lo'] = (11,7)
arglut['bimm12lo'] = (11,7)
arglut['zimm'] = (19,15)
arglut['shamt'] = (25,20)
arglut['shamtw'] = (24,20)

# for vectors
arglut['vt'] = (11,7)
arglut['vd'] = (11,7)
arglut['vs3'] = (11,7)
arglut['vs1'] = (19,15)
arglut['vs2'] = (24,20)
arglut['vm'] = (25,25)
arglut['wd'] = (26,26)
arglut['amoop'] = (31,27)
arglut['nf'] = (31,29)
arglut['simm5'] = (19,15)
arglut['rnd'  ] = (18,15)
arglut['zimm11'] = (30,20)


causes = [
  (0x00, 'misaligned fetch'),
  (0x01, 'fetch access'),
  (0x02, 'illegal instruction'),
  (0x03, 'breakpoint'),
  (0x04, 'misaligned load'),
  (0x05, 'load access'),
  (0x06, 'misaligned store'),
  (0x07, 'store access'),
  (0x08, 'user_ecall'),
  (0x09, 'supervisor_ecall'),
  (0x0A, 'hypervisor_ecall'),
  (0x0B, 'machine_ecall'),
  (0x0C, 'fetch page fault'),
  (0x0D, 'load page fault'),
  (0x0F, 'store page fault'),
]

csrs = [
  # Standard User R/W
  (0x001, 'fflags'),
  (0x002, 'frm'),
  (0x003, 'fcsr'),
  (0x000, 'ustatus'),
  (0x004, 'uie'),
  (0x005, 'utvec'),
  (0x008, 'vstart'),
  (0x009, 'vxsat'),
  (0x00A, 'vxrm'),
  (0x040, 'uscratch'),
  (0x041, 'uepc'),
  (0x042, 'ucause'),
  (0x043, 'utval'),
  (0x044, 'uip'),

  # Standard User RO
  (0xC00, 'cycle'),
  (0xC01, 'time'),
  (0xC02, 'instret'),
  (0xC03, 'hpmcounter3'),
  (0xC04, 'hpmcounter4'),
  (0xC05, 'hpmcounter5'),
  (0xC06, 'hpmcounter6'),
  (0xC07, 'hpmcounter7'),
  (0xC08, 'hpmcounter8'),
  (0xC09, 'hpmcounter9'),
  (0xC0A, 'hpmcounter10'),
  (0xC0B, 'hpmcounter11'),
  (0xC0C, 'hpmcounter12'),
  (0xC0D, 'hpmcounter13'),
  (0xC0E, 'hpmcounter14'),
  (0xC0F, 'hpmcounter15'),
  (0xC10, 'hpmcounter16'),
  (0xC11, 'hpmcounter17'),
  (0xC12, 'hpmcounter18'),
  (0xC13, 'hpmcounter19'),
  (0xC14, 'hpmcounter20'),
  (0xC15, 'hpmcounter21'),
  (0xC16, 'hpmcounter22'),
  (0xC17, 'hpmcounter23'),
  (0xC18, 'hpmcounter24'),
  (0xC19, 'hpmcounter25'),
  (0xC1A, 'hpmcounter26'),
  (0xC1B, 'hpmcounter27'),
  (0xC1C, 'hpmcounter28'),
  (0xC1D, 'hpmcounter29'),
  (0xC1E, 'hpmcounter30'),
  (0xC1F, 'hpmcounter31'),
  (0xC20, 'vl'),
  (0xC21, 'vtype'),

  # Standard Supervisor R/W
  (0x100, 'sstatus'),
  (0x104, 'sie'),
  (0x105, 'stvec'),
  (0x106, 'scounteren'),
  (0x140, 'sscratch'),
  (0x141, 'sepc'),
  (0x142, 'scause'),
  (0x143, 'stval'),
  (0x144, 'sip'),
  (0x180, 'satp'),

  # Standard Hypervisor R/w
  (0x200, 'vsstatus'),
  (0x204, 'vsie'),
  (0x205, 'vstvec'),
  (0x240, 'vsscratch'),
  (0x241, 'vsepc'),
  (0x242, 'vscause'),
  (0x243, 'vstval'),
  (0x244, 'vsip'),
  (0x280, 'vsatp'),
  (0x600, 'hstatus'),
  (0x602, 'hedeleg'),
  (0x603, 'hideleg'),
  (0x606, 'hcounteren'),
  (0x680, 'hgatp'),

  # Tentative CSR assignment for CLIC
  (0x007, 'utvt'),
  (0x045, 'unxti'),
  (0x046, 'uintstatus'),
  (0x048, 'uscratchcsw'),
  (0x049, 'uscratchcswl'),
  (0x107, 'stvt'),
  (0x145, 'snxti'),
  (0x146, 'sintstatus'),
  (0x148, 'sscratchcsw'),
  (0x149, 'sscratchcswl'),
  (0x307, 'mtvt'),
  (0x345, 'mnxti'),
  (0x346, 'mintstatus'),
  (0x348, 'mscratchcsw'),
  (0x349, 'mscratchcswl'),

  # Standard Machine R/W
  (0x300, 'mstatus'),
  (0x301, 'misa'),
  (0x302, 'medeleg'),
  (0x303, 'mideleg'),
  (0x304, 'mie'),
  (0x305, 'mtvec'),
  (0x306, 'mcounteren'),
  (0x340, 'mscratch'),
  (0x341, 'mepc'),
  (0x342, 'mcause'),
  (0x343, 'mtval'),
  (0x344, 'mip'),
  (0x3a0, 'pmpcfg0'),
  (0x3a1, 'pmpcfg1'),
  (0x3a2, 'pmpcfg2'),
  (0x3a3, 'pmpcfg3'),
  (0x3b0, 'pmpaddr0'),
  (0x3b1, 'pmpaddr1'),
  (0x3b2, 'pmpaddr2'),
  (0x3b3, 'pmpaddr3'),
  (0x3b4, 'pmpaddr4'),
  (0x3b5, 'pmpaddr5'),
  (0x3b6, 'pmpaddr6'),
  (0x3b7, 'pmpaddr7'),
  (0x3b8, 'pmpaddr8'),
  (0x3b9, 'pmpaddr9'),
  (0x3ba, 'pmpaddr10'),
  (0x3bb, 'pmpaddr11'),
  (0x3bc, 'pmpaddr12'),
  (0x3bd, 'pmpaddr13'),
  (0x3be, 'pmpaddr14'),
  (0x3bf, 'pmpaddr15'),
  (0x7a0, 'tselect'),
  (0x7a1, 'tdata1'),
  (0x7a2, 'tdata2'),
  (0x7a3, 'tdata3'),
  (0x7b0, 'dcsr'),
  (0x7b1, 'dpc'),
  (0x7b2, 'dscratch'),
  (0xB00, 'mcycle'),
  (0xB02, 'minstret'),
  (0xB03, 'mhpmcounter3'),
  (0xB04, 'mhpmcounter4'),
  (0xB05, 'mhpmcounter5'),
  (0xB06, 'mhpmcounter6'),
  (0xB07, 'mhpmcounter7'),
  (0xB08, 'mhpmcounter8'),
  (0xB09, 'mhpmcounter9'),
  (0xB0A, 'mhpmcounter10'),
  (0xB0B, 'mhpmcounter11'),
  (0xB0C, 'mhpmcounter12'),
  (0xB0D, 'mhpmcounter13'),
  (0xB0E, 'mhpmcounter14'),
  (0xB0F, 'mhpmcounter15'),
  (0xB10, 'mhpmcounter16'),
  (0xB11, 'mhpmcounter17'),
  (0xB12, 'mhpmcounter18'),
  (0xB13, 'mhpmcounter19'),
  (0xB14, 'mhpmcounter20'),
  (0xB15, 'mhpmcounter21'),
  (0xB16, 'mhpmcounter22'),
  (0xB17, 'mhpmcounter23'),
  (0xB18, 'mhpmcounter24'),
  (0xB19, 'mhpmcounter25'),
  (0xB1A, 'mhpmcounter26'),
  (0xB1B, 'mhpmcounter27'),
  (0xB1C, 'mhpmcounter28'),
  (0xB1D, 'mhpmcounter29'),
  (0xB1E, 'mhpmcounter30'),
  (0xB1F, 'mhpmcounter31'),
  (0x323, 'mhpmevent3'),
  (0x324, 'mhpmevent4'),
  (0x325, 'mhpmevent5'),
  (0x326, 'mhpmevent6'),
  (0x327, 'mhpmevent7'),
  (0x328, 'mhpmevent8'),
  (0x329, 'mhpmevent9'),
  (0x32A, 'mhpmevent10'),
  (0x32B, 'mhpmevent11'),
  (0x32C, 'mhpmevent12'),
  (0x32D, 'mhpmevent13'),
  (0x32E, 'mhpmevent14'),
  (0x32F, 'mhpmevent15'),
  (0x330, 'mhpmevent16'),
  (0x331, 'mhpmevent17'),
  (0x332, 'mhpmevent18'),
  (0x333, 'mhpmevent19'),
  (0x334, 'mhpmevent20'),
  (0x335, 'mhpmevent21'),
  (0x336, 'mhpmevent22'),
  (0x337, 'mhpmevent23'),
  (0x338, 'mhpmevent24'),
  (0x339, 'mhpmevent25'),
  (0x33A, 'mhpmevent26'),
  (0x33B, 'mhpmevent27'),
  (0x33C, 'mhpmevent28'),
  (0x33D, 'mhpmevent29'),
  (0x33E, 'mhpmevent30'),
  (0x33F, 'mhpmevent31'),

  # Standard Machine RO
  (0xF11, 'mvendorid'),
  (0xF12, 'marchid'),
  (0xF13, 'mimpid'),
  (0xF14, 'mhartid'),
]

csrs32 = [
  # Standard User RO
  (0xC80, 'cycleh'),
  (0xC81, 'timeh'),
  (0xC82, 'instreth'),
  (0xC83, 'hpmcounter3h'),
  (0xC84, 'hpmcounter4h'),
  (0xC85, 'hpmcounter5h'),
  (0xC86, 'hpmcounter6h'),
  (0xC87, 'hpmcounter7h'),
  (0xC88, 'hpmcounter8h'),
  (0xC89, 'hpmcounter9h'),
  (0xC8A, 'hpmcounter10h'),
  (0xC8B, 'hpmcounter11h'),
  (0xC8C, 'hpmcounter12h'),
  (0xC8D, 'hpmcounter13h'),
  (0xC8E, 'hpmcounter14h'),
  (0xC8F, 'hpmcounter15h'),
  (0xC90, 'hpmcounter16h'),
  (0xC91, 'hpmcounter17h'),
  (0xC92, 'hpmcounter18h'),
  (0xC93, 'hpmcounter19h'),
  (0xC94, 'hpmcounter20h'),
  (0xC95, 'hpmcounter21h'),
  (0xC96, 'hpmcounter22h'),
  (0xC97, 'hpmcounter23h'),
  (0xC98, 'hpmcounter24h'),
  (0xC99, 'hpmcounter25h'),
  (0xC9A, 'hpmcounter26h'),
  (0xC9B, 'hpmcounter27h'),
  (0xC9C, 'hpmcounter28h'),
  (0xC9D, 'hpmcounter29h'),
  (0xC9E, 'hpmcounter30h'),
  (0xC9F, 'hpmcounter31h'),

  # Standard Machine RW
  (0xB80, 'mcycleh'),
  (0xB82, 'minstreth'),
  (0xB83, 'mhpmcounter3h'),
  (0xB84, 'mhpmcounter4h'),
  (0xB85, 'mhpmcounter5h'),
  (0xB86, 'mhpmcounter6h'),
  (0xB87, 'mhpmcounter7h'),
  (0xB88, 'mhpmcounter8h'),
  (0xB89, 'mhpmcounter9h'),
  (0xB8A, 'mhpmcounter10h'),
  (0xB8B, 'mhpmcounter11h'),
  (0xB8C, 'mhpmcounter12h'),
  (0xB8D, 'mhpmcounter13h'),
  (0xB8E, 'mhpmcounter14h'),
  (0xB8F, 'mhpmcounter15h'),
  (0xB90, 'mhpmcounter16h'),
  (0xB91, 'mhpmcounter17h'),
  (0xB92, 'mhpmcounter18h'),
  (0xB93, 'mhpmcounter19h'),
  (0xB94, 'mhpmcounter20h'),
  (0xB95, 'mhpmcounter21h'),
  (0xB96, 'mhpmcounter22h'),
  (0xB97, 'mhpmcounter23h'),
  (0xB98, 'mhpmcounter24h'),
  (0xB99, 'mhpmcounter25h'),
  (0xB9A, 'mhpmcounter26h'),
  (0xB9B, 'mhpmcounter27h'),
  (0xB9C, 'mhpmcounter28h'),
  (0xB9D, 'mhpmcounter29h'),
  (0xB9E, 'mhpmcounter30h'),
  (0xB9F, 'mhpmcounter31h'),
]

opcode_base = 0
opcode_size = 7
funct_base = 12
funct_size = 3

def binary(n, digits=0):
  rep = bin(n)[2:]
  return rep if digits == 0 else ('0' * (digits - len(rep))) + rep

def make_c(match,mask):
  match_vars= {}
  mask_vars = {}
  print('/* Automatically generated by parse_opcodes.  */')
  print('#ifndef RISCV_ENCODING_H')
  print('#define RISCV_ENCODING_H')
  for name in namelist:
    name2 = name.upper().replace('.','_')
    match_vars[name] = "MATCH_%s" % name2
    mask_vars[name]  = "MASK_%s"  % name2
    print('#define %s %s' % (match_vars[name], hex(match[name])))
    print('#define %s %s' % (mask_vars[name] , hex(mask[name])))
  for num, name in csrs+csrs32:
    print('#define CSR_%s %s' % (name.upper(), hex(num)))
  for num, name in causes:
    print('#define CAUSE_%s %s' % (name.upper().replace(' ', '_'), hex(num)))
  print('#endif')

  print('#ifdef DECLARE_INSN')
  for name in namelist:
    name2 = name.replace('.','_')
    print('DECLARE_INSN(%s, MATCH_%s, MASK_%s)' % (name2, name2.upper(), name2.upper()))
  print('#endif')

  print('#ifdef DECLARE_CSR')
  for num, name in csrs+csrs32:
    print('DECLARE_CSR(%s, CSR_%s)' % (name, name.upper()))
  print('#endif')

  print('#ifdef DECLARE_CAUSE')
  for num, name in causes:
    print('DECLARE_CAUSE("%s", CAUSE_%s)' % (name, name.upper().replace(' ', '_')))
  print('#endif')
  
  for mnemonic in namelist:

      argstring = ",".join([acodes[a] for a in arguments[mnemonic]])

      line = "{%-22s, 0, INSN_CLASS_ZSCRYPTO, %10s, %s, %s, match_opcode, 0}," % (
        "\"%s\""%mnemonic,
        "\"%s\""%argstring,
        match_vars[mnemonic],
        mask_vars[mnemonic]
      )

      print(line)

def yank(num,start,len):
  return (num >> start) & ((1 << len) - 1)

def str_arg(arg0,name,match,arguments):
  if arg0 in arguments:
    return name or arg0
  else:
    start = arglut[arg0][1]
    len = arglut[arg0][0] - arglut[arg0][1] + 1
    return binary(yank(match,start,len),len)

def str_inst(name,arguments):
  return name.replace('.rv32','').upper()

def print_unimp_type(name,match,arguments):
  print("""
&
\\multicolumn{10}{|c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    '0'*32, \
    'UNIMP' \
  ))

def print_u_type(name,match,arguments):
  print("""
&
\\multicolumn{8}{|c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    str_arg('imm20','imm[31:12]',match,arguments), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_uj_type(name,match,arguments):
  print("""
&
\\multicolumn{8}{|c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    str_arg('jimm20','imm[20$\\vert$10:1$\\vert$11$\\vert$19:12]',match,arguments), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_s_type(name,match,arguments):
  print("""
&
\\multicolumn{4}{|c|}{%s} &
\\multicolumn{2}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    str_arg('imm12hi','imm[11:5]',match,arguments), \
    str_arg('rs2','',match,arguments), \
    str_arg('rs1','',match,arguments), \
    binary(yank(match,funct_base,funct_size),funct_size), \
    str_arg('imm12lo','imm[4:0]',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_sb_type(name,match,arguments):
  print("""
&
\\multicolumn{4}{|c|}{%s} &
\\multicolumn{2}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    str_arg('bimm12hi','imm[12$\\vert$10:5]',match,arguments), \
    str_arg('rs2','',match,arguments), \
    str_arg('rs1','',match,arguments), \
    binary(yank(match,funct_base,funct_size),funct_size), \
    str_arg('bimm12lo','imm[4:1$\\vert$11]',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_i_type(name,match,arguments):
  print("""
&
\\multicolumn{6}{|c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    str_arg('imm12','imm[11:0]',match,arguments), \
    str_arg('rs1','',match,arguments), \
    binary(yank(match,funct_base,funct_size),funct_size), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_csr_type(name,match,arguments):
  print("""
&
\\multicolumn{6}{|c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    str_arg('imm12','csr',match,arguments), \
    ('uimm' if name[-1] == 'i' else 'rs1'), \
    binary(yank(match,funct_base,funct_size),funct_size), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_ish_type(name,match,arguments):
  print("""
&
\\multicolumn{3}{|c|}{%s} &
\\multicolumn{3}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    binary(yank(match,26,6),6), \
    str_arg('shamt','shamt',match,arguments), \
    str_arg('rs1','',match,arguments), \
    binary(yank(match,funct_base,funct_size),funct_size), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_ishw_type(name,match,arguments):
  print("""
&
\\multicolumn{4}{|c|}{%s} &
\\multicolumn{2}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    binary(yank(match,25,7),7), \
    str_arg('shamtw','shamt',match,arguments), \
    str_arg('rs1','',match,arguments), \
    binary(yank(match,funct_base,funct_size),funct_size), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_r_type(name,match,arguments):
  print("""
&
\\multicolumn{4}{|c|}{%s} &
\\multicolumn{2}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    binary(yank(match,25,7),7), \
    str_arg('rs2','',match,arguments), \
    'zimm' in arguments and str_arg('zimm','imm[4:0]',match,arguments) or str_arg('rs1','',match,arguments), \
    str_arg('rm','',match,arguments), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_r4_type(name,match,arguments):
  print("""
&
\\multicolumn{2}{|c|}{%s} &
\\multicolumn{2}{c|}{%s} &
\\multicolumn{2}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    str_arg('rs3','',match,arguments), \
    binary(yank(match,25,2),2), \
    str_arg('rs2','',match,arguments), \
    str_arg('rs1','',match,arguments), \
    str_arg('rm','',match,arguments), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_amo_type(name,match,arguments):
  print("""
&
\\multicolumn{2}{|c|}{%s} &
\\multicolumn{1}{c|}{aq} &
\\multicolumn{1}{c|}{rl} &
\\multicolumn{2}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    binary(yank(match,27,5),5), \
    str_arg('rs2','',match,arguments), \
    str_arg('rs1','',match,arguments), \
    binary(yank(match,funct_base,funct_size),funct_size), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_fence_type(name,match,arguments):
  print("""
&
\\multicolumn{2}{|c|}{%s} &
\\multicolumn{3}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} &
\\multicolumn{1}{c|}{%s} & %s \\\\
\\cline{2-11}
  """ % \
  ( \
    str_arg('fm','fm',match,arguments), \
    str_arg('pred','pred',match,arguments), \
    str_arg('succ','',match,arguments), \
    str_arg('rs1','',match,arguments), \
    binary(yank(match,funct_base,funct_size),funct_size), \
    str_arg('rd','',match,arguments), \
    binary(yank(match,opcode_base,opcode_size),opcode_size), \
    str_inst(name,arguments) \
  ))

def print_header(*types):
  print("""
\\newpage

\\begin{table}[p]
\\begin{small}
\\begin{center}
\\begin{tabular}{p{0in}p{0.4in}p{0.05in}p{0.05in}p{0.05in}p{0.05in}p{0.4in}p{0.6in}p{0.4in}p{0.6in}p{0.7in}l}
& & & & & & & & & & \\\\
                      &
\\multicolumn{1}{l}{\\instbit{31}} &
\\multicolumn{1}{r}{\\instbit{27}} &
\\instbit{26} &
\\instbit{25} &
\\multicolumn{1}{l}{\\instbit{24}} &
\\multicolumn{1}{r}{\\instbit{20}} &
\\instbitrange{19}{15} &
\\instbitrange{14}{12} &
\\instbitrange{11}{7} &
\\instbitrange{6}{0} \\\\
\\cline{2-11}
""")
  if 'r' in types:
    print("""
&
\\multicolumn{4}{|c|}{funct7} &
\\multicolumn{2}{c|}{rs2} &
\\multicolumn{1}{c|}{rs1} &
\\multicolumn{1}{c|}{funct3} &
\\multicolumn{1}{c|}{rd} &
\\multicolumn{1}{c|}{opcode} & R-type \\\\
\\cline{2-11}
""")
  if 'r4' in types:
    print("""
&
\\multicolumn{2}{|c|}{rs3} &
\\multicolumn{2}{c|}{funct2} &
\\multicolumn{2}{c|}{rs2} &
\\multicolumn{1}{c|}{rs1} &
\\multicolumn{1}{c|}{funct3} &
\\multicolumn{1}{c|}{rd} &
\\multicolumn{1}{c|}{opcode} & R4-type \\\\
\\cline{2-11}
  """)
  if 'i' in types:
    print("""
&
\\multicolumn{6}{|c|}{imm[11:0]} &
\\multicolumn{1}{c|}{rs1} &
\\multicolumn{1}{c|}{funct3} &
\\multicolumn{1}{c|}{rd} &
\\multicolumn{1}{c|}{opcode} & I-type \\\\
\\cline{2-11}
""")
  if 's' in types:
    print("""
&
\\multicolumn{4}{|c|}{imm[11:5]} &
\\multicolumn{2}{c|}{rs2} &
\\multicolumn{1}{c|}{rs1} &
\\multicolumn{1}{c|}{funct3} &
\\multicolumn{1}{c|}{imm[4:0]} &
\\multicolumn{1}{c|}{opcode} & S-type \\\\
\\cline{2-11}
""")
  if 'sb' in types:
    print("""
&
\\multicolumn{4}{|c|}{imm[12$\\vert$10:5]} &
\\multicolumn{2}{c|}{rs2} &
\\multicolumn{1}{c|}{rs1} &
\\multicolumn{1}{c|}{funct3} &
\\multicolumn{1}{c|}{imm[4:1$\\vert$11]} &
\\multicolumn{1}{c|}{opcode} & B-type \\\\
\\cline{2-11}
""")
  if 'u' in types:
    print("""
&
\\multicolumn{8}{|c|}{imm[31:12]} &
\\multicolumn{1}{c|}{rd} &
\\multicolumn{1}{c|}{opcode} & U-type \\\\
\\cline{2-11}
""")
  if 'uj' in types:
    print("""
&
\\multicolumn{8}{|c|}{imm[20$\\vert$10:1$\\vert$11$\\vert$19:12]} &
\\multicolumn{1}{c|}{rd} &
\\multicolumn{1}{c|}{opcode} & J-type \\\\
\\cline{2-11}
""")

def print_subtitle(title):
  print("""
&
\\multicolumn{10}{c}{} & \\\\
&
\\multicolumn{10}{c}{\\bf %s} & \\\\
\\cline{2-11}
  """ % title)

def print_footer(caption=''):
  print("""
\\end{tabular}
\\end{center}
\\end{small}
%s
\\end{table}
  """ % caption)

def print_xcrypto_inst(n):
    ifields = opcodebits[n]
    fs      = []
    for hi,lo,val in ifields:
        width = 1 + hi - lo
        val = bin(val)[2:].rjust(width,"0")
        fs.append((hi,lo,val))
    for argname in arglut:
        if(argname in arguments[n]):
            hi,lo = arglut[argname]
            fs.append((hi,lo,argname))
    
    fs.sort(key=lambda fs:fs[0],reverse=True)

    for hi,lo,val in fs:
        width = 1 + hi - lo
        print( r'\bitbox{%d}{\tt %s}%%' % (width,val))
    print( r'\bitbox{%d}{\bf\tt %s}\\%%' % ( 9,  n))


def make_dec_wirename(instrname):
    return "dec_%s"     % instrname.lower().replace("xc.","").replace(".","_")

def make_verilog(match,mask):
    """
    Generate verilog for decoding all of the ISE instructions.
    """

    src_wire = "encoded"
    ise_args = set([])
    dec_wires= set([])

    for instr in namelist:
        wirename = make_dec_wirename(instr)
        tw       = "wire %s = " % (wirename.ljust(15))
        
        tw      += "(%s & 32'h%s) == 32'h%s;" % (
            src_wire, hex(mask[instr])[2:], hex(match[instr])[2:]
        )
        
        dec_wires.add(wirename)

        print(tw)

        for arg in arguments[instr]:
            ise_args.add(arg)

    for field in ise_args:
        wirename = "dec_arg_%s" % field.lower().replace(".","_")
        wirewidth= (arglut[field][0]-arglut[field][1])
        tw       = "wire [%d:0] %s = encoded[%d:%d];" % (
            wirewidth,
            wirename.ljust(15), arglut[field][0],arglut[field][1]
        )
        print(tw)

    invalidinstr = "wire dec_invalid_opcode = !(" + \
        " || ".join(list(dec_wires)) +  \
        ");" 
    print(invalidinstr)


def get_instr_encoding_strings(instr):
    """
    Returns a list of tuples of the form (X,Y) where X is the start
    of a bitfield in an instruction encoding, and Y is the value of the
    bitfield. Note that X is the Most Significant bit of the bitfield.
    E.g. (14, "101") indicates the func3 value.
    """
    imask = mask[instr]

    strings = []
    current_pos = None
    current_str = ""

    bitpos      = 31

    while(bitpos >= 0):
        while(bitpos >= 0 and ((imask >> bitpos) & 0x1) == 0):
            bitpos -= 1

        current_pos = bitpos
        current_str = "0b"

        while(bitpos>= 0 and ((imask >> bitpos) & 0x1) == 1):
            current_str += str((match[instr] >> bitpos) & 0x1)
            bitpos -= 1

        strings.append((current_pos, current_str))

    return strings


def make_sail_encdec_pattern(instr):
    """
    Returns a list of strings, represnting the SAIL encdec clause
    pattern which will decode to the supplied instruciton.
    """
    encoding_strings = get_instr_encoding_strings(instr)
    args             = arguments[instr].copy()
    args.reverse()

    encdec           = []

    while(len(encoding_strings) > 0 and len(args) > 0):
        arg_hi, arg_lo = arglut[args[0]]
        enc_hi, enc_s  = encoding_strings[0]

        if(arg_hi > enc_hi):
            encdec.append(args.pop(0))
        else:
            encdec.append(encoding_strings.pop(0)[1])

    while(len(encoding_strings)):
        encdec.append(encoding_strings.pop(0)[1])

    return encdec


def make_sail():
    """
    Generate code for the SAIL AST description.
    Creates clauses for the ast, assembly and encdec mappings.
    """
    
    encdec_clauses = []
    ast_clauses    = []
    asm_clauses    = []
    exec_clauses   = []

    for instr in namelist:
        iname = instr.upper().replace(".","_")

        iargs =  arguments[instr].copy()
        iargs.reverse()

        iarg_types = [sail_args_types[a] for a in iargs]

        encdec_str = make_sail_encdec_pattern(instr)

        clause_encdec = "mapping clause encdec = %15s   (%s) <-> %s" % (
            iname, ",".join(iargs), " @ ".join(encdec_str)
        )

        clause_ast    = "union   clause ast    = %15s : (%s)" % (
            iname, ",".join(iarg_types)
        )
        
        asm_tokens = arguments[instr].copy()

        for i in range(0,len(asm_tokens)):
            if(asm_tokens[i] in reg_names):
                asm_tokens[i] = "reg_name(%s)" % asm_tokens[i]

        asm_str = "\"%s\" ^ spc() ^ %s" % (
            instr, " ^ sep() ^ ".join(asm_tokens)
        )

        clause_asm    = "mapping clause assembly = %15s (%s) <-> %s" % (
            iname, ",".join(iargs), asm_str
        )

        clause_exec   = "function clause execute (%15s (%s)) = {%s}" % (
            iname, 
            ",".join(iargs),
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


def print_inst(n):
  print_xcrypto_inst(n)
    #print_r_type(n, match[n], arguments[n])

def print_insts(*names):
  for n in names:
    print_inst(n)

def make_supervisor_latex_table():
  print_header('r', 'i')
  print_subtitle('Trap-Return Instructions')
  print_insts('uret', 'sret', 'mret')
  print_subtitle('Interrupt-Management Instructions')
  print_insts('wfi')
  print_subtitle('Supervisor Memory-Management Instructions')
  print_insts('sfence.vma')
  print_subtitle('Hypervisor Memory-Management Instructions')
  print_insts('hfence.vvma')
  print_insts('hfence.gvma')
  print_footer('\\caption{RISC-V Privileged Instructions}')

def make_latex_table():
  print(r"""
\begin{bytefield}[bitwidth={1.05em},endianness={big}]{32}
\bitheader{0-31} \\
  """)
  for name in namelist:
      print_inst(name)
  print(r"""\end{bytefield}""")

def print_chisel_insn(name):
  s = "  def %-18s = BitPat(\"b" % name.replace('.', '_').upper()
  for i in range(31, -1, -1):
    if yank(mask[name], i, 1):
      s = '%s%d' % (s, yank(match[name], i, 1))
    else:
      s = s + '?'
  print(s + "\")")

def make_chisel():
  print('/* Automatically generated by parse_opcodes */')
  print('object Instructions {')
  for name in namelist:
    print_chisel_insn(name)
  print('}')
  print('object Causes {')
  for num, name in causes:
    print('  val %s = %s' % (name.lower().replace(' ', '_'), hex(num)))
  print('  val all = {')
  print('    val res = collection.mutable.ArrayBuffer[Int]()')
  for num, name in causes:
    print('    res += %s' % (name.lower().replace(' ', '_')))
  print('    res.toArray')
  print('  }')
  print('}')
  print('object CSRs {')
  for num, name in csrs+csrs32:
    print('  val %s = %s' % (name, hex(num)))
  print('  val all = {')
  print('    val res = collection.mutable.ArrayBuffer[Int]()')
  for num, name in csrs:
    print('    res += %s' % (name))
  print('    res.toArray')
  print('  }')
  print('  val all32 = {')
  print('    val res = collection.mutable.ArrayBuffer(all:_*)')
  for num, name in csrs32:
    print('    res += %s' % (name))
  print('    res.toArray')
  print('  }')
  print('}')

def print_sverilog_insn(name):
  s = "  localparam [31:0] %-18s = 32'b" % name.replace('.', '_').upper()
  for i in range(31, -1, -1):
    if yank(mask[name], i, 1):
      s = '%s%d' % (s, yank(match[name], i, 1))
    else:
      s = s + '?'
  print(s + ";")

def make_sverilog():
  print('/* Automatically generated by parse_opcodes */')
  print('package riscv_instr;')
  for name in namelist:
    print_sverilog_insn(name)
  print('  /* CSR Addresses */')
  for num, name in csrs+csrs32:
    print('  localparam logic [11:0] CSR_%s = 12\'h%s;' % (name.upper(), hex(num)[2:]))
  print('endpackage')

def signed(value, width):
  if 0 <= value < (1<<(width-1)):
    return value
  else:
    return value - (1<<width)

def print_go_insn(name):
  print('\tcase A%s:' % name.upper().replace('.', ''))
  m = match[name]
  opcode = yank(m, 0, 7)
  funct3 = yank(m, 12, 3)
  rs2 = yank(m, 20, 5)
  csr = yank(m, 20, 12)
  funct7 = yank(m, 25, 7)
  print('\t\treturn &inst{0x%x, 0x%x, 0x%x, %d, 0x%x}, true' % (opcode, funct3, rs2, signed(csr, 12), funct7))

def make_go():
  print('// Code generated by parse_opcodes; DO NOT EDIT.')
  print()
  print('package riscv')
  print()
  print('import "cmd/internal/obj"')
  print()
  print('type inst struct {')
  print('\topcode uint32')
  print('\tfunct3 uint32')
  print('\trs2    uint32')
  print('\tcsr    int64')
  print('\tfunct7 uint32')
  print('}')
  print()
  print('func encode(a obj.As) (i *inst, ok bool) {')
  print('\tswitch a {')
  for name in namelist:
    print_go_insn(name)
  print('\t}')
  print('\treturn nil, false')
  print('}')

def parse_inputs(args):
  inputs = []
  for fn in args:
      try:
          inputs.append(open(fn))
      except:
          assert(0)
  if not inputs:
      inputs.append(sys.stdin)

  for f in inputs:
    for line in f:
      line = line.partition('#')
      tokens = line[0].split()

      if len(tokens) == 0:
        continue
      assert len(tokens) >= 2

      name = tokens[0]
      pseudo = name[0] == '@'
      if pseudo:
        name = name[1:]
      mymatch = 0
      mymask = 0
      cover = 0

      if not name in list(arguments.keys()):
        arguments[name] = []
        opcodebits[name] = []

      for token in tokens[1:]:
        if len(token.split('=')) == 2:
          tokens = token.split('=')
          if len(tokens[0].split('..')) == 2:
            tmp = tokens[0].split('..')
            hi = int(tmp[0])
            lo = int(tmp[1])
            if hi <= lo:
              sys.exit("%s: bad range %d..%d" % (name,hi,lo))
          else:
            hi = lo = int(tokens[0])

          if tokens[1] != 'ignore':
            val = int(tokens[1], 0)
            if val >= (1 << (hi-lo+1)):
              sys.exit("%s: bad value %d for range %d..%d" % (name,val,hi,lo))
            opcodebits[name].append((hi,lo,val))
            mymatch = mymatch | (val << lo)
            mymask = mymask | ((1<<(hi+1))-(1<<lo))

          if cover & ((1<<(hi+1))-(1<<lo)):
            sys.exit("%s: overspecified" % name)
          cover = cover | ((1<<(hi+1))-(1<<lo))

        elif token in arglut:
          if cover & ((1<<(arglut[token][0]+1))-(1<<arglut[token][1])):
            sys.exit("%s: overspecified" % name)
          cover = cover | ((1<<(arglut[token][0]+1))-(1<<arglut[token][1]))
          arguments[name].append(token)

        else:
          sys.exit("%s: unknown token %s" % (name,token))

      if not (cover == 0xFFFFFFFF or cover == 0xFFFF):
        sys.exit("%s: not all bits are covered" % name)

      if pseudo:
        pseudos[name] = 1
      else:
        for name2,match2 in match.items():
          if name2 not in pseudos and (match2 & mymask) == mymatch:
            sys.exit("%s and %s overlap" % (name,name2))

      mask[name] = mymask
      match[name] = mymatch
      namelist.append(name)

    if f is not sys.stdin:
        f.close()
  return (namelist, pseudos, mask, match, arguments)

if __name__ == "__main__":
  parse_inputs(sys.argv[2:])

  if sys.argv[1] == '-tex':
    make_latex_table()
  elif sys.argv[1] == '-privtex':
    make_supervisor_latex_table()
  elif sys.argv[1] == '-chisel':
    make_chisel()
  elif sys.argv[1] == '-sverilog':
    make_sverilog()
  elif sys.argv[1] == '-verilog':
    make_verilog(match,mask)
  elif sys.argv[1] == '-sail-boilerplate':
    make_sail()
  elif sys.argv[1] == '-c':
    make_c(match,mask)
  elif sys.argv[1] == '-go':
    make_go()
  elif sys.argv[1] == '-check':
    pass
  else:
    assert 0
