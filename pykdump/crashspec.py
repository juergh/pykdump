#
# Time-stamp: <06/05/19 17:25:00 alexs>

# Functions that send commands to 'crash' and parse the output. Here we put
# only those functions that depend on crash-only commands, those that cannot
# be delegated to gdb, i.e. those where 'gdb command ...' is not available
# Some commands exist in two flavors, e.g. you can do both
# 'ptype name' and 'gdb ptype name'. But usually output is somewhat different

import re
import types


import Generic as Gen
from Generic import BaseStructInfo

import tparser
from tparser import hexl

import LowLevel
from LowLevel import getOutput

# Struct/Union info representation with methods to append data
class StructInfo(BaseStructInfo):
    def __init__(self, sname):
        BaseStructInfo.__init__(self, sname)
        # If command w/o explicit struct/union specifier does not work,
        # we'll try again
        for pref in ('', 'struct ', 'union '):
            rstr = getOutput(pref + sname + " -o ")
            #print rstr
            if (rstr.find("command not found") < 0): break
	#print "="*10, sname, "\n", rstr
	(self.stype, self.size, self.body) = tparser.StructInfo(rstr)
        lenb = len(self.body)
	for i  in range(0, lenb):
	    f = self.body[i]
            f.parentstype = self.stype
            size = f.size # fieldsize(f)
            if (size == -1):
                # This may be incorrect due to padding - but OK to be used to
                # read from memory
                try:
                    # If this is the last field in struct, use the whole
                    # struct size
                    if (i == lenb -1):
                        offsetnext = self.size
                    else:
                        offsetnext = self.body[i+1].offset
                    size = offsetnext  -f.offset
                except:
                    size = -1
	    if (size != -1):
		f.sizeof = size
                
	    self[f.fname] = f

            #f['reprtype'] = fieldtype(f)


# Symbol info
# Beware: it is possible to have multiple values, e.g.
#crash> sym send_IPI_all
#c0103140 (t) send_IPI_all  include/asm/mach-summit/mach_ipi.h: 21
#c01034d8 (t) send_IPI_all  include/asm/mach-bigsmp/mach_ipi.h: 21
#c0103710 (t) send_IPI_all  include/asm/mach-es7000/mach_ipi.h: 20
#c01039fc (t) send_IPI_all  include/asm/mach-default/mach_ipi.h: 27
#
# For addr->sym there might be sym+offset value:
# c012563b (T) sys_wait4+1  ../redhat/BUILD/kernel-2.6.9/linux-2.6.9/kernel/exit.c
re_syminfo = re.compile(r'^([0-9a-f]+) \((.)\)\s+([^\s]+)')
def syminfo(sym):
    # If 'sym' is a string, pass it as it is.
    # If it's integer, convert it to hex first
    if (type(sym) != types.StringType):
        sym = hexl(sym)
    command = "sym " + sym
    rs = getOutput(command)
    out = []
    for l in rs.splitlines():
        m = re_syminfo.search(l)
        if (m):
            out.append((int(m.group(1),16), m.group(2), m.group(3)))
    return out

# Sym to addr - return the first value only (if any). 0 means there is no
# such symbold
def sym2addr(sym):
    si = syminfo(sym)
    if (len(si) == 0):
        return 0
    else:
        return si[0][0]

# Addr to sym
# c0103141 (t) send_IPI_all+1  include/asm/mach-summit/mach_ipi.h: 21
def addr2sym(addr):
    si = syminfo(addr)
    if (len(si) == 0):
        return ""
    else:
        return si[0][2]

def symbol_exists(sym):
    si = syminfo(sym)
    if (len(si) == 0):
        return 0
    else:
        return 1



