#!/usr/bin/env python

# Time-stamp: <07/10/11 10:48:11 alexs>

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.

# Test low-level API


import sys
sys.path.append(".")


from pykdump.API import *

import pykdump.Generic as Gen
from pykdump.Generic import TypeInfo, VarInfo, SUInfo


import crash
loadModule("testmod", "../Extension/testmod/testmod.ko")


addr = sym2addr("asid")
asid = readSU("struct ASID", addr)

nfailed = 0
ntests = 0

ntests += 1
if(asid.bf1 == 1 and  asid.bf2 == 2 and  asid.bf3 == -2 and asid.bf4 == 123):
    pass
else:
    print "Bitfields failed"
    nfailed += 1

ntests += 1
if (asid.f1.ff.bb == "bbstring" and  asid.f2.buf == "buf"):
    pass
else:
    print "Strings/Chararrays failed"
    nfailed += 1

ntests += 1
if (asid.sarr[0].a0 == 11 and asid.sarr[1].a0 == 22 and asid.sarr[2].a0 == 33):
    pass
else:
    print "Struct arrays failed"
    nfailed += 1

# Integer Pointers 

ntests += 1
if (asid.lptr.Deref == 7 and asid.iptr.Deref == 6 \
    and asid.ipptr.Deref.Deref == 6 and asid.ippptr.Deref.Deref.Deref == 6):
    pass
else:
    print "Integer pointers failed"
    nfailed += 1

# Integer multidim arrays
ntests += 1
iarr2 = asid.iarr2
for i in range(5):
    for j in range(3):
        if (iarr2[i][j] != i*10 + j):
             print "Multidim Integer arrays failed"
             nfailed += 1
             break

# Pointer arithmetic
ntests += 1

sarrptr = asid.sarrptr
if (sarrptr[0].a0 == 11 and sarrptr[1].a0 == 22 and sarrptr[2].a0 == 33):
    pass
else:
    print "Pointer aritmetic failed"
    print sarrptr[0].a0, sarrptr[1].a0, sarrptr[2].a0
    nfailed += 1

# Pointer arrays
ntests += 1

ptrarr = asid.ptrarr
if (ptrarr[0].Deref.a0 == 11 and ptrarr[1].Deref.a0 == 22 \
    and ptrarr[2].Deref.a0 == 33):
    pass
else:
    print "Pointer arrays failed"
    print ptrarr[0].Deref.a0, ptrarr[1].Deref.a0, ptrarr[2].Deref.a0
    nfailed += 1

print "%d tests run, %d failed" % (ntests, nfailed)

