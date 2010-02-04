#!/usr/bin/env python

# Time-stamp: <09/08/14 11:15:39 alexs>

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.

# Test low-level API


import sys
#sys.path.append(".")
import time

#import cProfile

from pykdump.API import *

import pykdump.Generic as Gen
from pykdump.Generic import TypeInfo, VarInfo, SUInfo


import crash
loadModule("testmod", "../Extension/testmod/testmod.ko")

mynode = readSymbol("mynode")
print mynode.one, mynode.two

addr = sym2addr("asid")
asid = readSU("struct ASID", addr)

nfailed = 0
ntests = 0

ntests += 1
if(asid.li == 123456789 and  asid.i2 == -555):
    pass
else:
    print "Integers failed"
    nfailed += 1

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
print sarrptr
if (sarrptr[0].a0 == 11 and sarrptr[1].a0 == 22 and sarrptr[2].a0 == 33 and \
    (sarrptr+2).a0 == 33):
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

# Function pointers
ntests += 1
if (addr2sym(asid.funcptr) == "testfunc"):
    pass
else:
    print "Function Pointers"
    print addr2sym(asid.funcptr)
    nfailed += 1

print "%d tests run, %d failed" % (ntests, nfailed)

print " ------------ Performance testing --------------"

addr = sym2addr("asid")

tot = 100000

t0 = time.time()
for i in xrange(0, tot):
    readPtr(addr)
    
print "readPtr: %10.0f/s" % (tot/(time.time() - t0))

t0 = time.time()
size = 8
for i in xrange(0, tot):
    readIntN(addr, size, True)
    
print "readinteger: %10.0f/s" % (tot/(time.time() - t0))

t0 = time.time()
for i in xrange(0, tot):
    s = getStructInfo("struct ASID")

print "SUInfo: %10.0f/s" % (tot/(time.time() - t0))

t0 = time.time()
for i in xrange(0, tot):
    asid.li

print "struct.integer: %10.0f/s" % (tot/(time.time() - t0))

t0 = time.time()
for i in xrange(0, tot):
    asid.lptr
    
print "struct.iptr: %10.0f/s" % (tot/(time.time() - t0))

t0 = time.time()
for i in xrange(0, tot):
    asid.lptr.Deref
    
print "*(struct.iptr): %10.0f/s" % (tot/(time.time() - t0))

t0 = time.time()
for i in xrange(0, tot):
    s = readSU("struct ASID", addr)

print "readSU: %10.0f/s" % (tot/(time.time() - t0))

s = readSU("struct ASID", addr)
fi = s.PYT_sinfo["li"]
reader = fi.reader
faddr = addr + fi.offset
t0 = time.time()
for i in xrange(0, tot):
    reader(faddr)

print "intReader: %10.0f/s" % (tot/(time.time() - t0))

fi = s.PYT_sinfo["sptr"]
reader = fi.reader
faddr = addr + fi.offset
t0 = time.time()
for i in xrange(0, tot):
    reader(faddr)
    
    
print "ptrReader: %10.0f/s" % (tot/(time.time() - t0))


t0 = time.time()
for i in xrange(0, tot):
    fi = s.PYT_sinfo["sptr"]
    reader = fi.reader
    
print "getattr/reader: %10.0f/s" % (tot/(time.time() - t0))

t0 = time.time()
for i in xrange(0, tot):
    tptr = tPtr(addr, fi)
    
print "tPtr: %10.0f/s" % (tot/(time.time() - t0))



# Profiler stuff

def testfunc():
    for i in xrange(0, tot):
        #asid.lptr
        asid.lptr.Deref

cProfile.run('testfunc()')
