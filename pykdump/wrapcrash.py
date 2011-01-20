# -*- coding: utf-8 -*-
#

# High-level API built on top of C-module
# There are several layers of API. Ideally, the end-users should only call
# high-level functions that do not depend on internal

# Copyright (C) 2006-2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2008 Hewlett-Packard Co., All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.



import sys
import string, re
import struct

import types
from StringIO import StringIO
import pprint

pp = pprint.PrettyPrinter(indent=4)

from tparser import parseSUDef

experimental = False
experimental = True

debug = False

import Generic as Gen
from Generic import Bunch, TypeInfo, VarInfo, SUInfo, ArtStructInfo

hexl = Gen.hexl


# GLobals used my this module



# the default number of elements returned from list traversal

_MAXEL = 10000

# A well-known way to remove dups from sequence
def unique(s):
    u = {}
    for x in s:
        u[x] = 1
    return u.keys()

# An auxiliary function: create a multi-dim list based on index list,
# e.g. [2,3,4] =>  a[2][3][4] filled with None
def multilist(mdim):
    d1 = mdim[0]
    if (len(mdim) > 1):
        a = []
        for i in range(d1):
            a.append(multilist(mdim[1:]))
    else:
        a =  [None for i in range(d1)]
    return a

def _arr1toM(dims, arr1):    
    # We do this for 2- and 3-dim only
    out = multilist(dims)
    if (len(dims) == 2):
        I = dims[0]
        J = dims[1]
        for i in range(I):
            for j in range(J):
                out[i][j] = arr1[i*J+j]

    elif (len(dims) == 3):
        I = dims[0]
        J = dims[1]
        K = dims[2]
        for i in range(I):
            for j in range(J):
                for k in range(K):
                    out[i][j] = arr1[i*J*K+j*K +k]
    else:
        raise TypeError, "Array with dim >3"
    return out

    
# Classes to be used for basic types representation
# We adjust 'stype' if needed

def update_TI(f, e):
    # These fields are always set
    t_size = e["typelength"]
    f.codetype = e["codetype"]
    f.stype = e_to_tagname(e)

    f.size = t_size

    if (e.has_key("dims")):
        f.dims = e["dims"]

    if (e.has_key("stars")):
        f.ptrlev = e["stars"]

    if (e.has_key("uint")):
        f.uint = e["uint"]
    else:
        f.uint = None


    if (e.has_key("typedef")):
        f.typedef = e["typedef"]        # The initial type

    if (e.has_key("ptrbasetype")):
        f.ptrbasetype = e["ptrbasetype"] # The base type of pointer

    # A special case is a struct/union without tag. In this case
    # we create an artifical name for it

    # If we have a body, get details
    if (e.has_key("body")):
        tag = e_to_tagname(e)
        # Add this typeinfo to cache
        ff = SUInfo(tag, False)
        if (not ff.PYT_body):
            update_SUI(ff, e)
        f.details = ff
    # A function prototype
    elif (e.has_key("prototype")):
	prototype = f.prototype = []
	for ee in e["prototype"]:
	    fname = ee["fname"]
	    ti = TypeInfo('', False)
            update_TI(ti, ee)
	    prototype.append(ti)

def update_TI_fromgdb(f, sname):
    e = crash.gdb_typeinfo(sname)
    update_TI(f, e)

def update_EI_fromgdb(f, sname):
    # If sname does not start from 'enum', we are trying to get
    # a group of unnamed enums using one of its members
    try:
        if (sname.find("enum ") == -1):
            e = crash.gdb_whatis(sname)
            f.stype = "enum"
        else:
            e = crash.gdb_typeinfo(sname)
    except crash.error:
        raise TypeError, "cannot find enum <%s>" % sname
    if (e["codetype"] != TYPE_CODE_ENUM): # TYPE_CODE_ENUM
        raise TypeError, "%s is not a enum"
    f._Lst = e["edef"]
    for n, v in f._Lst:
        f[n] = v
        
        

# Choose a tag used for caching:
# - if we have typedef, use it
# - otherwise, use the real type
# - if the tag is non-descriptive (e.g. embedded structs), create a fakename
def e_to_tagname(e):
    if (e.has_key("typedef")):
        tag = e["typedef"]        # The initial type
    else:
        tag = e["basetype"]
    # Do we just one word in basetype? If yes, create a proper tag
    if (tag in ('struct', 'union')):
        tag = tag + " fake-" + str(id(e))

    return tag
        
 
   
def update_SUI(f, e):
    f.PYT_size = f.size = e["typelength"]
    for ee in e["body"]:
        fname = ee["fname"]
        f1 = VarInfo(fname, False)
        ti = TypeInfo('', False)
        update_TI(ti, ee)
        f1.ti = ti
        f1.bitoffset = ee["bitoffset"]
        f1.offset = f1.bitoffset/8
        if (ee.has_key("bitsize")):
            f1.bitsize = ee["bitsize"]

        f.append(fname, f1)


def update_TI_fromgdb(f, sname):
    e = crash.gdb_typeinfo(sname)
    update_TI(f, e)
    

def update_SUI_fromgdb(f, sname):
    try:
        e = crash.gdb_typeinfo(sname)
    except crash.error:
        raise TypeError, "no type " + sname
    # This can be a typedef to struct
    if (not e.has_key("body")):
        e = crash.gdb_typeinfo(e["basetype"])
    update_SUI(f, e)

class subStructResult(type):
    __cache = {}
    def __call__(cls, *args):
        sname = args[0]
        try:
            ncls = subStructResult.__cache[sname]
        except KeyError:
            supername = cls.__name__
            classname = '%s_%s' % (supername, sname)
            # Class names cannot contain spaces or -
            classname = classname.replace(' ', '_').replace('-', '_')
            execstr = 'class %s(%s): pass' % (classname, supername)
            #print '===', execstr
            exec execstr
            ncls = locals()[classname]
            ncls.PYT_symbol = sname
            ncls.PYT_sinfo = SUInfo(sname)
            ncls.PYT_size = ncls.PYT_sinfo.PYT_size;

        rc =  ncls.__new__(ncls, *args)
        rc.__init__(*args)
        subStructResult.__cache[sname] = ncls
        return rc


# Parse the derefence string
def parseDerefString(sname, teststring):
    si = getStructInfo(sname)
    out =[]
    codetype = -1
    if (debug):
	print '-------sname=%s, test=%s' % (sname, teststring)
    for f in teststring.split('.'):
        f = f.strip()
        if (si and si.has_key(f)):
            fi = si[f]
            offset = fi.offset
            if (debug):
                print f, "offset=%d" % offset
            ti = fi.ti
            codetype = ti.codetype
            isptr= False
            if (codetype == TYPE_CODE_PTR):
                # Pointer
                if (ti.stype == "(func)"):
                    tcodetype = -1      # Bogus
                    isptr = True
                else:
                    tti = ti.getTargetType()
                    tcodetype = ti.getTargetCodeType()
                if (debug):
                    print "    pointer:",
                if (tcodetype in TYPE_CODE_SU):
                    si = getStructInfo(tti.stype)
                    if (debug):
                        print tti.stype
                    isptr = True
            elif (codetype in TYPE_CODE_SU):
                # Struct/Union
                if (debug):
                    print "    SU:", ti.stype
                si = getStructInfo(ti.stype)
            else:
                si = None
                if (debug):
                    print "    codetype=%d" % codetype
            out.append((isptr, offset))
        else:
            if (debug):
                print "Cannot continue f=<%s>, codetype=%d" % (f, codetype)
            return False

    # If we reached this place, we have been able to dereference
    # everything. If the last field is of integer type, check for
    # bitsize/bitoffset
    # If the last field is of pointer type, we do not need to mark it
    # as such - the reader knows better what to do
    out[-1] = (False, out[-1][1])
    return (fi, out)
        


def pseudoAttrEvaluator(addr, vi, chain):
    addr = long(addr)
    for ptr, offset in chain:
        if (ptr):
            addr = readPtr(addr+offset)
        else:
            addr += offset
    # Now read the variable as defined by fi from address addr
    return vi.reader(addr)

# Pseudoattributes.
class PseudoAttr(object):
    def __init__(self, fi, chain):
        self.fi = fi
        self.chain = chain
    def __get__(self, obj, objtype):
        if (self.chain == None):
            return obj
        val = pseudoAttrEvaluator(long(obj),  self.fi, self.chain)
        return val

# Procedural
class PseudoAttrProc(object): 
    def __init__(self, proc):
        self.proc = proc
    def __get__(self, obj, objtype):
        return self.proc(obj)
  
class StructResult(long):
    __metaclass__ = subStructResult
    def __new__(cls, sname, addr = 0):
        return long.__new__(cls, addr)
    
    #def __init__(self, sname, addr = 0):
    #	pass

    # The next two methods implement pointer arithmetic, i.e.
    # stype *p
    # (p+i) points to addr + sizeof(stype)*i
    # p[i] is equivalent to (p+i)

    def __getitem__(self, i):
        if (type(i) == type("")):
            return self.PYT_sinfo[i]

        sz1 = self.PYT_size
        return StructResult(self.PYT_symbol, long(self) + i * sz1)

    # The __add__ method can break badly-written programs easily - if
    # we forget to cast the pointer to (void *)
    def __add__(self, i):
        #raise TypeError, "!!!"
        return self[i]
    
    def __getattr__(self, name):
        try:
            fi = self.PYT_sinfo[name]
        except KeyError:
            # Due to Python 'private' class variables mangling,
            # if we use a.__var inside 'class AAA', it will be
            # converted to a._AAA__var. This creates prob;ems for
            # emulating C to access attributes.
            # The approach I use below is ugly - but I have not found
            # a better way yet
            ind = name.find('__')
            if (ind > 0):
                name = name[ind:]
	    try:
                fi = self.PYT_sinfo[name]
	    except KeyError:
                msg = "<%s> does not have a field <%s>" % \
                      (self.PYT_symbol, name)
                raise KeyError, msg

        #print fi, fi.offset, fi.reader
        return fi.reader(long(self) + fi.offset)

    def __eq__(self, cmp):
	return (long(self) == cmp)
    def __str__(self):
        return "<%s 0x%x>" % \
               (self.PYT_symbol, long(self))

    def __repr__(self):
        return "StructResult <%s 0x%x> \tsize=%d" % \
               (self.PYT_symbol, long(self), self.PYT_size)
    # Print all fields (without diving into structs/unions)
    def Dump(self, indent = 0):
	sindent = ' ' * indent
	for fn in self.PYT_sinfo.PYT_body:
	    # For big arrays, print just 4 first elements
	    fi = self.PYT_sinfo[fn]
	    elements = fi.ti.elements
	    val = self.__getattr__(fn)
	    if (not isinstance(val, SmartString) and elements > 3):
	       val = str(val[:4])[:-1] + ", ..."
	    print sindent, "    %18s " % fn, val
	
	
    
    # Backwards compatibility
    #def __nonzero__(self):
    #    return (self.PYT_addr != 0)

    def __len__(self):
        return self.PYT_size

    def hasField(self, fname):
        return self.PYT_sinfo.has_key(fname)
        #return (self.PYT_sinfo.chainOK(fname) != False)

    def isNamed(self, sname):
        return sname == self.PYT_symbol

    def getDeref(self):
        return self

    def Eval(self, estr):
        cls = self.__class__
        try:
            (fi, chain) = cls.__cache[estr]
            #print "Got from Eval cache", estr, cls
            return pseudoAttrEvaluator(long(self), fi, chain)
        except AttributeError:
            #print "Creating a Eval cache for", cls
            cls.__cache = {}
        except KeyError:
            pass
        (fi, chain) = parseDerefString(self.PYT_symbol, estr)
        cls.__cache[estr] = (fi, chain)
        return pseudoAttrEvaluator(long(self), fi, chain)

    # Cast to another type. Here we assume that that one struct resides
    # as the first member of another one, this is met frequently in kernel
    # sources
    def castTo(self, sname):
        return StructResult(sname, long(self))

    Deref = property(getDeref)

def structSetAttr(sname, aname, estrings, sextra = []):
    if (type(estrings) == type("")):
        estrings = [estrings]

    try:
        cls = StructResult(sname).__class__
    except TypeError:
        # This struct does not exist - return False
        return False
    #print sname, cls
    for s in estrings:
        # A special case - an empty string means "return ourself"
        if (s == ""):
            rc =  [None, None]
        else:
            rc = parseDerefString(sname, s)
        if (rc):
            fi, chain = rc
	    pa = PseudoAttr(fi, chain)
            setattr(cls,  aname, pa)
	    for extra in sextra:
		ecls = StructResult(extra).__class__
		setattr(ecls,  aname, pa)
            return True
    return False

# Set a general procedural attr        
def structSetProcAttr(sname, aname, meth):
    try:
        cls = StructResult(sname).__class__
    except TypeError:
        # This struct does not exist - return False
        return False

    setattr(cls, aname, PseudoAttrProc(meth))
    return True

# A factory function for integer readers
def ti_intReader(ti, bitoffset = None, bitsize = None):
    def signedReader(addr):
        #s = readmem(addr, size)
        #return mem2long(s, signed = True)
        return readIntN(addr, size, True)
    def unsignedReader(addr):
        #s = readmem(addr, size)
        #return mem2long(s)
        return readIntN(addr, size)
    def signedBFReader(addr):
        #s = readmem(addr, size)
        #val = mem2long(s)
        val = readIntN(addr, size)
        val = (val >> bitoffset) & mask
        sign = val >> (bitsize - 1)
        if (sign):
            return val - mask -1
        else:
            return val
    def unsignedBFReader(addr):
        #s = readmem(addr, size)
        #val = mem2long(s)
        val = readIntN(addr, size)
        val = (val>>bitoffset) & mask
        return val

    def charArray(addr):
	s = readmem(addr, dim1)
        val = SmartString(s, addr, None)
        return val

    # Arrays
    def signedArrayReader(addr):
        s = readmem(addr, totsize)
        val = mem2long(s, signed = True, array = elements)
        if (len(dims) > 1):
            val = _arr1toM(dims, val)
        return val

    def unsignedArrayReader(addr):
        s = readmem(addr, totsize)
        val =  mem2long(s, array = elements)
	# A subtle problem: for array=1 mem2long returns and
	# integer, not a list. This is bad for declarations like
	# in bits[1]
        if (len(dims) > 1):
            val = _arr1toM(dims, val)
	elif (elements == 1):
	    val = [val]
        return val

    # A special case like unsigned char tb_data[0];
    # Return intDimensionlessArray
    def zeroArrayReader(addr):
        return intDimensionlessArray(addr, size, not unsigned)

    size = ti.size
    uint = ti.uint
    unsigned = (uint == None or uint)
    dims = ti.dims
    elements = ti.elements
    totsize = size * elements
    if (debug):
        print "Creating an intReader size=%d" % size, \
              "uint=", uint, \
              "bitsize=", bitsize, "bitoffset=", bitoffset

    #print "dims=", dims
    if (dims != None and len(dims) == 1 and ti.stype == 'char'):
        # CharArray
        dim1 = dims[0]
	# If dimension is zero, return the address. Some structs
	# have this at the end, e.g. 
	# struct Qdisc {
	# ...
	#     char data[0];
	# };
	if (dim1 == 0):
	    return zeroArrayReader
        else:
            return charArray
    elif (dims != None and  len(dims) == 1 and dims[0] == 0):
        return zeroArrayReader
    elif (unsigned):
        if (bitsize == None):
            if (dims == None):
                return unsignedReader
            else:
                return unsignedArrayReader
        else:
            mask = (~(~0<<bitsize))
            return unsignedBFReader
    else:
        if (bitsize == None):
            if (dims == None):
                return signedReader
            else:
                return signedArrayReader
        else:
            mask = (~(~0<<bitsize))
            return signedBFReader



# A factory function for struct/union readers
def suReader(vi):
    def reader1(addr):
        return StructResult(stype, addr)

    def readerarr(addr):
        out = []
        for i in range(elements):
            sr = StructResult(stype, addr + i * size)
            out.append(sr)
        if (len(dims) > 1):
            out = _arr1toM(dims, out)
        return out

    # A special case, e.g. struct sockaddr_un name[0]
    def zeroArrayReader(addr):
        return StructResult(stype, addr)

    ti = vi.ti
    dims = ti.dims
    elements = ti.elements
    size = ti.size
    stype = ti.stype

    if (elements == 1):
        return reader1
    elif (elements == 0):
        return zeroArrayReader
    else:
        return readerarr
    

# A factory function for pointer readers
def ptrReader(vi, ptrlev):
    # Struct/Union reader
    def ptrSU(addr):
        ptr = readPtr(addr)
        return StructResult(stype, ptr)
    def strPtr(addr):
        ptr = readPtr(addr)
        # If ptr = NULL, return None, needed for backwards compatibility
        if (ptr == 0):
            return None
        # Usually a string pointer points to a NULL-terminates string
        # But it can be used for crah/byte-array as well
        # So we do not really know how many bytes to read. I expected that
        # 256 is a reasonable number but small strings at the end of pages
        # trigger "Cannot access memory" in some rare cases
        try:
	    s = readmem(ptr, 256)
	except crash.error:
	    bytes = (((ptr>>8) +1)<<8) - ptr
	    s = readmem(ptr, bytes)
        return SmartString(s, addr, ptr)
    def genPtr(addr):
        return tPtr(readPtr(addr), vi)

    def funcPtr(addr):
        ptr = readPtr(addr)
	if (ptr and machine == "ia64"):
	    ptr = readPtr(ptr)
        return ptr

    def ptrArray(addr):
        val = []
        for i in range(elements):
            ptr = readPtr(addr + i * size)
            val.append(tPtr(ptr, vi))
        if (len(dims) > 1):
            val = _arr1toM(dims, val)
        return val
   
    # A special case like struct x8664_pda *_cpu_pda[0];
    # Convert it internally to struct x8664_pda **_cpu_pda;
    # 
    def ptrArr0(addr):
        tptr = tPtr(addr, vi)
        tptr.ptrlev += 1
        return tptr

    ti = vi.ti
    dims = ti.dims
    elements = ti.elements
    size = ti.size
    stype = ti.stype
        
    if (ptrlev == 1 and stype == 'char'):
        reader = strPtr
    elif (ti.ptrbasetype == 6):      # A pointer to function
	reader = funcPtr
    elif (ptrlev == 1 and ti.ptrbasetype in (3, 4) \
          and dims == None): #A pointer to struct/union
	reader = ptrSU
    else:
        if (dims != None):
            if (len(dims) == 1 and elements <= 1):
                return ptrArr0
            else:
                return ptrArray
        else:
            # A generic ptr
            reader = genPtr
    return reader

        
# Wrapper functions to return attributes of StructResult

def Addr(obj, extra = None):
    if (isinstance(obj, StructResult)):
        # If we have extra set, we want to know the address of this field
        if (extra == None):
            return long(obj)
        else:
            off = obj.PYT_sinfo[extra].offset
            return long(obj) + off
    elif (isinstance(obj, SmartString) or isinstance(obj, SmartList)):
          return obj.addr
    else:
        raise TypeError, type(obj)

# Dereference a tPtr object - at this moment 1-dim pointers to SU only
def Deref(obj):
    if (isinstance(obj, tPtr)):
        return obj.Deref
    if (isinstance(obj, StructResult)):
        # This is needed for backwards compatibility only!
        return obj
    else:
        raise TypeError, "Trying to dereference a non-pointer " + str(obj)


# When we do readSymbol and have pointers to struct, we need a way
# to record this info instead of just returning integer address

# To make dereferences faster, we store the basetype and ptrlev

class tPtr(long):
    def __new__(cls, l, vi):
        return long.__new__(cls, l)
    def __init__(self, l, vi):
        self.vi = vi
        self.ptrlev = vi.ti.ptrlev
        #self.ptrlev = vi.ptrlev
    # For pointers, index access is equivalent to pointer arithmetic
    def __getitem__(self, i):
        #sz1 = self.vi.ti.size
        return self.getArrDeref(i)
    def getArrDeref(self, i):
        addr = long(self)
        ptrlev = self.ptrlev
        if (addr == 0):
            msg = "\nNULL pointer %s" % repr(self)
            raise IndexError, msg

        if (ptrlev == 1):
            dereferencer = self.vi.dereferencer # sets vi.tsize as well
            addr += i * self.vi.tsize
            return  dereferencer(addr)
        elif (ptrlev == 2 and self.vi.ti.tcodetype in TYPE_CODE_SU):
            addr += i * self.vi.ti.size
            return self.vi.dereferencer(readPtr(addr))
        else:
            addr += i * self.vi.ti.size
            ntptr = tPtr(readPtr(addr), self.vi)
            ntptr.ptrlev = ptrlev - 1
            return ntptr
    def getDeref(self, i = None):
        addr = long(self)
        if (addr == 0):
            msg = "\nNULL pointer %s" % repr(self)
            raise IndexError, msg

        if (self.ptrlev == 1):
            return self.vi.dereferencer(addr)
        else:
            ntptr = tPtr(readPtr(addr), self.vi)
            ntptr.ptrlev = self.ptrlev - 1
            return ntptr
    def __repr__(self):
        stars = '*' * self.ptrlev
        return "<tPtr addr=0x%x ctype='%s %s'>" % \
               (self, self.vi.ti.stype, stars)
    Deref = property(getDeref)

    # Backwards compatibility
    def getPtype(self):
        return self.vi
    ptype = property(getPtype)


class SmartString(str):
    def __new__(cls, s, addr, ptr):
        return str.__new__(cls, s.split('\0')[0])
    def __init__(self, s, addr, ptr):
        self.addr = addr
        self.ptr = ptr
        self.__fullstr = s
    def __long__(self):
        return self.ptr
    def __getslice__(  self, i, j):
	return self.__fullstr.__getslice__(i, j)
    def __getitem__(self, key):
	return self.__fullstr.__getitem__(key)

class SmartList(list):
    def __new__(cls, l = [], addr = None):
        return list.__new__(cls, l)
    def __init__(self, l = [], addr = None):
        list.__init__(self, l)
        self.addr = addr
    
    

# Print the object delegating all work to GDB. At this moment can do this
# for StructResult only

def printObject(obj):
    if (isinstance(obj, StructResult)):
        cmd = "p *(%s *)0x%x" %(obj.PYT_symbol, long(obj))
        print cmd
        s = exec_gdb_command(cmd)
        # replace the 1st line with something moe useful
        first, rest = s.split("\n", 1)
	print "%s 0x%x {" %(obj.PYT_symbol, long(obj))
        print rest
    else:
        raise TypeError
        

# =============================================================
#
#           ======= read functions =======
#
# =============================================================
def readU8(addr):
    s = readmem(addr, 1)
    return mem2long(s)


def readU16(addr):
    s = readmem(addr, 2)
    return mem2long(s)

def readU32(addr):
    s = readmem(addr, 4)
    return mem2long(s)

def readS32(addr):
    s = readmem(addr, 4)
    return mem2long(s, signed = True)

def readU64(addr):
    s = readmem(addr, 8)
    return mem2long(s)

def readS64(addr):
    s = readmem(addr, 8)
    return mem2long(s, signed = True)
    
# addr should be numeric here
def readSU(symbol, addr):
    return StructResult(symbol, addr)

#          ======== read arrays =========


# Read an array of structs/unions given the structname, start and dimension
def readSUArray(suname, startaddr, dim=0):
    # If dim==0, return a Generator
    if (dim == 0):
        return SUArray(suname, startaddr)
    sz = struct_size(suname)
    # Now create an array of StructResult.
    out = []
    for i in range(0,dim):
        out.append(StructResult(suname, startaddr+i*sz))
    return out


#          ======== read a chunk of physical memory ===

def readProcessMem(taskaddr, uvaddr, size):
    # We cannot read through the page boundary
    out = []
    while (size > 0):
        paddr = uvtop(taskaddr, uvaddr)

        cnt = crash.PAGESIZE - crash.PAGEOFFSET(uvaddr)
        if (cnt > size):
            cnt = size

        out.append(readmem(paddr, cnt, crash.PHYSADDR))
        uvaddr += cnt
        size -= cnt
    return string.join(out)
    
#          ======== read lists  =========


# Emulate list_for_each + list_entry
# We assume that 'struct mystruct' contains a field with
# the name 'listfieldname'
# Finally, by default we do not include the address f the head itself
#
# If we pass a string as 'headaddr', this is the symbol pointing
# to structure itself, not its listhead member
def readSUListFromHead(headaddr, listfieldname, mystruct, maxel=_MAXEL,
                     inchead = False):
    msi = getStructInfo(mystruct)
    offset = msi[listfieldname].offset
    if (type(headaddr) == types.StringType):
        headaddr = sym2addr(headaddr) + offset
    out = []
    for p in readList(headaddr, 0, maxel, inchead):
        out.append(readSU(mystruct, p - offset))
    return out

# Read a list of structures connected via direct next pointer, not
# an embedded listhead. 'shead' is either a structure or tPtr pointer
# to structure

def readStructNext(shead, nextname, inchead = True):
    if (not isinstance(shead, StructResult)):
	# This should be tPtr
        if (shead == 0):
            return []
	shead = Deref(shead)
    stype = shead.PYT_symbol
    offset = shead.PYT_sinfo[nextname].offset
    out = []
    for p in readList(Addr(shead), offset, inchead=inchead):
        out.append(readSU(stype, p))
    return out 

#    ======= Arrays Without Dimension =============
#
#  In some cases we have declarations like
#  struct AAA *ptr[];
#
# unsigned long __per_cpu_offset[0];

class intDimensionlessArray(long):
    def __new__(cls, addr, isize, signed):
        return long.__new__(cls, addr)
    def __init__(self, addr, isize, signed):
        self.isize = isize
        self.signed = signed
    def __getitem__(self, i):
        addr = long(self) + i * self.isize
        return readIntN(addr, self.isize, self.signed)
    def __repr__(self):
	return "<intDimensionlessArray addr=0x%x, sz=%d, signed=%d>" %\
            (long(self), self.isize, self.signed)


class tPtrDimensionlessArray(object):
    def __init__(self, ptype, addr):
        self.ptype = ptype
        self.addr = addr
        self.size = pointersize
    def __getitem__(self, key):
        addr = readPtr(self.addr + pointersize * key)
        return tPtr(addr, self.ptype)


#     ======= return a Generator to iterate through SU array
def SUArray(sname, addr, maxel = _MAXEL):
    size = getSizeOf(sname)
    addr -= size
    while (maxel):
        addr += size
        yield readSU(sname, addr)
    return


# Walk list_Head and return the full list (or till maxel)
#
# Note: By default we do not include the 'start' address.
# This emulates the behavior of list_for_each_entry kernel macro.
# In most cases the head is standalone and other list_heads are embedded
# in parent structures.

def readListByHead(start, offset=0, maxel = _MAXEL):
    return readList(start, offset, maxel, False)

# An alias
list_for_each_entry = readListByHead

# Another attempt to make working with listheads easily.
# We assume that listhead here is declared outside any specific structure,
# e.g.
# struct list_head modules;
# 
# We can do the following:
# ListHead(addr) - will return a list of all linked objects, excluding
# the head itself.
#
# ListHead(addr, "struct module").list - will return a list of
# "struct module" results, linked by the embedded struct list_head list;
#

class ListHead(list):
    def __new__(cls, lhaddr, sname = None, maxel = _MAXEL):
	return list.__new__(cls)
    def __init__(self, lhaddr, sname, maxel = _MAXEL):
	self.sname = sname
	self.maxel = _MAXEL
	count = 0
	next = lhaddr
	while (count < maxel):
            next = readPtr(next)
            if (next == 0 or next == lhaddr):
                break
            self.append(next)
            count += 1
	
    def __getattr__(self, fname):
	off = member_offset(self.sname, fname)
	return [readSU(self.sname, a-off) for a in self]
	
	

# readList returns the addresses of all linked structures, including
# the start address. If the start address is 0, it returns an empty list

# For list declared using LIST_HEAD, the empty list is when both next and prev
# of LIST_HEAD point to its own address

def readList(start, offset=0, maxel = _MAXEL, inchead = True):
    start = long(start)     # equivalent to (void *) cast
    if (start == 0):
        return []
    if (inchead):
        count = 1
        out = [start]
    else:
        out = []
        count = 0
    next = start
    while (count < maxel):
        # If we get an error while reading lists, report it but return what we
        # have already collected anyway
        try:
	    next = readPtr(next + offset)
	except crash.error, val:
	    print val
	    break
        if (next == 0 or next == start):
            break
        out.append(next)
        count += 1
    return out

# The same as readList, but in case we are interested
# in partial lists even when there are low-level errors 
# Returns (partiallist, error/None)
def readBadList(start, offset=0, maxel = _MAXEL, inchead = True):
    start = long(start)     # equivalent to (void *) cast
    # A dictionary used to detect duplicates
    ha = {}
    if (start == 0):
        return []
    if (inchead):
        count = 1
        out = [start]
	ha[start] = 1
    else:
        out = []
        count = 0
    next = start
    while (count < maxel):
	try:
            next = readPtr(next + offset)
	except crash.error, err:
	    return (out, err)
        if (next == 0 or next == start):
            break
	elif (ha.has_key(next)):
	    err = "Duplicate entry"
	    return (out, err)
	ha[next] = 1
        out.append(next)
        count += 1
    return (out, None)

#     ======= get list size for LIST_HEAD =====
def getListSize(addr, offset, maxel):
    if (addr == 0):
        return 0


    count = 0                           # We don't include list_head

    next = addr
    while (count < maxel):
        next = readPtr(next + offset)
        if (next == 0 or next == addr):
            break
        count += 1
    return count

#     ======= read from global according to its type  =========
def readSymbol(symbol, art = None):
    vi = whatis(symbol)
    return vi.reader(vi.addr)
    



# Get sizeof(type)
def getSizeOf(vtype):
    return struct_size(vtype)

# Similar to C-macro in kernel sources - container of a field
def container_of(ptr, ctype, member):
    offset = member_offset(ctype, member)
    return readSU(ctype, long(ptr) - offset)

# .........................................................................
import time


# 8K - pages
shift = 12
psize = 1 << shift
_page_cache = {}


# Flush cache (for tools running on a live system)
def flushCache():
    _page_cache.clear()
    
# ..............................................................
    
# Get a list of non-empty bucket addrs (ppointers) from a hashtable.
# A hashtable here is is an array of buckets, each one is a structure
# with a pointer to next structure. On 2.6 'struct hlist_head' is used
# but we don't depend on that, we just need to know the offset of the
# 'chain' (a.k.a. 'next') in our structure
#
# start - address of the 1st hlist_head
# bsize - the size of a structure embedding hlist_head
# items - a dimension of hash-array
# chain_off - an offset of 'hlist_head' in a bucket
def getFullBuckets(start, bsize, items, chain_off=0):
    chain_sz = pointersize
    m = readmem(start, bsize * items)
    buckets = []
    for i in xrange(0, items):
       chain_s = i*bsize + chain_off
       s = m[chain_s:chain_s+chain_sz]
       bucket = mem2long(s)
       #bucket = mem2long(m, chain_sz, chain_s, False)
       if (bucket != 0):
           #print i
           buckets.append(bucket)
    del m
    return buckets

# Traverse hlist_node hash-lists. E.g.
# hlist_for_each_entry("struct xfrm_policy", table, "bydst")

def hlist_for_each_entry(emtype, head, member):
    pos = head.first                    # struct hlist_node *first
    si = SUInfo(emtype)
    offset = si[member].offset
    while (pos):
        yield readSU(emtype, long(pos) - offset)
        pos = pos.next

    return
    


def getStructInfo(stype):
    si = SUInfo(stype)
    return si


__whatis_cache = {}

def whatis(symbol):
    try:
	return __whatis_cache[symbol]
    except KeyError:
	pass
    try:
        e = crash.gdb_whatis(symbol)
    except crash.error:
        raise TypeError, "There's no symbol <%s>" % symbol

    # Return Varinfo
    vi = VarInfo(e["fname"])
    ti = TypeInfo('', False)
    update_TI(ti, e)
    vi.ti = ti
    vi.addr = sym2addr(symbol)

    # This is for backwards compatibility only, will be obsoleted
    vi.ctype = ti.stype
    __whatis_cache[symbol] = vi
    return vi

# We cannot subclass from ArtStructInfo as signature is different

def sdef2ArtSU(sdef):
    sname, finfo = parseSUDef(sdef)
    uas = ArtStructInfo(sname)
    uas.__init__(sname)
    for ftype, fn in finfo:
	#print ftype, fn
	try:
	    ti = TypeInfo(ftype)
	except crash.error:
	    #print "  Cannot get typeinfo for %s" % ftype
	    sp = ftype.find('*')
	    if (sp != -1):
		btype = ftype[:sp].strip()
		#print "    btype=<%s>" % btype
		# Check whether StructInfo exists for btype
		#si = getStructInfo(btype)
		#print si
		# Yes, replace the name with something existing and try again
		newftype = ftype.replace(btype, "struct list_head", 1)
		#print "     new ftype=<%s>" % newftype
		ti = TypeInfo(newftype)
		# Force the evaluation of lazy eval attributes
		ti.tcodetype
		ti.elements
		ti.stype = btype
		#ti.dump()
	    
	vi = VarInfo(fn)
	vi.ti = ti
	vi.offset = uas.PYT_size
	vi.bitoffset = vi.offset * 8

	SUInfo.append(uas, fn, vi)
	# Adjust the size
	uas.PYT_size += vi.size
	uas.size = uas.PYT_size
    return uas
    

#
#
#  -- emulating low-level functions that can be later replaced by
#  Python extension to crash
#
#
# {"symbol_exists",  py_crash_symbol_exists, METH_VARARGS},
# {"struct_size",  py_crash_struct_size, METH_VARARGS},
# {"union_size",  py_crash_union_size, METH_VARARGS},
# {"member_offset",  py_crash_member_offset, METH_VARARGS},
# {"member_size",  py_crash_member_size, METH_VARARGS},
# {"get_symbol_type",  py_crash_get_symbol_type, METH_VARARGS},


# Return -1 if the struct is unknown. At this moment this function
# works for any type, not just for structs
# We cache the results (even negative ones). The cache should be invalidated

__struct_size_cache = {}
# when we load/unload modules
def struct_size(sname):
    try:
	return __struct_size_cache[sname]
    except KeyError:
	pass
    try:
        si = TypeInfo(sname)
        sz = si.size
    except:
        sz = -1
    __struct_size_cache[sname]= sz
    return sz

def invalidate_cache_info(sname = None):
    if (sname and __struct_size_cache.has_key(sname)):
	del __struct_size_cache[sname]
    else:
	__struct_size_cache.clear()

def struct_exists(sname):
    if (struct_size(sname) == -1):
        return False
    else:
        return True
    
def member_size(sname, fname):
    #print "++member_size", sname, fname
    sz = -1
    try:
        ti = getStructInfo(sname)[fname].ti
        sz = ti.size * ti.elements
    except KeyError:
        pass
    return sz


# Find a member offset. If field name contains a dot, we do our
# best trying to find its offset checking intermediate structures as
# needed

def member_offset(sname, fname):
    try:
        si = getStructInfo(sname)
        if (fname.find('.') == -1):
            return si[fname].offset
        else:
            # We have dots in field name, try to walk the structures
            return -1                   # Not done yet
    except:
        return -1

    


# A cached version
__cache_symbolexists = {}
def symbol_exists(sym):
    try:
        return  __cache_symbolexists[sym]
    except:
        rc = noncached_symbol_exists(sym)
        __cache_symbolexists[sym] = rc
        return rc

# Exec either a standard crash command, or a epython command
def exec_command(cmdline):
    argv = cmdline.split()
    #print "argv", argv, "cmds=",  crash.get_epython_cmds()
    if (argv[0] in crash.get_epython_cmds()):
        # This is a epython command. In principle, we should parse using
        # shell-like syntax (i.e. using shlex), but this is probably an overkill
        crash.exec_epython_command(*argv)
    else:
        print crash.exec_crash_command(cmdline)


# Aliases
union_size = struct_size


import crash
from crash import sym2addr, addr2sym, sym2alladdr
from crash import  mem2long, readInt, FD_ISSET
from crash import get_pathname
def exec_gdb_command(cmd):
    return crash.get_GDB_output(cmd).replace('\r', '')

noncached_symbol_exists = crash.symbol_exists
exec_crash_command = crash.exec_crash_command
exec_gdb_command = crash.get_GDB_output
getFullBuckets = crash.getFullBuckets
readPtr = crash.readPtr
readIntN = crash.readInt
sLong = crash.sLong
le32_to_cpu = crash.le32_to_cpu
le16_to_cpu = crash.le16_to_cpu
cpu_to_le32 = crash.cpu_to_le32
uvtop = crash.uvtop
getListSize = crash.getListSize
# For some reason the next line runs slower than GDB version
#GDB_sizeof = crash.struct_size
readmem = crash.readmem
set_readmem_task = crash.set_readmem_task
nc_member_offset = crash.member_offset
Gen.parseDerefString = parseDerefString


def print_stats():
    print "count_cached_attr=%d (%d)" % (count_cached_attr, count_total_attr)
