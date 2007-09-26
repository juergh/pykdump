#
# -*- coding: latin-1 -*-
# Time-stamp: <07/09/26 16:46:07 alexs>

# Functions/classes used while driving 'crash' externally via PTY
# Most of them should be replaced later with low-level API when
# using Python loaded to crash as shared library
# There are several layers of API. Ideally, the end-users should only call
# high-level functions that do not depend on internal

# Copyright (C) 2006-2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2007 Hewlett-Packard Co., All rights reserved.
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

import threading
import types
from StringIO import StringIO
import pprint

pp = pprint.PrettyPrinter(indent=4)

import tparser
import nparser

experimental = False
experimental = True

#GDBStructInfo = tparser.GDBStructInfo
GDBStructInfo = nparser.GDBStructInfo


import Generic as Gen
from Generic import BaseStructInfo, FieldInfo

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
    out = multilist(multidim)
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
class BaseTypeinfo(object):
    def __init__(self, size, dims = [1]):
        # dims is a list of array dimensions, e.g. for
        # [2][3][4] we'll have [2,3,4]
        # Size of this basetype. If we want to represent arrays,
        # this is a size of one element
        self.size = size
        self.dims = dims
        self.elements = reduce(lambda x, y: x*y, dims)
        self.totsize = self.size * self.elements

# Simple integers and arrays of them. Not bitfields or anything fancy
class pykdump_Integer(BaseTypeinfo):
    def __init__(self, size, signed = True, dims = [1]):
        BaseTypeinfo.__init__(self, size, dims)
        self.signed = signed
    def readobj_1(self, addr, s = None):
        if (not s):
            s = readmem(addr, self.totsize)
        return mem2long(s, signed = self.signed)
    def readobj(self, addr, s = None):
        #print "-- sz=", self.size, "signed=",  self.signed, \
        #      "totsize=", self.totsize, "elements=", self.elements
        if (not s):
            s = readmem(addr, self.totsize)
        # Performance: check whether keywords slow down the code
        val = mem2long(s, signed = self.signed, array=self.elements)
        if (self.elements == 1):
            # Most frequent case
            #self.readobj = self.readobj_1
            return mem2long(s, signed = self.signed)
        val =  mem2long(s, signed = self.signed, array=self.elements)
        if (len(self.dims) == 1):
            # 1-dimarray
            return val
        else:
            return _arr1toM(self.dims, val)
        

# Pointers
class pykdump_Pointer(BaseTypeinfo):
    def __init__(self, size, signed = True, dims = [1]):
        BaseTypeinfo.__init__(self, size, dims)
    def readobj(self, addr, s = None):
        if (not s):
            s = readmem(addr, self.totsize)
        # Performance: check whether keywords slow down the code
        val = mem2long(s, signed = self.signed, array=self.elements)
        if (self.elements == 1):
            # Most frequent case
            #self.readobj = self.readobj_1
            return mem2long(s, signed = self.signed)
        val =  mem2long(s, signed = self.signed, array=self.elements)
        if (len(self.dims) == 1):
            # 1-dimarray
            return val
        else:
            return _arr1toM(self.dims, val)
        


# Struct/Union info representation with methods to append data

# Convert the new typeinfo output to old-style

def new2old(ns):
    out = []
    #print "--", type(ns)
    #pp.pprint(ns)
    try:
        body = ns["body"]
    except KeyError:
        body = [ns]
    for e in body:
        f = FieldInfo()
        try:
            # This is an aggregate, e.g. struct
            f.fname = e["fname"]
            bitoffset = e["bitoffset"]
            f.offset = bitoffset/8
        except KeyError:
            # This is a non-aggregate
            f.fname = '-'
        f.type = e["basetype"].split()
        sz1 = sz =  e["typelength"]
        new_dims = [1]
        if (e.has_key("dims")):
            new_dims = e["dims"]
            dims = e["dims"]
            if (len(dims) == 1):
                f.array = dims[0]
            else:
                f.array = dims
            sz *= reduce(lambda x, y: x*y, dims)

        # For integer types add accessor (but not for arrays of chars yet)
        if (e.has_key("uint")):
            uint = e["uint"]
            # char a[dim] is a special case
            if (sz1 == 1 and not uint and \
                e.has_key("dims") and len(new_dims) == 1):
                pass
            else:
                accessor = pykdump_Integer(sz1, uint, new_dims)
                f.accessor = accessor

        if (e.has_key("stars")):
            f.star = '*' * e["stars"]
        if (e.has_key("bitsize")):
            f.bitfield = e["bitsize"]
            f.bitoffset = e["bitoffset"] - f.offset*8
        if (e.has_key("body")):
            # Recurse
            s1 = new2old(e)
            f.body = s1
            f.parentstype = ns["basetype"]
            #f.size = e["typelength"]
        else:
            # Non-aggregate field
            pass
        f.size = sz

        # We use this flag to mark new-style FieldInfo
        f.new = True
        out.append(f)
    return out
            

class StructInfo(BaseStructInfo):
    def __init__(self, stype):
        BaseStructInfo.__init__(self, stype)

        try:
            newsi = crash.gdb_typeinfo(stype)
        except:
            errmsg = "The type <%s> does not exist in this dump" % stype
            raise TypeError, errmsg

        self.stype = stype
        self.size = newsi["typelength"]
        self.body = new2old(newsi)

        for f in self.body:
            self[f.fname] = f

        # Add ourselves to cache
        self.addToCache()
        

# Artificial StructInfo - in case we don't have the needed symbolic info,
# we'd like to be able to assemble it manually

class ArtStructInfo(BaseStructInfo):
    def __init__(self, stype):
        BaseStructInfo.__init__(self, stype)
        # Add ourselves to cache
        self.size = 0
        self.body = []
        self.addToCache()

    # Append info. Reasonable approaches:
    # 1. Append (inline) an already existing structinfo.
    # 2. Append a field manually (do we need to parse its definition string?)
    #
    # In both cases we'll append with offset equal to self.size
    def append(self, obj):
        # If obj is a string, we'll need to parse it - not done yet
        if (type(obj) == types.StringType):
            f = tparser.OneStatement.parseString(obj).asList()[0]
            f.offset = self.size
            size = f.size
            if (size == -1):
                raise TypeError

            self.body.append(f)
            self[f.fname] = f 
            self.size += size
            #raise TypeError
        else:
            off = self.size
            # append adjusting offsets
            addsize = obj.size
            body = obj.body
            for f in body:
                fn = f.copy()           # We don't want to spoil the original
                try:
                    fn.offset += off
                except:
                    pass
                self.body.append(fn)
                self[fn.fname] = fn
            # Adjust the original size
            self.size += addsize

# Artificial StructInfo for Unions - in case we don't have the needed symbolic
# info, we'd like to be able to assemble it manually. We cannot use the same
# class for both Struct and Union as when we assemble them manually offsets
# are computed differently. Or maybe we can merge these two classes and
# use separate append_as_struct and append_as_union methods ?

class ArtUnionInfo(BaseStructInfo):
    def __init__(self, stype):
        BaseStructInfo.__init__(self, stype)
        self.size = 0
        self.body = []

        # Add ourselves to cache
        self.addToCache()

    # Append info. Reasonable approaches:
    # 1. Append a field manually (do we need to parse its definition string?)
    def append(self, obj):
        # If obj is a string, we'll need to parse it - not done yet
        if (type(obj) == types.StringType):
            try:
                f = tparser.OneStatement.parseString(obj).asList()[0]
            except:
                print "Cannot parse <%s>, parent type=<%s>" %(obj, self.stype)
                raise TypeError
            f.offset = 0
            size = f.size
            if (size == -1):
                raise TypeError

            self.body.append(f)
            self[f.fname] = f
            if (self.size < size):
                self.size = size
           

# An auxiliary class to be used in StructResult to process dereferences

# Warning: this is obsoleted and will go away sooner or later

import inspect
class Dereference:
    __first = True
    def __init__(self, sr):
	#raise AttributeError, "Dereference"
	if (Dereference.__first):
	    frame, fn, lineno, subr, stmts, sl = inspect.stack()[-2]
	    print "!!!Warning: do not use Deref attribute for non-pointers"
	    print "!!!  trying to use it for", sr
	    print "!!!  at line %d of %s (%s)" % (lineno, fn, subr)
	    print "!!!\t", stmts[sl]
	    Dereference.__first = False
        self.sr = sr
    def __getattr__(self, f):
        # Get address from the struct.
        #addr = self.sr.__getattr__(f)
	addr = readPtr(Addr(self.sr, f))
	if (addr == 0):
	    msg = "\nNULL pointer %s->%s" % (
	                                       str(self.sr), f)
	    raise IndexError, msg

        stype = self.sr.PYT_sinfo[f].basetype
        return readSU(stype, addr) 


# A cache to simplify access fo StructResult atributes. Indexed by
# (PYT_symbol, attr)
# Value is (type,  off, sz, signed)
# At this moment for 1-dim
# integer values only


# Raw Struct Result - read directly from memory, lazy evaluation


# Warning: there can be a namespace collision if strcut/union of interest
# has a field with the same name as one of our methods. I am not sure
# whether we shall ever meet this but just in case there should be a method
# to bypass the normal accessor approach (GDBderef at this moment)
count_cached_attr = 0
count_total_attr = 0
class StructResult(object):
    _cache_access = {}
    PYT_deref = "Deref"
    def __init__(self, sname, addr, data = None):
        # If addr is symbolic, convert it to real addr
        if (type(addr) == types.StringType):
            addr = sym2addr(addr)
	self.PYT_symbol = sname
	self.PYT_addr = addr
        self.PYT_sinfo = getStructInfo(sname)
        self.PYT_size = self.PYT_sinfo.size;
        if (data):
            self.PYT_data = data
        else:
            try:
                self.PYT_data = readmem(addr, self.PYT_size)
            except crash.error, msg:
                print "crash.error: %s sname=%s" % (msg, sname)
                raise crash.error, msg
    
    def __getitem__(self, name):
        return self.PYT_sinfo[name]

    def __str__(self):
        return "<%s 0x%x>" % \
               (self.PYT_symbol, self.PYT_addr)
    def __repr__(self):
        return "StructResult <%s 0x%x> \tsize=%d" % \
               (self.PYT_symbol, self.PYT_addr, self.PYT_size)
    def __nonzero__(self):
        return True
    def __len__(self):
        return self.PYT_size

    def hasField(self, fname):
        return self.PYT_sinfo.has_key(fname)
    
    def isNamed(self, sname):
	return sname == self.PYT_symbol
    
    # Cast to another type. Here we assume that that one struct resides
    # as the first member of another one, this is met frequently in kernel
    # sources
    def castTo(self, sname):
        newsize = struct_size(sname)
	# If the new size is smaller than the old one, reuse data
	if (newsize <= self.PYT_size):
	    # We don't truncate data as we rely on PYT_size
	    return StructResult(sname, self.PYT_addr, self.PYT_data)
	else:
	    return StructResult(sname, self.PYT_addr)
	

    # It is highly untrivial to read the field properly as there
    # are many subcases. We probably need to split it into several subroutines,
    # maybe internal to avoid namespace pollution
    def __getattr__(self, name):
        ind = name.find('__')
        if (ind > 0):
            name = name[ind:]
        # A special case - dereference
        if (name == StructResult.PYT_deref):
            return Dereference(self)

        # 'ni' object should be the same for all StructResults with
        # the same SU
        ni = self.PYT_sinfo[name]
        off = ni.offset
        sz = ni.size



        # if sz == -1, this means that we cannot find the size of this
        # field. It usually happens when we try to obtain the size
        # of artificial SU before creating them. In this case, pass the
        # whole chunk of data (starting from off:)

        if (sz == -1):
            s = self.PYT_data[off:]
        else:
            s = self.PYT_data[off:off+sz]

        # This can be an array...
        fieldaddr = self.PYT_addr + off
        try:
            return ni.accessor.readobj(fieldaddr, s)
        except AttributeError:
            pass

	try:
	    one, two = _ni_cache[id(ni)]
	    if (type(one) == type(True)):
	       return mem2long(s, signed = one, array=two)
	    if (one == 'tPtr'):
	        return tPtr(mem2long(s), ni)
	    elif (one== 'SU'):
		return StructResult(two, fieldaddr, s)
	except KeyError:
	    pass
	
        reprtype = ni.smarttype
	
        if (sz >0 and len(s) != sz):
            print ni.ctype, name, off, sz, len(s), len(self.PYT_data)
            raise TypeError

        if (reprtype == "SU"):
            val = _getSU(fieldaddr, ni, s)
        elif (reprtype == "CharArray"):
            val = _getCharArray(fieldaddr, ni, s)
        elif (reprtype == "String"):
            val = _getString(fieldaddr, ni, s) 
        elif (reprtype in ('UInt', 'SInt', 'Ptr', 'FPtr', 'SUptr')):
            val =  _getInt(fieldaddr, ni, s)
        else:
            raise 'TypeError', reprtype
            #return oldStructResult.__getattr__(self, name)

        return val
    
    # An ugly hack till we implement something better
    # We want to be able to do something like
    # s.GDBderef('->addr->name->sun_path')
    #
    def GDBderef(self, derefexpr):
        # Use our type and addr
        cmd = "p ((%s *) 0x%x)%s"%(self.PYT_sinfo.stype, self.PYT_addr, derefexpr)
        #print cmd
        resp = exec_gdb_command(cmd)
        f = tparser.derefstmt.parseString(resp).asList()[0]
        return f


_ni_cache = {}


def _getInt(fieldaddr, ni, s = None):
    dim = ni.dim
    if (dim == 0):
        # We assume we should return a pointer to this offset
        return fieldaddr

    sz = ni.size
    if (s == None):
        s = readmem(fieldaddr, sz)

    smarttype = ni.smarttype
    
    if (ni.has_key("bitfield") and smarttype != "UInt"):
	raise "TypeError", ni

    if (smarttype == 'FPtr'):
        val = mem2long(s)
        if (dim == 1):
            if (val and machine == "ia64"):
                val = readPtr(val)
        else:
            raise "TypeError", "Cannot process fptr arrays"
    elif (smarttype == 'SInt'):
        val = mem2long(s, signed = True, array=dim)
	#_ni_cache[id(ni)] = (True, dim)
    
    elif (smarttype == 'UInt'):
        val = mem2long(s, array=dim)
	# Are we a bitfield??
	if (ni.has_key("bitfield")):
	    if (dim != 1):
		raise "TypeError", ni
            else:	
                val = (val&(~(~0<<ni.bitoffset+ ni.bitfield)))>>ni.bitoffset
        else:
            #_ni_cache[id(ni)] = (False, dim)
            pass
        
    elif (smarttype in ('SUptr', 'Ptr')):
        if (dim == 1):
            val = tPtr(mem2long(s), ni)
	    _ni_cache[id(ni)] = "tPtr", None
        else:
            val = []
            sz1 = sz/dim
            # We should strip dim/array information for 1-dim arrays
	    # But what if we have a multidimensional array?
            nf = ni.mincopy
            for i in range(dim):
                val.append(tPtr(mem2long(s[i*sz1:(i+1)*sz1]), nf))
    else:
        raise TypeError, str(smarttype) + ' ' + str(dim)

    return val
 

def _getString(fieldaddr, ni, s = None):
    if (s == None):
        ptr = readPtr(fieldaddr)
    else:
        ptr = mem2long(s)
    if (ptr == 0):
        return None
    else:
        s = readmem(ptr, 256)
        return SmartString(s, fieldaddr, ptr)

def _getCharArray(fieldaddr, ni, s = None):
    dim = ni.dim
    sz = ni.size
    if (dim == 0):
        # We assume we should return a pointer to this offset
        val = fieldaddr
    else:
        # Return it as a string - may contain ugly characters!
        # not NULL-terminated like String reprtype
        if (s == None):
            s = readmem(fieldaddr, sz)
        val = SmartString(s, fieldaddr, None)

    return val

# Convert an embedded struct/union fieldinfo into a StructInfo
# We create a fake name and adjust offsets if they are available
class embeddedStructInfo(BaseStructInfo):
    def __init__(self, stype, fi):
        BaseStructInfo.__init__(self, stype)
        self.size = fi.size
        self.body = fi.body

        for f in self.body:
            self[f.fname] = f

        # Add ourselves to cache
        self.addToCache()


def _getSU(fieldaddr, ni, s = None):
    sz = ni.size
    name = ni.fname
    # This can be an array...
    dim = ni.dim
    ftype = ni.basetype
    #print ftype
    #pp.pprint(ni)

    # This can be a fake type - in this case we might need to create it
    if (ftype.find('-') != -1):
        su = ni.type[0]
        # Check whether we have already created this faketype
        try:
            au = getStructInfo(ftype, createnew=False)
        except TypeError:
            #print "Creating", ftype
            #pp.pprint(ni)

            # With new low-level interface, we can use embedded
            if (ni.new):
                au = embeddedStructInfo(ftype, ni)
            else:
                if (su == 'struct'):
                    au = ArtStructInfo(ftype)
                elif (su == 'union'):
                    au = ArtUnionInfo(ftype)
                else:
                    raise TypeError, su
                for fi in ni.body:
                    au.append(fi.cstmt)

    # This can be an array...
    if (dim != 1):
        # We sometimes meet dim=0, e.g.
        # struct sockaddr_un name[0];
        # I am not sure about that but let us process by
        # loading new data from this address
        if (dim == 0):
            #print "dim=0", ftype, hexl(self.PYT_addr + off)
            val = StructResult(ftype, fieldaddr)
        else:
            sz1 = sz/dim
            val = []
            for i in range(0, dim):
                if (s):
                    s1 = s[i*sz1:(i+1)*sz1]
                else:
                    s1 = None
                one =  StructResult(ftype, fieldaddr+i*sz1, s1)
                val.append(one)
    else:
        # We return this in case of SU with an 'external' type
        val = StructResult(ftype, fieldaddr, s)
	_ni_cache[id(ni)] = "SU", ftype
    return val
# Convert a flat (1-dim) list to multidimensional

def _flat2Multi(symi, out):    
    multidim = symi.indices
    if (type(multidim) == type([])):
        # We do this for 2- and 3-dim only
        out1 = multilist(multidim)
        if (len(multidim) == 2):
            I = multidim[0]
            J = multidim[1]
            for i in range(I):
                for j in range(J):
                    out1[i][j] = out[i*J+j]
        
        elif (len(multidim) == 3):
            I = multidim[0]
            J = multidim[1]
            K = multidim[2]
            for i in range(I):
                for j in range(J):
                    for k in range(K):
                        out1[i][j] = out[i*J*K+j*K +k]
        else:
            raise TypeError, "Array with dim >3"
        return out1
    else:
        return out
    



# Wrapper functions to return attributes of StructResult

def Addr(obj, extra = None):
    if (isinstance(obj, StructResult)):
        # If we have extra set, we want to know the address of this field
        if (extra == None):
            return obj.PYT_addr
        else:
            off = obj.PYT_sinfo[extra].offset
            return obj.PYT_addr + off
    elif (isinstance(obj, SmartString)):
          return obj.addr
    else:
        raise TypeError, type(obj)

# Dereference a tPtr object - at this moment 1-dim pointers to SU only
def Deref(obj):
    if (isinstance(obj, tPtr)):
        addr = long(obj)
	if (addr == 0):
	    msg = "\nNULL pointer %s" % repr(obj)
            raise IndexError, msg
	ptype = obj.ptype
	# Optimization fpr "SUptr"
	if (ptype.smarttype == "SUptr"):
	    return readSU(ptype.basetype, addr)

        dpt = ptype.deref
        # OK, now we either have another pointer or SU itself
        if (dpt.smarttype == "SU"):
            return readSU(dpt.basetype, addr)
        elif (dpt.smarttype in ("Ptr", "SUptr")):
            return tPtr(readPtr(addr), dpt)
        else:
            raise TypeError, str(obj.ptype)


# When we do readSymbol and have pointers to struct, we need a way
# to record this info instead of just returnin integer address

# A general typed Pointer
class tPtr(long):
    def __new__(cls, l, ptype):
        return long.__new__(cls, l)
    def __init__(self, l, ptype):
        # If ptype is a string, treat it as typename and assume we
        # want to declare a pointer to this type
        if (type(ptype) == type("")):
            # This is a hack, please reimplement
            self.ptype = whatis(ptype, ptype + " dummy;")
            self.ptype.typedef = False
        else:
            self.ptype = ptype
    # For pointers, index access is equivalent to pointer arithmetic
    def __getitem__(self, i):
        dpt = self.ptype.deref
        smarttype = dpt.smarttype
        if (smarttype == "SU"):
            sz = sizeof(dpt.basetype)
            return readSU(dpt.basetype, long(self) + i * sz)
        elif (smarttype in ("Ptr", "SUptr")):
            return tPtr(readPtr(self + i * pointersize), dpt)
        else:
            raise TypeError, str(self.ptype)
    def getDeref(self):
        return Deref(self)
    def __repr__(self):
        return "<tPtr addr=0x%x ctype='%s'>" % (self, self.ptype.ctype)
    Deref = property(getDeref)


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
    

# Print the object delegating all work to GDB. At this moment can do this
# for StructResult only

def printObject(obj):
    if (isinstance(obj, StructResult)):
        cmd = "p *(%s *)0x%x" %(obj.PYT_symbol, obj.PYT_addr)
        print cmd
        s = exec_gdb_command(cmd)
        # replace the 1st line with something moe useful
        first, rest = s.split("\n", 1)
	print "%s 0x%x {" %(obj.PYT_symbol, obj.PYT_addr)
        print rest
    else:
        raise TypeError
        

# =============================================================
#
#           ======= read functions =======
#
# =============================================================


def readU16(addr):
    s = readmem(addr, 2)
    return mem2long(s)

def readU32(addr):
    s = readmem(addr, 4)
    return mem2long(s)

def readS32(addr):
    s = readmem(addr, 4)
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

def readStructNext(shead, nextname):
    if (not isinstance(shead, StructResult)):
        if (shead == 0):
            return []
        else:
            shead = Deref(shead)
    stype = shead.PYT_symbol
    offset = shead.PYT_sinfo[nextname].offset
    out = []
    for p in readList(Addr(shead), offset):
        out.append(readSU(stype, p))
    return out 

#     ======= return a Generator to iterate through SU array
def SUArray(sname, addr, maxel = _MAXEL):
    size = getSizeOf(sname)
    addr -= size
    while (maxel):
        addr += size
        yield readSU(sname, addr)
    return

#    ======= Arrays Without Dimension =============
#
#  In some cases we have declarations like 
#  struct AAA *ptr[];

class tPtrDimensionlessArray(object):
    def __init__(self, ptype, addr):
	self.ptype = ptype
	self.addr = addr
	self.size = pointersize
    def __getitem__(self, key):
	addr = readPtr(self.addr + pointersize * key)
	return tPtr(addr, self.ptype)

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

# readList returns the addresses of all linked structures, including
# the start address. If the start address is 0, it returns an empty list

# For list declared using LIST_HEAD, the empty list is when both next and prev
# of LIST_HEAD point to its own address

def readList(start, offset=0, maxel = _MAXEL, inchead = True):
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
        next = readPtr(next + offset)
        if (next == 0 or next == start):
            break
        out.append(next)
        count += 1
    return out

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



# Try to read symbol according to its type and return the appropriate object
# For example, if this is a struct, return StructObj, if this is an array
# of Structs, return a list of StructObj

def readSymbol(symbol, art = None):
    symi = whatis(symbol, art)
    stype = symi.basetype
    swtype = symi.smarttype
    addr = symi.addr

    # This can be an array...
    dim = symi.dim

    
    size = symi.size
    # There is a special case - on some kernels we obtain zero-dimensioned
    # arrays, e.g. on 2.6.9 sizeof(ipv4_table) = 0 and it ise declared as
    # ctl_table ipv4_table[] = {...}
    # In this case we return a generator to this array and expect that
    # there is an end marker that lets programmer detect EOF. For safety
    # reasons, we limit the number of returned entries to _MAXEL
    if (dim == 0 and size == 0):
	if (swtype == "SU"):
	    sz1 = getSizeOf(stype)
            return SUArray(stype, addr)
	elif (swtype == "SUptr" or swtype ==  "Ptr"):
	    # We don't want to preserve dim=0 information
	    nf = symi.mincopy
	    #print "SYMI:", symi
	    #print "NF:", nf
 	    return tPtrDimensionlessArray(nf, addr)

    sz1 = size/dim

    s = readmem(addr, size)

    #print "ctype=<%s> swtype=<%s> dim=%d" % (symi.ctype, swtype, dim)
    out = None
    if (swtype == "SU"):
        out = _getSU(addr, symi)
    elif (swtype in ("SInt", "UInt", 'Ptr', 'SUptr')):
        out = _getInt(addr, symi)
    else:
        raise TypeError, symi.ctype

    # If we have multidim set and 'out' is a list, convert it to
    # a list of lists as needed

    if (type(out) == type([])):
        out = _flat2Multi(symi, out)

    return out


# Get sizeof(type)
def getSizeOf(vtype):
    return struct_size(vtype)

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

# Traverse list_head linked lists


def getStructInfo(stype, createnew = True):
    try:
        return Gen.getSIfromCache(stype)
    except:
        if (not createnew):
            raise TypeError, "Unknown Type <%s>" % stype
        pass
    #print "  -- SI Cache miss:", stype
    # StructInfo() constructor adds itself to cache
    si = StructInfo(stype)
    return si



def whatis(symbol, art = None):
    try:
        newsi = crash.gdb_whatis(symbol)
    except crash.error:
        raise TypeError, "There's no symbol <%s>" % symbol

    f = new2old(newsi)[0]
    f.addr = sym2addr(symbol)
    return f


# Check whether our basetype is really a typedef. We need this to understand how
# to generate 'smarttype'. E.g. for __u32 we'll find that this is an unsigned integer
# For typedefs to pointers we'll know that this is really a pointer type and should
# be treated as such.
# Possible return values:
#           None    - this is not a typedef, not transformation possible
#           Int     - this is a signed Integer type
#           Uint    - this is a Unsigned integer type
#           Ptr     - this is a pointer, do not try to do anything else
#           SUPtr   - this is a pointer to SU
#           String  - this is a pointer to Char

def isTypedef(basetype):
    return None



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


# Return -1 if the struct is unknown
def struct_size(sname):
    try:
        si = getStructInfo(sname)
        return si.size
    except:
        return -1

def struct_exists(sname):
    if (struct_size(sname) == -1):
        return False
    else:
        return True
    
def member_size(sname, fname):
    #print "++member_size", sname, fname
    sz = -1
    try:
        fi = getStructInfo(sname)[fname]
        sz = fi.size
        if (fi.has_key("array")):
            sz *= fi.array
    except:
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
    


# Aliases
union_size = struct_size


import crash
from crash import sym2addr, addr2sym
from crash import  mem2long, FD_ISSET
def exec_gdb_command(cmd):
    return crash.get_GDB_output(cmd).replace('\r', '')

noncached_symbol_exists = crash.symbol_exists
exec_crash_command = crash.exec_crash_command
exec_gdb_command = crash.get_GDB_output
getFullBuckets = crash.getFullBuckets
readPtr = crash.readPtr
sLong = crash.sLong
le32_to_cpu = crash.le32_to_cpu
le16_to_cpu = crash.le16_to_cpu
cpu_to_le32 = crash.cpu_to_le32
uvtop = crash.uvtop
getListSize = crash.getListSize
# For some reason the next line runs slower than GDB version
#GDB_sizeof = crash.struct_size
readmem = crash.readmem
nc_member_offset = crash.member_offset
pointersize = getSizeOf("void *")




def print_stats():
    print "count_cached_attr=%d (%d)" % (count_cached_attr, count_total_attr)
