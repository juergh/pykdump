# -*- coding: utf-8 -*-
#
#  Generic classes and subroutines
#
# Time-stamp: <11/03/24 15:36:16 alexs>
#

# Copyright (C) 2006-2011 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2011 Hewlett-Packard Co., All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Pubic License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


import string
import pprint

import os
import copy
import types
from types import *

from StringIO import StringIO

pp = pprint.PrettyPrinter(indent=4)

#import wrapcrash as d
d = None

# These options can be reset from API.py
debug = 0
livedump = False

# GLobals used my this module


# The standard hex() appends L for longints
def hexl(l):
    return "0x%x" % l


def unsigned16(l):
    return l & 0xffff

def unsigned32(l):
    return l & 0xffffffff

def unsigned64(l):
    return l & 0xffffffffffffffff

# A helper class to implement lazy attibute computation. It calls the needed
# function only once and adds the result as an attribute so that next time
# we will not try to compute it again

class LazyEval(object):
    def __init__(self, name, meth):
        self.name = name
        self.meth = meth
    def __get__(self, obj, objtype):
        # Switch 
        #print " ~~lazy~~ ", self.name
        val = self.meth(obj)
        setattr(obj, self.name, val)
        #obj.__setattr__(self.name, val)
        return val

# A dict-like container
class Bunch(dict):
    def __init__(self, d = {}):
        dict.__init__(self, d)
        self.__dict__.update(d)
    def __setattr__(self, name, value):
        dict.__setitem__(self, name, value)
        object.__setattr__(self, name, value) 
    def __setitem__(self, name, value):
        dict.__setitem__(self, name, value)
        object.__setattr__(self, name, value)
    def copy(self):
        return Bunch(dict.copy(self))
    def __str__(self):
        prn = StringIO()
        keys = self.keys()
        keys.sort()
        for k in keys:
            print >> prn, "  ", k.ljust(12), self[k]
        rc = prn.getvalue()
        prn.close()
        return rc

# Memoize methods with one simple arg  
class MemoizeTI(type):
    __cache = {}
    def __call__(cls, *args):
        sname = args[0]
        try:
            return MemoizeTI.__cache[sname]
        except KeyError:
            rc =  super(MemoizeTI, cls).__call__(*args)
            MemoizeTI.__cache[sname] = rc
            return rc

class MemoizeSU(type):
    __cache = {}
    def __call__(cls, *args):
        sname = args[0]
        try:
            return MemoizeSU.__cache[sname]
        except KeyError:
            rc =  super(MemoizeSU, cls).__call__(*args)
            MemoizeSU.__cache[sname] = rc
            return rc
    @staticmethod
    def purgecache():
	MemoizeSU.__cache.clear()
	print "SU Cache purged, len=", len(MemoizeSU.__cache)
 


# Memoize cache. Is mainly used for expensive exec_crash_command

__memoize_cache = {}

CU_LIVE = 1                             # Update on live
CU_LOAD = 2                             # Update on crash 'mod' load
CU_PYMOD = 4                            # Update on Python modules reload
CU_TIMEOUT = 8				# Update on timeout change

# CU_PYMOD is needed if we are reloading Python modules (by deleting it)
# In this case we need to invalidate cache entries containing references
# to classes defined in the deleted modules


def memoize_cond(condition):
    def deco(fn):
        def newfunc(*args):
            key = (condition, fn.__name__) + args
	    # If CU_LIVE is set and we are on live kernel, do not
	    # memoize
	    if (condition & CU_LIVE and livedump):
		if (debug > 2):
		    print "do not memoize: live kernel", key
		return fn(*args)
            try:
                return __memoize_cache[key]
            except KeyError:
		if (debug > 1):
                    print "Memoizing", key
                val =  fn(*args)
                __memoize_cache[key] = val
                return val
        return newfunc
    return deco
  
def print_memoize_cache():
    keys = __memoize_cache.keys()
    keys.sort()
    for k in keys:
	v = __memoize_cache[k]
	try:
            print k, v
	except Exception, val:
	    print "\n\t", val, 'key=', k
	
# Purge those cache entries that have at least one of the specified 
# flags	set
def purge_memoize_cache(flags):
    keys = __memoize_cache.keys()
    keys.sort()
    for k in keys:
	ce_flags = k[0]
	if (ce_flags & flags):
	    if (debug > 1):
		print "Purging cache entry", k
	    del __memoize_cache[k]

# Limit a potentially infinite sequence so that while iterating
# it we'll stop not later than after N elements

def iterN(seq, N):
    it = iter(seq)
    for i in range(N):
        yield it.next()
    return


# INTTYPES = ('char', 'short', 'int', 'long', 'signed', 'unsigned',
#             '__u8', '__u16', '__u32', '__u64',
#              'u8', 'u16', 'u32', 'u64',
#             )
# EXTRASPECS = ('static', 'const', 'volatile')

# Representing types. Here is how we do it:

# 1. basetype or 'target type' - a symbolic name after removing * and
# arrays. For example, for 'struct test **a[2]' this will be 'struct test'.
#
# 2. type of basetype: integer/float/struct/union/func etc.
#    for integers: signed/unsigned and size
#
# 3. Numbers of stars (ptrlev) or None
#
# 4. Dimensions as a list or None

class TypeInfo(object):
    X__metaclass__ = MemoizeTI
    def __init__(self, stype, gdbinit = True ):
        self.stype = stype
        self.size = -1
        self.dims = None
        self.ptrlev = None
        self.typedef = None
        self.details = None
        # For integer types
        self.integertype = None
        if (gdbinit):
            d.update_TI_fromgdb(self, stype)

    def getElements(self):
        if (self.dims):
            elements = reduce(lambda x, y: x*y, self.dims)
        else:
            elements = 1
        return elements

    # Get target info for arrays/pointers - i.e. the same type
    # but without ptrlev or dims
    def getTargetType(self):
        return TypeInfo(self.stype)

    def getTargetCodeType(self):
        return self.getTargetType().codetype

    def fullname(self):
        out = []
        if (self.ptrlev != None):
            out.append('*' * self.ptrlev)

        # Here we will insert the varname
        pref = string.join(out, '')
        
        out = []
        if (self.dims != None):
            for i in self.dims:
                out.append("[%d]" % i)
        suff = string.join(out, '')
        return (self.stype, pref,suff)
  
        
    # A full form with embedded structs unstubbed
    def fullstr(self, indent = 0):
        stype, pref, suff = self.fullname()
        if (self.details):
            rc = self.details.fullstr(indent)+ ' ' + pref + \
                 suff + ';'
        else:
            rc =  ' ' * indent + "%s %s%s;" % \
                 (stype, pref, suff)
        return rc

    def __repr__(self):
        stype, pref, suff = self.fullname()
	if (stype == "(func)"):
	    out = []
	    for ati in self.prototype:
		astype, apref, asuff = ati.fullname()
	        out.append(("%s %s%s" % (astype, apref, asuff)).strip())
	    stype = out[0]
	    suff = "(func)(" + string.join(out[1:], ", ") + ")" 

        out = "TypeInfo <%s %s%s> size=%d" % (stype, pref, suff, self.size)
        return out
    # For debugging purposes
    def dump(self):
	print " -------Dumping all attrs of TypeInfo %s" % self.stype
	for n in dir(self):
	    if (n in ('__doc__', '__module__', '__weakref__')):
		continue
	    a = getattr(self, n)
	    if (type(a) in (StringType, IntType, NoneType, ListType)):
	       print "  fn=%-12s " % n, a
	print " -----------------------------------------------"
    elements = LazyEval("elements", getElements)
    tcodetype = LazyEval("tcodetype", getTargetCodeType)


# Representing enums
class EnumInfo(dict):
    def __setitem__(self, name, value):
        dict.__setitem__(self, name, value)
        object.__setattr__(self, name, value)
    def __init__(self, stype):
        dd = {}
        self.stype = stype
        d.update_EI_fromgdb(self, stype)
    def __str__(self):
        out = []
        for n, v in self._Lst:
            out.append("%s = %d" % (n, v))
        return self.stype + " {" + string.join(out, " ,") +"}"
    def getnam(self, v1):
        for n,v in self.items():
            if (v == v1):
                return n
        return v1




# A global Variable or a struct/union field
# This is TypeInfo plus name plus addr.
# For SU we add manually two attributes: offset and parent

class VarInfo(object):
     def __init__(self,  name = None, addr = -1):
         self.name = name
         self.addr = addr
         self.bitsize = None
         self.ti = None
     # A short form for printing inside struct
     def shortstr(self, indent = 0):
         stype, pref, suff = self.ti.fullname()
         rc =  ' ' * indent + "%s %s%s%s;" % \
              (stype, pref, self.name, suff)
         return rc

     # A full form with embedded structs unstubbed
     def fullstr(self, indent = 0):
         stype, pref, suff = self.ti.fullname()
         details =self.ti.details
         if (self.bitsize != None):
             suff +=":%d" % self.bitsize

         if (self.ti.details):
             rc = self.ti.details.fullstr(indent)+ ' ' + pref + \
                  self.name + suff + ';'
         else:
             rc =  ' ' * indent + "%s %s%s%s;" % \
                  (stype, pref, self.name, suff)
         #return rc
         # Add offset etc.
         size = self.ti.size * self.ti.elements
         return rc + ' | off=%d size=%d' % (self.offset, size)

     # Return a dereferencer for this varinfo (PTR type)
     def getDereferencer(self):
         ti = self.ti
         tti = ti.getTargetType()
         nvi = VarInfo()
         nvi.ti = tti
         self.tsize = tti.size
         #print "Creating a dereferencer for", self
         return nvi.getReader()
     # Return a reader for this varinfo
     def getReader(self, ptrlev = None):
         ti = self.ti
         if (self.bitsize != None):
             bitoffset = self.bitoffset - self.offset * 8
         else:
             bitoffset = None
         
         codetype = ti.codetype
         if (codetype == TYPE_CODE_INT):
             return d.ti_intReader(ti, bitoffset, self.bitsize)
         elif (codetype in TYPE_CODE_SU):
             # Struct/Union
             return d.suReader(self)
         elif (codetype == TYPE_CODE_PTR):
             #print "getReader", id(self), self
             # Pointer
             if (ptrlev == None):
                 ptrlev = ti.ptrlev
             return d.ptrReader(self, ptrlev)
	 elif (codetype == TYPE_CODE_ENUM):     # TYPE_CODE_ENUM
	     return d.ti_intReader(ti, bitoffset, self.bitsize)
         else:
             raise TypeError, "don't know how to read codetype "+str(codetype)


     def __repr__(self):
         stype, pref, suff = self.ti.fullname()
	 if (stype == "(func)"):
	     out = []
	     for ati in self.ti.prototype:
		 astype, apref, asuff = ati.fullname()
	         out.append(("%s %s%s" % (astype, apref, asuff)).strip())
	     stype = out[0]
	     suff = "(" + string.join(out[1:], ", ") + ")" 
         out = "%s <%s%s %s%s> addr=0x%x" % (self.__class__.__name__,
                                             stype, pref,
                                             self.name, suff, self.addr)
         return out

     def getPtrlev(self):
         return self.ti.ptrlev

     # Backwards compatibility
     def getBaseType(self):
         return self.ti.stype

     def getSize(self):
         return self.ti.size * self.ti.elements

     def getArray(self):
         dims = self.ti.dims
         if (len(dims) == 1):
             return dims[0]
         else:
             return dims
    
     reader = LazyEval("reader", getReader)
     dereferencer = LazyEval("dereferencer", getDereferencer)

     # Backwards compatibility
     basetype = LazyEval("basetype", getBaseType)
     size = LazyEval("size", getSize)
     array = LazyEval("array", getArray)
     ptrlev = LazyEval("ptrlev", getPtrlev)


# Pseudo-variables - to map pseudo-attrs
class PseudoVarInfo(VarInfo):
    pass

# This is unstubbed struct representation - showing all its fields.
# Each separate field is represented as SFieldInfo and access to fields
# is possible both via attibutes and dictionary
class SUInfo(dict):
    __metaclass__ = MemoizeSU
    def __init__(self, sname, gdbinit = True):
        #print "Creating SUInfo", sname
        #self.parentstype = None
        #dict.__init__(self, {})

        # These three attributes will not be accessible via dict 
        object.__setattr__(self, "PYT_sname", sname)
        object.__setattr__(self, "PYT_body",  []) # For printing only
        #object.__setattr__(self, "PYT_dchains", {}) # Deref chains cache
        if (gdbinit):
            d.update_SUI_fromgdb(self, sname)

    def __setitem__(self, name, value):
        dict.__setitem__(self, name, value)
        object.__setattr__(self, name, value)

    def append(self, name, value):
        self.PYT_body.append(name)
        self[name] = value
        # A special case: empty name. We can meet this while
        # adding internal union w/o fname, e.g.
        # union {int a; char *b;}
        if (not name):
            #print "name <%s>, value <%s>" % (name, str(value))
            ti = value.ti
            if (ti.codetype == TYPE_CODE_UNION):      # Union
                usi = SUInfo(ti.stype)
                #print ti.stype, usi
                for fn in usi.PYT_body:
                    #print "Adding", fn, usi[fn].ti
                    vi = VarInfo(fn)
                    vi.ti = usi[fn].ti
                    vi.addr = 0
                    vi.offset = value.offset
                    self[fn] = vi
        
    def fullstr(self, indent = 0):
        inds = ' ' * indent
        out = []
        out.append(inds + self.PYT_sname + " {")
        for fn in self.PYT_body:
            out.append(self[fn].fullstr(indent+4))
        out.append(inds+ "}")
        return string.join(out, "\n")

    def __repr__(self):
        return self.fullstr()
    
    def __str__(self):
        out = ["<SUInfo>"]
        out.append(self.PYT_sname + " {")
        for fn in self.PYT_body:
            out.append("    " + self[fn].shortstr())
        out.append("}")
        return string.join(out, "\n")
    # Is the derefence chain OK?
#     def chainOK(self, dstr):
#         try:
#             return self.PYT_dchains[dstr]
#         except KeyError:
#             pass
#         res = parseDerefString(self.PYT_sname, dstr)
        
#         self.PYT_dchains[dstr] = res
#         return res
        


class ArtStructInfo(SUInfo):
    def __init__(self, sname):
        SUInfo.__init__(self, sname, False)
        self.size = self.PYT_size = 0
    def append(self, ftype, fname):
        vi = VarInfo(fname)
        vi.ti = TypeInfo(ftype)
        vi.offset = self.PYT_size
        vi.bitoffset = vi.offset * 8

        SUInfo.append(self, fname, vi)
        # Adjust the size
        self.PYT_size += vi.size
        self.size = self.PYT_size
    # Inline an already defined SUInfo adding its fields and
    # adjusting their offsets
    def inline(self, si):
        osize = self.PYT_size
        for f in si.PYT_body:
            vi = copy.copy(si[f])
            vi.offset += osize
            vi.bitoffset += 8 *osize
            SUInfo.append(self, vi.name, vi)
            
        # Adjust the size
        self.PYT_size += si.PYT_size
        self.size += si.PYT_size
            
        

 

            
# If 'flags' integer variable has some bits set and we assume their
# names/values are in a dict-like object, return a string. For example,
# decoding interface flags we will print "UP|BROADCAST|RUNNING|MULTICAST"
#
# Do not consider dictionary keys that have several bits set

def dbits2str(flags, d, offset = 0):
    # Return True if there is 1-bit only
    def bit1(f):
        nb = 0
        while (f):
            if (f & 1):
                nb += 1
            if (nb > 1):
                return False
            f >>= 1
        return nb == 1
    
    out = ""
    for name, val in d.items():
        if (bit1(val) and (flags & val)):
            if (out == ""):
                out = name[offset:]
            else:
                out += "|" + name[offset:]
    return out


# Join left and right panels, both as multiline strings
def print2columns(left,right):
    left = left.split("\n")
    right = right.split("\n")
    for l, r in map(None, left, right):
        if (l == None):
            l = ""
        if (r == None):
            r = ""
        print l.ljust(38), r


class KernelRev(str):
    def __init__(self, s):
        self.ov = KernelRev.conv(s)

    def __lt__(self, s):
        nv = KernelRev.conv(s)
        return self.ov < nv
    def __le__(self, s):
        nv = KernelRev.conv(s)
        return self.ov <= nv
    def __gt__(self, s):
        nv = KernelRev.conv(s)
        return self.ov > nv
    def __ge__(self, s):
        nv = KernelRev.conv(s)
        return self.ov >= nv
    
    def conv(s):
        a = [0, 0, 0]
        for i, v in enumerate(s.split('.')):
            a[i] = long(v)
        return a[0] * 100000 + a[1] * 1000 + a[2]
    conv = staticmethod(conv)
