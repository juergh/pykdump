# -*- coding: utf-8 -*-
#
#  Generic classes and subroutines
#
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2019 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------

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

import os, sys
import copy
import inspect
from collections import defaultdict


from io import StringIO
from functools import reduce
from itertools import zip_longest
long = int

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
        keys = sorted(self.keys())
        for k in keys:
            print ("  ", k.ljust(12), self[k], file=prn)
        rc = prn.getvalue()
        prn.close()
        return rc

# A special subclass of Bunch to be used for 'DataCache' class
# In particular, we can register handlerk subroutines that will
# be called when we change iterm value
class _Bunch(Bunch):
    def __init__(self, d = {}):
        super().__init__(d)
        # Used for regiestered handlers
        object.__setattr__(self, '_registered', defaultdict(list))
    def clear(self):
        for name in self.keys():
            object.__delattr__(self, name)
        dict.clear(self)
    def __setitem__(self, name, value):
        super().__setitem__(name,value)
        if (name in self._registered):
            for func, o, ownermod in self._registered[name]:
                func(value)
                if (_debugDCache):
                    print(" Setting {}={} for {}".format(name, value, o))
    def __getattr__(self, name):
        return None
    def _register(self, pyctlname, func, o, ownermod):
        self._registered[pyctlname].append((func, o, ownermod))
        if (_debugDCache):
            print(" <{}> {} option registered".format(pyctlname, o))

    # Delete all entries related to a specific module - this is needed
    # during reload
    def _delmodentries(self, mod):
        _reg = self._registered
        for k in _reg:
            # _reg[k][2] is ownermoddule
            lst = _reg[k]
            lst[:] = [e for e in lst if e[2] is not mod]
            _reg[k] = lst
    def Dump(self):
        _reg = self._registered
        out = []
        if (_reg):
            out.append(" -- Listing registered options --")
            for k in _reg:
                v = self[k]
                for func, o, ownermod in _reg[k]:
                    if (inspect.ismodule(o)):
                        descr = " in {}".format(o.__name__)
                    else:
                        nowner = ownermod.__name__
                        descr = "{} in {}".format(type(o).__name__, nowner)
                    out.append("     <{}={}>  {}".\
                               format(k, v, descr))
            s = "\n".join(out)
            print(s)

class DataCache(object):
    def __init__(self):
        self._tmp = _Bunch()
        self._perm = _Bunch()
    @property
    def tmp(self):
        return self._tmp
    @property
    def perm(self):
        return self._perm
    def cleartmp(self):
        # Clear both attrs and dict
        self._tmp.clear()
    def clearperm(self):
        # Clear both attrs and dict
        self._perm.clear()
    def __str__(self):
        return "{} in tmp, {} in perm".format(len(self._tmp), len(self._perm))
    def dump(self):
        if (len(self.tmp)):
            print("   ** DCache.tmp **")
            print(self.tmp)
        if (len(self.perm)):
            print("   ** DCache.perm **")
            print(self.perm)

DCache = DataCache()

# Get module object from whete we call this subroutine

def getCurrentModule(depth = 1):
    cframe = inspect.currentframe()
    m = inspect.getmodule(cframe)
    f = inspect.getouterframes(cframe)[depth]

    # The following does not work when called from ZIP (Why?)
    #m = inspect.getmodule(f.frame)
    #return m

    # An alternative approach:
    mname = f.frame.f_globals["__name__"]
    return sys.modules[mname]

# Register object handler to change its attribute externally
def registerObjAttrHandler(o, attrname, pyctlname=None, default=None):
    __D = DCache.perm
    if (pyctlname is None):
        pyctlname = attrname
    def __func(value):
        setattr(o, attrname, value)
        return value
    # If it is not set yet, set it to default
    if (default is None and hasattr(o, attrname)):
        default = getattr(o, attrname)

    if (not pyctlname in __D):
        __D[pyctlname] = default
    __func(default)             # Create it if needed
    __D._register(pyctlname, __func, o, getCurrentModule(2))

# Register a handler for a module attribute, where module is the one
# where we call this subroutine from
def registerModuleAttr(attrname, pyctlname=None, default=None):
    cmod = getCurrentModule(2)
    registerObjAttrHandler(cmod, attrname, pyctlname, default)

# We need the next line as it is used in registerObjAttrHandler
_debugDCache = 0
registerModuleAttr('debugMemoize', default=0)
registerModuleAttr('_debugDCache', 'debugDCache')

# Produce an object that will return True a predefined number of times.
# For example:
# twice = TrueOnce(2)
# for in in range(5):
#    if(twice): print("OK")

class TrueOnce():
    def __init__(self, v = 1):
        self.v = v
    def __bool__(self):
        if (self.v > 0):
            self.v -= 1
            return True
        else:
            return False

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
    def __call__(cls, *args):
        key = (args[0], MemoizeSU)
        try:
            return _typeinfo_cache[key]
        except KeyError:
            rc =  super(MemoizeSU, cls).__call__(*args)
            _typeinfo_cache[key] = rc
            return rc
    @staticmethod
    def purgecache(sn = None):
        purge_typeinfo(sn)



# A cache for anything typeinfo-related. The key to memoize on is
# (sn, function) -and we assume that 'sn' is always the first argument
# (sn, arg1, ...) where 'sn' is struct/type name. The idea is that when we need
# to change structure definition on the fly (e.g. multiple definitons)
# we want to do just purge_type_info(sn) and it will purge all related caches

_typeinfo_cache = {}
def memoize_typeinfo(fn):
    def newfunc(*args, **keyargs):
        key = (args[0], fn.__name__) + args[1:]
        try:
            return _typeinfo_cache[key]
        except KeyError:
            #print ("Memoizing", key)
            val =  fn(*args)
            _typeinfo_cache[key] = val
            return val
    return newfunc

def purge_typeinfo(sn = None):
    if (sn is None):
        _typeinfo_cache.clear()
        return
    for k in list(_typeinfo_cache.keys()):
        if (k[0] == sn):
            del _typeinfo_cache[k]


# Memoize cache. Is mainly used for expensive exec_crash_command

__memoize_cache = {}

CU_LIVE = 1                             # Update on live
CU_LOAD = 2                             # Update on crash 'mod' load
CU_PYMOD = 4                            # Update on Python modules reload
CU_TIMEOUT = 8                          # Update on timeout change

# CU_PYMOD is needed if we are reloading Python modules (by deleting it)
# In this case we need to invalidate cache entries containing references
# to classes defined in the deleted modules


def memoize_cond(condition):
    def deco(fn):
        def newfunc(*args, **keyargs):
            memoize = keyargs.get("MEMOIZE", True)
            #print('fn=',fn, "memoize=", memoize)
            newfunc.__memoize = memoize
            if (not memoize):
                return fn(*args)
            key = (condition, fn.__name__) + args
            # If CU_LIVE is set and we are on live kernel, do not
            # memoize
            if (condition & CU_LIVE and livedump):
                if (debugMemoize > 2):
                    print ("do not memoize: live kernel", key)
                return fn(*args)
            try:
                return __memoize_cache[key]
            except KeyError:
                if (debugMemoize > 1):
                    print ("Memoizing", key)
                val =  fn(*args)
                __memoize_cache[key] = val
                return val
        return newfunc
    return deco

def print_memoize_cache():
    #keys = sorted(__memoize_cache.keys())
    keys = list(__memoize_cache.keys())
    for k in keys:
        v = __memoize_cache[k]
        try:
            print (k, v)
        except Exception as val:
            print ("\n\t", val, 'key=', k)

# Purge those cache entries that have at least one of the specified
# flags set
def purge_memoize_cache(flags):
    #keys = sorted(__memoize_cache.keys())
    keys = list(__memoize_cache.keys())
    for k in keys:
        ce_flags = k[0]
        if (ce_flags & flags):
            if (debugMemoize > 1):
                print ("Purging cache entry", k)
            del __memoize_cache[k]

#  select and retirn the value of one expression only

__PY_select_cache = {}
def PY_select(*expr):
    f =  sys._getframe(1)
    outlocals = f.f_locals
    outglobals = f.f_globals
    cid = __fid(2)
    key = (cid, expr)
    if (key in __PY_select_cache):
        #print("from cache")
        return eval(__PY_select_cache[key][0], outglobals, outlocals)
    for  e in expr:
        try:
            #print("Evaluating", e)
            ee = eval(e, outglobals, outlocals)
            break
        except (KeyError, NameError, TypeError, AttributeError):
            #print(e, "is bad")
            pass
    else:
        return None
    code = compile(e, '<string>', 'eval')
    __PY_select_cache[key] = (code, e)
    return ee

def PY_select_stats():
    kv = [(k[0], v) for k, v in __PY_select_cache.items()]
    for k, v in sorted(kv) :
        print("{} -> {}".format(k, v[1]))

def __fid(depth=1):
    f = sys._getframe(depth)
    cid = (f.f_code.co_filename, f.f_lineno)
    #print(cid)
    return cid

# Purge PY_select cache
def PY_select_purge():
    __PY_select_cache.clear()

#
# ------------------------------------------------------------------
#
# Limit a potentially infinite sequence so that while iterating
# it we'll stop not later than after N elements

def iterN(seq, N):
    it = iter(seq)
    for i in range(N):
        yield next(it)
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
        pref = ''.join(out)

        out = []
        if (self.dims != None):
            for i in self.dims:
                out.append("[%d]" % i)
        suff = ''.join(out)
        return (self.stype, pref,suff)

    # A string without a terminating ';', suitable for function args description
    def typestr(self):
        stype, pref, suff = self.fullname()
        if (self.details):
            rc = "{} {} {}".format(self.details.fullstr(), pref, suff);
        else:
            if(pref == '' and suff == ''):
                return stype
            else:
                rc = "{} {}{}".format(stype, pref, suff)
        return rc

    # A full form with embedded structs unstubbed.
    # Terminated by ;, to emulate C-style definition
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
            suff = "(func)(" + ", ".join(out[1:]) + ")"

        out = "TypeInfo <%s %s%s> size=%d" % (stype, pref, suff, self.size)
        return out
    # For debugging purposes
    def dump(self):
        print (" -------Dumping all attrs of TypeInfo %s" % self.stype)
        for na in ('stype', 'size', 'dims', 'ptrlev', 'typedef', 'details'):
            a = getattr(self, na)
            # if (type(a) in (StringType, IntType, NoneType, ListType)):
            #    print ("  fn=%-12s " % n, a)
            print("  {}, {} ".format(na, a))
        print (" -----------------------------------------------")
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
        return self.stype + " {" + " ,".join(out) +"}"
    def getnam(self, v1):
        for k,v in self.items():
            if (v == v1):
                return k
        # Unknown value
        return '<{}, bad value {}>'.format(self.stype, v1)



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
             if (self.name):
                 rc = self.ti.details.fullstr(indent)+ ' ' + pref + \
                      self.name + suff + '+;'
             else:
                 rc = self.ti.details.fullstr(indent)+  pref + suff + ';'

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
             return d.ti_enumReader(ti)
         elif (codetype == TYPE_CODE_BOOL):
             return d.ti_boolReader(ti, bitoffset, self.bitsize)
         else:
             raise TypeError("don't know how to read codetype "+str(codetype))


     def __repr__(self):
         stype, pref, suff = self.ti.fullname()
         if (stype == "(func)"):
             out = []
             for ati in self.ti.prototype:
                 astype, apref, asuff = ati.fullname()
                 out.append(("%s %s%s" % (astype, apref, asuff)).strip())
             stype = out[0]
             suff = "(" + ", ".join(out[1:]) + ")"
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
#class SUInfo(dict, metaclass = MemoizeSU):
class SUInfo(dict):
    __metaclass__ = MemoizeSU
    def __init__(self, sname, gdbinit = True):
        #self.parentstype = None
        #dict.__init__(self, {})

        # These three attributes will not be accessible via dict
        object.__setattr__(self, "PYT_sname", sname)
        # PYT_body is needed for printing mainly. As we can have internal
        # struct/union with empty names and there can be several of them,
        # we cannot rely on name to save info.
        #   As a result, each element is (name, ti)
        object.__setattr__(self, "PYT_body",  []) # For printing only
        #object.__setattr__(self, "PYT_dchains", {}) # Deref chains cache
        if (gdbinit):
            d.update_SUI_fromgdb(self, sname)

    def __setitem__(self, name, value):
        dict.__setitem__(self, name, value)
        object.__setattr__(self, name, value)

    def append(self, name, value):
        # A special case: empty name. We can meet this while
        # adding internal union w/o fname, e.g.
        # union {int a; char *b;}
        self.PYT_body.append((name, value))
        if (name):
            self[name] = value
        else:
            self.__appendAnonymousSU(value)
    # Append an anonymous SU. We add its members to our parent's namespace
    # with appropriate offsets
    def __appendAnonymousSU(self, value):
        ti = value.ti
        #print "name <%s>, value <%s>" % (name, str(value))
        # Anonymous structs/unions can be embedded and multilevel
        if (not ti.codetype in TYPE_CODE_SU):
            raise TypeError("field without a name " + str(value))
        usi = SUInfo(ti.stype)
        #print ti.stype, usi
        if (ti.codetype == TYPE_CODE_UNION):
            for fn, usi_v in usi.PYT_body:
                #print "Adding", fn, usi[fn].ti
                vi = VarInfo(fn)
                vi.ti = usi_v.ti
                vi.addr = 0
                vi.offset = value.offset
                if (fn):
                    self[fn] = vi
                else:
                    self.__appendAnonymousSU(vi)

        elif (ti.codetype == TYPE_CODE_STRUCT):
            for fn, usi_v in usi.PYT_body:
                #print "Adding", fn, usi[fn].ti
                vi = VarInfo(fn)
                vi.ti = usi_v.ti
                vi.addr = 0
                vi.offset = value.offset + usi_v.offset
                if (fn):
                    self[fn] = vi
                else:
                    self.__appendAnonymousSU(vi)

    def fullstr(self, indent = 0):
        inds = ' ' * indent
        out = []
        out.append(inds + self.PYT_sname + " {")
        for fn, vi in self.PYT_body:
            out.append(vi.fullstr(indent+4))
        out.append(inds+ "}")
        return "\n".join(out)

    def __repr__(self):
        return self.fullstr()

    def __str__(self):
        out = ["<SUInfo>"]
        out.append(self.PYT_sname + " {")
        for fn, vi in self.PYT_body:
            out.append("    " + vi.shortstr())
        out.append("}")
        return "\n".join(out)
    # Get field names in the same order as present in struct
    def getFnames(self):
        return [e[0] for e in self.PYT_body]


SUInfo = MemoizeSU('SUInfo', (SUInfo,), {})

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
        for f, tvi in si.PYT_body:
            vi = copy.copy(tvi)
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
    for l, r in zip_longest(left, right, fillvalue= ''):
        print (l.ljust(38), r)


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

