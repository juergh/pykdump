#
#  Code that does not depend on whether we use embedded API or PTY
#
# Time-stamp: <07/07/03 14:11:09 alexs>
#
import string
import pprint

import os
import tempfile


pp = pprint.PrettyPrinter(indent=4)

#import wrapcrash as d
d = None

# GLobals used my this module


# The standard hex() appends L for longints
def hexl(l):
    return "0x%x" % l


def unsigned16(l):
    return l & 0xffff

def unsigned32(l):
    return l & 0xffffffff

# INTTYPES = ('char', 'short', 'int', 'long', 'signed', 'unsigned',
#             '__u8', '__u16', '__u32', '__u64',
#              'u8', 'u16', 'u32', 'u64',
#             )
# EXTRASPECS = ('static', 'const', 'volatile')

# Struct/Union info representation base class. It does not contain methods
# to add info as they rely at this moment on parser

# Here we assume that the full type name is used - with struct/union word if needed
class BaseStructInfo(dict):
    # This is used for global caching of StructInfo
    PYT__sinfo_cache = {}
    def __init__(self, stype):
        dict.__init__(self, {})
        self.stype = stype
        self.size = -1
        self.body = []
        self.reclevel = 0

    # Field ptype suitable for passing to crash/gdb, e.g.
    # for 'struct tcp_ehash_bucket *__tcp_ehash;' we return
    # 'struct tcp_ehash_bucket'

    #def fieldbasetype(self, fname):
    #    fi = self[fname]
    #    return fi.basetype
    
    def __repr__(self):
        return "StructInfo <%s> size=%d" % \
                   (self.stype, self.size) +\
                   "\n" + pp.pformat(self.body)

    def addToCache(self):
        stype = self.stype
        #print "++Adding to cache: ", stype
        BaseStructInfo.PYT__sinfo_cache[stype] = self



# A helper class to implement lazy attibute computation. It calls the needed
# function only once and adds the result as an attribute so that next time
# we will not try to compute it again

class LazyEval(object):
    def __init__(self, name, meth):
        self.name = name
        self.meth = meth
    def __get__(self, obj, objtype):
        # Switch 
        #print " ~~lazy~~ ", self.name, '\t', obj.fname
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

# A class to manipulate field info easily. Initially it was a dictionary but
# it should be easier to use attributes

class FieldInfo(dict):
    deref_cache = {}
    def __init__(self, d = {}):
        self.parentstype = None
        dict.__init__(self, d)
        self.__dict__.update(d)
    def __setattr__(self, name, value):
        dict.__setitem__(self, name, value)
        object.__setattr__(self, name, value) 
    def __setitem__(self, name, value):
        dict.__setitem__(self, name, value)
        object.__setattr__(self, name, value)
    def __delattr__(self, name):
        dict.__delitem__(self, name)
        object.__delattr__(self, name)
    def copy(self):
        return FieldInfo(dict.copy(self))
    # A minimal copy - to be used in tPtr
    def mincopy(self):
        newdict ={}
        newdict['type'] = self.type
        newdict['typedef'] = self.typedef
        nf = FieldInfo(newdict)
        return nf
    
    # If self desribes a pointer, Deref returns
    # a new FieldInfo which describes a dereferenced pointer
    def Deref(self):
	try:
	    return FieldInfo.deref_cache[id(self)]
	except KeyError:
	    pass
        try:
            star = self.star
        except AttributeError:
            raise TypeError, "Cannot dereference non-pointers"
        if (self.dim != 1):
            raise TypeError, "Cannot dereference arrays"
        nf = self.mincopy()
        newstar = star[1:]
        if (newstar):
            nf.star = newstar
	#FieldInfo.deref_cache[id(self)] = nf
        return nf

    # Dimension. For multidim arrays a total size, i.e. i1*i2*...*in
    def getDim(self):
        if (type(self.indices) == type([])):
            dimtot = reduce(lambda x,y: x*y, self.indices)
        else:
            dimtot = self.indices
        return dimtot

    # Indices as they found by parser. For 1-dim array just an int,
    # for multidim a list, e.g. [2][3][4] -> [2,3,4]
    def getIndices(self):
        if (self.has_key("array")):
            return self["array"]
        else:
            return 1

    # If the line with field definition is
    # 'struct hello *ptr[10];' we might need different pieces of it
    
    # Base type, without * and other modifiers - 'struct hello'
    # For structs/unions declared inside other struct/union, we
    # create a fakename and artificial struct/union as needed
    def getBaseType(self):
        # Here we have a special case: a struct declared directly in another
        # struct (so that it is not declared globally). For example:
        #
        # struct AA {
        #   struct {} fname;
        #
        # struct AA {
        #   struct BB {} fname;

        # In this case (no type defined globally) we generate a fakename
        # 'struct AA-struct-fname' or 'struct AA-struct-BB-fname'

        #print '++', self.parentstype, self.type, self.fname
        if (not self.has_key('body')):
            # A normal case
            return string.join(self.type)
        else:
            ftype = string.join(self.type, '-')
            fakename = self.parentstype+ '-' + ftype + '-' + self.fname
            return fakename

    
    # Ctype, i.e. the basetype with * as needed 'struct hello *'
    def getCtype(self):
        try:
            return self.basetype + ' ' + self.star
        except:
            return self.basetype

    # Smart Type to return the most useful value. E.g. if
    # we have 'char *' we convert it to Python string
    # 'SUptr'
    def getSmartType(self):
        return _smartType(self)


    # The full statement incuding name, dimension and ; - suitable
    # for our parsed
    def getCstmt(self):
        if (self.dim and self.dim != 1):
            dims = "[%d]" % self.dim
        else:
            dims = ""
        return self.ctype + ' ' + self.fname + dims + ';'
    
    basetype = LazyEval("basetype", getBaseType)
    ctype = LazyEval("ctype", getCtype)
    smarttype = LazyEval("smarttype", getSmartType)
    cstmt = LazyEval("cstmt", getCstmt)
    dim = LazyEval("dim", getDim)
    indices = LazyEval("indices", getIndices)



# Get field size as best as we can. Return -1 if we cannot do it
def fieldsize(f):
    size = -1
    if (f.has_key("star") or f.has_key("func")):
        size = d.pointersize
    elif (f["type"][0] == "enum"):
        size = d.getSizeOf("int")
    else:
        #ftype = string.join(f["type"])
        ftype = f.basetype
        size =  d.getSizeOf(ftype)
    # Correct the size if this is an array
    if (f.has_key("array")):
        size *= f.dim
    return size

# Find the best data representation a field. E.g. we want (char *)
# to be printed as string, integer types as integers
def _smartType(fi):
    # Analyse ctype
    def analyseCtype(ctype):
        spl = ctype.split()
        # The new type can be a function declaration.
        # At this moment we detect this by a presense of '(*)' string
        if (ctype.find('(*)') != -1):
            return 'FPtr'

        signtype = 'S'
        maintype = 'Int'
        if ('unsigned' in spl):
            signtype = 'U'
        if ('struct' in spl or 'union' in spl):
            maintype = 'SU'
        elif ('char' in spl):
            maintype = 'char'
        star = None
        if (ctype.find('*') >= 0):
            star = '*'

        # If we have SU + star here, we still return just Ptr
        stype = 'UInt'
        if (maintype == 'SU'):
            stype = 'SU'
        elif (maintype == 'char' and star and signtype == 'S'):
            stype = 'String'
        elif (maintype == 'char'):
            if (signtype == 'U'):
                stype = 'UChar'
            else:
                stype = 'Char'
        elif (star):
            stype = 'Ptr'
        elif (signtype == 'S'):
            stype = 'SInt'

        return stype

    # Reduce typedefs if any
    newctype = d.isTypedef(fi.basetype)
    if (newctype):
        stype = analyseCtype(newctype)
        fi.typedef = True
    else:
        stype = analyseCtype(fi.basetype)
        fi.typedef = False

    # In some cases we need to change the returned type.
    # E.g. if it was SU and we have a '*', change this to SUptr
    fullstype = stype
    try:
        star = fi.star
    except:
        star = ''

    if (fi.has_key('func') or fullstype == 'FPtr'):
        fullstype = 'FPtr'
    elif (stype == 'Char'):
        if (star == '*'):
            fullstype = 'String'
        elif (fi.has_key("array")):
            fullstype = "CharArray"
        else:
            fullstype = 'SInt'
    elif (stype == 'UChar'):
        fullstype = 'UInt'
    elif (stype == 'SU' and star == '*'):
        fullstype = 'SUptr'
    elif (star):
        fullstype = 'Ptr'

    #print 'SMARTTYPE for <%s>  is %s (stype=%s)' % (fi.ctype, fullstype, stype)
    return fullstype
    
    
def getSIfromCache(stype):
    return BaseStructInfo.PYT__sinfo_cache[stype]

# For debugging
def printSICache():
    pp.pprint(BaseStructInfo.PYT__sinfo_cache.keys())

            
# If 'flags' integer variable has some bits set and we assume their
# names/values are in a dict-like object, return a string. For example,
# decoding interface flags we will print "UP|BROADCAST|RUNNING|MULTICAST"

def dbits2str(flags, d, offset = 0):
    out = ""
    for name, val in d.items():
        if (val and (flags & val)):
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

class PYT_tmpfiles:
    def __init__(self):
        self.tempdir = tempfile.mkdtemp("pycrash")
        self.flist = []
    def mkfifo(self):
        fifoname = self.tempdir + "/" + "PYT_fifo"
        try:
            os.mkfifo(fifoname)
        except OSError, (err, errstr):
            if (err == errno.EEXIST):
                # Check whether it's FIFO and writable
                st_mode = os.stat(fifoname)[0]
                if (not stat.S_ISFIFO(st_mode)):
                    print "FATAL: %s is not a FIFO" % fifoname
                    fifoname = None             # To prevent cleanup
                    sys.exit(1)
            else:
                print "FATAL: cannot mkfifo %s in the current directory" % fifoname
                sys.exit(1)
        self.flist.append(fifoname)
        return fifoname
    
    def cleanup(self):
        for f in self.flist:
            try:
                os.unlink(f)
                #print "unlinking", f
            except:
                pass
        os.rmdir(self.tempdir)
        #print "rmdir", self.tempdir

    def mkfile(self):
        fd, fname = tempfile.mkstemp('', '', self.tempdir)
        self.flist.append(fname)
        return os.fdopen(fd, "w"), fname
