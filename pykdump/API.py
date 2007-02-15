# module pykdump.API
#
# Time-stamp: <07/02/15 15:52:35 alexs>

# This is the only module from pykdump that should be directly imported
# by applications. We want to hide the details of specific implementation from
# end-user. In particular, this module decides what backends to use
# depending on availability of low-level shared library dlopened from crash
#
# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.
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

__doc__ = '''
This is the toplevel API for Python/crash framework. Most programs should
not call low-level functions directly but use this module instead.
'''

import pykdump                          # For version check

# sys is a builtin and does not depend on sys.path. But we cannot load 'os' yet
# if we are running a binary distribution with Python libraries at
# non-standard location
import sys, os, os.path
import zlib

from optparse import OptionParser

# Check the version of Python interpreter we are using
if (sys.maxint < 2**32):
    python_64 = False
else:
    python_64 = True



# We should be careful about the path to 'lib-dynload' as shared libraries are
# different for 32-bit and 64-bit versions. Format of .pyc/.pyo files is
# compatible but the contents of some of them can be specific to installation

pyroot = None
if (python_64 and os.environ.has_key("PYTHON64LIB")):
    pyroot = os.environ["PYTHON64LIB"]
elif (not python_64 and os.environ.has_key("PYTHON32LIB")):
    pyroot = os.environ["PYTHON32LIB"]

if (pyroot):
    # Insert it only if needed
    if (not pyroot in sys.path):
        sys.path.insert(1, pyroot)

# At this point we should be able to load external modules dynamically
# and import modules from non-standard (e.g. PYTHON32LIB) places


import string, re
import time
import stat
import atexit

import LowLevel as ll
import wrapcrash
import Generic as gen
from Generic import Bunch



hexl = gen.hexl
unsigned16 = gen.unsigned16
unsigned32 = gen.unsigned32

dbits2str = gen.dbits2str
print2columns = gen.print2columns

shelf = None
PersistentCache = True


# Similar to sys.exit() but does not call the os._exit()

def cleanup():
    global shelf
    if (shelf != None):
        print "++Saving Cache++"
        shelf[getDumpstring()] = gen.PYT__sinfo_cache
        shelf.close()

    print "Execution took %6.2fs (real) %6.2fs (CPU)" % (time.time() - t_starta,
                                                         os.times()[0] - t_start)


# Module globals
sys_info = Bunch()
API_options = Bunch()

dumpstring = None

from wrapcrash import readPtr, readU16, readU32, readSymbol, readSU, \
     readList, readListByHead,  list_for_each_entry, \
     readSUArray, readSUListFromHead, readStructNext, \
     getStructInfo, getFullBuckets,\
     struct_exists, struct_size, symbol_exists,\
     ArtStructInfo, ArtUnionInfo, getTypedefInfo,\
     Addr, SmartString,\
     sym2addr, addr2sym, readmem, \
     struct_size, union_size, member_offset, member_size, \
     getSizeOf, whatis, printObject,\
     exec_gdb_command, exec_crash_command, \
     flushCache

from tparser import CEnum, CDefine
    
# The following function is used to do some black magic - adding methods
# to classes dynmaically after dump is open.
# E.g. we cannot obtain struct size before we have access to dump

def funcToMethod(func,clas,method_name=None):
    """This function adds a method dynamically"""
    import new
    method = new.instancemethod(func,None,clas)
    if not method_name: method_name=func.__name__
    setattr(clas, method_name, method)

    

def addLazyMethods():
    """Add methods for lazy evaluation"""
    # Methods to be added dynamically to FieldInfo
    def _getSizeOf(self):
        return gen.fieldsize(self)
    gen.FieldInfo.size = gen.LazyEval("size", _getSizeOf)

    def _getOffset(self):
        offset = wrapcrash.GDBmember_offset(self.parentstype, self.fname)
        return offset
    gen.FieldInfo.offset = gen.LazyEval("offset", _getOffset)
    


# Run this after dump is open
def initAfterDumpIsOpen():
    """Do needed initializations after dump is successfully opened"""
    global __dump_is_accessible
    __dump_is_accessible = True
    wrapcrash.pointersize = sys_info.pointersize = getSizeOf("void *")
    
    _doSys()

    # Check whether this is a live dump
    if (sys_info.DUMPFILE.find("/dev/") == 0):
        sys_info.livedump = True
    else:
        sys_info.livedump = False


    # Make some of our methods available for other modules
    gen.d = wrapcrash

    # It's OK to cache struct info on live kernels, but we shouldn't
    # cache memory access and results (if we want to watch non-static
    # picture)
    
    addLazyMethods()
    #  Set scroll width to avoid splitting lines
    exec_gdb_command("set width 300")

    # Check the kernel version and set HZ
    sys_info.kernel = re.search(r'^(\d+\.\d+\.\d+)', sys_info.RELEASE).group(1)
    if (sys_info.kernel >= "2.6.0"):
        sys_info.HZ = 1000
    else:
        sys_info.HZ = 100

    if (symbol_exists("cfq_slice_async")):
        sys_info.HZ = readSymbol("cfq_slice_async") * 25

    # Convert CPUS to integer
    sys_info.CPUS = int(sys_info.CPUS)
    
    # This is where debug kernel resides
    try:
        sys_info.DebugDir = os.path.dirname(sys_info["DEBUG KERNEL"])
    except KeyError:
	sys_info.DebugDir = os.path.dirname(sys_info["KERNEL"])
    
    # A list of top directories where we will search for debuginfo
    kname = sys_info.RELEASE
    RHDIR = "/usr/lib/debug/lib/modules/" + kname
    CGDIR = "/usr/lib/kernel-image-%s-dbg/lib/modules/%s/" %(kname, kname)
    debuginfo = [RHDIR, CGDIR]
    if (not  sys_info.livedump):
        # Append the directory of where the dump is located
        debuginfo.append(getDebugDir())
    # Finally, there's always a chance that this kernel is compiled
    # with debuginfo
    debuginfo.append("/lib/modules/" + kname)
    sys_info.debuginfo = debuginfo


def getDumpstring():
    """Return DUMPFILE as was reported by crash"""
    return sys_info.DUMPFILE

# Detect the type of vmlinux file
# {alexs 14:15:00} file /usr/src/linux-source-2.6.12/vmlinux
#/usr/src/linux-source-2.6.12/vmlinux: ELF 64-bit LSB executable, AMD x86-64, version 1 #
#(SYSV), statically linked, not stripped

# ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
def guessDumptype(cmd):
    """Guess dump type based on vmlinux"""
    re_vmlinux = re.compile(r'(\s|^)(\S*vmlinux\S*)\b')
    m = re_vmlinux.search(cmd)
    if (not m):
	return None
    fn = m.group(2)
    #print fn
    p = os.popen("file -L " + fn, "r")
    s = p.read().split(':', 1)[1]
    p.close()
    if (s.find('32-bit') != -1):
	return "IA32"
    elif (s.find('64-bit') != -1):
	return "AMD64"
    else:
	return None

# Try to guess what dump files can be used in a given directory
# We expect to find vmcore*, vmlinux* and maybe System.map*. Ideally they should
# all have matching version, e.g.
#
# System.map-2.6.9-22.ELsmp      vmlinux-2.6.9-22.ELsmp vmcore-netdump-2.6.9-22.ELsmp
#
# But in reality vmcore quite often has a different name

def findDumpFiles(dir):
    """Find files related to dump in a given directory"""
    # Obtain the list of files
    # If 'dir' passed is empty, try to use '.'
    if (dir):
        dirlist = os.listdir(dir)
    else:
        dirlist = os.listdir('.')
    mapfile = ""
    namelist = ""
    dumpfile = ""

    # Check whether name seems to be that of compressed file or .debug file
    def isReasonable(s1):
	for s2 in (".gz", ".tgz", ".bz2", ".debug"):
	    if (s1[-len(s2):] == s2):
		return False
	return True

    for f in dirlist:
        if (f.find("System.map") == 0):
            mapfile = os.path.join(dir, f)
        # In case there are both vmlinux-rel and vmlinux-rel.debug we need
        # the 1st one
        elif (f.find("vmlinux") == 0 and isReasonable(f)):
            namelist = os.path.join(dir, f)
        elif (f.find("vmcore") == 0 and isReasonable(f)):
            dumpfile = os.path.join(dir, f)


    # If nothing suitable is found and we passed an empty dir, try to
    # run on a live kernel
    if (not dir and not dumpfile):
	mapfile = namelist = dumpfile = ""
        uname = os.uname()[2]
        # Now try to find in /boot System.map-<uname> and vmlinux-<uname>
        testmap =  "/boot/System.map-"+uname
        testkern = "/boot/vmlinux-"+uname
        if (os.access(testmap, os.R_OK) and os.access(testkern, os.R_OK)):
            mapfile = testmap
            namelist = testkern
            dumpfile = "--memory_module=crash"
	    # We don't need this for IA64
	    if (os.uname()[-1] == 'ia64'):
		dumpfile = ''
    return (mapfile, namelist, dumpfile)

# For fbase specified as 'nfsd' find all files like nfds.o, nfsd.ko,
# nfsd.o.debug and nfsd.ko.debug that are present in a given directory

def possibleModuleNames(topdir, fbase):
    """Find filenames matching a given module name"""
    if (topdir == None):
        return None
    exts = (".ko.debug", ".o.debug", ".ko", ".o")
    lfb = len(fbase)

    for d, dummy, files in os.walk(topdir):
        for f in files:
            if (f.find(fbase) != 0):
                continue
            ext = f[lfb:]
            for e in exts:
                if (ext == e):
                    return os.path.join(d, fbase + e)
    return None
        
    
        
def getDebugDir():
    """Return the directory that contains the debug kernel"""
    # We assume that this is where debug kernel is located
    return sys_info.DebugDir


# Loading extra modules. Some defauls locations for debuginfo:

# RH /usr/lib/debug/lib/modules/uname/...
# CG /usr/lib/kernel-image-2.6.10-telco-1.27-mckinley-smp-dbg/lib/modules/2.6.10-telco-1.27-mckinley-smp/...

# So we'll try these directories first, then the default /lib/modules/uname,
# then the dump directory

# If we load module successfully, we receive
#  MODULE   NAME          SIZE  OBJECT FILE
# f8a95800  sunrpc      139173  /data/Dumps/test/sunrpc.ko.debug

__loaded_Mods = {}
def loadModule(modname, ofile = None):
    """Load module file into crash"""
    try:
        return __loaded_Mods[modname]
    except KeyError:
        pass
    if (ofile == None):
        for t in sys_info.debuginfo:
            ofile = possibleModuleNames(t, modname)
            if (ofile):
                break
        if (debug):
            print "Loading", ofile
    if (ofile == None):
        return False
    rc = exec_crash_command("mod -s %s %s" % (modname, ofile))
    success = (rc.find("MODULE") != -1)
    __loaded_Mods[modname] = success
    return success
    
# Execute 'sys' command and put its split output into a dictionary
# Some names contain space and should be accessed using a dict method, e.g.
# sys_info["LOAD AVERAGE"]
def _doSys():
    """Execute 'sys' commands inside crash and return the parsed results"""
    for il in exec_crash_command("sys").splitlines():
        spl = il.split(':', 1)
        if (len(spl) == 2):
            sys_info.__setattr__(spl[0].strip(), spl[1].strip())


# Preprocess options, splitting them into these for API_wide and those
# userscript-specific
def __preprocess(iargv,op):
    """Preprocess options separating these controlling API
    from those passed to program as arguments
    """
    # Split the arguments into API/app

    aargv = []                              # API args
    uargv = []                              # Application args

    #print "iargv=", iargv

    while(iargv):
        el = iargv.pop(0)
        # All elements starting from '.' and '/' go to aargv
        if (el[0] in ('/', '.')):
            aargv.append(el)
        elif (el[:2] == '--'):
            # Check whether this option is present in optparser's op
            optstr = el.split('=')[0]
            opt =  op.get_option(optstr)
            #print "el, opt", el, opt
            if (opt):
                nargs = opt.nargs
                aargv.append(el)
                # If we don't have '=', grab the next element too
                if (el.find('=') == -1 and nargs):
                    aargv.append(iargv.pop(0))
            else:
                uargv.append(el)
        else:
            uargv.append(el)
    #print "aargv=", aargv
    #print "uargv", uargv
    return (aargv, uargv)

# Search for a given file in a list of directories
def __findFile(dirlist, fname):
    """Search sys.path for a given file"""
    for d in dirlist:
        pathname = os.path.join(d, fname)
        if (os.access(pathname, os.R_OK | os.X_OK)):
            return pathname
    return None


# This routine is called automatically when you import API. It analyzes
# sys.argv to obtain info about dump location when the script is running
# externally. When running from embedded, it ignores dump location but
# is still doing options parsing. This can be used to enable debugging
# or experimental features
# It is not needed to call this. But if you do, it will process options passed
# from sys.argv (if any) which can be used for debugging
#
# To simplify the processing we use the following approach: all debugging
# options should be 'long', all app options (if any) should be 'short'

def openDump():
    """Open dump by executing 'crash' if needed."""
    
    op = OptionParser()
    op.add_option("--ext", dest="UseExt",
              action="store", type="int", default=1,
              help="enable/disable extension if available")
    
    op.add_option("--crash", dest="crashex",
              action="store", default=None,
              help="Specify the name of the 'crash' executable")

    op.add_option("--nopsyco", dest="nopsyco", default=0,
              action="store_true",
              help="disable Psyco even if it available")

    op.add_option("--debug", dest="debug", default=0,
              action="store", type="int",
              help="enable debugging output")

    op.add_option("--experimental", dest="experimental", default=0,
              action="store_true",
              help="enable experimental features (for developers only)")

    # Before real parsing, separate API-options from
    # userscript-options

    script = sys.argv[0]
    if (len(sys.argv) > 1):
        (aargs, uargs) = __preprocess(sys.argv[1:], op)
    else:
        aargs = uargs = []

    (o, args) = op.parse_args(aargs)

    
    crashex = o.crashex                 # Use crash32/crash64 as needed
    useext = o.UseExt                   # Use extension if possible

    debug = API_options.debug = o.debug
    wrapcrash.experimental = API_options.experimental = o.experimental
    

    filtered_argv = [script]
    if (uargs):
        filtered_argv += uargs
    
    # Check whether we can import 'crash' - if yes, we are inside extension and
    # should not try to open the dump again
    try:
        # If we can do this, we are called from crash
        import crash as crashmod
        ll.GDBgetOutput = crashmod.get_GDB_output
        sys.argv = filtered_argv
        if (debug):
            print "-------crash module %s--------" % crashmod.version
        return
    except ImportError:
        pass

    # --------------------------------------------------------------------
    # If we are here, we are running externally, maybe without extension
    # --------------------------------------------------------------------
    
    #print args
    if (len(args) ==  1):
        files = findDumpFiles(args[0])
    else:
        files = findDumpFiles('')
    if (files[1]):
        cmd = string.join(files)
    else:
        print "Cannot find dump in the specified directory"
        sys.exit(1)
        
    if (crashex == None):
        dtype = guessDumptype(cmd)
        #print cmd, dtype
        if (dtype == 'IA32'):
            crashex = 'crash32'
        elif (dtype == 'AMD64'):
            crashex = 'crash64'
        else:
            crashex = 'crash'

    if (sys.stdout.isatty()):
        print crashex + " " + cmd

    if (sys.stdout.isatty()):
        print "Starting crash...",
        sys.stdout.flush()
    info = ll.openDump(cmd, crashex)
    if (not info):
        print "Cannot open the dump"
        sys.exit(1)
    if (sys.stdout.isatty()):
        print "done!\n",
        sys.stdout.flush()

    # At this point the dump is open and we have access to it

    # Convert info into a dictionary
    outdict = {}
    for il in info:
        spl = il.split(':', 1)
        if (len(spl) == 2):
            outdict[spl[0].strip()] = spl[1].strip()
    #print outdict
    # Obtain the dumphost (MACHINE)
    machine = outdict["MACHINE"].split()[0]

    # Now we try to load the extension. We rely on .crash*rc do define its
    # location

    crashrc = '.' + os.path.basename(crashex) + 'rc'

    pythonso = None
    re_extend = re.compile(r'^\s*extend\s+(\S+)$')
    for f in os.path.expanduser("~/" + crashrc), crashrc:
        if (os.access(f, os.R_OK)):
            # Search for "extend path" line
            for l in open(f, "r"):
                m = re_extend.match(l)
                if (m):
                    pythonso = m.group(1)

    if (useext):
        rc = ll.getOutput("extend %s" % pythonso)
    else:
        rc = ''
    if (rc.find("shared object loaded") >= 0):
        if (debug):
            print "Extension available"
        # Invoke the same script again, with the same parameters
        cmd = "epython " + string.join(sys.argv)
        #print ll.getOutput(cmd)
        #sys.exit(0)
        ll.sendLine("epython " + string.join(sys.argv))
        ll.sendLine("quit")
        try:
            pass
            ll.interact()
        except:
            pass
        sys.exit(0)
    else:
        if (debug):
            print "*** no embedded Python"
        wrapcrash.fifoname = ll.fifoname
    sys.argv = filtered_argv

    # If we reach this point, we are running with PTY-interface
    # Use Psyco if is available and not suppressed by option
    if (not o.nopsyco):
        try:
            import psyco
            psyco.full()
            print " *** Using Psyco ***"
        except:
            pass

    return



# ----------- do some initializations ----------------

openDump()
debug = API_options.debug
initAfterDumpIsOpen()
if (API_options.debug):
    print "-------PyKdump %s-------------" % pykdump.__version__
t_start = os.times()[0]
t_starta = time.time()
#atexit.register(cleanup)
