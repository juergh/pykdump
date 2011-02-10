# -*- coding: utf-8 -*-
# module pykdump.API
#
# Time-stamp: <11/02/09 12:22:01 alexs>


# This is the only module from pykdump that should be directly imported
# by applications. We want to hide the details of specific implementation from
# end-user. In particular, this module decides what backends to use
# depending on availability of low-level shared library dlopened from crash
#
# Copyright (C) 2006-2011 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2011 Hewlett-Packard Co., All rights reserved.
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

# Messages to be used for warnings and errors
WARNING = "+++WARNING+++"
ERROR =   "+++ERROR+++"


import sys, os, os.path
import re, string
import time
import stat
import atexit

import pykdump                          # For version check
require_cmod_version = pykdump.require_cmod_version
  
require_cmod_version(pykdump.minimal_cmod_version)


# Here we make some pieces of other modules classes/functions/varibles
# visible to API

import Generic as gen
from Generic import Bunch, ArtStructInfo, EnumInfo, iterN, \
     memoize_cond, purge_memoize_cache, \
     CU_LIVE, CU_LOAD, CU_PYMOD, CU_TIMEOUT

hexl = gen.hexl
unsigned16 = gen.unsigned16
unsigned32 = gen.unsigned32

dbits2str = gen.dbits2str
print2columns = gen.print2columns



import crash
HZ = crash.HZ

crash.WARNING = WARNING                 # To be used from C-code

import pprint

# For binary compatibility with older module
try:
    set_default_timeout = crash.set_default_timeout
except AttributeError:
    def set_default_timeout(timeout):
	return None


import wrapcrash

from wrapcrash import readU8, readU16, readU32, readS32, \
     readU64, readS64, readInt, readPtr, \
     readSymbol, readSU, \
     sLong, le32_to_cpu, cpu_to_le32, le16_to_cpu, \
     readList, readBadList, getListSize, readListByHead,  list_for_each_entry, \
     ListHead, hlist_for_each_entry, \
     readSUArray, readSUListFromHead, readStructNext, \
     getStructInfo, getFullBuckets, FD_ISSET, \
     struct_exists, symbol_exists,\
     Addr, Deref, SmartString, tPtr, \
     sym2addr, addr2sym, sym2alladdr, \
     get_pathname, \
     readmem, uvtop, readProcessMem, set_readmem_task, \
     struct_size, union_size, member_offset, member_size, \
     getSizeOf, container_of, whatis, printObject,\
     exec_gdb_command, exec_crash_command, exec_command,\
     structSetAttr, structSetProcAttr, sdef2ArtSU

gen.d = wrapcrash
# Add all GDB-registered types as Generic and wrapcrash variables
for n in dir(crash):
    if (n.find('TYPE_CODE') == 0):
        setattr(gen, n, getattr(crash, n))
        setattr(wrapcrash, n, getattr(crash, n))
    TYPE_CODE_SU = (crash.TYPE_CODE_STRUCT, crash.TYPE_CODE_UNION)
    setattr(gen, 'TYPE_CODE_SU', TYPE_CODE_SU)
    setattr(wrapcrash, 'TYPE_CODE_SU', TYPE_CODE_SU)

from tparser import CEnum, CDefine

# API module globals
sys_info = Bunch()
API_options = Bunch()

# Timeout used on a previous run
global __timeout_exec
__timeout_exec = 0

# Check whether we output to a real file.

def isfileoutput():
    if (sys.stdout.isatty()):
	return False
    mode = os.fstat(sys.stdout.fileno())[stat.ST_MODE]
    return stat.S_ISREG(mode)
    

# Process common (i.e. common for all pykdump scripts) options.
from optparse import OptionParser, Option
def __epythonOptions():
    """Process epython common options and filter them out"""

    op = OptionParser(add_help_option=False, option_class=Option)
    op.add_option("--experimental", dest="experimental", default=0,
              action="store_true",
              help="enable experimental features (for developers only)")

    op.add_option("--debug", dest="debug", default=0,
              action="store", type="int",
              help="enable debugging output")
    
    op.add_option("--timeout", dest="timeout", default=120,
              action="store", type="int",
              help="set default timeout for crash commands")

    op.add_option("--reload", dest="reload", default=0,
              action="store_true",
              help="reload already imported modules from Linuxdump")

    op.add_option("--dumpcache", dest="dumpcache", default=0,
              action="store_true",
              help="dump API caches info")

    op.add_option("--ofile", dest="filename",
                  help="write report to FILE", metavar="FILE")


    if (len(sys.argv) > 1):
        (aargs, uargs) = __preprocess(sys.argv[1:], op)
    else:
        aargs = uargs = []
 
    (o, args) = op.parse_args(aargs)
    wrapcrash.experimental = API_options.experimental = o.experimental
    global debug, __timeout_exec
    debug = API_options.debug = gen.debug = o.debug

    if (o.reload):
	purge_memoize_cache(CU_PYMOD)
        for k, m in sys.modules.items()[:]:
            if(k.split('.')[0] == 'LinuxDump' and m):
                del sys.modules[k]
                print "--reloading", k
    
    if  (o.timeout):
	set_default_timeout(o.timeout)
	# Purge the CU_TIMEOUT caches if we _increase_ the timeout
	# This makes sense if some commands did not complete and we
	# re-run with bigger timeout
	if (o.timeout > __timeout_exec):
	    purge_memoize_cache(CU_TIMEOUT)
	__timeout_exec = o.timeout
	
    if (o.filename):
        sys.stdout = open(o.filename, "w")

    sys.argv[1:] = uargs
    #print "EPYTHON sys.argv=", sys.argv

    API_options.dumpcache = o.dumpcache

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
        # All elements starting from '.' and '/' go to aargv - but only
        # they match the existing directories. We can specify directories
        # from command-line to make pykdump to search for vmcore/vmlinux
        # files in them. But some options (e.g. output to a file) may
        # use arguments like /tmp/t.out
        
        if (el[0] in ('/', '.') and os.path.isdir(el)):
            aargv.append(el)
        elif (el[:2] == '--' or el[0] == '-'):
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

# This function is called on every 'epython' invocation
# It is called _before_ we  start the real script
# This is done by 'epython' command.
# Here we can print information messages  and initialize statistics

re_apidebug=re.compile(r'^--apidebug=(\d+)$')
def enter_epython():
    global t_start, t_starta, pp
    t_start = os.times()[0]
    t_starta = time.time()
    
    # We might redefine stdout every time we execute a command...
    pp = pprint.PrettyPrinter(indent=4)
    #print "Entering Epython"

    # Process hidden '--apidebug=level' and '--reload' options
    # filtering them out from sys.argv
    __epythonOptions()

    # The dumpfile name can optionally have extra info appended, e.g.
    # /Dumps/Linux/test/vmcore-netdump-2.6.9-22.ELsmp  [PARTIAL DUMP]
    dumpfile = sys_info.DUMPFILE.split()[0]
    #cwd = os.getcwd()
    dumpfile = os.path.abspath(dumpfile)
    text = "%s  (%s)" % (dumpfile, sys_info.RELEASE)
    lpad = (77-len(text))/2
    # Print vmcore name/path when not on tty
    if (isfileoutput()):
        print "\n", 'o' * lpad, text, 'o' * lpad
    
    # Use KVADDR
    set_readmem_task(0)


# We call this when exiting epython
def exit_epython():
    if API_options.dumpcache:
        #BaseStructInfo.printCache()
        #wrapcrash.BaseTypeinfo.printCache()
        pass
    cleanup()


def cleanup():
    set_readmem_task(0)
    try:
        print "\n ** Execution took %6.2fs (real) %6.2fs (CPU)" % \
                                        (time.time() - t_starta,
					 os.times()[0] - t_start)
    except IOError:
	pass



    
# The following function is used to do some black magic - adding methods
# to classes dynmaically after dump is open.
# E.g. we cannot obtain struct size before we have access to dump

def funcToMethod(func,clas,method_name=None):
    """This function adds a method dynamically"""
    import new
    method = new.instancemethod(func,None,clas)
    if not method_name: method_name=func.__name__
    setattr(clas, method_name, method)



# For fbase specified as 'nfsd' find all files like nfds.o, nfsd.ko,
# nfsd.o.debug and nfsd.ko.debug that are present in a given directory

def possibleModuleNames(topdir, fbase):
    """Find filenames matching a given module name"""
    if (topdir == None):
        return None
    exts = (".ko.debug", ".o.debug", ".ko", ".o")
    lfb = len(fbase)
    #print "++ searching for", fbase, " at", topdir

    for d, dummy, files in os.walk(topdir):
        for f in files:
            if (f.find(fbase) != 0):
                continue
            ext = f[lfb:]
            for e in exts:
                if (ext == e):
                    return os.path.join(d, fbase + e)
    return None
        

# Loading extra modules. Some defauls locations for debuginfo:

# RH /usr/lib/debug/lib/modules/uname/...
# CG /usr/lib/kernel-image-2.6.10-telco-1.27-mckinley-smp-dbg/lib/modules/2.6.10-telco-1.27-mckinley-smp/...

# So we'll try these directories first, then the default /lib/modules/uname,
# then the dump directory

# If we load module successfully, we receive
#  MODULE   NAME          SIZE  OBJECT FILE
# f8a95800  sunrpc      139173  /data/Dumps/test/sunrpc.ko.debug


__loaded_Mods = {}
def loadModule(modname, ofile = None, altname = None):
    """Load module file into crash"""
    
    # In some cases we load modules renaming them. 
    # In this case modname is the original name (used to search for debug)
    # and altname is the name in 'mod' output
    if (not altname):
	altname = modname
    try:
        return __loaded_Mods[modname]
    except KeyError:
        pass

    if (debug > 1):
        print "Starting module search", modname
    if (ofile == None):
        for t in sys_info.debuginfo:
            if (debug > 1):
                print t
            # Some modules use different names in file object and lsmod, e.g.:
            # dm_mod -> dm-mod.ko
	    for mn in (modname, modname.replace("_", "-")):
	       ofile = possibleModuleNames(t, mn)
	       if (ofile):
		   break
	    if (ofile):
		break
        if (debug > 1):
            print "Loading", ofile
    if (ofile == None):
        return False
    # If we specify a non-loaded module, exec_crash_command does not return
    if (debug > 1):
        print "Checking for altname"
    if (not altname in lsModules()):
	return False
    if (debug > 1):
        print "Trying to insert", altname, ofile
    rc = exec_crash_command("mod -s %s %s" % (altname, ofile))
    success = (rc.find("MODULE") != -1)
    __loaded_Mods[modname] = success
    # Invalidate typeinfo caches
    wrapcrash.invalidate_cache_info()
    # Invalidate memoize_cache entries with CU_LOAD set
    purge_memoize_cache(CU_LOAD)
    return success

# Unload module

def delModule(modname):
    #print __loaded_Mods
    try:
        del __loaded_Mods[modname]
        exec_crash_command("mod -d %s" % modname)
	if (debug):
	    print "Unloading", modname
    except KeyError:
        pass

# get modules list. We need it mainly to find 
__mod_list = []
def lsModules():
    if (len(__mod_list) > 1):
	return __mod_list
    
    try:
	# On older kernels, we have module_list
	kernel_module = sym2addr("kernel_module")
	if (kernel_module):
	    module_list = readSymbol("module_list")    
	    for m in readStructNext(module_list, "next", inchead = False):
		if (long(m) != kernel_module):
		    __mod_list.append(m.name)
	else:
	    # On new kernels, we have a listhead
	    lh = ListHead(sym2addr("modules"), "struct module")
	    for m in lh.list:
	       __mod_list.append(m.name)
    except:
	# If anything went wrong, return a partial list	
	pass
    return __mod_list


# Execute 'sys' command and put its split output into a dictionary
# Some names contain space and should be accessed using a dict method, e.g.
# sys_info["LOAD AVERAGE"]
def _doSys():
    """Execute 'sys' commands inside crash and return the parsed results"""
    for il in exec_crash_command("sys").splitlines():
        spl = il.split(':', 1)
        if (len(spl) == 2):
            sys_info.__setattr__(spl[0].strip(), spl[1].strip())

    	
# -----------  initializations ----------------

# What happens if we use 'epython' command several times without 
# leaving 'crash'? The first time import statements really do imports running
# some code, next time the import statement just sees that the code is already
# imported and it does not execute statements inside modules. So the code
# here is executed only the first time we import API (this might change if we
# purge modules, e.g. for debugging).
# 
# But the function enter_python() is called every time - the first time when
# we do import, next times as it is registered as a hook


pointersize = getSizeOf("void *")
sys_info.pointersize = wrapcrash.pointersize = pointersize
sys_info.pointermask = 2**(pointersize*8)-1
_doSys()

# Check whether this is a live dump
if (sys_info.DUMPFILE.find("/dev/") == 0):
    sys_info.livedump = gen.livedump = True
else:
    sys_info.livedump = gen.livedump = False


# Check the kernel version and set HZ
kernel = re.search(r'^(\d+\.\d+\.\d+)', sys_info.RELEASE).group(1)
sys_info.kernel = gen.KernelRev(kernel)
sys_info.HZ = HZ

# Convert CPUS to integer
sys_info.CPUS = int(sys_info.CPUS)

# Extract hardware from MACHINE
sys_info.machine = wrapcrash.machine = sys_info["MACHINE"].split()[0]

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

if (sys_info.DebugDir == ""):
    sys_info.DebugDir ="."
if (not  sys_info.livedump):
    # Append the directory of where the dump is located
    debuginfo.append(sys_info.DebugDir)
else:
    # Append the current directory (useful for development)
    debuginfo.insert(0, '.')
# Finally, there's always a chance that this kernel is compiled
# with debuginfo
debuginfo.append("/lib/modules/" + kname)
sys_info.debuginfo = debuginfo

if (pointersize == 4):
    readLong = readS32
    readULong = readU32
    readInt = readS32
    readUInt = readU32
    INT_MASK = LONG_MASK = 0xffffffff
    INT_SIZE = 4
    PTR_SIZE = LONG_SIZE = 4
elif (pointersize == 8):
    readInt = readS32
    readUInt = readU32
    readLong = readS64
    readULong = readU64
    INT_MASK = 0xffffffff
    LONG_MASK = 0xffffffffffffffff
    INT_SIZE = 4
    PTR_SIZE = LONG_SIZE = 8

INT_MAX = ~0L&(INT_MASK)>>1
LONG_MAX = ~0L&(LONG_MASK)>>1
HZ = sys_info.HZ

enter_epython()

# Hooks used by C-extension
sys.enterepython = enter_epython
sys.exitepython = exit_epython

if (API_options.debug):
    print "-------PyKdump %s-------------" % pykdump.__version__
#atexit.register(cleanup)
