# Find different python locations that we need to use in Makefile
from __future__ import print_function

import sys
import string
import getopt
import os.path, glob
from distutils.core import setup, Extension
from distutils.sysconfig import *

# Files to write

cmk="crash.mk"
slmk="slocal.mk"

debug = False

opts, args = getopt.getopt(sys.argv[1:],
                           'd',
                           ['crashdir=']
                           )
crashdir = None
fd = sys.stdout

# pyconf.py is in Extension directory, Top is one level up
pyconf_dir = os.path.dirname(sys.argv[0])
if (not pyconf_dir):
    pyconf_dir = '.'
#print("pyconf_dir=", pyconf_dir)
topdir = os.path.abspath(pyconf_dir+"/..") # Top dir of PyKdump


# Process the options that set values, other will be processed later
for o, a in opts:
    if (o == '-d'):
        debug = True
    elif (o == '--crashdir'):
        crashdir = os.path.realpath(a)


# ---------- Crash mk part -------------------------------------------------

# To make it easier to building  both x86 and x86_64 on a x86_64 host,
# we use a special convention - if  crash directory contains files crash32
# and crash64, this means that we can use that directory both for 

# Check whether crash sourcetree is installed and compiled at this location
try:
    re_target = re.compile(r'^TARGET=(\w+)$')
    re_gdb = re.compile(r'^GDB=gdb-(\d).\d.*$')
    re_crashvers = re.compile(r'^VERSION=([\.\d]+)\s*$')
    target = None
    gdb_major = None
    crash_vers = None
    for l in open(os.path.join(crashdir, "Makefile"), "r"):
        m = re_target.match(l)
        if (m):
            target = m.group(1)
        m = re_gdb.match(l)
        if (m):
            gdb_major = int(m.group(1))
        m = re_crashvers.match(l)
        if (m):
            crash_vers = m.group(1)
                
except:
    print("Cannot find Makefile in the specified CRASHDIR", crashdir)
    sys.exit(0)

if (not target):
    print("Bad Makefile in ", crashdir)

print("target=%s" % target)

if (not debug):
    fd = open(cmk, "w+")
    
ol = []
ol.append("# Configuration options for 'crash' tree")
ol.append("CRASHDIR := %s" % crashdir)
try:
    gdbdir = glob.glob("%s/gdb*/gdb" % crashdir)[0]
except:
    print("Cannot find GDB directory in crash sourcetree")
    sys.exit(2)
ol.append("GDBDIR := %s" % gdbdir)
ol.append("GDBINCL =  -I$(GDBDIR)  -I$(GDBDIR)/config  -I$(GDBDIR)/../bfd \\")
ol.append("  -I$(GDBDIR)/../include -I$(GDBDIR)/../intl")
# We need to use different includes and prototypes for GDB6 and GDB7
if (gdb_major == 7):
    ol.append("EXTRA := -DGDB7 -I$(GDBDIR)/common")
ol.append("TARGET := %s" % target)
ol.append("CRASHVERS := %s" % crash_vers)
fd.write("\n".join(ol))
fd.write("\n")

if (not debug):
    fd.close()

#
# ---------- Python mk part------------------------------------------------
# 

# Python version (major), e.g. 2.5 for 2.5.2
pv = sys.version_info
pyvers = "%d.%d" % (pv[0], pv[1])
pymajor = pv[0]

# The directory where python executable is located, i.e. where we have built it
# It can be different from Python sourcetree directory!

python_exe = sys.executable
python_buildir =  os.path.dirname(python_exe)
#print ("python_buildir=", python_buildir)
python_srcdir = get_config_var('srcdir')      # This is relative to builddir
python_srcdir = os.path.abspath(os.path.join(python_buildir, python_srcdir))
#print ("python_srcdir=", python_srcdir)

# We need the directory where pyconfig.h is located
inc1 = get_python_inc()
#print ("inc1", inc1)

# Where pyconfig.h is located (the build directory)
inc2 = os.path.dirname(get_config_h_filename())
#print ("inc2", inc2)

includes = "-I%s -I%s" % (inc1, inc2)
#print("includes=", includes)

import pprint
#pprint.pprint(get_config_vars())

extralibs = get_config_var('LIBS')
syslibs = get_config_var('SYSLIBS')
cc = get_config_var('CC')
cflags = get_config_var('CFLAGS')
ldflags = get_config_var('LINKFORSHARED')


# Python archive library, e.g. libpython2.7.a
pyliba =  os.path.join(python_buildir, get_config_var('LIBRARY'))

# Python Standard Library sources - we do not compile/install them
stdlib = os.path.join(python_srcdir, 'Lib')
compileall = os.path.join(stdlib, "compileall.py")

linkflags = " ".join((
    ' -nostartfiles -shared',
    ldflags
    ))

libs = " ".join((
    pyliba,
    extralibs,
    syslibs
    ))

ol = []
if (not debug):
    fd = open(slmk, "w+")

ol.append("# Configuration options for Python")
ol.append("PYTHONSRCDIR := %s" % python_srcdir)
ol.append("PYTHON := %s" % python_exe)

# Common stuff both for local and slocal
ol.append("PYINCLUDE := %s" % includes)
ol.append("CC := %s" % cc)
ol.append("CFLAGS := %s" % cflags)
ol.append("LIBS := %s" % libs)
ol.append("LINKFLAGS := %s" % linkflags)
ol.append("TOPDIR := %s" % topdir)
ol.append("PYMAJOR := %s" % pymajor)

ol.append("STDLIBP :=  %s" % stdlib)
if (pymajor == 3):
    ol.append("COMPALL :=  %s -b" % compileall)
else:
    ol.append("COMPALL :=  %s" % compileall)
ol.append("MINPYLIB_FILES := minpylib-%s.lst" % pyvers)

fd.write("\n".join(ol))
fd.write("\n")
if (not debug):
    fd.close()
