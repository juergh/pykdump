#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Find different python locations that we need to use in Makefile
from __future__ import print_function

import sys
import string
import getopt
import os.path, glob
from distutils.core import setup, Extension
from distutils.sysconfig import *

debug = False

opts, args = getopt.getopt(sys.argv[1:],
                           'ds',
                           ['writefiles',
                            'crashdir=', "pythondir=",
                            'cc', 'cflags', 'includes',
                            'linkflags', 'libs', 'srcdir', 'stdlib',
                            'compileall', 'pyvers', 'subdirbuild']
                           )

for o, a in opts:
    if (o == '-d'):
        debug = True

# Python version (major), e.g. 2.5 for 2.5.2
pv = sys.version_info
pyvers = "%d.%d" % (pv[0], pv[1])
pymajor = pv[0]
pythondir = os.path.realpath(a)

import pprint
#pprint.pprint(get_config_vars())

# System libraries we need to link with
testprog = get_config_var('TESTPROG')
extralibs = get_config_var('LIBS')
syslibs = get_config_var('SYSLIBS')
cc = get_config_var('CC')
cflags = get_config_var('CFLAGS')
ldflags = get_config_var('LINKFORSHARED')
# This is where local (not system-wide!) Python library is installed
#   Depending on Python version/distribution, this can be one of the following:
# 'LIBP', 'LIBDEST', 'DESTLIB'
stdlib = get_config_var('LIBP')
if (not stdlib):
    stdlib = get_config_var('LIBDEST')
stdlib = os.path.join(pythondir, 'Lib')
compileall = os.path.join(stdlib, "compileall.py")
# Strip2 levels
#for i in range(2):
#    stdlib = os.path.split(stdlib)[0]

#for k,v in get_config_vars().items():
#   print k, v

# If compiler is not installed (i.e. compiled but no 'make install'),
# we have config_h equal to './pyconfig.h'

config_h = get_config_h_filename()
if (debug):
    print(" *** pyconfig.h at %s ***" % config_h)

srcdir = ''

# We did not run 'make install' and are using the sourcetree
sourcetree = os.path.dirname(get_makefile_filename())
if (debug):
    print(" *** Source-tree Python at %s ***" % sourcetree)

# We need the directory where pyconfig.h is located
inc1 = get_python_inc()
inc2 = os.path.dirname(config_h)
srcdir = os.path.dirname(inc1)
includes = "-I%s -I%s" % (inc1, inc2)

# At this moment this works with static build only
pylib =  os.path.join(sourcetree, get_config_var('LIBRARY'))


linkflags = " ".join((
    ' -nostartfiles -shared',
    ldflags
    ))

libs = " ".join((
    pylib,
    extralibs,
    syslibs
    ))


if (debug):
    print("\t INCLUDES=%s" % includes)
    print("\t PYLIBRARY=%s" % pylib)
    print("\t EXTRALIBS=%s" % extralibs)
    print("\t CC=%s" % cc)
    print("\t CFLAGS=%s" % cflags)
    print("\t LDFLAGS=%s" % ldflags)
    print("\t --------------------")
    print("\t LINLKFLAGS=%s" % linkflags)
    print("\t LIBS=%s" % libs)


    print("\n")
    print(get_python_inc())
    print(get_python_lib())

    print(get_config_var('LINKFORSHARED'))
    print(get_config_var('LIBPL'))
    print(get_config_var('INCLUDEPY'))
    print(get_config_var('LIBRARY'))
    print(get_config_var('LIBS'))

crashdir = None
writefiles = False

topdir = os.path.abspath(os.getcwd()+"/..") # Top dir of PyKdump


for o, a in opts:
    if (o == '--cc'):
        print(cc)
    elif (o == '--cflags'):
        print(cflags)
    elif (o == '--includes'):
        print(includes)
    elif (o == '--linkflags'):
        print(linkflags)
    elif (o == '--libs'):
        print(libs)      
    elif (o == '--srcdir'):
        print(srcdir)     
    elif (o == '--stdlib'):
        print(stdlib)     
    elif (o == '--compileall'):
        print(compileall)
    elif (o == '--pyvers'):
        print(pyvers)
    elif (o == '--crashdir'):
        crashdir = os.path.realpath(a)
    elif (o == '--pythondir'):
        pythondir = os.path.realpath(a)
    elif (o == '--writefiles'):
        writefiles = True
    elif (o == '--subdirbuild'):
        topdir = os.path.abspath(os.getcwd()+"/../..")
        

if (not writefiles):
    sys.exit(0)


    
print("\n *** Creating configuration files ***")

cmk="crash.mk"
lmk="local.mk"
slmk="slocal.mk"

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

fd.close()
            

# ---------- Python mk parts------------------------------------------------
# 
ol = []
fd = open(slmk, "w+")
ol.append("# Configuration options for static-build")
ol.append("PYTHONDIR := %s" % pythondir)
ol.append("PYTHON := env LD_LIBRARY_PATH=%s %s/python" %\
          (pythondir, pythondir))

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
fd.close()
              
