#!/usr/bin/env python

# Find different python locations that we need to use in Makefile

import sys
import string
import getopt
import os.path, glob
from distutils.core import setup, Extension
from distutils.sysconfig import *

debug = False
staticbuild = False
sourcetree = False

opts, args = getopt.getopt(sys.argv[1:],
                           'ds',
                           ['sourcetree', 'writefiles',
                            'crashdir=', "pythondir=",
			    'static', 'cc', 'cflags', 'includes',
                            'linkflags', 'libs', 'srcdir', 'stdlib',
                            'compileall', 'pyvers']
                           )

for o, a in opts:
    if (o == '-d'):
        debug = True
    elif (o == '--static'):
        staticbuild = True
    elif (o == '-s'):
        sourcetree = True

# Python version (major), e.g. 2.5 for 2.5.2
pv = sys.version_info
pyvers = "%d.%d" % (pv[0], pv[1])

# System libraries we need to link with
testprog = get_config_var('TESTPROG')
extralibs = get_config_var('LIBS')
syslibs = get_config_var('SYSLIBS')
cc = get_config_var('CC')
cflags = get_config_var('CFLAGSFORSHARED')
ldflags = get_config_var('LINKFORSHARED')
stdlib = get_config_var('LIBP')
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
    print " *** pyconfig.h at %s ***" % config_h

srcdir = ''

if (sourcetree):
    # We did not run 'make install' and are using the sourcetree
    sourcetree = os.path.dirname(get_makefile_filename())
    if (debug):
        print " *** Source-tree Python at %s ***" % sourcetree

    inc1 = get_python_inc()
    srcdir = inc2 = os.path.dirname(inc1)
    includes = "-I%s -I%s" % (inc1, inc2)

    # At this moment this works with static build only
    pylib =  os.path.join(sourcetree, get_config_var('LIBRARY'))
else:
    # A properly-installed Python
    if (debug):
        print " *** A Properly Installed Python ***"
    includes = "-I%s" % get_python_inc()

    if (staticbuild):
        # A library for static build
        pylib = os.path.join(get_config_var('LIBPL'),
                             get_config_var('LIBRARY'))
    else:
        # A library for dynamic build
        pylib =  get_config_var('BLDLIBRARY')


linkflags = string.join((
    ' -nostartfiles -shared',
    ldflags
    ))

libs = string.join((
    extralibs,
    pylib,
    syslibs
    ))


if (debug):
    print "\t INCLUDES=%s" % includes
    print "\t PYLIBRARY=%s" % pylib
    print "\t EXTRALIBS=%s" % extralibs
    print "\t CC=%s" % cc
    print "\t CFLAGS=%s" % cflags
    print "\t LDFLAGS=%s" % ldflags
    print "\t --------------------"
    print "\t LINLKFLAGS=%s" % linkflags
    print "\t LIBS=%s" % libs


    print "\n"
    print get_python_inc()
    print get_python_lib()

    print get_config_var('LINKFORSHARED')
    print get_config_var('LIBPL')
    print get_config_var('INCLUDEPY')
    print get_config_var('LIBRARY')
    print get_config_var('LIBS')

crashdir = None
writefiles = False

for o, a in opts:
    if (o == '--cc'):
        print cc
    elif (o == '--cflags'):
        print cflags
    elif (o == '--includes'):
        print includes
    elif (o == '--linkflags'):
        print linkflags
    elif (o == '--libs'):
        print libs      
    elif (o == '--srcdir'):
        print srcdir     
    elif (o == '--stdlib'):
        print stdlib     
    elif (o == '--compileall'):
        print compileall
    elif (o == '--pyvers'):
        print pyvers
    elif (o == '--crashdir'):
        crashdir = a
    elif (o == '--pythondir'):
        pythondir = a
    elif (o == '--writefiles'):
        writefiles = True
        

if (not writefiles):
    sys.exit(0)


# Here we start writing the configuration files
if (sourcetree):
    btype = "static"
else:
    btype = "dynamic"
    
print "\n *** Creating configuration files for a %s build ***" %btype

cmk="crash.mk"
lmk="local.mk"
slmk="slocal.mk"

# ---------- Crash mk part -------------------------------------------------

# Check whether crash sourcetree is installed and compiled at this location
try:
    re_target = re.compile(r'^TARGET=(\w+)$')
    re_gdb = re.compile(r'^GDB=gdb-(\d).\d$')
    target = None
    gdb_major = None
    for l in open(os.path.join(crashdir, "Makefile"), "r"):
        m = re_target.match(l)
        if (m):
            target = m.group(1)
        m = re_gdb.match(l)
        if (m):
            gdb_major = int(m.group(1))
            
except:
    print "Cannot find Makefile in the specified CRASHDIR", crashdir
    sys.exit(0)

if (not target):
    print "Bad Makefile in ", crashdir

print "target=%s" % target

fd = open(cmk, "w+")
ol = []
ol.append("# Configuration options for 'crash' tree")
ol.append("CRASHDIR := %s" % crashdir)
try:
    gdbdir = glob.glob("%s/gdb*/gdb" % crashdir)[0]
except:
    print "Cannot find GDB directory in crash sourcetree"
    sys.exit(2)
ol.append("GDBDIR := %s" % gdbdir)
ol.append("GDBINCL =  -I$(GDBDIR)  -I$(GDBDIR)/config  -I$(GDBDIR)/../bfd \\")
ol.append("  -I$(GDBDIR)/../include -I$(GDBDIR)/../intl")
# We need to use different includes and prototypes for GDB6 and GDB7
if (gdb_major == 7):
    ol.append("EXTRA := -DGDB7 -I$(GDBDIR)/common")
ol.append("TARGET := %s" % target)
fd.write(string.join(ol, "\n"))
fd.write("\n")

fd.close()
            

# ---------- Python mk parts------------------------------------------------
# 
ol = []
if (sourcetree):
    fd = open(slmk, "w+")
    ol.append("# Configuration options for static-build")
    ol.append("PYTHONDIR := %s" % pythondir)
    ol.append("PYTHON := env LD_LIBRARY_PATH=%s %s/python" %\
              (pythondir, pythondir))
else:
    fd = open(lmk, "w+")
    ol.append("# Configuration options for local build")
    ol.append("PYTHON := %s"% os.environ["PYTHON"])

# Common stuff both for local and slocal
ol.append("PYINCLUDE := %s" % includes)
ol.append("CC := %s" % cc)
ol.append("CFLAGS := %s" % cflags)
ol.append("LIBS := %s" % libs)
ol.append("LINKFLAGS := %s" % linkflags)

# Extras for static build
if (sourcetree):
    ol.append("STDLIBP :=  %s" % stdlib)
    ol.append("COMPALL :=  %s" % compileall)
    ol.append("MINPYLIB_FILES := minpylib-%s.lst" % pyvers)

fd.write(string.join(ol, "\n"))
fd.write("\n")
fd.close()
              
