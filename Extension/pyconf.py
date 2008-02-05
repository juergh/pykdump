#!/usr/bin/env python

# Find different python locations that we need to use in Makefile

import sys
import string
import getopt
import os.path
from distutils.core import setup, Extension
from distutils.sysconfig import *

debug = False
staticbuild = False
sourcetree = False

opts, args = getopt.getopt(sys.argv[1:],
                           'ds',
                           ['sourcetree',
			    'static', 'cc', 'cflags', 'includes',
                            'linkflags', 'libs', 'srcdir', 'stdlib',
                            'compileall']
                           )

for o, a in opts:
    if (o == '-d'):
        debug = True
    elif (o == '--static'):
        staticbuild = True
    elif (o == '-s'):
	sourcetree = True

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
