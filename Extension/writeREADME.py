#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------


# Write README file to be added to ZIP-archive

# To facilitate migration to Python-3, we start from using
# future statements/builtins
from __future__ import print_function

import sys
import os
import re
import time
import platform

sys.path.append("../progs")
sys.path.append("../../progs")

# We expect that 2 args are passed to this program:
# arg1 - crash version
# arg2 - C-module name (to get embedded version)

def c_vers(fn):
    fd = open(fn, "rb")
    l = b""

    while(True):
        nl = fd.read(256)
        if (len(nl) == 0):
            # Cannot find ID
            c_id = None
            break
        m = re.search(b"(@\(#\)pycrash [0-9.]+)\0", l+nl)
        if (m):
            c_id = m.group(1)[12:]
            break
        l = nl

    if (not c_id):
        print ("Cannot locate the version of C-module")
        sys.exit(0)
    else:
        if (sys.version_info[0] == 3):
            c_id =  str(c_id, 'latin1')
        return c_id

# Get GLIBC version from 'ldd --version' output
def get_glibc():
    fd = os.popen("ldd --version", "r")
    l = fd.readline()
    glib = l.split()[-1]
    fd.read()                           # To prevent EPIPE
    fd.close()
    return glib

print("__info = '''")
print(" === Information About This Archive === ")
print("    Created on", time.asctime())
print("    GLIBC:", get_glibc())
pi = sys.version_info
print("    Python: %d.%d.%d" % (pi[0], pi[1], pi[2]))
print("    The build is based on crash-%s" % sys.argv[1])
print("    C-bindings version %s" % c_vers(sys.argv[2]))

# We do not expect this to fail as its __init__.py does not use C-api
from pykdump import __version__
print("\n   --- PyKdump API Version: {} ----".format(__version__))


print("\n   --- Programs Included ------")

__commands = ["xportshow", "crashinfo", "taskinfo", "nfsshow", "hanginfo",
	"fregs"]

for c in __commands:
    try:
        exec ("import " + c)
    except ImportError as e:
        print ("  ", e)
    except SyntaxError as e:
        print("    !!!Syntax errors in {}".format(c))

print("'''")
print("print(__info)")
