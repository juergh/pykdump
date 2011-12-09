#!/usr/bin/env python
# -*- coding: utf-8 -*-


# Write README file to be added to ZIP-archive

# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function

import sys
import os
import re

sys.path.append("../progs")
sys.path.append("../../progs")

# We expect that 2 args are passed to thos program:
# arg1 - crash version
# arg2 - C-module name (to get embedded version)

def c_vers(fn):
    fd = open(fn, "r")
    l = ""

    while(True):
        nl = fd.read(256)
        if (len(nl) == 0):
            # Cannot find ID
            c_id = None
            break
        m = re.search(r"(@\(#\)pycrash [0-9.]+)\0", l+nl)
        if (m):
            c_id = m.group(1)[12:]
            break
        l = nl

    if (not c_id):
        print ("Cannot locate the version of C-module")
        sys.exit(0)
    else:
        return c_id

print("   === Information About This Archive === ")
print(" This build is based on crash-%s" % sys.argv[1])
print(" C-bindings version %s" % c_vers(sys.argv[2]))

print("\n   --- Programs Included ------")

__commands = ["xportshow", "crashinfo", "taskinfo"]

for c in __commands:
    try:
        exec "import " + c
    except ImportError as e:
        print (e)
