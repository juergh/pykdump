#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2017 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------

# Python3.2 introduced __pycache__ stuff (PEP 3147) but we do not want to put
# all this into our ZIP. This script copies/renames files to follow
# the old directory structure


import sys
import string
import os, os.path
import py_compile

# Usage: makestdlib.py stdlibdir filelist


if (len(sys.argv) < 4):
    print ("Usage: makestdlib.py STDLIBDIR DSTDIR FILELIST")
    sys.exit(1)


stdlibdir = sys.argv[1]
dstdir = sys.argv[2]
flist = sys.argv[3]

# Create destination directory
try:
    os.mkdir(dstdir)
except OSError:
    pass

for l in open(flist, "r"):
    l = l.strip()
    # Ignore empty and comment lines
    if (not l or l[0] == '#'):
        continue
    fsrc = os.path.join(stdlibdir, l)
    fdst = os.path.join(dstdir, l+'c')
    #print("<%s> -> <%s>" % (fsrc, fdst))
    # Create output directory if needed
    dstsubdir = os.path.dirname(fdst)
    if (not os.path.exists(dstsubdir)):
        print("makedirs %s" % dstsubdir)
        os.makedirs(dstsubdir)
    py_compile.compile(fsrc, fdst)

# Add an empty site.py
site_py = "site.py"
open(site_py, 'a').close()
py_compile.compile(site_py, os.path.join(dstdir, site_py+'c'))
os.unlink(site_py)
