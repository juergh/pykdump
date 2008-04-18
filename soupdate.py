#!/usr/bin/env python

# Update mpykdump.so files without recompilation, just uzing ZIP

# Time-stamp: <08/04/18 13:47:57 alexs>

# Copyright (C) 2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2008 Hewlett-Packard Co., All rights reserved.

# Update mpykdump.so

import re
import os, sys

import subprocess

# Directories where we should search for files and extensions 
MYLIBS = {
    "progs" : ".py",
    "pykdump" : ".pyc",
    "LinuxDump" : ".pyc"
    }

# 1495771

import zipfile
import os
import tempfile

from pykdump import *

if (len(sys.argv) < 2):
    print "Usage: %s <mpykdumpfile>" % sys.argv[0]
    sys.exit(1)
    
inzip = sys.argv[1]

try:
    zf = zipfile.ZipFile(inzip, 'r')
except:
    print inzip, "is not a zipfile, or it is not readable"
    sys.exit(2)

# Obtain the versions of C-module (embedded in ZIP) and pykdump
import pykdump

fd = open(inzip, "r")
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
    print "Cannot locate the version of C-module, assuming 0.6"
    c_id = "0.6"

require_cmod_version(minimal_cmod_version, c_id)

# To be able to update ZIP-file, we need the directory to be writable

dirpath = os.path.dirname(inzip)
try:
    tmp = tempfile.TemporaryFile('w+b', -1, 'pkd', 'pkd', dirpath)
except OSError:
    print "To update ZIP-files the directory <%s> should be writable" %dirpath
    sys.exit(1)


ilist = zf.infolist()

# A list of files present in ZIP that we would like to update
zip_list =  []
for n in zf.namelist():
    dirpart = n.split("/")[0]
    if (not dirpart in MYLIBS):
        continue
    zip_list.append(n)

zf.close()

# Get a list of all PYC-files in the directories of interest, check their
# permissions and whether they are already present in ZIP-file
def extNames(topdir, exts):
    """Find .pyc files"""
    if (topdir == None):
        return
    if (type(exts) == type("")):
        exts = (exts,)
    for d, dummy, files in os.walk(topdir):
        for f in files:
            ext = os.path.splitext(f)[1]
            for e in exts:
                if (ext == e):
                    yield os.path.join(d, f)
    return

localfs_files = []
for l,e in MYLIBS.items():
    for f in extNames(l, e):
        localfs_files.append(f)

# Check whether all files present in zip have counterparts in local FS.
# If not, issue a warning

for f in zip_list:
    if (not f in localfs_files and f[-1] != '/'):
        print "WARNING: %s is present in zip but not local FS" % f
        
# For .pyc-files that are not present in zipfile, we ask whether they
# should be added. For .py-files (normally only those from progs/) we never
# add anything. The reasoning for that is that progs/ often has small testing
# programs that are not even in the repository

update_list = []
for f in localfs_files:
    ext = os.path.splitext(f)[1]
    if (not f in zip_list):
        if (ext == '.pyc'):
            # Ask whether this should be added
            print f, 'is not present in ZIP, should we add it [y]/n? ',
            c = sys.stdin.readline()[0]
            print ""
            if (c == 'n'):
                continue
        else:
            continue
    #print f
    update_list.append(f)


#sys.exit(0)
cmd = "zip -q  %s -@" % inzip
#zd = os.popen(cmd, "w")
pobj = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE)
zd = pobj.stdin
for n in update_list:
    zd.write(n + "\n")
zd.close()

errcode = pobj.wait()
if (errcode != 0):
    print "There was an error in processing, errcode=%d" % errcode
    sys.exit(1)

