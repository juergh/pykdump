# module LinuxDump.fs
#
# Time-stamp: <13/07/29 15:57:01 alexs>
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2013 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------
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

from __future__ import print_function

# Vversion number
__version__ = '0.2'


from pykdump.API import *

import string
import os.path

#__all__ = ["proto", "routing"]


# Generic FS stuff, used by all FS
#----------------------------------------------------------------------
@memoize_cond(CU_LIVE)
def getMount():
    rc = exec_crash_command("mount")
    mounts = rc.splitlines()[1:]
    mlist = []
    for l in mounts:
        vfsmount, superblk, fstype, devname, mnt = l.split()
        vfsmount = long(vfsmount, 16)
        superblk = long(superblk, 16)
        mnt = os.path.normpath(mnt)
        mlist.append((vfsmount, superblk, fstype, devname, mnt))
    return mlist

# Search for a superblock addr in mounts and if found, return the first vfsmnt
@memoize_cond(CU_LIVE)
def sb2Vfsmnt(sbaddr):
    for mlist in getMount():
        if (long(mlist[1]) == long(sbaddr)):
            return mlist[0]
    return 0

# We could probably interface C-version from 'crash'. But it is useful
# to have pure Python version for debugging purposes

# We pass tPtr objects to this function

def XXXget_pathname(dentry, vfsmnt, root, rootmnt):

    out = []
    while(True):
        if (dentry == root and vfsmnt == rootmnt):
            break

        if (dentry == vfsmnt.Deref.mnt_root or IS_ROOT(dentry)):
            print ("Traversing mount point")
            # Global root?
            if (vfsmnt.Deref.mnt_parent == vfsmnt):
                # Yes, global root
                return "Global root"
            dentry = vfsmnt.Deref.mnt_mountpoint
            vfsmnt = vfsmnt.Deref.mnt_parent
            continue
        parent = dentry.Deref.d_parent
        namelen = dentry.Deref.d_name.len
        name =  readmem(dentry.Deref.d_name.name, namelen)
        out.insert(0, name)
        dentry = parent
    return '/' + string.join(out, '/')

def get_dentry_name(dentry):
    namelen = dentry.d_name.len
    if (namelen):
        # PyKdump does not convert it to SmartString automatically
        # as it is unsigned, 'const unsigned char *name;'
        addr = int(dentry.d_name.name)
        return  SmartString(readmem(addr, namelen), addr, None)
        #return readmem(dentry.d_name.name, namelen)
    else:
        return ""
    

def IS_ROOT(x):
        return (x == x.Deref.d_parent)

__sb = AttrSetter("struct super_block")
__sb.Frozen = ["s_frozen", "s_writers.frozen"]

def sb_frozen(sb):
    return sb.Frozen  
        
