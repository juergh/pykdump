# module LinuxDump.fs
#
# Time-stamp: <10/11/25 16:32:45 alexs>
#
# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.
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

# Vversion number
__version__ = '0.1'

# Copyright notice string
__copyright__ = """\
Copyright (c) 2006,2007 Alex Sidorenko; mailto:asid@hp.com
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.
"""

from pykdump.API import *

import string

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
            print "Traversing mount point"
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
    return readmem(dentry.d_name.name, namelen)
    

def IS_ROOT(x):
        return (x == x.Deref.d_parent)

        
        
