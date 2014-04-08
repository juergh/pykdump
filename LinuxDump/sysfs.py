#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Subroutines to query/traverse sysfs

# --------------------------------------------------------------------
# (C) Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------

# To facilitate migration to Python-3, we use future statements/builtins
from __future__ import print_function

from pykdump.API import *

import sys

from LinuxDump.fs import *
from LinuxDump.trees import *


# Subroutines as used on 3.11 kernels

__SYSFS_c = '''
#define SYSFS_TYPE_MASK                 0x00ff
#define SYSFS_DIR                       0x0001
#define SYSFS_KOBJ_ATTR                 0x0002
#define SYSFS_KOBJ_BIN_ATTR             0x0004
#define SYSFS_KOBJ_LINK                 0x0008
'''

_SYSFS_TYPES_311 = CDefine(__SYSFS_c)

__SYSFS_c = '''    
#define SYSFS_ROOT              0x0001
#define SYSFS_DIR               0x0002
#define SYSFS_KOBJ_ATTR         0x0004
#define SYSFS_KOBJ_BIN_ATTR     0x0008
#define SYSFS_KOBJ_LINK         0x0020
'''
_SYSFS_TYPES_2618 = CDefine(__SYSFS_c)

# Decode sysfs dirent. Return (name, type) where types are strings like used by 'ls':


def decode_sysfs_dirent_311(sd):
    stype = (sd.s_flags & _SYSFS_TYPES.SYSFS_TYPE_MASK)
    name = sd.s_name
    try:
        attr = __SYSFS2attr[stype]
    except KeyError:
        attr = '?{}'.format(stype)
    return (name, attr)

def decode_sysfs_dirent_2632(sd):
    s_type = sd.s_type
    s_element = sd.s_element
    name = '?'
    if (s_type == _SYSFS_TYPES.SYSFS_ROOT):
        name = '.'
    elif (s_type == _SYSFS_TYPES.SYSFS_DIR):
        name = get_dentry_name(sd.s_dentry)
    elif (s_type == _SYSFS_TYPES.SYSFS_KOBJ_ATTR):
        name = readSU("struct attribute", s_element).name
    elif (s_type == _SYSFS_TYPES.SYSFS_KOBJ_BIN_ATTR):
        binattr = readSU("struct bin_attribute", s_element)
        name =  binattr.attr.name
    elif (s_type == _SYSFS_TYPES.SYSFS_KOBJ_LINK):
        symlink = readSU("struct sysfs_symlink", s_element)
        name = symlink.link_name
    else:
        name = '?'
    try:
        attr = __SYSFS2attr[s_type]
    except KeyError:
        attr = '?{}'.format(s_type)
    return (name, attr)

# Iterate over all entries in sysfs_dirent

def for_all_dirents_311(sd):
    root = sd.s_dir.children
    return for_all_rbtree(root, "struct sysfs_dirent", "s_rb")

# Parent directory
def sysfs_parent_311(sd):
    return sd.s_parent

def sysfs_parent_2618(sd):
    if (not sd.s_dentry):
        return None
    parent_dentry = sd.s_dentry.d_parent
    sdaddr = parent_dentry.d_fsdata
    return readSU("struct sysfs_dirent",  sdaddr)
    


def for_all_dirents_2632(sd):
    root = sd.s_dir.inode_tree
    return for_all_rbtree(root, "struct sysfs_dirent", "inode_node")

def for_all_dirents_3080(sd):
    s_children = sd.s_dir.children
    return readStructNext(s_children, "s_sibling")


def for_all_dirents_2618(sd):
    s_children = ListHead(sd.s_children, "struct sysfs_dirent")
    for sd in s_children.s_sibling:
        yield sd




# ----------------------Generic subroutines, the same for all kernels---
# Map SYSFS_XXX to strings describing dirent type
# '/' - dir, '@' - symlink, '.' - normal file, '?' - unknown/bad



def print_sysfs_dirent(sd):
    for e in for_all_dirents(sd):
        name, etype = decode_sysfs_dirent(e)
        print(e, name, etype)

# Decode the full path going up to parent. To prevent infinite loops,
# limit to 100
def sysfs_fullpath(sd):
    p = sd
    out = []
    count = 100
    while(p and count):
        name, etype = decode_sysfs_dirent(p)
        out.append(name)
        p = sysfs_parent(p)
        count -= 1
    out.reverse()
    if (count == 0):
        return "Bad sysfs_dirent"
    return "/".join(out)

# Does this dirent describe a block device? Returns name or None
def blockdev_name(sd):
    bname = ""
    try:
        all_dirents = list(for_all_dirents(sd))
    except crash.error:
        return "Bad sysfs_dirent"
    for e in all_dirents:
        name, etype = decode_sysfs_dirent(e)
        nsplit = name.split(':')        # For RHEL5
        if (name == 'block' and etype == '/'):
            # There should be one entry only
            out = list(for_all_dirents(e))
            if (len(out) == 1):
                (bname, btype) = decode_sysfs_dirent(out[0])
                return bname
        elif (nsplit[0] == 'block' and etype == '@'):
            return nsplit[1]
    return bname
                
                       
        
# ======================================================================
        
# Decide what subroutines to use for our kernel
__sn = "struct sysfs_dirent"


# For debugging only - remove after
def gendev2sd(gendev):
    kobj = gendev.kobj
    if (not kobj.ktype):
        return None
    return kobj.sd

def gendev2sd_old(gendev):
    dentry = gendev.kobj.dentry
    return readSU("struct sysfs_dirent", dentry.d_fsdata)

if (member_size(__sn, "s_rb") != -1):
    # 3.11
    _SYSFS_TYPES = _SYSFS_TYPES_311
    decode_sysfs_dirent = decode_sysfs_dirent_311
    for_all_dirents = for_all_dirents_311
    sysfs_parent = sysfs_parent_311
elif (member_size(__sn, "inode_node") != -1):
    # 2.6.32
    _SYSFS_TYPES = _SYSFS_TYPES_311
    decode_sysfs_dirent = decode_sysfs_dirent_311
    for_all_dirents = for_all_dirents_2632
    sysfs_parent = sysfs_parent_311
elif (member_size(__sn, "s_children") != -1):
    # 2.6.18
    _SYSFS_TYPES = _SYSFS_TYPES_2618
    decode_sysfs_dirent = decode_sysfs_dirent_2632
    for_all_dirents = for_all_dirents_2618
    sysfs_parent = sysfs_parent_2618
    gendev2sd = gendev2sd_old
elif (member_size(__sn, "s_sibling") != -1):
    # SLES11 with 3.0.80
    _SYSFS_TYPES = _SYSFS_TYPES_311
    decode_sysfs_dirent = decode_sysfs_dirent_311
    for_all_dirents = for_all_dirents_3080
    sysfs_parent = sysfs_parent_311
    #gendev2sd = gendevsd_old
    
    


__SYSFS2attr = {
    _SYSFS_TYPES.SYSFS_DIR : '/',
    _SYSFS_TYPES.SYSFS_KOBJ_ATTR : '.',
    _SYSFS_TYPES.SYSFS_KOBJ_BIN_ATTR : '.',
    _SYSFS_TYPES.SYSFS_KOBJ_LINK : '@'
    }
# MAIN

if __name__ == "__main__":
    # You should pass an address of 'struct device' 
    addr = int(sys.argv[1], 16)
    gendev = readSU("struct device", addr)
    print(gendev)
    sd = gendev2sd(gendev)
    if (not sd):
        print("Does not have a sysfs entry")
        sys.exit(0)
    print(sd)
    print(sysfs_fullpath(sd))

    print(blockdev_name(sd))
