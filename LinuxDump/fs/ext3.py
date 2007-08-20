# module LinuxDump.fs.ext3
#
# Time-stamp: <07/08/20 10:37:57 alexs>
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

__doc__ = '''
This is a package providing  access to EXT3-specific structures.
'''
from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump.percpu import  percpu_counter_sum



# Find all EXT3 FS
#       struct statfs {
#          long    f_type;     /* type of filesystem (see below) */
#          long    f_bsize;    /* optimal transfer block size */
#          long    f_blocks;   /* total data blocks in file system */
#          long    f_bfree;    /* free blocks in fs */
#          long    f_bavail;   /* free blocks avail to non-superuser */
#          long    f_files;    /* total file nodes in file system */
#          long    f_ffree;    /* free file nodes in fs */
#          fsid_t  f_fsid;     /* file system id */
#          long    f_namelen;  /* maximum length of filenames */
#       };

# Get free space on EXT3 mounted at superblock

def statfs_Ext3(sbaddr):
    if (not loadModule("ext3")):
        print "Cannot load a debuggable ext3.ko"

    buf = Bunch()

    sb = readSU("struct super_block", sbaddr)

    s = getStructInfo("struct ext3_sb_info")

    # Here we use the same variable names as in C ext3_statfs
    sbi = EXT3_SB(sb)
    es = sbi.Deref.s_es

    f_bfree = percpu_counter_sum(sbi.s_freeblocks_counter)

    sb_free = es.s_free_blocks_count

    #print "s_free_blocks_count=%d" % sb_free


    overhead = le32_to_cpu(es.s_first_data_block)
    ngroups = sbi.s_groups_count
    for i in range(ngroups):
        overhead += ext3_bg_has_super(sb, i) + \
                    ext3_bg_num_gdb(sb, i)

    overhead += (ngroups * (2 + EXT3_SB(sb).s_itb_per_group))

    
    s_r_blocks_count = le32_to_cpu(es.s_r_blocks_count)
    f_blocks = le32_to_cpu(es.s_blocks_count) - overhead

    block_size = (sbi.s_frag_size * sbi.s_frags_per_block)/1024

    # We convert to 1k blocksize

    buf.f_blocks = f_blocks * block_size                           
    buf.f_bfree = f_bfree * block_size
    buf.f_bavail = (f_bfree - s_r_blocks_count)*block_size
    
    buf.f_files = le32_to_cpu(es.s_inodes_count);
    buf.f_ffree = percpu_counter_sum(sbi.s_freeinodes_counter);
    return buf

def test_root(a, b):
    if (a == 0):
        return 1
    while (1):
        if (a == 1):
            return 1
        if (a % b):
            return 0
        a = a / b


def ext3_group_sparse(group):
    return (test_root(group, 3) or test_root(group, 5) or test_root(group, 7))

EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER = 0x0001

def ext3_bg_has_super(sb, group):

    if (EXT3_HAS_RO_COMPAT_FEATURE(sb,EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER) and
        not ext3_group_sparse(group)):
        return 0
    return 1

def EXT3_SB(sb):
    return readSU("struct ext3_sb_info", sb.s_fs_info)    

def EXT3_HAS_RO_COMPAT_FEATURE(sb,mask):
    return (EXT3_SB(sb).Deref.s_es.s_feature_ro_compat & cpu_to_le32(mask))

def ext3_bg_num_gdb(sb, group):
    if (EXT3_HAS_RO_COMPAT_FEATURE(sb,EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER) \
        and not ext3_group_sparse(group)):
        return 0
    return EXT3_SB(sb).s_gdb_count



def showExt3():
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        if (fstype != 'ext3' or mnt[:5] == '/dev/'):
            continue
        print "0x%x 0x%x %8s   %s" % (vfsmount, superblk, fstype, mnt)
        s = statfs_Ext3(superblk)
        print s
