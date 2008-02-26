# module LinuxDump.fs.ext3
#
# Time-stamp: <07/08/21 10:25:20 alexs>
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

debug = API_options.debug

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

# 2.6.9:
	#buf->f_type = EXT3_SUPER_MAGIC;
	#buf->f_bsize = sb->s_blocksize;
	#buf->f_blocks = le32_to_cpu(es->s_blocks_count) - overhead;
	#buf->f_bfree = ext3_count_free_blocks (sb);
	#buf->f_bavail = buf->f_bfree - le32_to_cpu(es->s_r_blocks_count);
	#if (buf->f_bfree < le32_to_cpu(es->s_r_blocks_count))
		#buf->f_bavail = 0;
	#buf->f_files = le32_to_cpu(es->s_inodes_count);
	#buf->f_ffree = ext3_count_free_inodes (sb);
	#buf->f_namelen = EXT3_NAME_LEN;

# 2.6.20:

	#buf->f_type = EXT3_SUPER_MAGIC;
	#buf->f_bsize = sb->s_blocksize;
	#buf->f_blocks = le32_to_cpu(es->s_blocks_count) - overhead;
	#buf->f_bfree = percpu_counter_sum(&sbi->s_freeblocks_counter);
	#buf->f_bavail = buf->f_bfree - le32_to_cpu(es->s_r_blocks_count);
	#if (buf->f_bfree < le32_to_cpu(es->s_r_blocks_count))
		#buf->f_bavail = 0;
	#buf->f_files = le32_to_cpu(es->s_inodes_count);
	#buf->f_ffree = percpu_counter_sum(&sbi->s_freeinodes_counter);
	#buf->f_namelen = EXT3_NAME_LEN;
	#fsid = le64_to_cpup((void *)es->s_uuid) ^
	       #le64_to_cpup((void *)es->s_uuid + sizeof(u64));
	#buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
	#buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;

# 2.4.20:
	#buf->f_type = EXT3_SUPER_MAGIC;
	#buf->f_bsize = sb->s_blocksize;
	#buf->f_blocks = le32_to_cpu(es->s_blocks_count) - overhead;
	#buf->f_bfree = ext3_count_free_blocks (sb);
	#buf->f_bavail = buf->f_bfree - le32_to_cpu(es->s_r_blocks_count);
	#if (buf->f_bfree < le32_to_cpu(es->s_r_blocks_count))
		#buf->f_bavail = 0;
	#buf->f_files = le32_to_cpu(es->s_inodes_count);
	#buf->f_ffree = ext3_count_free_inodes (sb);
	#buf->f_namelen = EXT3_NAME_LEN;
	

# If we don't have a debugging ext3.o on 2.4, try to use an artificial
# struct (first several lines of the complete struct)

__EXT3_SUPER_BLOCK_24 = '''
struct ext3_super_block {
/*00*/	__u32	s_inodes_count;		/* Inodes count */
	__u32	s_blocks_count;		/* Blocks count */
	__u32	s_r_blocks_count;	/* Reserved blocks count */
	__u32	s_free_blocks_count;	/* Free blocks count */
/*10*/	__u32	s_free_inodes_count;	/* Free inodes count */
	__u32	s_first_data_block;	/* First Data Block */
	__u32	s_log_block_size;	/* Block size */
	__s32	s_log_frag_size;	/* Fragment size */
/*20*/	__u32	s_blocks_per_group;	/* # Blocks per group */
	__u32	s_frags_per_group;	/* # Fragments per group */
	__u32	s_inodes_per_group;	/* # Inodes per group */
	__u32	s_mtime;		/* Mount time */
/*30*/	__u32	s_wtime;		/* Write time */
	__u16	s_mnt_count;		/* Mount count */
	__s16	s_max_mnt_count;	/* Maximal mount count */
	__u16	s_magic;		/* Magic signature */
	__u16	s_state;		/* File system state */
	__u16	s_errors;		/* Behaviour when detecting errors */
	__u16	s_minor_rev_level;	/* minor revision level */
/*40*/	__u32	s_lastcheck;		/* time of last check */
	__u32	s_checkinterval;	/* max. time between checks */
	__u32	s_creator_os;		/* OS */
	__u32	s_rev_level;		/* Revision level */
/*50*/	__u16	s_def_resuid;		/* Default uid for reserved blocks */
	__u16	s_def_resgid;		/* Default gid for reserved blocks */
	__u32	s_first_ino;		/* First non-reserved inode */
	__u16   s_inode_size;		/* size of inode structure */
	__u16	s_block_group_nr;	/* block group # of this superblock */
	__u32	s_feature_compat;	/* compatible feature set */
/*60*/	__u32	s_feature_incompat;	/* incompatible feature set */
	__u32	s_feature_ro_compat;	/* readonly-compatible feature set */
'''

__EXT3_GROUP_DESC = '''
	__u32	bg_block_bitmap;		/* Blocks bitmap block */
	__u32	bg_inode_bitmap;		/* Inodes bitmap block */
	__u32	bg_inode_table;		/* Inodes table block */
	__u16	bg_free_blocks_count;	/* Free blocks count */
	__u16	bg_free_inodes_count;	/* Free inodes count */
	__u16	bg_used_dirs_count;	/* Directories count */
	__u16	bg_pad;
	__u32	bg_reserved[3];
'''

def __createArt24():
    sb = ArtStructInfo("struct ext3_super_block")
    for l in __EXT3_SUPER_BLOCK_24.splitlines():
	# Get rid of comments
	i_beg = l.find('__')
	i_end= l.find(';') + 1
	l = l[i_beg:i_end].strip()
	if (l):
	   #print l
	   sb.append(l)
    sb = ArtStructInfo("struct ext3_group_desc")
    for l in __EXT3_GROUP_DESC.splitlines():
	# Get rid of comments
	i_beg = l.find('__')
	i_end= l.find(';') + 1
	l = l[i_beg:i_end].strip()
	if (l):
	   #print l
	   sb.append(l)
    

def statfs_Ext3(sbaddr):

    buf = Bunch()

    sb = readSU("struct super_block", sbaddr)

    s = getStructInfo("struct ext3_sb_info")

    # Here we use the same variable names as in C ext3_statfs
    sbi = EXT3_SB(sb)
    es = Deref(sbi.s_es)
    
    if (debug):
	print sbi, es

    if (__count_func):
	f_bfree = ext3_count_free_blocks(sb)
    else:
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
    if (debug):
	print "blocks_count=%d overhead=%d" %(s_r_blocks_count, overhead)

    block_size = (sbi.s_frag_size * sbi.s_frags_per_block)/1024
    buf.f_bsize = sb.s_blocksize

    # We convert to 1k blocksize

    buf.f_blocks = f_blocks * block_size                           
    buf.f_bfree = f_bfree * block_size
    buf.f_bavail = (f_bfree - s_r_blocks_count)*block_size
    
    buf.f_files = le32_to_cpu(es.s_inodes_count)
    if (__count_func):
	buf.f_ffree = ext3_count_free_inodes(sb)
    else:
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
    if (__v_24):
	return sb.u.ext3_sb
    else:
	ptr = sb.s_fs_info
        return readSU("struct ext3_sb_info", ptr)

def EXT3_HAS_RO_COMPAT_FEATURE(sb,mask):
    return (EXT3_SB(sb).s_es.Deref.s_feature_ro_compat & cpu_to_le32(mask))

def ext3_bg_num_gdb(sb, group):
    if (EXT3_HAS_RO_COMPAT_FEATURE(sb,EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER) \
        and not ext3_group_sparse(group)):
        return 0
    return EXT3_SB(sb).s_gdb_count


# Older EXT3 stuff (< 2.6.10)
def ext3_count_free_blocks(sb):
    desc_count = 0
    ngroups = EXT3_SB(sb).s_groups_count
    for i in range(ngroups):
	gd = ext3_get_group_desc(sb, i)
	desc_count += le16_to_cpu(gd.bg_free_blocks_count)
    return desc_count;

# 2.4 'struct super_block' has 'u' union
def ext3_count_free_inodes(sb):
    if (__v_24):
        return le32_to_cpu(sb.u.ext3_sb.s_es.Deref.s_free_inodes_count)
    desc_count = 0
    #print "s_groups_count=%d" % EXT3_SB(sb).s_groups_count
    for i in range(EXT3_SB(sb).s_groups_count):
	gd = ext3_get_group_desc(sb, i)
	desc_count += le16_to_cpu(gd.bg_free_inodes_count);
    return desc_count

def ext3_get_group_desc(sb, block_group):
    sbi = EXT3_SB(sb)
    if (block_group >= sbi.s_groups_count):
	raise IndexError, "ext3_error"

    group_desc = block_group / EXT3_DESC_PER_BLOCK(sb)
    desc = block_group % EXT3_DESC_PER_BLOCK(sb)
    if (not sbi.s_group_desc[group_desc]):
	raise IndexError, "ext3_error"

    # struct buffer_head **s_group_desc
    ael = sbi.s_group_desc[group_desc]
    #print "group_desc=", group_desc, " ael=", repr(ael)
    #gdp = Addr(Deref(sbi.s_group_desc[group_desc]).b_data)
    #print "group_desc=%d" % group_desc
    gdp = readSU("struct buffer_head", sbi.s_group_desc[group_desc]).b_data
    gdp = gdp.ptr
    #print "  ", repr(sbi.s_group_desc[group_desc]), hexl(gdp)
    #print repr(gdp), 'desc=', desc
    etype = "struct ext3_group_desc"
    sz = struct_size(etype)
    return readSU(etype, gdp + desc*sz)

def EXT3_DESC_PER_BLOCK(s):
    return (EXT3_SB(s).s_desc_per_block)

def showExt3():
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        if (fstype != 'ext3' or mnt[:5] == '/dev/'):
            continue
        print "\n0x%x 0x%x %8s   %s" % (vfsmount, superblk, fstype, mnt)
        s = statfs_Ext3(superblk)
	print "%10d    size of fs in 1KB blocks" % s.f_blocks
        print "%10d    file system block size" % s.f_bsize
	print "%10d    free blocks" % s.f_bfree
	print "%10d    free blocks for non-root" % s.f_bavail
	print "%10d    inodes" % s.f_files
	print "%10d    free inodes" % s.f_ffree

# Tests to understand what is the kernel we are running on
if (not struct_exists("struct ext3_super_block")):
    # Try to load the module and then check for struct again
    loadModule("ext3")
    if (not struct_exists("struct ext3_super_block")):
        print "Cannot load a debuggable ext3.ko"
        sys.exit(1)

if (member_size("struct super_block", "s_fs_info") == -1):
    # 2.4 kernels
    __v_24 = True
    __count_func = True
    __createArt24()
else:
    __v_24 = False
    # I am not sure about the following test, need to doublecheck
    if (sys_info.kernel >= "2.6.12"):
	__count_func = False
    else:
	__count_func = True

if (debug):
    if (__v_24):
        print "Using v2.4 way to compute EXT3 statfs"

    if (__count_func):
        print "Using functions to compute EXT3 statfs"

