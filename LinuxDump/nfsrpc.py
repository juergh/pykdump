#
# -*- coding: latin-1 -*-
# Time-stamp: <07/10/11 12:16:51 alexs>

# NFS & RPC  functions

from pykdump.API import *

_c_NFS_flags = '''
#define NFS_MOUNT_SOFT		0x0001	/* 1 */
#define NFS_MOUNT_INTR		0x0002	/* 1 */
#define NFS_MOUNT_SECURE	0x0004	/* 1 */
#define NFS_MOUNT_POSIX		0x0008	/* 1 */
#define NFS_MOUNT_NOCTO		0x0010	/* 1 */
#define NFS_MOUNT_NOAC		0x0020	/* 1 */
#define NFS_MOUNT_TCP		0x0040	/* 2 */
#define NFS_MOUNT_VER3		0x0080	/* 3 */
#define NFS_MOUNT_KERBEROS	0x0100	/* 3 */
#define NFS_MOUNT_NONLM		0x0200	/* 3 */
#define NFS_MOUNT_BROKEN_SUID	0x0400	/* 4 */
#define NFS_MOUNT_NOACL		0x0800  /* 4 */
#define NFS_MOUNT_STRICTLOCK	0x1000	/* reserved for NFSv4 */
#define NFS_MOUNT_SECFLAVOUR	0x2000	/* 5 */
#define NFS_MOUNT_FLAGMASK	0xFFFF

/* Feature flag for the NFS_ACL protocol extension */
#define NFSACL			0x10000
'''

NFS_flags = CDefine(_c_NFS_flags)

_c_NFS_inode_flags_old ='''
/*
 * Legal inode flag values
 */
#define NFS_INO_STALE		0x0001		/* possible stale inode */
#define NFS_INO_ADVISE_RDPLUS   0x0002          /* advise readdirplus */
#define NFS_INO_REVALIDATING	0x0004		/* revalidating attrs */
#define NFS_INO_INVALID_ATTR	0x0008		/* cached attrs are invalid */
#define NFS_INO_INVALID_DATA	0x0010		/* cached data is invalid */
#define NFS_INO_INVALID_ATIME	0x0020		/* cached atime is invalid */
'''


if (sys_info.kernel <= "2.6.12"):
    NFS_INO = CDefine(_c_NFS_inode_flags_old)

def print_nfsmount(vfs):
    pass

def container_of(ptr, ctype, member):
    offset = member_offset(ctype, member)
    return readSU(ctype, long(ptr) - offset)
    
# Print NFS details of a given inode
def print_nfs_inode(inode):
    nfs_inode = container_of(inode, "struct nfs_inode", "vfs_inode")
    flags = nfs_inode.flags
    print "%s %s" % (str(nfs_inode), dbits2str(flags, NFS_INO, 4))