#
# -*- coding: latin-1 -*-
# Time-stamp: <07/10/11 12:16:51 alexs>

# NFS & RPC  functions

from pykdump.API import *

_NFS_flags = '''
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


def print_nfsmount(vfs):
    