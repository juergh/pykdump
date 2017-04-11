#
# -*- coding: latin-1 -*-
#
# --------------------------------------------------------------------
# (C) Copyright 2012-2017 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------

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

_c_NFS_caps = '''
/* Server capabilities */
#define NFS_CAP_READDIRPLUS	1  //(1U << 0)
#define NFS_CAP_HARDLINKS	2  //(1U << 1)
#define NFS_CAP_SYMLINKS	4  //(1U << 2)
#define NFS_CAP_ACLS		8  //(1U << 3)
#define NFS_CAP_ATOMIC_OPEN	16 //(1U << 4)
'''

NFS_flags = CDefine(_c_NFS_flags)
NFS_caps = CDefine(_c_NFS_caps)

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

#/*
# * RPC task flags
# */
_c_RPC_flags = '''
#define RPC_TASK_ASYNC		0x0001		/* is an async task */
#define RPC_TASK_SWAPPER	0x0002		/* is swapping in/out */
#define RPC_CALL_MAJORSEEN	0x0020		/* major timeout seen */
#define RPC_TASK_ROOTCREDS	0x0040		/* force root creds */
#define RPC_TASK_DYNAMIC	0x0080		/* task was kmalloc'ed */
#define RPC_TASK_KILLED		0x0100		/* task was killed */
#define RPC_TASK_SOFT		0x0200		/* Use soft timeouts */
#define RPC_TASK_SOFTCONN	0x0400		/* Fail if can't connect */
#define RPC_TASK_SENT		0x0800		/* message was sent */
#define RPC_TASK_TIMEOUT	0x1000		/* fail with ETIMEDOUT on timeout */
#define RPC_TASK_NOCONNECT	0x2000		/* return ENOTCONN if not connected */
#define RPC_TASK_NO_RETRANS_TIMEOUT	0x4000		/* wait forever for a reply */
'''

RPC_flags = CDefine(_c_RPC_flags)

if (sys_info.kernel <= "2.6.12"):
    NFS_INO = CDefine(_c_NFS_inode_flags_old)

    
# Print NFS details of a given inode
def print_nfs_inode(inode):
    nfs_inode = container_of(inode, "struct nfs_inode", "vfs_inode")
    flags = nfs_inode.flags
    print ("%s %s" % (str(nfs_inode), dbits2str(flags, NFS_INO, 4)))
