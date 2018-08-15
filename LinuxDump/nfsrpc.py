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

__doc__ = '''
This is a package providing useful tables and functions for NFS, RPC
and related stuff.
'''

from pykdump.API import *

from LinuxDump.inet import *
from .fs import getMount

#__all__ = ["get_nfs_mounts", "is_NFSD"]


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

# The debuggable versions of modules we need
# There is no easy way to understand whether the loaded module is debuginfo
# or not - e.g. on a live testing systems the default modules can contain
# symbolic info. So we just check for some struct definitions

__needed_kmods = ('nfs', 'nfsd', 'sunrpc', 'lockd', 'nfsv3', 'nfsv4')
__needed_kmods_info = '''
To use this program, you need 'crash' to be able to find
some extra debuginfo DLKMs, not just vmlinux. These modules should either
be somewhere where 'crash' can find them, or you can extract them and put
into the same directory where vmcore resides. Here is the list of modules
you need:
  ''' + "\n  ".join(__needed_kmods)

__needed_structs = ("struct rpc_task", "struct nlm_wait",
                    "struct svc_export", "struct ip_map")

def init_Structures():
    load_Structures()
    finalize_Structures()

# Check whether all needed structures are present
def load_Structures():
    def missingStructs():
        missing_structs = []
        for sn in __needed_structs:
            if(not struct_exists(sn)):
                missing_structs.append(sn)
        return missing_structs
    # No need to try load again after the 1st invocation of DLKMs are loaded as needed
    if (not missingStructs()):
        # We have already found and loaded all needed DLKMs
        return
    # Do not try to load modules if they are not in use - maybe
    # this host does not use NFS at all!

    if(not "nfs" in lsModules()):
        print("This host is not using NFS!")
        sys.exit(0)

    # Part I - try to load all modules from the required list.
    nodlkms = []
    for m in __needed_kmods:
        if (m in lsModules() and not loadModule(m)):
            nodlkms.append(m)

    if (nodlkms):
        s = ",".join(nodlkms)
        print("+++Cannot find debuginfo for DLKMs: {}".format(s))
    # Now check whether all structs are available. If not, print
    # and explanation and exit

    missing_structs = missingStructs()
    # on RHEL5 NFS-client (no server), 'nfsd' is not loaded and
    # not really needed. So 'struct svc_export' is not needed either
    if (not is_NFSD()):
        try:
            missing_structs.remove("struct svc_export")
        except ValueError:
            pass
    if (missing_structs):
        s = ", ".join(missing_structs)
        print("+++Cannot find symbolic info for:\n  {}".format(s))
        print(__needed_kmods_info)
        sys.exit(0)

@memoize_cond(CU_LIVE)
def is_NFSD():
    return ('nfsd' in lsModules())
    
# Computer offsets and create pseudoattrs
def finalize_Structures():
    # A strange problem: sometimes after module is loaded, crash.gdb_typeinfo
    # returns a stub only. Using crash 'struct' command replaces the stub
    # with real info
    exec_crash_command("struct nfs_server")
    __init_attrs()
    
def __init_attrs():
    sn = "struct rpc_task"
    #
    structSetAttr(sn, "P_name", ["tk_msg.rpc_proc.p_name", 
                                 "tk_client.cl_procinfo.p_name"])
    structSetAttr(sn, "P_proc", ["tk_msg.rpc_proc.p_proc", "tk_msg.rpc_proc"])
    structSetAttr(sn, "CL_procinfo", "tk_client.cl_procinfo")
    structSetAttr(sn, "CL_vers", ["tk_client.cl_pmap_default.pm_vers",
                                  "tk_client.cl_pmap.pm_vers",
                                  "tk_client.cl_vers"])
    structSetAttr(sn, "CL_prog", ["tk_client.cl_pmap_default.pm_prog",
                                  "tk_client.cl_pmap.pm_prog",
                                  "tk_client.cl_prog"])

    sn = "struct file_lock"
    structSetAttr(sn, "Inode", ["fl_file.f_path.dentry.d_inode",
                                "fl_file.f_dentry.d_inode"])

    sn = "struct nlm_file"
    structSetAttr(sn, "Inode", ["f_file.f_path.dentry.d_inode",
                                "f_file.f_dentry.d_inode"])

    sn = "struct file"
    structSetAttr(sn, "Dentry", ["f_dentry", "f_path.dentry"])
    structSetAttr(sn, "Mnt", ["f_vfsmnt", "f_path.mnt"])

    sn = "struct nfs_server"

    structSetAttr(sn, "Hostname", ["hostname", "nfs_client.cl_hostname"])
    structSetAttr(sn, "Rpccl", ["client", "nfs_client.cl_rpcclient"])

    sn = "struct nfs_client"
    structSetAttr(sn, "Saddr4", ["cl_addr.sin_addr.s_addr", "cl_addr.__data"])

    sn = "struct svc_sock"
    structSetAttr(sn, "SockList", ["sk_list", "sk_xprt.xpt_list"])


# Fill-in and return a list of info about mounted NFS-shares.
@memoize_cond(CU_LIVE)
def get_nfs_mounts():
    nfs_mounts = []
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        if (fstype in ("nfs", "nfs4")):
            vfsmount = readSU("struct vfsmount" , vfsmount)
            sb = readSU("struct super_block", superblk)
            srv = readSU("struct nfs_server", sb.s_fs_info)
            srv_host = srv.Hostname
            nfs_mounts.append((srv_host, srv, mnt))
    return nfs_mounts


# Check for NFS loopback mounts
def if_loopback_NFS():
    my_ipv4, my_ipv6 = netdevice.get_host_IPs()
    for hostname, srv, mnt in get_nfs_mounts():
        addr_in = PY_select(
            'srv.nfs_client.cl_addr.castTo("struct sockaddr_in")',
            'srv.addr'
            )
        ip = ntodots(addr_in.sin_addr.s_addr)
        print(hostname, ip)
        if (ip in my_ipv4):
            return True
    return False

    
   
# Print NFS details of a given inode
def print_nfs_inode(inode):
    nfs_inode = container_of(inode, "struct nfs_inode", "vfs_inode")
    flags = nfs_inode.flags
    print ("%s %s" % (str(nfs_inode), dbits2str(flags, NFS_INO, 4)))

#static inline struct nfs_server *NFS_SERVER(const struct inode *inode)
#{
         #return NFS_SB(inode->i_sb);
#}

def NFS_SERVER(inode):
    return NFS_SB(inode.i_sb)

# static inline struct nfs_server *NFS_SB(const struct super_block *s)
# {
#         return (struct nfs_server *)(s->s_fs_info);
# }

def NFS_SB(s):
    return readSU("struct nfs_server", s.s_fs_info)

init_Structures()    

