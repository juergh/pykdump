#!/usr/bin/env python

# Print info about NFS/RPC

from pykdump.API import *

from pykdump.API import *

# For INET stuff
from LinuxDump.inet import *
from LinuxDump.inet import proto, netdevice
from LinuxDump.inet.proto import tcpState, sockTypes, \
    IPv4_conn, IPv6_conn, IP_sock,  P_FAMILIES

import string

debug = API_options.debug

NFS3_C = '''
#define NFS3PROC_NULL		0
#define NFS3PROC_GETATTR	1
#define NFS3PROC_SETATTR	2
#define NFS3PROC_LOOKUP		3
#define NFS3PROC_ACCESS		4
#define NFS3PROC_READLINK	5
#define NFS3PROC_READ		6
#define NFS3PROC_WRITE		7
#define NFS3PROC_CREATE		8
#define NFS3PROC_MKDIR		9
#define NFS3PROC_SYMLINK	10
#define NFS3PROC_MKNOD		11
#define NFS3PROC_REMOVE		12
#define NFS3PROC_RMDIR		13
#define NFS3PROC_RENAME		14
#define NFS3PROC_LINK		15
#define NFS3PROC_READDIR	16
#define NFS3PROC_READDIRPLUS	17
#define NFS3PROC_FSSTAT		18
#define NFS3PROC_FSINFO		19
#define NFS3PROC_PATHCONF	20
#define NFS3PROC_COMMIT		21
'''

NFS2_C = '''
#define NFSPROC_NULL		0
#define NFSPROC_GETATTR		1
#define NFSPROC_SETATTR		2
#define NFSPROC_ROOT		3
#define NFSPROC_LOOKUP		4
#define NFSPROC_READLINK	5
#define NFSPROC_READ		6
#define NFSPROC_WRITECACHE	7
#define NFSPROC_WRITE		8
#define NFSPROC_CREATE		9
#define NFSPROC_REMOVE		10
#define NFSPROC_RENAME		11
#define NFSPROC_LINK		12
#define NFSPROC_SYMLINK		13
#define NFSPROC_MKDIR		14
#define NFSPROC_RMDIR		15
#define NFSPROC_READDIR		16
#define NFSPROC_STATFS		17
'''

NFS2_PROCS = CDefine(NFS2_C)
NFS3_PROCS = CDefine(NFS3_C)


# Check whether all needed structures are present
def init_Structures():
    if (symbol_exists("nlmdbg_cookie2a")):
	RPC_DEBUG = True
    else:
	RPC_DEBUG = False
    if (symbol_exists("rpciod_workqueue")):
	RECENT = True
    else:
	RECENT = False
    print "RPC_DEBUG=", RPC_DEBUG, ", Recent=", RECENT
    
    if (not struct_exists("struct rpc_task")):
        if (not loadModule("sunrpc") or not struct_exists("struct rpc_task")):
	    print "Cannot proceed, please install a debugging copy of 'sunrpc'"
	    sys.exit(0)


init_Structures()


# On 2.4 and earlier 2.6:

# struct rpc_task {
#         struct list_head        tk_list;        /* wait queue links */
# #ifdef RPC_DEBUG
#         unsigned long           tk_magic;       /* 0xf00baa */
# #endif
#         struct list_head        tk_task;        /* global list of tasks */

# On newer 2.6:

# struct rpc_task {
# #ifdef RPC_DEBUG
# 	unsigned long		tk_magic;	/* 0xf00baa */
# #endif
# 	atomic_t		tk_count;	/* Reference count */
# 	struct list_head	tk_task;	/* global list of tasks */


# Obtain all_tasks
def print_all_tasks():
    all_tasks = readSUListFromHead("all_tasks", "tk_task", "struct rpc_task")
    # Check whether it's 2.4 or 2.6
    newk = (member_size("struct rpc_clnt", "cl_pmap_default") != -1)
    for s in all_tasks:
        # On a live system we can easily get bad addresses
        try:
            print s
            tk_client = s.Deref.tk_client
            cl_xprt= tk_client.Deref.cl_xprt
            print "\tProtocol=",cl_xprt.prot, ", Server=", tk_client.cl_server
            inetsock = cl_xprt.Deref.inet
            #print  "\t",IPv4_conn(sock=inetsock)
            cl_procinfo = tk_client.Deref.cl_procinfo
            #print "\tprocname=", cl_procinfo.p_procname, tk_client.cl_protname
            tk_msg = s.tk_msg
            if (newk):
                rpc_proc = tk_msg.Deref.rpc_proc.p_proc
            else:
                rpc_proc = tk_msg.rpc_proc
            if (newk):
               cl_pmap= tk_client.cl_pmap_default
            else:
               cl_pmap= tk_client.cl_pmap
            vers = cl_pmap.pm_vers
            prog = cl_pmap.pm_prog
            if (prog == 100003 and vers == 2):
                procname = "%d(%s)" % (rpc_proc, NFS2_PROCS.value2key(rpc_proc))
            elif (prog == 100003 and vers == 3):
                procname = "%d(%s)" % (rpc_proc, NFS3_PROCS.value2key(rpc_proc))
            else:
                procname = "%d" % rpc_proc
            print "\trpc_proc=", procname 

            print "\tpmap_prog=", cl_pmap.pm_prog, ", pmap_vers=", cl_pmap.pm_vers
        except:
            pass


# Print info about RPC status
def print_rpc_status():
    all_tasks = sym2addr("all_tasks")
    l = readList(all_tasks, 0, maxel=100000, inchead=False)
    print "all_tasks has %d elements" % len(l)
    

# Get dirty inodes
#	struct list_head	s_dirty;	/* dirty inodes */
#	struct list_head	s_io;		/* parked for writeback */

def print_test():
    for sa in readList(sym2addr("super_blocks"), 0, inchead=False):
        sb = readSU("struct super_block", sa)
        fsname = sb.Deref.s_type.name
        if (fsname != "nfs"):
            continue
        s_dirty = readSUListFromHead(Addr(sb.s_dirty), "i_list", "struct inode")
        s_io = readSUListFromHead(Addr(sb.s_io), "i_list", "struct inode")
        if (len(s_dirty) | len(s_io)):
            print sb, fsname, \
                  "len(s_dirty)=%d len(s_io)=%d" % (len(s_dirty),len(s_io))

print_rpc_status()
print_test()
