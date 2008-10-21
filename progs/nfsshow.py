#!/usr/bin/env python

# Print info about NFS/RPC

from pykdump.API import *

from pykdump.API import *

# For INET stuff
from LinuxDump.inet import *
from LinuxDump.inet import proto, netdevice
from LinuxDump.inet.proto import tcpState, sockTypes, \
    IP_sock,  P_FAMILIES

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

__NFSMOD = True

# Check whether all needed structures are present
def init_Structures():
    global __NFSMOD
    if (symbol_exists("nlmdbg_cookie2a")):
	RPC_DEBUG = True
    else:
	RPC_DEBUG = False
    if (symbol_exists("rpciod_workqueue")):
	RECENT = True
    else:
	RECENT = False
    #print "RPC_DEBUG=", RPC_DEBUG, ", Recent=", RECENT
    
    if (not struct_exists("struct rpc_task")):
        if (not loadModule("nfs") \
            or not struct_exists("struct rpc_task") \
            or not struct_exists("struct nfs_inode")):
	    print "Some functionality missing. ",
            print "Please install a debuginfo copy of 'nfs' module"
            __NFSMOD = False
	    #sys.exit(0)
    __init_attrs()




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

def old_print_rpc_task(s):
    newk = (member_size("struct rpc_clnt", "cl_pmap_default") != -1)
    # On a live system we can easily get bad addresses
    try:
	print s, hexl(s.tk_flags)
	tk_client = s.Deref.tk_client
	cl_xprt= tk_client.Deref.cl_xprt
	print "\tProtocol=",cl_xprt.prot, ", Server=", tk_client.cl_server
	inetsock = cl_xprt.Deref.inet
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
	
def __init_attrs():
    sn = "struct rpc_task"
    #
    structSetAttr(sn, "P_name", "tk_client.cl_procinfo.p_name")
    structSetAttr(sn, "P_proc", ["tk_msg.rpc_proc.p_proc", "tk_msg.rpc_proc"])
    structSetAttr(sn, "CL_procinfo", "tk_client.cl_procinfo")
    structSetAttr(sn, "CL_vers", ["tk_client.cl_pmap_default.pm_vers",
                                  "tk_client.cl_pmap.pm_vers",
                                  "tk_client.cl_vers"])
    structSetAttr(sn, "CL_prog", ["tk_client.cl_pmap_default.pm_prog",
                                  "tk_client.cl_pmap.pm_prog",
                                  "tk_client.cl_prog"])
    
# Print RPC task (struct rpc_task)
def print_rpc_task(s):
    # On a live system we can easily get bad addresses
    try:
        #print s
        cl_pi = s.CL_procinfo
        rpc_proc = s.P_proc
        pn = cl_pi[rpc_proc].p_name

        tk_client = s.tk_client
        cl_xprt= tk_client.cl_xprt
        print "\tProtocol=",cl_xprt.prot, ", Server=", tk_client.cl_server
        
        print "\tprocname=", pn, tk_client.cl_protname
       
        vers = s.CL_vers
        prog = s.CL_prog
        if (prog == 100003 and vers == 2):
            procname = "%d(%s)" % (rpc_proc, NFS2_PROCS.value2key(rpc_proc))
        elif (prog == 100003 and vers == 3):
            procname = "%d(%s)" % (rpc_proc, NFS3_PROCS.value2key(rpc_proc))
        else:
            procname = "%d" % rpc_proc
        print "\trpc_proc=", procname 

        print "\tpmap_prog=", prog, ", pmap_vers=", vers
    except crash.error:
        pass

# Obtain all_tasks
def print_all_tasks():
    all_tasks = readSUListFromHead("all_tasks", "tk_task", "struct rpc_task")
    # Check whether it's 2.4 or 2.6
    newk = (member_size("struct rpc_clnt", "cl_pmap_default") != -1)
    for s in all_tasks:
        print_rpc_task(s)


# Print info about RPC status
def print_rpc_status():
    all_tasks = sym2addr("all_tasks")
    #l = readList(all_tasks, 0, maxel=100000, inchead=False)
    print "all_tasks has %d elements" % getListSize(all_tasks, 0, 10000000)
    for qname in ("schedq", "childq", "delay_queue"):
        tasks = readSU("struct rpc_wait_queue", sym2addr(qname)).tasks
	print "Number of elements in %15s:" % qname,
        for lh in tasks:
	    #print hexl(Addr(lh))
	    print " [%d] " % getListSize(Addr(lh), 0, 10000000),
	print ""
    
    return
    # Print schedq elements
    shedq0 = readSU("struct rpc_wait_queue", sym2addr("schedq")).tasks[0]
    for ta in readList(Addr(shedq0), 0, maxel=20, inchead=False):
        rpct = readSU("struct rpc_task", ta)
	print_rpc_task(rpct)
	

# Getting all tasks.
#
# On recent 2.6:
#/*
# * All RPC clients are linked into this list
# */
#static LIST_HEAD(all_clients);

def get_all_clients():
    all_clients = sym2addr("all_clients")
    allc = readSUListFromHead(all_clients, "cl_clients",
                              "struct rpc_clnt")
    return allc

# Get all RPC tasks
def get_all_tasks_old():
    all_taddr = sym2addr("all_tasks")
    all_tasks = readSUListFromHead(all_taddr, "tk_task", "struct rpc_task")
    clients = {}
    for t in all_tasks:
        clients.setdefault(t.tk_client, []).append(t)

    for cl, v in clients.items():
        # Print Client Info
        print cl
        # Print Task Info
        for t in v:
            print "\t", t, getListSize(t.tk_task, 0, 1000)

# Get all RPC tasks
def get_all_tasks():
    out = []
    for cl in get_all_clients():
        tasks = readSUListFromHead(long(cl.cl_tasks), "tk_task",
                                   "struct rpc_task")
        print cl, len(tasks)
        for t in tasks:
            print_rpc_task(t)

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
        try:
            s_io = readSUListFromHead(Addr(sb.s_io), "i_list", "struct inode")
        except KeyError:
            s_io = []
        if (len(s_dirty) | len(s_io)):
            print sb, fsname, \
                  "len(s_dirty)=%d len(s_io)=%d" % (len(s_dirty),len(s_io))


def container_of(ptr, ctype, member):
    offset = member_offset(ctype, member)
    return readSU(ctype, long(ptr) - offset)

def INT_LIMIT(bits):
    return (~(1 << (bits - 1)))
# Print nlm_blocked list

def print_nlm_blocked():
    lh = ListHead(sym2addr("nlm_blocked"), "struct nlm_wait")
    for block in lh.b_list:
	fl_blocked = block.b_lock
	owner = fl_blocked.fl_u.nfs_fl.owner.pid 
	haddr = block.b_host.h_addr      # This is sockaddr_in
	ip = ntodots(haddr.sin_addr.s_addr)
	print " ---- block ", block
	inode = fl_blocked.fl_file.f_dentry.d_inode
	nfs_inode = container_of(inode, "struct nfs_inode", "vfs_inode")
	fh = nfs_inode.fh
	data = fh.data[:fh.size]
	print "  fl_start=%d fl_end=%d owner=%d ip=%s" % (fl_blocked.fl_start,
	               fl_blocked.fl_end, owner, ip)
	# Print FH-data
	print "   ", nfs_inode
	print "   FH size=%d" % fh.size, "data=",
	for c in data:
	   sys.stdout.write("%02x" % c)
	print ""

init_Structures()

print INT_LIMIT(64)
#print_rpc_status()
#print_test()
#get_all_tasks_old()

print_nlm_blocked()
sys.exit(0)
# Print info for a given superblock

sb_addr = int(sys.argv[1], 16)

sb = readSU("struct super_block", sb_addr)
server = readSU("struct nfs_server", sb.s_fs_info)
rpc_client = server.client
nfs_client = server.nfs_client
print server, rpc_client, nfs_client
