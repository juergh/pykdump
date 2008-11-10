#!/usr/bin/env python

# Print info about NFS/RPC

from pykdump.API import *

from pykdump.API import *

# For FS stuff
from LinuxDump.fs import *

# For INET stuff
from LinuxDump.inet import *

from LinuxDump.inet import proto, netdevice
from LinuxDump.inet.proto import tcpState, sockTypes, \
    IP_sock,  P_FAMILIES

# For NFS/RPC stuff
from LinuxDump.nfsrpc import *

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
        if (not loadModule("nfs") or not loadModule("lockd") \
            or not struct_exists("struct rpc_task") \
            or not struct_exists("struct nfs_inode")):
	    print "Some functionality missing. ",
            print "Please install debuginfo copies of 'nfs' and 'lockd' modules"
            __NFSMOD = False
	    #sys.exit(0)
    sizeloff = getSizeOf("loff_t")
    bits = sizeloff*8
    global OFFSET_MAX, OFFSET_MASK
    OFFSET_MASK = (~(~0<<bits))
    OFFSET_MAX =  (~(1 << (bits - 1))) & OFFSET_MASK
    __init_attrs()


# Traversing RPC-cache
def print_rpc_cache(c):
    hs = c.hash_size
    ht = c.hash_table
    print c

    for i in range(hs):
        e = ht[i]
        if (e):
            for h in readStructNext(e, "next"):
                exp = container_of(h, "struct svc_export", "h")
                print h, exp, exp.ex_path, exp.ex_client.name


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

    sn = "struct file_lock"
    structSetAttr(sn, "Inode", ["fl_file.f_path.dentry.d_inode",
                                "fl_file.f_dentry.d_inode"])

    sn = "struct nlm_file"
    structSetAttr(sn, "Inode", ["f_file.f_path.dentry.d_inode",
                                "f_file.f_dentry.d_inode"])

    sn = "struct nfs_server"
    structSetAttr(sn, "Hostname", ["hostname", "nfs_client.cl_hostname"])
    structSetAttr(sn, "Rpccl", ["client", "nfs_client.cl_rpcclient"])
                                

    
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



def INT_LIMIT(bits):
    return (~(1 << (bits - 1)))


# Print 'struct file_lock' info
def print_file_lock(fl):
    lockhost = fl.fl_owner.castTo("struct nlm_host")
    print lockhost
    

# Print nlm_blocked list

def print_nlm_blocked_clnt(nlm_blocked):
    lh = ListHead(nlm_blocked, "struct nlm_wait")
    for block in lh.b_list:
	fl_blocked = block.b_lock
	owner = fl_blocked.fl_u.nfs_fl.owner.pid 
	haddr = block.b_host.h_addr      # This is sockaddr_in
	ip = ntodots(haddr.sin_addr.s_addr)
	print " ---- block ", block
	#inode = fl_blocked.fl_file.f_dentry.d_inode
        inode = fl_blocked.Inode
	nfs_inode = container_of(inode, "struct nfs_inode", "vfs_inode")
        print inode, nfs_inode
	fh = nfs_inode.fh
	data = fh.data[:fh.size]
        fl_start = fl_blocked.fl_start
        fl_end = fl_blocked.fl_end
        if (fl_end == OFFSET_MAX):
            length = 0
        else:
            length = (fl_end - fl_start + 1) & OFFSET_MASK
	print "  fl_start=%d fl_len=%d owner=%d ip=%s" % (fl_start,
                                                          length, owner, ip)
	# Print FH-data
	print "   ", nfs_inode
	print "  FH size=%d\n    data" % fh.size,
	for c in data:
	   sys.stdout.write("%02x" % c)
	print ""

# built-in crash command 'files -l' is broken on recent kernels
#static struct hlist_head	nlm_files[FILE_NRHASH];
def print_nlm_files():
    nlm_files = readSymbol("nlm_files")
    for h in nlm_files:
        if (h.first == 0):
            continue
        #print h
        for e in hlist_for_each_entry("struct nlm_file", h, "f_list"):
            print e
            f_file = e.f_file
            f_path = f_file.f_path
            print "  ", get_pathname(f_path.dentry, f_path.mnt)
            for fl in readStructNext(e.Inode.i_flock, "fl_next"):
                lockhost = fl.fl_owner.castTo("struct nlm_host")
                print "    ", lockhost.h_name

# Print nfs-server info
def print_nfs_server(nfs, mntpath = None):
    print "--%s---- %s ---- %s ----" % (str(nfs), nfs.Hostname, mntpath)
    print "   flags=<%s>," % dbits2str(nfs.flags, NFS_flags, 10),
    print " caps=<%s>" % dbits2str(nfs.caps, NFS_caps, 8)
    print "   rsize=%d, wsize=%d" % (nfs.rsize, nfs.wsize)
    print "   acregmin=%d, acregmax=%d, acdirmin=%d, acdirmax=%d" % \
          (nfs.acregmin, nfs.acregmax, nfs.acdirmin, nfs.acdirmax)
    print "   ", nfs.Rpccl
    

    
def print_nfsmount():
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        if (fstype != "nfs"):
            continue
        vfsmount = readSU("struct vfsmount" , vfsmount)
        sb = readSU("struct super_block", superblk)
        srv = readSU("struct nfs_server", sb.s_fs_info)
        print_nfs_server(srv, mnt)
        

init_Structures()

# There are two nlm_blocked lists: the 1st one declared in clntlock.c,
# the 2nd one in svclock.c.

# E.g.:
# ffffffff88cf6240 (d) nlm_blocked
# ffffffff88cf6800 (d) nlm_blocked

# The client listhead is typically followed by 'nlmclnt_lock_ops'
# (but not on 2.4),  the svs by 'nlmsvc_procedures'
# So we assume that address near 'nlmclnt_lock_ops' is the client addr

anchor = sym2addr("nlmclnt_lock_ops")
#print "anchor", hexl(anchor)

clnt, svc = tuple(sym2alladdr("nlm_blocked"))

if (abs(clnt-anchor) > abs(svc-anchor)):
    clnt, svc = svc, clnt

#print "nlm_blocked clnt=", hexl(clnt), getListSize(clnt, 0, 1000)
#print "nlm_blocked svc=", hexl(svc), getListSize(svc, 0, 1000)
#print_nlm_blocked_clnt(clnt)
#print_nlm_files()

print_nfsmount()
#print_rpc_status()
#print_test()
#get_all_tasks_old()

HZ = sys_info.HZ

svc_export_cache = readSU("struct cache_detail", sym2addr("svc_export_cache"))
if (svc_export_cache):
    print_rpc_cache(svc_export_cache)

lru_head = sym2addr("lru_head")
if (lru_head):
    sn = "struct svc_cacherep"
    jiffies = readSymbol("jiffies")
    offset = member_offset(sn, "c_hash")
    for e in ListHead(lru_head, sn).c_lru:
        #print e
        #print e, ntodots(e.c_addr.sin_addr.s_addr), e.c_timestamp, e.c_state
        hnode = e.c_hash
        for he in readList(hnode, 0):
            hc = readSU(sn, he-offset)
            secago = (jiffies-hc.c_timestamp)/HZ
            if (secago > 100):
                continue
            print "  ", hc, ntodots(hc.c_addr.sin_addr.s_addr), \
                  secago,\
                  hc.c_state
