#!/usr/bin/env python

# Print info about NFS/RPC

from pykdump.API import *

# For FS stuff
from LinuxDump.fs import *

# For INET stuff
from LinuxDump.inet import *

from LinuxDump.inet import proto, netdevice
from LinuxDump.inet.proto import tcpState, sockTypes, \
    IP_sock,  P_FAMILIES, format_sockaddr_in, protoName

# For NFS/RPC stuff
from LinuxDump.nfsrpc import *

import string, struct
from socket import ntohl, ntohs, htonl, htons


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

nfs_avail = {}

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

    # We need debuggable versions of the following:
    #
    # 'nfs' for basic NFS-client hosts
    # 'lockd' for locking info - both on clients and servers
    # 'nfsd' for NFS-servers additional info

    nfs_avail.clear()

    for m, sn in (("nfs", "struct rpc_task"),
                 ("lockd", "struct nlm_wait"),
                 ("nfsd", "struct svc_export")
                 ):
        nfs_avail[m] = False
        if (m in lsModules()):
            if((struct_exists(sn) or (loadModule(m) and struct_exists(sn)))):
                nfs_avail[m] = True
            else:
                print "WARNING: cannot find debuginfo for module %s" % m
    
    # A strange problem: sometimes after module is loaded, crash.gdb_typeinfo
    # returns a stub only. Using crash 'struct' command replaces the stub
    # with real info
    exec_crash_command("struct nfs_server")
    sizeloff = getSizeOf("loff_t")
    bits = sizeloff*8
    global OFFSET_MAX, OFFSET_MASK
    OFFSET_MASK = (~(~0<<bits))
    OFFSET_MAX =  (~(1 << (bits - 1))) & OFFSET_MASK
    __init_attrs()

# Compute delay between a given timestamp and jiffies
def __j_delay(ts, jiffies):
    v = (jiffies - ts) & INT_MASK
    if (v > INT_MAX):
        v = "     n/a"
    elif (v > HZ*3600*10):
        v = ">10hours"
    else:
        v = "%8.1f" % (float(v)/HZ)
    return v

# To store IP-addr the older kernels use 'struct sockaddr_in, 
# newer kernels use 

#struct __kernel_sockaddr_storage {
#    short unsigned int ss_family;
#    char __data[126];
#}
# and it is casted to 'struct sockaddr'

def format_cl_addr(s):
    try:
        family = s.sin_family
        # This is sockaddr_in
        return ntodots(s.sin_addr.s_addr)
    except:
        family = s.ss_family
        if (family == P_FAMILIES.PF_INET):
            n = htonl(struct.unpack("I", s.__data[:4])[0])
            return ntodots(n)
        elif (family == P_FAMILIES.PF_INET6):
            pass
        return "???"


# Print NFS-exported directories
def print_nfs_exports(v = 0):
    c = readSU("struct cache_detail",
                              sym2addr("svc_export_cache"))

    hs = c.hash_size
    ht = c.hash_table
    print "  -----NFS-exports ------"
    #print c

    for i in range(hs):
        e = ht[i]
        if (e):
            for h in readStructNext(e, "next"):
                exp = container_of(h, "struct svc_export", "h")
                print "    ", exp.ex_path, exp.ex_client.name,
                if (v):
                    print "  ", exp
                else:
                    print ""


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

    sn = "struct nfs_client"
    structSetAttr(sn, "Saddr4", ["cl_addr.sin_addr.s_addr", "cl_addr.__data"])
                                

# Decode and print info about XPRT
def print_xprt(xprt):
    pass
    
# Decode and Print one RPC task (struct rpc_task)
def print_rpc_task(s):
    # On a live system we can easily get bad addresses
    try:
        #print s
        cl_pi = s.CL_procinfo
        rpc_proc = s.P_proc
        tk_client = s.tk_client
	#pn = cl_pi[rpc_proc].p_name
        #pn = tk_client.cl_protname
        cl_xprt= tk_client.cl_xprt
        addr_in = cl_xprt.addr.castTo("struct sockaddr_in")
	ip = ntodots(addr_in.sin_addr.s_addr)
        print "\tProtocol=",cl_xprt.prot, ", Server=", tk_client.cl_server, ip
        
        print "\t  procname=", tk_client.cl_protname
       
        vers = s.CL_vers
        prog = s.CL_prog
        if (prog == 100003 and vers == 2):
            procname = "%d(%s)" % (rpc_proc, NFS2_PROCS.value2key(rpc_proc))
        elif (prog == 100003 and vers == 3):
            procname = "%d(%s)" % (rpc_proc, NFS3_PROCS.value2key(rpc_proc))
        else:
            procname = "%d" % rpc_proc
        print "\t  rpc_proc=", procname 

        print "\t  pmap_prog=", prog, ", pmap_vers=", vers
	
	rqst = s.tk_rqstp
	
	retries = rqst.rq_retries
	if (retries):
	   print "\t  rq_retries=", rqst.rq_retries, "rq_timeout=", rqst.rq_timeout,\
	       "rq_majortimeo", rqst.rq_majortimeo
	tk_callback = s.tk_callback
	if (tk_callback):
	    print "\t  callback=%s" % addr2sym(tk_callback)
    except crash.error:
        pass

# print all rpc pending tasks
def print_all_rpc_tasks():
    # Obtain all_tasks
    tasks = get_all_rpc_tasks()
    xprtlist = []
    print "  ------- %d RPC Tasks ---------" % len(tasks)
    for t in tasks:
        # On a live kernel pointers may get invalid while we are processing
        try:
            xprt = t.tk_rqstp.rq_xprt
            if (not xprt in xprtlist):
                xprtlist.append(xprt)
            print "    ---", t
            print_rpc_task(t)
        except (IndexError, crash.error):
            # Null pointer and invalid addr
            continue
    # Print XPRT vitals
    print " --- XPRT Info ---"
    for xprt in xprtlist:
        try:
            print "  ...", xprt, "..."
            jiffies = readSymbol("jiffies")
            print "    last_used %s s ago" % __j_delay(xprt.last_used, jiffies)
            for qn in ("binding", "sending", "resend", "pending", "backlog"):
                try:
                    print "    len(%s) queue is %d" % (qn,
                                                       getattr(xprt, qn).qlen)
                except KeyError:
                    pass
	    try:
                xprt.stat.Dump()
	    except KeyError:
		# There is no 'stat' field in xprt on 2.6.9
		pass
	       
        except (IndexError, crash.error):
            # Null pointer and invalid addr
            continue            
    
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
        for ft in v:
	    for t in readSUListFromHead(long(ft.tk_task), "tk_task",
                                   "struct rpc_task"):
		print "    ", t
		print_rpc_task(t)

# Get all RPC tasks
def oldnew_get_all_tasks():
    out = []
    for cl in get_all_clients():
        tasks = readSUListFromHead(long(cl.cl_tasks), "tk_task",
                                   "struct rpc_task")
        print cl, len(tasks)
        for t in tasks:
            print_rpc_task(t)

def get_all_rpc_tasks():
    all_taddr = sym2addr("all_tasks")
    if (all_taddr):
	return readSUListFromHead(all_taddr, "tk_task", "struct rpc_task")
    all_clients = sym2addr("all_clients")
    allc = readSUListFromHead(all_clients, "cl_clients", "struct rpc_clnt")
    out = []
    for cl in allc:
	out += readSUListFromHead(long(cl.cl_tasks), "tk_task",
                                   "struct rpc_task")
    
    return out
	

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

# Print FH
def printFH(fh, indent = 0):
    def chunk(seq, size):
        for i in range(0, len(seq), size):
            yield seq[i:i+size]
    sz = fh.size
    data = fh.data[:sz]
    s = []
    for c in data:
        s.append("%02x" % c)
    FH = "FH(%d)" % sz
    lFH = len(FH)
    s =  string.join(s,'')
    sb = s[:76-indent-lFH]
    se = s[76-indent-lFH:]
    print ' ' * indent, FH, sb
    for ss in chunk(se, 76-indent - lFH):
        print ' ' * (indent + lFH + 1), ss

# Print nlm_blocked list

def print_nlm_blocked_clnt(nlm_blocked):
    lh = ListHead(nlm_blocked, "struct nlm_wait")
    if (len(lh)):
        print "  ................ Waiting For Locks ........................."

    for block in lh.b_list:
	fl_blocked = block.b_lock
	owner = fl_blocked.fl_u.nfs_fl.owner.pid 
        haddr = block.b_host.h_addr.castTo("struct sockaddr_in")
	ip = ntodots(haddr.sin_addr.s_addr)
	print "    ----  ", block
	#inode = fl_blocked.fl_file.f_dentry.d_inode
        inode = fl_blocked.Inode
	nfs_inode = container_of(inode, "struct nfs_inode", "vfs_inode")
        print "     ", inode, nfs_inode
	fh = nfs_inode.fh
        fl_start = fl_blocked.fl_start
        fl_end = fl_blocked.fl_end
        if (fl_end == OFFSET_MAX):
            length = 0
        else:
            length = (fl_end - fl_start + 1) & OFFSET_MASK
	print "         fl_start=%d fl_len=%d owner=%d ip=%s" % (fl_start,
                                                          length, owner, ip)
	# Print FH-data
	printFH(fh, 8)

# built-in crash command 'files -l' is broken on recent kernels
#   On newer kernels (e.g. 2.6.20) we have
# static struct hlist_head	nlm_files[FILE_NRHASH];
#   On older kernels (e.g. 2.6.9-2.6.18) we have
# static struct nlm_file *	nlm_files[FILE_NRHASH];
def new_print_nlm_files():
    nlm_files = readSymbol("nlm_files")
    print "  -- Files NLM locks for clients ----"
    for h in nlm_files:
        if (h.first == 0):
            continue
        #print h
        for e in hlist_for_each_entry("struct nlm_file", h, "f_list"):
            f_file = e.f_file
            f_path = f_file.f_path
            print "    File:", get_pathname(f_path.dentry, f_path.mnt), \
                  "   ", e
            for fl in readStructNext(e.Inode.i_flock, "fl_next"):
                lockhost = fl.fl_owner.castTo("struct nlm_host")
                print "       Host:", lockhost.h_name

def print_nlm_files():
    nlm_files = readSymbol("nlm_files")
    print "  -- Files NLM locks for clients ----"
    for e in nlm_files:
	if (not e):
	    continue
	# Deref the pointer
        e = Deref(e)	

	f_file = e.f_file
	f_path = f_file.f_path
	print "    File:", get_pathname(f_path.dentry, f_path.mnt), \
		"   ", e
	for fl in readStructNext(e.Inode.i_flock, "fl_next"):
	    lockhost = fl.fl_owner.castTo("struct nlm_host")
	    print "       Host:", lockhost.h_name

# Print nfs-server info
def print_nfs_server(nfs, mntpath = None):
    print "    --%s %s:%s" % (str(nfs), nfs.Hostname, mntpath)
    print "       flags=<%s>," % dbits2str(nfs.flags, NFS_flags, 10),
    print " caps=<%s>" % dbits2str(nfs.caps, NFS_caps, 8),
    print " rsize=%d, wsize=%d" % (nfs.rsize, nfs.wsize)
    # Here the verbose sections starts
    if (True):
	return
    print "       acregmin=%d, acregmax=%d, acdirmin=%d, acdirmax=%d" % \
          (nfs.acregmin, nfs.acregmax, nfs.acdirmin, nfs.acdirmax)
    # Stats for nfs_server (struct nfs_iostats *io_stats;) are not very
    # interesting (just events/bytes per cpu). So let us rather print
    # stats for nfs_client


nfs_mounts = []

# FIll-in and return a list of info about mounted NFS-shares. 
def get_nfs_mounts():    
    del nfs_mounts[:]
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        if (fstype == "nfs"):
            vfsmount = readSU("struct vfsmount" , vfsmount)
            sb = readSU("struct super_block", superblk)
            srv = readSU("struct nfs_server", sb.s_fs_info)
	    srv_host = srv.Hostname
            nfs_mounts.append((srv_host, srv, mnt))
    return nfs_mounts

def print_nfsmount():
    print "  ............. struct nfs_server ....................."
    nfs_cl_dict = {}
    for hostname, srv, mnt in nfs_mounts:
        print_nfs_server(srv, mnt)
	try:
	   nfs_cl = srv.nfs_client
	   nfs_cl_dict[long(nfs_cl)] = nfs_cl
	except KeyError:
	    # This is old 2.6, no struct nfs_client
	    rpc_clnt = srv.client
	    addr_in = srv.addr
	    ip = ntodots(addr_in.sin_addr.s_addr)
	    print "        IP=%s" % ip
    if (nfs_cl_dict):
	print "  ............. struct nfs_client ....................."
	for nfs_cl in nfs_cl_dict.values():
	    # At this moment, only IPv4
	    addr_in = nfs_cl.cl_addr.castTo("struct sockaddr_in")
	    ip = ntodots(addr_in.sin_addr.s_addr)
	    print "     ---", nfs_cl, nfs_cl.cl_hostname, ip
	    rpc_clnt = nfs_cl.cl_rpcclient
	    #print rpc_clnt, rpc_clnt.cl_metrics
    
    # Stats are per RPC program, and all clients are using "NFS" 
    cl_stats = rpc_clnt.cl_stats 
    rpc_prog = cl_stats.program
    print "  .... Stats for program ", rpc_prog.name
    cl_stats.Dump()


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

#print_rpc_status()
#print_test()
#get_all_tasks_old()

HZ = sys_info.HZ

# Printing info for NFS-client
def host_as_client():
    print '*'*20, " Host As A NFS-client ", '*'*20
    print_nfsmount()
    print_nlm_blocked_clnt(clnt)

#print_nlm_files()

    

# Printing info for NFS-server
def host_as_server():

    print '*'*20, " Host As A NFS-server ", '*'*20

    # Exportes filesystems
    print_nfs_exports(1)

    # Locks we are holding for clients
    print_nlm_files()

    # Time in seconds - show only the recent ones
    new_enough = 10
    lru_head = sym2addr("lru_head")
    rpc_list = []
    if (lru_head):
        sn = "struct svc_cacherep"
        jiffies = readSymbol("jiffies")
        offset = member_offset(sn, "c_hash")
        for e in ListHead(lru_head, sn).c_lru:
            #print e
            #print e, ntodots(e.c_addr.sin_addr.s_addr), e.c_timestamp, e.c_state
	    if (e.c_state == 0):       # RC_UNUSED
		continue
            hnode = e.c_hash
            for he in readList(hnode, 0):
                hc = readSU(sn, he-offset)
                secago = (jiffies-hc.c_timestamp)/HZ
                if (secago > new_enough):
                    continue
                rpc_list.append((secago, hc))
                
        if (rpc_list):
            rpc_list.sort()
            print "  -- Recent RPC Reply-cache Entries (most recent first)"
            for secago, hc in rpc_list:
                prot = protoName(hc.c_prot)
                proc = hc.c_proc
		try:
		    saddr = format_sockaddr_in(hc.c_addr)
		except TypeError:
		    saddr = "n/a"
                print "   ", hc, prot, saddr, secago, hc.c_state
                


if ( __name__ == '__main__'):
    from optparse import OptionParser, SUPPRESS_HELP

    op =  OptionParser()


    op.add_option("-a", dest="All", default = 0,
                  action="store_true",
                  help="print all")
		  
    op.add_option("--server", dest="Server", default = 0,
                  action="store_true",
                  help="print info about this host as an NFS-server")
    
    op.add_option("--client", dest="Client", default = 0,
                  action="store_true",
                  help="print info about this host as an NFS-client")
		  
    op.add_option("--rpctasks", dest="Rpctasks", default = 0,
                  action="store_true",
                  help="print RPC tasks")
		  
    
    (o, args) = op.parse_args()
    
    if (o.Client):
        if (nfs_avail["nfs"] and get_nfs_mounts()):
	    host_as_client()
	     
    if (o.Server):
	if (nfs_avail["nfsd"]):
	    host_as_server()
    
    if (o.Rpctasks):
	    print_all_rpc_tasks()
