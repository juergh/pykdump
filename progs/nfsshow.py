#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Time-stamp: <11/04/27 12:51:21 alexs>

# Copyright (C) 2010-2011 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2010-2011 Hewlett-Packard Co., All rights reserved.

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
                  ("nfsd", "struct svc_export"),
                  ("sunrpc", "struct ip_map")
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



# -- get a generator for a cache with a given name. We iterate
# both through hash-table and its buckets and return non-null
# 'struct cache_head'
def getCache(cname):
    details = None
    cache_list = ListHead(sym2addr("cache_list"), "struct cache_detail")
    
    for c in cache_list.others:
        if (c.name == cname):
            details = c
            break

    if (not details):
        return
    
    table = details.hash_table
    size = details.hash_size
    for i in range(size):
        ch1 = table[i]
        if (not ch1):
            continue
        ch1 = Deref(ch1)
        for ch in readStructNext(ch1, "next"):
            #print ch, ch.flags
            yield ch




# Getting addr form ip_map.m_addr
#struct in6_addr {
#    union {
#        __u8 u6_addr8[16];
#        __be16 u6_addr16[8];
#        __be32 u6_addr32[4];
#    } in6_u;
#}

#define	CACHE_VALID	0	/* Entry contains valid data */
#define	CACHE_NEGATIVE	1	/* Negative entry - there is no match for the key */
#define	CACHE_PENDING	2	/* An upcall has been sent but no reply received yet*/

__CACHE_VALID = 0
__CACHE_NEGATIVE = 1

def test_bit(nbit, val):
    return ((val >> nbit) == 1)

def _test_cache(ch):
    #	if (test_bit(CACHE_VALID, &h->flags) &&
    #    !test_bit(CACHE_NEGATIVE, &h->flags))
    return (test_bit(__CACHE_VALID, ch.flags) and not
            test_bit(__CACHE_NEGATIVE, ch.flags))


# static inline int key_len(int type)
# {
# 	switch(type) {
# 	case FSID_DEV:		return 8;
# 	case FSID_NUM: 		return 4;
# 	case FSID_MAJOR_MINOR:	return 12;
# 	case FSID_ENCODE_DEV:	return 8;
# 	case FSID_UUID4_INUM:	return 8;
# 	case FSID_UUID8:	return 8;
# 	case FSID_UUID16:	return 16;
# 	case FSID_UUID16_INUM:	return 24;
# 	default: return 0;
# 	}
# }

def key_len(t):
    if (t == __F.FSID_DEV):   return 8
    elif(t == __F.FSID_NUM):  return 4
    elif(t == __F.FSID_MAJOR_MINOR):	return 12
    elif(t == __F.FSID_ENCODE_DEV):	return 8
    elif(t == __F.FSID_UUID4_INUM):	return 8
    elif(t == __F.FSID_UUID8):	return 8
    elif(t == __F.FSID_UUID16):	return 16
    elif(t == __F.FSID_UUID16_INUM):	return 24
    else: return 0

# Older kernels
def key_len_old(t):
    if (t == 0):   return 8
    elif(t == 1):  return 4
    elif(t == 2):	return 12
    elif(t == 3):	return 8
    else: return 0
    
# NFS Export Cache (as reported by /proc/net/rpc/nfsd.export/contents)
# #domain fsidtype fsid [path]
# 192.168.0/24 1 0x00000000 /
# 192.168.0/24 6 0x4b47467c994212335620b49e04ab2baf /data

def print_nfsd_fh(v=0):
    ip_table = getCache("nfsd.fh")
    print "----- NFS FH (/proc/net/rpc/nfsd.fh)------------"
    print "#domain fsidtype fsid [path]"
    for ch in ip_table:
        ek = container_of(ch, "struct svc_expkey", "h")
        out = []
        out.append("%s %d 0x" %( ek.ek_client.name, ek.ek_fsidtype))
        #for (i=0; i < key_len(ek->ek_fsidtype)/4; i++)
	#	seq_printf(m, "%08x", ek->ek_fsid[i]);
        for i in range(key_len(ek.ek_fsidtype)/4):
            out.append("%08x" % ek.ek_fsid[i])

        if (_test_cache(ch)):
            # On older kernels we have ek.ek_mnt and ek.ek_dentry
            # On newer ones exp.ek_path.mnt and ek.ek_path.dentry
            try:
                path = ek.ek_path
                pathname = get_pathname(path.dentry, path.mnt)
            except:
                pathname = get_pathname(ek.ek_dentry, ek.ek_mnt)
            out.append(" " + pathname)
        s = "".join(out)
        print s

# NFS Export Cache (as reported by /proc/net/rpc/nfsd.export/contents)
def print_nfsd_export(v=0):
    ip_table = getCache("nfsd.export")
    print "----- NFS Exports (/proc/net/rpc/nfsd.export)------------"
    for ch in ip_table:
        exp = container_of(ch, "struct svc_export", "h")
        if (_test_cache(ch)):
            # On older kernels we have exp.ex_mnt and exp.ex_dentry
            # On newer ones exp.ex_path.mnt and exp.exp_path.dentry
            try:
                path = exp.ex_path
                pathname = get_pathname(path.dentry, path.mnt)
            except:
                pathname = get_pathname(exp.ex_dentry, exp.ex_mnt)
            print "    ", pathname, exp.ex_client.name,
            if (v):
                print "  ", exp
            else:
                print ""

            
# IP Map Cache (as reported by /proc/net/rpc/auth.unix.ip/contents)
def print_ip_map_cache():
    ip_table = getCache("auth.unix.ip")
    print "-----IP Map (/proc/net/rpc/auth.unix.ip)------------"
    #         nfsd              192.168.0.6  192.168.0/24
    print "    #class              IP         domain"
    for ch in ip_table:
        im = container_of(ch, "struct ip_map", "h")
        dom = ""
        if (_test_cache(ch)):
            dom = im.m_client.h.name;
	# On new kernels, m_addr is 'strict in6_addr'
	# On old (2.6.18) it is just 'struct in_addr'
	addr = im.m_addr
	if (addr.hasField("s_addr")):
	    # IPv4-only
	    addr_s = ntodots(addr.s_addr)
	else:
	    # IPv6
	    if (ipv6_addr_v4mapped(im.m_addr)):
		addr_s =  ntodots(im.m_addr.in6_u.u6_addr32[3])
	    else:
		addr_s = ntodots6(im.m_addr)
        print "    %-8s %20s  %s" % (im.m_class, addr_s, dom)

# /* access the groups "array" with this macro */
# #define GROUP_AT(gi, i) \
# 	((gi)->blocks[(i) / NGROUPS_PER_BLOCK][(i) % NGROUPS_PER_BLOCK])

#define NGROUPS_PER_BLOCK	((unsigned int)(PAGE_SIZE / sizeof(gid_t)))

NGROUPS_PER_BLOCK = PAGESIZE/struct_size("gid_t")
def GROUP_AT(gi, i):
    return gi.blocks[i/NGROUPS_PER_BLOCK][i % NGROUPS_PER_BLOCK]

# Unix GID Cache (as reported by /proc/net/rpc/auth.unix.gid/contents)
def print_unix_gid(v=0):
    gid_table = getCache("auth.unix.gid")
    print "-----GID Map (/proc/net/rpc/auth.unix.gid)------------"
    print "#uid cnt: gids..."
    for ch in gid_table:
        ug = container_of(ch, "struct unix_gid", "h")
        dom = ""
        if (_test_cache(ch)):
            glen = ug.gi.ngroups
        else:
            glen = 0
        out = []
        out.append("%u %d:" % (ug.uid, glen))
        for i in range(glen):
            out.append(" %d" % GROUP_AT(ug.gi, i))
        print "".join(out)
                   
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
	
	if (rqst and rqst.rq_retries):
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
    flen = getListSize(sym2addr("all_tasks"), 0, 10000000)
    xprtlist = []
    print "  ------- %d RPC Tasks ---------" % flen
    for t in tasks:
	print_rpc_task(t)
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
            for qn in ("binding", "sending","resend", "pending", "backlog"):
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
    return
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


# Print 'struct svc_serv'
# 2.6.18 kernel
#   On this kernel, sv_permsock is a list of svc_sock linked via sk_list
# 2.6.35 kernel
#   On this kernel, sv_permosck is a list of svc_sock linked via sk_xprt.xpt_list
def print_svc_serv(srv):
    print "  -- Sockets Used by NLM"
    print "     -- Permanent Sockets"
    for s in ListHead(Addr(srv.sv_permsocks), "struct svc_sock").SockList:
	print "\t", s, "\n  ", IP_sock(s.sk_sk)
    if (srv.sv_tmpcnt):
	print " -- Temp Sockets"
        for s in ListHead(Addr(srv.sv_tempsocks), "struct svc_sock").SockList:
	    print "\t", s, "\n  ", IP_sock(s.sk_sk)
	

# On 2.6.35 we have a list of registered transports
# static LIST_HEAD(svc_xprt_class_list);

def XXprint_nlm_serv():
    # This exists on 2.6.18 but not on 2.6.35
    addr = sym2addr("svc_xprt_class_list")
    ll = ListHead(addr, "struct svc_xprt_class").xcl_list
    for s in ll:
        print s
    for c in get_all_clients():
        print c, c.cl_protname
        
# Print NLM stuff

def print_nlm_serv():
    # This exists on 2.6.18 but not on 2.6.35
    try:
        svc_serv = readSymbol("nlmsvc_serv")
    except TypeError:
        # On 2.6.35 we have
        # static struct svc_rqst		*nlmsvc_rqst;
        nlmsvc_rqst = readSymbol("nlmsvc_rqst")
        # Maybe we should print svc_rqst here?
        svc_serv = nlmsvc_rqst.rq_server
    print_svc_serv(svc_serv)

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

def print_nlm_files():
    nlm_files = readSymbol("nlm_files")
    print "  -- Files NLM locks for clients ----"
    def get_all_nlm_files():
        try:
            #print "New style"
            for h in nlm_files:
                if (h.first == 0):
                    continue
                #print h
                for e in hlist_for_each_entry("struct nlm_file", h, "f_list"):
                    yield e
        except (KeyError, AttributeError):
	    # struct nlm_file *nlm_files[32];
	    # struct nlm_file {
	    #     struct nlm_file *f_next;
	    
            for e in nlm_files:
                if (not e):
                    continue
                # Deref the pointer
                for e in readStructNext(e, "f_next"):
		    yield e
                
           
    for e in get_all_nlm_files():
	f_file = e.f_file
	print "    File:", get_pathname(f_file.Dentry, f_file.Mnt)
	print "         ", e
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
# The following exists on new kernels but not on old (e.g. 2.6.18)
try:
    __F = EnumInfo("enum nfsd_fsid")
except TypeError:
    __F = None
    key_len = key_len_old

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
def host_as_server(v = 0):

    print '*'*20, " Host As A NFS-server ", '*'*20

    # Exportes filesystems
    print_ip_map_cache()
    print ""
    print_nfsd_export(v)
    print ""
    print_nfsd_fh(v)
    print ""
    print_unix_gid(v)
    print ""

    # Locks we are holding for clients
    print_nlm_files()

    # Print RPC-reply cache only when verbosity>=2
    if (v < 2):
	return
    # Time in seconds - show only the recent ones
    new_enough = 10 * HZ
    lru_head = sym2addr("lru_head")
    rpc_list = []
    if (lru_head):
        sn = "struct svc_cacherep"
        jiffies = readSymbol("jiffies")
        offset = member_offset(sn, "c_hash")
        for e in ListHead(lru_head, sn).c_lru:
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
                

detail = 0

if ( __name__ == '__main__'):
    from optparse import OptionParser, SUPPRESS_HELP

    op =  OptionParser()


    op.add_option("-a","--all", dest="All", default = 0,
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

    op.add_option("--locks", dest="Locks", default = 0,
		    action="store_true",
		    help="print NLM locks")

    op.add_option("-v", dest="Verbose", default = 0,
	action="count",
	help="verbose output")

    
    (o, args) = op.parse_args()

    detail = o.Verbose
    
    if (o.Client or o.All):
        if (nfs_avail["nfs"] and get_nfs_mounts()):
	    host_as_client()
	     
    if (o.Server or o.All):
	if (nfs_avail["nfsd"]):
	    host_as_server(detail)
    
    if (o.Rpctasks or o.All):
	print_all_rpc_tasks()

    if (o.Locks or o.All):
        print '*'*20, " NLM(lockd) Info", '*'*20
	print_nlm_files()
	print_nlm_serv()

