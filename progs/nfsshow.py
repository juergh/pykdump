#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Time-stamp: <14/06/04 12:14:22 alexs>

# --------------------------------------------------------------------
# (C) Copyright 2006-2014 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------

# Print info about NFS/RPC

from __future__ import print_function

__version__ = "1.0.1"

from collections import Counter

from pykdump.API import *

# For FS stuff
from LinuxDump.fs import *

# Mutex
from LinuxDump.KernLocks import decode_mutex

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

# The debuggable versions of modules we need
# There is no easy way to understand whether the loaded module is debuginfo
# or not - e.g. on a live testing systems the default modules can contain
# symbolic info. So we just check for some struct definitions

__needed_kmods = ('nfs', 'nfsd', 'sunrpc', 'lockd')
__needed_kmods_info = '''
To use this program, you need 'crash' to be able to find
some extra debuginfo DLKMs, not just vmlinux. These modules should either
be somewhere where 'crash' can find them, or you can extract them and put
into the same directory where vmcore resides. Here is the list of modules
you need:
  ''' + "\n  ".join(__needed_kmods)

__needed_structs = ("struct rpc_task", "struct nlm_wait",
                    "struct svc_export", "struct ip_map")

__NO_NFSD = False

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

#  * Reserved bit positions in xprt->state (3.10 kernel)
#  */
__XPRT_C = '''
#define XPRT_LOCKED             0
#define XPRT_CONNECTED          1
#define XPRT_CONNECTING         2
#define XPRT_CLOSE_WAIT         3
#define XPRT_BOUND              4
#define XPRT_BINDING            5
#define XPRT_CLOSING            6
#define XPRT_CONNECTION_ABORT   7
#define XPRT_CONNECTION_CLOSE   8
#define XPRT_CONGESTED          9
'''

__XPRT_BITS = CDefine(__XPRT_C)
# For 3.0 we need to replace XPRT_CONGESTED->XPRT_INITIALIZED
if (sys_info.kernel < "3.10.0"):
    __XPRT_BITS["XPRT_INITIALIZED"] = __XPRT_BITS["XPRT_CONGESTED"]
    del __XPRT_BITS["XPRT_CONGESTED"]

# Convert it to proper bits
XPRT_BITS = {k: 1<<v for k,v in __XPRT_BITS.items()}
#print(XPRT_BITS)
#print (dbits2str(17, XPRT_BITS))

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
    if (not 'nfsd' in lsModules()):
        global __NO_NFSD
        __NO_NFSD = True
        try:
            missing_structs.remove("struct svc_export")
        except ValueError:
            pass
    if (missing_structs):
        s = ", ".join(missing_structs)
        print("+++Cannot find symbolic info for:\n  {}".format(s))
        print(__needed_kmods_info)
        sys.exit(0)

# Computer offsets and create pseudoattrs
def finalize_Structures():
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
    print ("----- NFS FH (/proc/net/rpc/nfsd.fh)------------")
    if (v >= 0):
        print ("#domain fsidtype fsid [path]")
    entries = 0
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
        entries += 1
        if (v >=0):
            print (s)

    if (v < 0):
        # Summary
        print("    {} entries".format(entries))



# NFS Export Cache (as reported by /proc/net/rpc/nfsd.export/contents)
def print_nfsd_export(v=0):
    ip_table = getCache("nfsd.export")
    print ("----- NFS Exports (/proc/net/rpc/nfsd.export)------------")
    entries = 0
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
            entries += 1
            if (v > 0):
                extra = "  {}".format(exp)
            else:
                extra = ""
            if (v >=0):
                print ("    ", pathname, exp.ex_client.name, extra)

    if (v < 0):
        # Summary
        print("    {} entries".format(entries))


# IP Map Cache (as reported by /proc/net/rpc/auth.unix.ip/contents)
def print_ip_map_cache():
    ip_table = getCache("auth.unix.ip")
    print ("-----IP Map (/proc/net/rpc/auth.unix.ip)------------")
    #         nfsd              192.168.0.6  192.168.0/24
    print ("    #class              IP         domain")
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
        print ("    %-8s %20s  %s" % (im.m_class, addr_s, dom))

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
    print ("-----GID Map (/proc/net/rpc/auth.unix.gid)------------")
    print ("#uid cnt: gids...")
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
        print ("".join(out))

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
def print_rpc_task(s, v = 0):
    # On a live system we can easily get bad addresses
    try:
        #print s
        cl_pi = s.CL_procinfo
        rpc_proc = s.P_proc
        tk_client = s.tk_client
        tk_status = s.tk_status
	#pn = cl_pi[rpc_proc].p_name
        #pn = tk_client.cl_protname
        cl_xprt= tk_client.cl_xprt
        addr_in = cl_xprt.addr.castTo("struct sockaddr_in")
	ip = ntodots(addr_in.sin_addr.s_addr)
        print ("\tProtocol=",cl_xprt.prot, ", Server=", tk_client.cl_server, ip)
        if (v > 1):
            print("\t ", tk_client)
            print("\t ", cl_xprt)

        print ("\t  procname=", tk_client.cl_protname)

        vers = s.CL_vers
        prog = s.CL_prog
        if (prog == 100003 and vers == 2):
            procname = "%d(%s)" % (rpc_proc, NFS2_PROCS.value2key(rpc_proc))
        elif (prog == 100003 and vers == 3):
            procname = "%d(%s)" % (rpc_proc, NFS3_PROCS.value2key(rpc_proc))
        else:
            procname = "%d" % rpc_proc
        print ("\t  rpc_proc={}  tk_status={}".format(procname, tk_status))

        print ("\t  pmap_prog=", prog, ", pmap_vers=", vers)

	rqst = s.tk_rqstp

	if (rqst):
            if(rqst.rq_retries):
                print ("\t  rq_retries=", rqst.rq_retries, "rq_timeout=", rqst.rq_timeout,\
                "rq_majortimeo", rqst.rq_majortimeo)
            #print("\t  rq_slen={}".format(rqst.rq_snd_buf.len))
	tk_callback = s.tk_callback
	if (tk_callback):
	    print ("\t  callback=%s" % addr2sym(tk_callback))
    except crash.error:
        pass

# decode/print xprt
def print_xprt(xprt, v = 0):
    try:
        print ("      ...", xprt, "...")
        print("        state={}".format(dbits2str(xprt.state, XPRT_BITS)))
        jiffies = readSymbol("jiffies")
        print ("        last_used %s s ago" % __j_delay(xprt.last_used, jiffies))
        if (v < 1):
            return
        for qn in ("binding", "sending","resend", "pending", "backlog"):
            try:
                print ("        len(%s) queue is %d" % (qn,
                                                    getattr(xprt, qn).qlen))
            except KeyError:
                pass
        try:
            xprt.stat.Dump()
        except KeyError:
            # There is no 'stat' field in xprt on 2.6.9
            pass
    except (IndexError, crash.error):
        # Null pointer and invalid addr
        return
    print("")

# print all rpc pending tasks
def print_all_rpc_tasks(v=1):
    # Obtain all_tasks
    tasks = get_all_rpc_tasks()
    if (symbol_exists("all_tasks")):
        flen = getListSize(sym2addr("all_tasks"), 0, 10000000)
    else:
        flen = len(tasks)
    xprtlist = []
    print ("  ------- %d RPC Tasks ---------" % flen)
    allc = get_all_rpc_clients()
    if (allc):
        print ("      --- %d RPC Clients ----" % len(allc))
    for t in tasks:
        if (v >= 0):
            print ("    ---", t)
            print_rpc_task(t, v)
        # On a live kernel pointers may get invalid while we are processing
        try:
            xprt = t.tk_rqstp.rq_xprt
            if (not xprt in xprtlist):
                xprtlist.append(xprt)
            #print_rpc_task(t)
        except (IndexError, crash.error):
            # Null pointer and invalid addr
            continue
    # Print XPRT vitals
    print (" --- XPRT Info ---")
    for xprt in xprtlist:
        print_xprt(xprt, 2)

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
    print ("all_tasks has %d elements" % getListSize(all_tasks, 0, 10000000))
    return
    for qname in ("schedq", "childq", "delay_queue"):
        tasks = readSU("struct rpc_wait_queue", sym2addr(qname)).tasks
	print ("Number of elements in %15s:" % qname, end='')
        for lh in tasks:
	    #print hexl(Addr(lh))
	    print (" [%d] " % getListSize(Addr(lh), 0, 10000000), end='')
	print ("")

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
        print (cl)
        # Print Task Info
        for ft in v:
	    for t in readSUListFromHead(long(ft.tk_task), "tk_task",
                                   "struct rpc_task"):
		print ("    ", t)
		print_rpc_task(t)


# Get all RPC clients for kernels where they exist
def get_all_rpc_clients():
    all_clients = sym2addr("all_clients")
    if (all_clients == -1):
        return []
    return readSUListFromHead(all_clients, "cl_clients", "struct rpc_clnt")

def get_all_rpc_tasks():
    all_taddr = sym2addr("all_tasks")
    if (all_taddr):
	return readSUListFromHead(all_taddr, "tk_task", "struct rpc_task")

    out = []
    allc = get_all_rpc_clients()
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
            print (sb, fsname, \
                  "len(s_dirty)=%d len(s_io)=%d" % (len(s_dirty),len(s_io)))



def INT_LIMIT(bits):
    return (~(1 << (bits - 1)))


# Print 'struct file_lock' info
def print_file_lock(fl):
    lockhost = fl.fl_owner.castTo("struct nlm_host")
    print (lockhost)

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
    print (' ' * indent, FH, sb)
    for ss in chunk(se, 76-indent - lFH):
        print (' ' * (indent + lFH + 1), ss)


# Print 'struct svc_serv'
# 2.6.18 kernel
#   On this kernel, sv_permsock is a list of svc_sock linked via sk_list
# 2.6.35 kernel
#   On this kernel, sv_permosck is a list of svc_sock linked via sk_xprt.xpt_list
def print_svc_serv(srv):
    print ("  -- Sockets Used by NLM")
    print ("     -- Permanent Sockets")
    for s in ListHead(Addr(srv.sv_permsocks), "struct svc_sock").SockList:
	print ("\t", s, "\n  ", IP_sock(s.sk_sk))
    if (srv.sv_tmpcnt):
	print (" -- Temp Sockets")
        for s in ListHead(Addr(srv.sv_tempsocks), "struct svc_sock").SockList:
	    print ("\t", s, "\n  ", IP_sock(s.sk_sk))


# On 2.6.35 we have a list of registered transports
# static LIST_HEAD(svc_xprt_class_list);

def XXprint_nlm_serv():
    # This exists on 2.6.18 but not on 2.6.35
    addr = sym2addr("svc_xprt_class_list")
    ll = ListHead(addr, "struct svc_xprt_class").xcl_list
    for s in ll:
        print (s)
    for c in get_all_clients():
        print (c, c.cl_protname)

# Print NLM stuff

def print_nlm_serv():
    # This exists on 2.6.18 but not on 2.6.35
    try:
        svc_serv = readSymbol("nlmsvc_serv")
    except TypeError:
        # On 2.6.35 we have
        # static struct svc_rqst		*nlmsvc_rqst;
        nlmsvc_rqst = readSymbol("nlmsvc_rqst")
        # This is NULL if we are NFSv3-only
        if (not nlmsvc_rqst):
            return
        # Maybe we should print svc_rqst here?
        svc_serv = nlmsvc_rqst.rq_server
    print_svc_serv(svc_serv)

# Print nlm_blocked list

def print_nlm_blocked_clnt(nlm_blocked):
    lh = ListHead(nlm_blocked, "struct nlm_wait")
    if (len(lh)):
        print ("  ................ Waiting For Locks .........................")

    for block in lh.b_list:
	fl_blocked = block.b_lock
	owner = fl_blocked.fl_u.nfs_fl.owner.pid
        haddr = block.b_host.h_addr.castTo("struct sockaddr_in")
	ip = ntodots(haddr.sin_addr.s_addr)
	print ("    ----  ", block)
	#inode = fl_blocked.fl_file.f_dentry.d_inode
        inode = fl_blocked.Inode
	nfs_inode = container_of(inode, "struct nfs_inode", "vfs_inode")
        print ("     ", inode, nfs_inode)
	fh = nfs_inode.fh
        fl_start = fl_blocked.fl_start
        fl_end = fl_blocked.fl_end
        if (fl_end == OFFSET_MAX):
            length = 0
        else:
            length = (fl_end - fl_start + 1) & OFFSET_MASK
	print ("         fl_start=%d fl_len=%d owner=%d ip=%s" % (fl_start,
                                                          length, owner, ip))
	# Print FH-data
	printFH(fh, 8)

# built-in crash command 'files -l' is broken on recent kernels
#   On newer kernels (e.g. 2.6.20) we have
# static struct hlist_head	nlm_files[FILE_NRHASH];
#   On older kernels (e.g. 2.6.9-2.6.18) we have
# static struct nlm_file *	nlm_files[FILE_NRHASH];

def print_nlm_files():
    nlm_files = readSymbol("nlm_files")
    once = TrueOnce(1)

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
	if (once):
            print ("  -- Files NLM locks for clients ----")
	print ("    File:", get_pathname(f_file.Dentry, f_file.Mnt))
	print ("         ", e)
	for fl in readStructNext(e.Inode.i_flock, "fl_next"):
	    lockhost = fl.fl_owner.castTo("struct nlm_host")
	    print ("       Host:", lockhost.h_name)

# Print info for remote nfs-server (we are a client!)
def print_remote_nfs_server(nfs, mntpath):
    print ("    --%s %s:%s" % (str(nfs), nfs.Hostname, mntpath))
    print ("       flags=<%s>," % dbits2str(nfs.flags, NFS_flags, 10), end='')
    print (" caps=<%s>" % dbits2str(nfs.caps, NFS_caps, 8), end='')
    print (" rsize=%d, wsize=%d" % (nfs.rsize, nfs.wsize))
    # Here the verbose sections starts
    if (True):
	return
    print ("       acregmin=%d, acregmax=%d, acdirmin=%d, acdirmax=%d" % \
          (nfs.acregmin, nfs.acregmax, nfs.acdirmin, nfs.acdirmax))
    # Stats for nfs_server (struct nfs_iostats *io_stats;) are not very
    # interesting (just events/bytes per cpu). So let us rather print
    # stats for nfs_client


nfs_mounts = []

# Fill-in and return a list of info about mounted NFS-shares.
def get_nfs_mounts():
    del nfs_mounts[:]
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        if (fstype in ("nfs", "nfs4")):
            vfsmount = readSU("struct vfsmount" , vfsmount)
            sb = readSU("struct super_block", superblk)
            srv = readSU("struct nfs_server", sb.s_fs_info)
	    srv_host = srv.Hostname
            nfs_mounts.append((srv_host, srv, mnt))
    return nfs_mounts

def print_nfsmount(v = 0):
    if (v):
        print (" Mounted NFS-shares ".center(70, '-'))
    else:
        # Object to be used for summary
        count_all = 0
        count_flag = Counter()
        count_caps = Counter()
    nfs_cl_dict = {}
    for hostname, srv, mnt in nfs_mounts:
        if(v):
            print_remote_nfs_server(srv, mnt)
        else:
            # Prepare a summary
            count_all += 1
            count_flag[dbits2str(srv.flags, NFS_flags, 10)] += 1
            count_caps[dbits2str(srv.caps, NFS_caps, 8)] += 1
	try:
	   nfs_cl = srv.nfs_client
	   nfs_cl_dict[long(nfs_cl)] = nfs_cl
	except KeyError:
	    # This is old 2.6, no struct nfs_client
	    rpc_clnt = srv.client
	    addr_in = srv.addr
	    ip = ntodots(addr_in.sin_addr.s_addr)
	    if (v):
                print ("        IP=%s" % ip)
    if (v == 0 and count_all):
        # Print a summary
        print(" {} mounted shares, by flags/caps:".format(count_all))
        for k, v in count_flag.items():
            print ("  {:3d} shares with flags=<{}>".format(v, k))
        for k, v in count_caps.items():
            print ("  {:3d} shares with caps=<{}>".format(v, k))
    if (nfs_cl_dict):
	print ("  ............. struct nfs_client .....................")
	for nfs_cl in nfs_cl_dict.values():
	    # At this moment, only IPv4
	    addr_in = nfs_cl.cl_addr.castTo("struct sockaddr_in")
	    ip = ntodots(addr_in.sin_addr.s_addr)
	    print ("     ---", nfs_cl, nfs_cl.cl_hostname, ip)
	    rpc_clnt = nfs_cl.cl_rpcclient
	    # Print/decode the transport
	    xprt = rpc_clnt.cl_xprt
            print_xprt(xprt, detail)
	    #print rpc_clnt, rpc_clnt.cl_metrics

    # Stats are per RPC program, and all clients are using "NFS"
    cl_stats = rpc_clnt.cl_stats
    rpc_prog = cl_stats.program
    print ("  .... Stats for program ", rpc_prog.name)
    cl_stats.Dump()

# Decode sockaddr_storage and return (ip, port). Works for AF_INET and AF_INET6.
# For unknown families, returns ("Unknown family", None)
# For ss_faimily=0 returns (None, None)
def decode_ksockaddr(ksockaddr):
    family = ksockaddr.ss_family
    # char __data[126]
    data = ksockaddr.__data.ByteArray
    if (family == socket.AF_INET):
        port = data[0]*256+data[1]
        ip = socket.inet_ntop(socket.AF_INET, struct.pack(4*'B', *data[2:2+4]))
        return (ip, port)
    elif (family == socket.AF_INET6):
        port = data[0]*256+data[1]
        ip = socket.inet_ntop(socket.AF_INET6, struct.pack(16*'B', *data[6:6+16]))
        return (ip, port)
    elif (family == 0):
        return (None, None)
    else:
        return ("Unknown family {}".format(family), None)

def print_svc_xprt(v = 0):
    # Get nfsd_serv. On 2.6.32 it was a global variable, later it was moved
    # to init_net.gen[nfsd_net_id]
    # On 2.6.18 it is a global variable but lists are different
    try:
        nfsd_serv = readSymbol("nfsd_serv")
    except TypeError:
        try:
            # On recent kernels, there are many  interesting
            # tables in "init_net", but not on 2.6.32 it is not available
            nfsd_net_id = readSymbol("nfsd_net_id") - 1
            net = get_ns_net()
            nfsd_net_ptr = net.gen.ptr[nfsd_net_id]
            nfsd_net = readSU("struct nfsd_net", nfsd_net_ptr)
            nfsd_serv = nfsd_net.nfsd_serv
        except KeyError:
            return
    if (not nfsd_serv):
        # No NFS-server running on this host
        return

    if (v >= 0):
        print (" ============ SVC Transports/Sockets ============")
    sn = "struct svc_xprt"              # RHEL6
    if (struct_exists(sn)):
        lnk = "xpt_list"
    else:
        sn = "struct svc_sock"          # RHEL5
        lnk = "sk_list"
    for st, lst in (
        ("sv_permsocks", ListHead(nfsd_serv.sv_permsocks, sn)),
        ("sv_tempsocks", ListHead(nfsd_serv.sv_tempsocks, sn ))):

        if (v >= 0):
            print("\n *** {} ***".format(st))

        for x in getattr(lst, lnk):
            if (sn == "struct svc_xprt"):       # RHEL6
                mutex =  x.xpt_mutex
                s_struct ='{!s:-^50}{:-^28}'.format(x, addr2sym(x.xpt_class))
                laddr = (l_ip, l_port) = decode_ksockaddr(x.xpt_local)
                raddr = (r_ip, r_port) = decode_ksockaddr(x.xpt_remote)
                s_addr = "  Local: {} Remote: {}".format(laddr, raddr)
            else:
                mutex = x.sk_mutex
                s_struct = '{!s:-^78}'.format(x)
                s_addr = str(IP_sock(x.sk_sk))
            counter = mutex.count.counter
            if (v >= 0 or counter != 1):
                print(s_struct)
                print(s_addr)
            if (counter != 1):
                print("   +++ mutex is in use +++", mutex)
                decode_mutex(mutex)


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
def host_as_client(v = 0):
    print ('*'*20, " Host As A NFS-client ", '*'*20)
    print_nfsmount(v)
    print_nlm_blocked_clnt(clnt)

#print_nlm_files()



# Printing info for NFS-server
def host_as_server(v = 0):

    if (__NO_NFSD):
        return
    print ('*'*20, " Host As A NFS-server ", '*'*20)

    # Exportes filesystems
    if (v >= 0):
        print_ip_map_cache()
        print ("")
    print_nfsd_export(v)
    print ("")
    print_nfsd_fh(v)
    print ("")
    if (v >= 0):
        print_unix_gid(v)
        print ("")

    # Locks we are holding for clients
    print_nlm_files()

    print_svc_xprt(v)

    # Print RPC-reply cache only when verbosity>=2
    if (v >=0 and v < 2):
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
            if (v < 0):
                print(" -- {} RPC Reply-cache Entries in last 10s".format(
                    len(rpc_list)))
                return
            print ("  -- Recent RPC Reply-cache Entries (most recent first)")
            for secago, hc in rpc_list:
                prot = protoName(hc.c_prot)
                proc = hc.c_proc
		try:
		    saddr = format_sockaddr_in(hc.c_addr)
		except TypeError:
		    saddr = "n/a"
                print ("   ", hc, prot, saddr, secago, hc.c_state)


detail = 0

if ( __name__ == '__main__'):
    import argparse

    parser =  argparse.ArgumentParser()


    parser.add_argument("-a","--all", dest="All", default = 0,
                  action="store_true",
                  help="print all")

    parser.add_argument("--server", dest="Server", default = 0,
                  action="store_true",
                  help="print info about this host as an NFS-server")

    parser.add_argument("--client", dest="Client", default = 0,
                  action="store_true",
                  help="print info about this host as an NFS-client")

    parser.add_argument("--rpctasks", dest="Rpctasks", default = 0,
                  action="store_true",
                  help="print RPC tasks")

    parser.add_argument("--locks", dest="Locks", default = 0,
		    action="store_true",
		    help="print NLM locks")
    parser.add_argument("--version", dest="Version", default = 0,
                  action="store_true",
                  help="Print program version and exit")


    parser.add_argument("-v", dest="Verbose", default = 0,
	action="count",
	help="verbose output")


    o = args = parser.parse_args()

    detail = o.Verbose

    if (o.Version):
        print ("nfsshow version %s" % (__version__))
        sys.exit(0)

    if (o.Client or o.All):
        if (get_nfs_mounts()):
	    host_as_client(detail)

    if (o.Server or o.All):
        host_as_server(detail)

    if (o.Rpctasks or o.All):
	print_all_rpc_tasks(detail)

    if (o.Locks or o.All):
        print ('*'*20, " NLM(lockd) Info", '*'*20)
	print_nlm_files()
	print_nlm_serv()

    # If no options have been provided, print just a summary
    if (len(sys.argv) > 1):
        sys.exit(0)

    if (get_nfs_mounts()):
        host_as_client()

    # As server
    host_as_server(-1)

    # RPC tasks
    print(" RPC ".center(70, '='))
    print_all_rpc_tasks(-1)



