#!/usr/bin/env/python
# --------------------------------------------------------------------
# (C) Copyright 2018-2019 Red Hat, Inc.
#
# Author: Scott Mayhew
# Author: Frank Sorenson
#
# Contributors:
# - Dave Wysochanski: Rename script and cleanup for upstream submit
# - Alex Sidorenko: improving options parsing
# --------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

__author__ = "Scott Mayhew / Frank Sorenson"
__version__ = "0.1"

from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump.fs.fs_h import *
from LinuxDump.Time import ktime_t
import textwrap
from textwrap import TextWrapper

import socket
import struct

__NFS_MOUNT_FLAGS='''
#define NFS_MOUNT_SOFT          0x0001  /* 1 */
#define NFS_MOUNT_INTR          0x0002  /* 1 */ /* now unused, but ABI */
#define NFS_MOUNT_SECURE        0x0004  /* 1 */
#define NFS_MOUNT_POSIX         0x0008  /* 1 */
#define NFS_MOUNT_NOCTO         0x0010  /* 1 */
#define NFS_MOUNT_NOAC          0x0020  /* 1 */
#define NFS_MOUNT_TCP           0x0040  /* 2 */
#define NFS_MOUNT_VER3          0x0080  /* 3 */
#define NFS_MOUNT_KERBEROS      0x0100  /* 3 */
#define NFS_MOUNT_NONLM         0x0200  /* 3 */
#define NFS_MOUNT_BROKEN_SUID   0x0400  /* 4 */
#define NFS_MOUNT_NOACL         0x0800  /* 4 */
#define NFS_MOUNT_STRICTLOCK    0x1000  /* reserved for NFSv4 */
#define NFS_MOUNT_SECFLAVOUR    0x2000  /* 5 */
#define NFS_MOUNT_NORDIRPLUS    0x4000  /* 5 */
#define NFS_MOUNT_UNSHARED      0x8000  /* 5 */
#define NFS_MOUNT_FLAGMASK      0xFFFF

/* The following are for internal use only */
#define NFS_MOUNT_LOOKUP_CACHE_NONEG    0x10000
#define NFS_MOUNT_LOOKUP_CACHE_NONE     0x20000
#define NFS_MOUNT_NORESVPORT            0x40000

#define NFS_MOUNT_LOCAL_FLOCK   0x100000
#define NFS_MOUNT_LOCAL_FCNTL   0x200000
'''

__RPC_DISPLAY_FORMAT='''
enum rpc_display_format_t {
    RPC_DISPLAY_ADDR = 0,
    RPC_DISPLAY_PORT,
    RPC_DISPLAY_PROTO,
    RPC_DISPLAY_HEX_ADDR,
    RPC_DISPLAY_HEX_PORT,
    RPC_DISPLAY_NETID,
    RPC_DISPLAY_MAX
};
'''

__RPC_AUTH_FLAVORS='''
enum rpc_auth_flavors {
    RPC_AUTH_NULL  = 0,
    RPC_AUTH_UNIX  = 1,
    RPC_AUTH_SHORT = 2,
    RPC_AUTH_DES   = 3,
    RPC_AUTH_KRB   = 4,
    RPC_AUTH_GSS   = 6,
    RPC_AUTH_MAXFLAVOR = 8,
    /* pseudoflavors: */
    RPC_AUTH_GSS_KRB5  = 390003,
    RPC_AUTH_GSS_KRB5I = 390004,
    RPC_AUTH_GSS_KRB5P = 390005,
    RPC_AUTH_GSS_LKEY  = 390006,
    RPC_AUTH_GSS_LKEYI = 390007,
    RPC_AUTH_GSS_LKEYP = 390008,
    RPC_AUTH_GSS_SPKM  = 390009,
    RPC_AUTH_GSS_SPKMI = 390010,
    RPC_AUTH_GSS_SPKMP = 390011
};
'''

__IP_PROTOS='''
enum {
    IPPROTO_IP = 0,               /* Dummy protocol for TCP               */
    IPPROTO_ICMP = 1,             /* Internet Control Message Protocol    */
    IPPROTO_IGMP = 2,             /* Internet Group Management Protocol   */
    IPPROTO_IPIP = 4,             /* IPIP tunnels (older KA9Q tunnels use 94) */
    IPPROTO_TCP = 6,              /* Transmission Control Protocol        */
    IPPROTO_EGP = 8,              /* Exterior Gateway Protocol            */
    IPPROTO_PUP = 12,             /* PUP protocol                         */
    IPPROTO_UDP = 17,             /* User Datagram Protocol               */
    IPPROTO_IDP = 22,             /* XNS IDP protocol                     */
    IPPROTO_DCCP = 33,            /* Datagram Congestion Control Protocol */
    IPPROTO_RSVP = 46,            /* RSVP protocol                        */
    IPPROTO_GRE = 47,             /* Cisco GRE tunnels (rfc 1701,1702)    */

    IPPROTO_IPV6   = 41,          /* IPv6-in-IPv4 tunnelling              */

    IPPROTO_ESP = 50,            /* Encapsulation Security Payload protocol */
    IPPROTO_AH = 51,             /* Authentication Header protocol       */
    IPPROTO_BEETPH = 94,         /* IP option pseudo header for BEET */
    IPPROTO_PIM    = 103,         /* Protocol Independent Multicast       */

    IPPROTO_COMP   = 108,                /* Compression Header protocol */
    IPPROTO_SCTP   = 132,         /* Stream Control Transport Protocol    */
    IPPROTO_UDPLITE = 136,        /* UDP-Lite (RFC 3828)                  */

    IPPROTO_RAW    = 255,         /* Raw IP packets                       */
    IPPROTO_MAX
};
'''

__ADDRESS_FAMILIES='''
/* Supported address families. */
#define AF_UNSPEC       0
#define AF_UNIX         1       /* Unix domain sockets          */
#define AF_LOCAL        1       /* POSIX name for AF_UNIX       */
#define AF_INET         2       /* Internet IP Protocol         */
#define AF_AX25         3       /* Amateur Radio AX.25          */
#define AF_IPX          4       /* Novell IPX                   */
#define AF_APPLETALK    5       /* AppleTalk DDP                */
#define AF_NETROM       6       /* Amateur Radio NET/ROM        */
#define AF_BRIDGE       7       /* Multiprotocol bridge         */
#define AF_ATMPVC       8       /* ATM PVCs                     */
#define AF_X25          9       /* Reserved for X.25 project    */
#define AF_INET6        10      /* IP version 6                 */
#define AF_ROSE         11      /* Amateur Radio X.25 PLP       */
#define AF_DECnet       12      /* Reserved for DECnet project  */
#define AF_NETBEUI      13      /* Reserved for 802.2LLC project*/
#define AF_SECURITY     14      /* Security callback pseudo AF */
#define AF_KEY          15      /* PF_KEY key management API */
#define AF_NETLINK      16
#define AF_ROUTE        AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET       17      /* Packet family                */
#define AF_ASH          18      /* Ash                          */
#define AF_ECONET       19      /* Acorn Econet                 */
#define AF_ATMSVC       20      /* ATM SVCs                     */
#define AF_RDS          21      /* RDS sockets                  */
#define AF_SNA          22      /* Linux SNA Project (nutters!) */
#define AF_IRDA         23      /* IRDA sockets                 */
#define AF_PPPOX        24      /* PPPoX sockets                */
#define AF_WANPIPE      25      /* Wanpipe API Sockets */
#define AF_LLC          26      /* Linux LLC                    */
#define AF_IB           27      /* Native InfiniBand address    */
#define AF_CAN          29      /* Controller Area Network      */
#define AF_TIPC         30      /* TIPC sockets                 */
#define AF_BLUETOOTH    31      /* Bluetooth sockets            */
#define AF_IUCV         32      /* IUCV sockets                 */
#define AF_RXRPC        33      /* RxRPC sockets                */
#define AF_ISDN         34      /* mISDN sockets                */
#define AF_PHONET       35      /* Phonet sockets               */
#define AF_IEEE802154   36      /* IEEE802154 sockets           */
#define AF_MAX          37      /* For now.. */
'''

NFS_MOUNT_FLAGS=CDefine(__NFS_MOUNT_FLAGS)
RPC_DISPLAY_FORMAT=CEnum(__RPC_DISPLAY_FORMAT)
RPC_AUTH_FLAVORS=CEnum(__RPC_AUTH_FLAVORS)
IP_PROTOS=CEnum(__IP_PROTOS)
ADDRESS_FAMILIES=CDefine(__ADDRESS_FAMILIES)

HZ = sys_info.HZ
NFS_PORT = 2049
UINT_MAX = ~0    # check this - no unsigned int's in python
NFS_OPTION_FSCACHE = 0x00000001

RPCBIND_NETID_UDP = "udp"
RPCBIND_NETID_TCP = "tcp"
RPCBIND_NETID_UDP6 = "udp6"
RPCBIND_NETID_TCP6 = "tcp6"
RPCBIND_NETID_LOCAL = "local"

def __mnt_is_readonly(v):
    mnt = readSU("struct vfsmount", v)
    if mnt.mnt_flags & MNT_FLAGS.MNT_READONLY:
        return True
    if mnt.mnt_sb.s_flags & MS_FLAGS.MS_RDONLY:
        return True
    return False

def sb_opts(s):
    fs_info = { MS_FLAGS.MS_SYNCHRONOUS: ", sync",
        MS_FLAGS.MS_DIRSYNC: ", dirsync",
        MS_FLAGS.MS_MANDLOCK: ", mand"
    }
    options = ""
    sb = readSU("struct super_block", s)
    for flag in fs_info:
        if sb.s_flags & flag:
            options += fs_info[flag]
    return options

def mnt_opts(v):
    mnt_info = { MNT_FLAGS.MNT_NOSUID: ", nosuid",
        MNT_FLAGS.MNT_NODEV: ", nodev",
        MNT_FLAGS.MNT_NOEXEC: ", noexec",
        MNT_FLAGS.MNT_NOATIME: ", noatime",
        MNT_FLAGS.MNT_NODIRATIME: ", nodiratime",
        MNT_FLAGS.MNT_RELATIME: ", relatime",
        MNT_FLAGS.MNT_STRICTATIME: ", strictatime"
    }
    options = ""
    mnt = readSU("struct vfsmount", v)
    for flag in mnt_info:
        if mnt.mnt_flags & flag:
            options += mnt_info[flag]
    return options

def rpc_peeraddr2str(clnt, format):
    xprt = readSU("struct rpc_clnt", clnt).cl_xprt
    if xprt.address_strings[format] is not None:
        return xprt.address_strings[format]
    else:
        return "unprintable"

# FIXME: put this into LinuxDump as a library to include
def xprt_connected(xprt):
    return xprt.state & 2

# Is this even reachable via in-tree kernel code?
def xs_local_print_stats(xprt):
    idle_time = 0
    if xprt_connected(xprt):
        idle_time = (readSymbol("jiffies") - xprt.last_used) / sys_info.HZ

    print("xprt:  local %lu %lu %lu %ld %lu %lu %lu %llu %llu %lu %llu %llu" %
          (xprt.stat.bind_count, xprt.stat.connect_count,
           xprt.stat.connect_time / sys_info.HZ, idle_time, xprt.stat.sends,
           xprt.stat.recvs, xprt.stat.bad_xids, xprt.stat.req_u,
           xprt.stat.bklog_u, xprt.stat.max_slots, xprt.stat.sending_u,
           xprt.stat.pending_u))

def xs_tcp_print_stats(xprt):
    transport = container_of(xprt, "struct sock_xprt", "xprt");
    idle_time = 0
    if xprt_connected(xprt):
        idle_time = (readSymbol("jiffies") - xprt.last_used) / sys_info.HZ

    try:
        print("xprt:  tcp %u %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu" %
              (transport.srcport, xprt.stat.bind_count, xprt.stat.connect_count,
               xprt.stat.connect_time / sys_info.HZ, idle_time, xprt.stat.sends,
               xprt.stat.recvs, xprt.stat.bad_xids, xprt.stat.req_u,
               xprt.stat.bklog_u, xprt.stat.max_slots, xprt.stat.sending_u,
               xprt.stat.pending_u))
    except KeyError:
        print("xprt:  tcp %u %lu %lu %lu %lu %lu %lu %lu %lu %lu" %
              (transport.srcport, xprt.stat.bind_count, xprt.stat.connect_count,
               xprt.stat.connect_time / sys_info.HZ, idle_time, xprt.stat.sends,
               xprt.stat.recvs, xprt.stat.bad_xids, xprt.stat.req_u,
               xprt.stat.bklog_u))


def xs_udp_print_stats(xprt):
    transport = container_of(xprt, "struct sock_xprt", "xprt");
    print("xprt:  udp %u %lu %lu %lu %lu %lu %lu %lu %lu %lu" %
          (transport.srcport, xprt.stat.bind_count, xprt.stat.sends,
           xprt.stat.recvs, xprt.stat.bad_xids, xprt.stat.req_u,
           xprt.stat.bklog_u, xprt.stat.max_slots, xprt.stat.sending_u,
           xprt.stat.pending_u))

def rpc_xprt_print_stats(clnt):
    xprt = readSU("struct rpc_clnt", clnt).cl_xprt
    if xprt.ops.print_stats == sym2addr("xs_udp_print_stats"):
        xs_udp_print_stats(xprt)
    if xprt.ops.print_stats == sym2addr("xs_local_print_stats"):
        xs_local_print_stats(xprt)
    if xprt.ops.print_stats == sym2addr("xs_tcp_print_stats"):
        xs_tcp_print_stats(xprt)

def nfs_pseudoflavor_to_name(flavor):
# NB: lipkey and spkm3 omitted on purpose (nobody uses them)
    sec_flavors = {
        RPC_AUTH_FLAVORS.RPC_AUTH_NULL: "null",
        RPC_AUTH_FLAVORS.RPC_AUTH_UNIX: "sys",
        RPC_AUTH_FLAVORS.RPC_AUTH_GSS_KRB5: "krb5",
        RPC_AUTH_FLAVORS.RPC_AUTH_GSS_KRB5I: "krb5i",
        RPC_AUTH_FLAVORS.RPC_AUTH_GSS_KRB5P: "krb5p",
        UINT_MAX: "unknown"
    }
    for flav in sec_flavors:
        if flav == flavor:
            break
    return sec_flavors[flav]

def nfs_mountd_netid_to_str(n):
    nfss = readSU("struct nfs_server", n)
    sap = readSU("struct sockaddr", nfss.mountd_address)
    options = ""
    options += ", mountproto="
    if sap.sa_family == ADDRESS_FAMILIES.AF_INET:
        if nfss.mountd_protocol == IP_PROTOS.IPPROTO_UDP:
            options += RPCBIND_NETID_UDP
        elif nfss.mountd_protocol == IP_PROTOS.IPPROTO_TCP:
            options += RPCBIND_NETID_TCP
        else:
            options += "auto"
    elif sap.sa_family == ADDRESS_FAMILIES.AF_INET6:
        if nfss.mountd_protocol == IP_PROTOS.IPPROTO_UDP:
            options += RPCBIND_NETID_UDP6
        elif nfss.mountd_protocol == IP_PROTOS.IPPROTO_TCP:
            options += RPCBIND_NETID_TCP6
        else:
            options += "auto"
    else:
        options += "auto"
    return options

def nfs_mountd_options(n):
    # RHEL5 does not have nfs_server.mountd_address
    if member_size("struct nfs_server", "mountd_address") <= 0:
        return ""
    options = ""
    nfss = readSU("struct nfs_server", n)
    sap = readSU("struct sockaddr", nfss.mountd_address)
    if sap.sa_family == ADDRESS_FAMILIES.AF_INET:
        sin = readSU("struct sockaddr_in", sap)
        options += ", mountaddr=%s" % socket.inet_ntoa(struct.pack("!I",
            socket.ntohl(sin.sin_addr.s_addr)))
    elif sap.sa_family == ADDRESS_FAMILIES.AF_INET6:
        sin6 = readSU("struct sockaddr_in6", sap)
        options += ", mountaddr=%s" % socket.inet_ntop(socket.AF_INET6,
            struct.pack("!I", socket.ntohl(sin6.sin_addr.s_addr)))
    else:
        options += ", mountaddr=unspecified"
    if nfss.mountd_version:
        options += ", mountvers=%u" % nfss.mountd_version
    if nfss.mountd_port:
        options += ", mountport=%u" % nfss.mountd_port
    return options + nfs_mountd_netid_to_str(nfss)

def nfs_nfsv4_options(n):
    nfss = readSU("struct nfs_server", n)
    clp = readSU("struct nfs_client", nfss.nfs_client)
    return ", clientaddr=%s" % clp.cl_ipaddr +\
           ", minorversion=%u" % clp.cl_minorversion

# XXX: add showdefaults?
def nfs_mount_options(n):
    nfs_info = { NFS_MOUNT_FLAGS.NFS_MOUNT_SOFT: (", soft", ", hard"),
        NFS_MOUNT_FLAGS.NFS_MOUNT_POSIX: (", posix", ""),
        NFS_MOUNT_FLAGS.NFS_MOUNT_NOCTO: (", nocto", ""),
        NFS_MOUNT_FLAGS.NFS_MOUNT_NOAC: (", noac", ""),
        NFS_MOUNT_FLAGS.NFS_MOUNT_NONLM: (", nolock", ""),
        NFS_MOUNT_FLAGS.NFS_MOUNT_NOACL: (", noacl", ""),
        NFS_MOUNT_FLAGS.NFS_MOUNT_NORDIRPLUS: (", nordirplus", ""),
        NFS_MOUNT_FLAGS.NFS_MOUNT_UNSHARED: (", nosharecache", ""),
        NFS_MOUNT_FLAGS.NFS_MOUNT_NORESVPORT: (", noresvport", "")
    }
    nfss = readSU("struct nfs_server", n)
    clp = readSU("struct nfs_client", nfss.nfs_client)
    options = ""
    version = clp.rpc_ops.version
    options += ", vers=%u" % version
    options += ", rsize=%u" % nfss.rsize
    options += ", wsize=%u" % nfss.wsize
    if nfss.bsize != 0:
        options += ", bsize=%u" % nfss.bsize
    options += ", acregmin=%u" % (nfss.acregmin/HZ)
    options += ", acregmax=%u" % (nfss.acregmax/HZ)
    options += ", acdirmin=%u" % (nfss.acdirmin/HZ)
    options += ", acdirmax=%u" % (nfss.acdirmax/HZ)
    for flag in nfs_info:
        if nfss.flags & flag:
            options += nfs_info[flag][0]
        else:
            options += nfs_info[flag][1]
    # RHEL5 does not have rpc_xprt.address_strings
    if member_size("struct rpc_xprt", "address_strings") > 0:
        options += ", proto=%s" % rpc_peeraddr2str(nfss.client,
                         RPC_DISPLAY_FORMAT.RPC_DISPLAY_NETID)
    else:
        if nfss.client.cl_xprt.prot == 6:
            options += ", proto=tcp"
        elif nfss.client.cl_xprt.prot == 17:
            options += ", proto=udp"
        else:
            options += ", proto=%s" % nfss.client.cl_xprt.prot
    # RHEL5 does not have nfs_server.port
    if member_size("struct nfs_server", "port") > 0:
        if version == 4:
            if nfss.port != NFS_PORT:
                options += ", port=%u" % nfss.port
        else:
            if nfss.port:
                options += ",port=%u" % nfss.port
    # RHEL5 has nfs_client.retrans_timeo and retrans_count
    if member_size("struct nfs_client", "retrans_timeo") > 0:
        options += ", timeo=%lu" % (10 * clp.retrans_timeo / HZ)
    else:
        options += ", timeo=%lu" %\
                   (10 * nfss.client.cl_timeout.to_initval / HZ)
    if member_size("struct nfs_client", "retrans_count") > 0:
        options += ", retrans=%u" % clp.retrans_count
    else:
        options += ",retrans=%u" % nfss.client.cl_timeout.to_retries
    options += ", sec=%s" %\
               nfs_pseudoflavor_to_name(nfss.client.cl_auth.au_flavor)
    if version != 4:
        options += nfs_mountd_options(nfss)
    else:
        options += nfs_nfsv4_options(nfss)
    # RHEL5 does not have nfs_server.options
    if member_size("struct nfs_server", "options") > 0:
        if nfss.options & NFS_OPTION_FSCACHE:
           options += ", sc"
    if nfss.flags & NFS_MOUNT_FLAGS.NFS_MOUNT_LOOKUP_CACHE_NONEG:
        if nfss.flags & NFS_MOUNT_FLAGS.NFS_MOUNT_LOOKUP_CACHE_NONE:
            options += ", lookupcache=none"
        else:
            options += ", lookupcache=pos"
    local_flock = nfss.flags & NFS_MOUNT_FLAGS.NFS_MOUNT_LOCAL_FLOCK
    local_fcntl = nfss.flags & NFS_MOUNT_FLAGS.NFS_MOUNT_LOCAL_FCNTL
    if not local_flock and not local_fcntl:
        options += ", local_lock=none"
    elif local_flock and local_fcntl:
        options += ", local_lock=all"
    elif local_flock:
        options += ", local_lock=flock"
    else:
        options += ", local_lock=posix"
    # NB: in the kernel, this is done by nfs_show_options, which calls
    # nfs_show_mount_options
    # RHEL5 does not have rpc_xprt.address_strings
    if member_size("struct rpc_xprt", "address_strings") > 0:
        options += ", addr=%s" % rpc_peeraddr2str(nfss.client,
                           RPC_DISPLAY_FORMAT.RPC_DISPLAY_ADDR)
    else:
        options += ", addr=%s" % nfss.nfs_client.cl_hostname
    return options

def supported_fstype(s_type):
    if s_type != sym2addr("nfs_fs_type") and\
       s_type != sym2addr("nfs4_fs_type"):
          print("Skipping unsupported super_block type %s" % s_type.name)
          return False
    return True

def show_vfsmnt(v):
    # RHEL7 has a 'struct vfsmount' embedded in a 'struct mount'
    if member_size("struct vfsmount", "mnt_devname") > 0:
        mnt = vfsmount = readSU("struct vfsmount", v)
        sb = readSU("struct super_block", mnt.mnt_sb)
    else:
        mnt = readSU("struct mount", v)
        sb = readSU("struct super_block", mnt.mnt.mnt_sb)
        vfsmount = readSU("struct vfsmount", mnt.mnt)

    if not supported_fstype(sb.s_type):
        return
    if mnt.mnt_devname:
        options = mnt.mnt_devname
    else:
        options = "none"
    options += " "
    options += get_pathname(mnt.mnt_mountpoint, vfsmount)
    options += " "
    options += sb.s_type.name
    print(options)
    if __mnt_is_readonly(v):
        options = "opts: ro"
    else:
        options = "opts: rw"
    options += sb_opts(sb)
    # TODO: security_sb_show_options
    options += mnt_opts(v)
    nfss = readSU("struct nfs_server", sb.s_fs_info)
    options += nfs_mount_options(nfss)
    print(textwrap.fill(options, width=100, initial_indent='',
                        subsequent_indent='      '))

# thanks stackoverflow
def auto_int(x):
    return int(x,0)



# emulate /proc/self/mountstats

from LinuxDump.libmisc import (get_enum_tag_value, get_enum_string,
                              arg_value, get_per_cpu)


LOCAL_DEFINES_C = '''
#define NFS_OPTION_FSCACHE  0x00000001  /* - local caching enabled */
'''
LOCAL_DEFINES = CDefine(LOCAL_DEFINES_C)

def rpc_proc_name(op, procs):
    if procs[op].p_name:
        return "  {:20s}: ".format(procs[op].p_name)
    if op == 0:
        return "  {:20s}: ".format("NULL")
    return "  {:20d}: ".format(op)

def _add_rpc_iostats(a, b):
    a.om_ops += b.om_ops
    a.om_ntrans += b.om_ntrans
    a.om_timeouts += b.om_timeouts
    a.om_bytes_sent += b.om_bytes_sent
    a.om_bytes_recv += b.om_bytes_recv
    a.om_queue += b.om_queue
    a.om_rtt += b.om_rtt
    a.om_execute += b.om_execute

def convert_rpc_iostats_ktime_metrics(metrics):
    metrics.om_queue = ktime_t(metrics.om_queue)
    metrics.om_rtt = ktime_t(metrics.om_rtt)
    metrics.om_execute = ktime_t(metrics.om_execute)

def show_rpc_clnt_iostats(addr):
    cl = readSU("struct rpc_clnt", addr)
    stats = cl.cl_metrics
    xprt = cl.cl_xprt
    maxproc = cl.cl_maxproc

    if not stats:
        print("sorry, stats are NULL")
        return

    cl_start = cl
    rpc_procinfo = cl.cl_procinfo

    print("  {:20}  {:>10s} {:>10} {:>7} "
          "{:>12} {:>12} {:>6} {:>6} {:>6}"
          .format("", "ops", "trans", "tmout",
          "bytes sent", "bytes recv", "q/op", "rtt/op", "exe/op"))
    for op in range(0, maxproc):
        metrics = readSU("struct rpc_iostats", stats[op])
        convert_rpc_iostats_ktime_metrics(metrics)
        print("{}".format(rpc_proc_name(op, rpc_procinfo)), end='')

        cl = cl_start
        while (cl != cl.cl_parent):
            parent_cl = readSU("struct rpc_clnt", cl.cl_parent)
            parent_metrics = readSU("struct rpc_iostats",\
                                    parent_cl.cl_metrics[op])
            convert_rpc_iostats_ktime_metrics(parent_metrics)
            _add_rpc_iostats(metrics, parent_metrics)
            cl = cl.cl_parent

        if metrics.om_ops:
            queue = metrics.om_queue / metrics.om_ops / 1000000.0
            rtt = metrics.om_rtt / metrics.om_ops / 1000000.0
            execute = metrics.om_execute / metrics.om_ops / 1000000.0
        else:
            queue = 0; rtt = 0 ; execute = 0

        print("{:10d} {:10d} {:7d} "
              "{:12d} {:12d} {:6.2f} "
              "{:6.2f} {:6.2f}"
              .format(metrics.om_ops, metrics.om_ntrans, metrics.om_timeouts,
                      metrics.om_bytes_sent, metrics.om_bytes_recv, queue,
                      rtt, execute))

def show_nfss_stats(m):
    # RHEL7 has a 'struct vfsmount' embedded in a 'struct mount'
    if member_size("struct vfsmount", "mnt_devname") > 0:
        mnt = readSU("struct vfsmount", m)
        sb = readSU("struct super_block", mnt.mnt_sb)
    else:
        mnt = readSU("struct mount", m)
        sb = readSU("struct super_block", mnt.mnt.mnt_sb)

    if not supported_fstype(sb.s_type):
        return

    nfss = readSU("struct nfs_server", sb.s_fs_info)

    # TODO: mount options, ala /proc/self/mountinfo
    # i.e.: opts:    rw,vers=3,rsize=262144,wsize=262144 ...

    jiffies = readSymbol("jiffies")
    HZ = sys_info.HZ
    print("age: {}".format((jiffies - nfss.mount_time)/HZ))

    # TODO: decode caps and other bitmaps
    print("caps: caps=0x%x, wtmult=%u, dtsize=%u, bsize=%u, namelen=%u" %
          ( nfss.caps, nfss.wtmult, nfss.dtsize, nfss.bsize, nfss.namelen))
    if nfss.nfs_client.rpc_ops.version == 4:
        if member_size("struct nfs_server", "attr_bitmask") == 12:
            print("nfsv4: bm0=0x%x,bm1=0x%x,bm2=0x%x,acl=%x" %
                  (nfss.attr_bitmask[0], nfss.attr_bitmask[1],
                   nfss.attr_bitmask[2], nfss.acl_bitmask))
        else:
            print("nfsv4: bm0=0x%x,bm1=0x%x,acl=%x" %
                  (nfss.attr_bitmask[0], nfss.attr_bitmask[1],
                   nfss.acl_bitmask))

    auth = nfss.client.cl_auth
    print("sec: flavor={}".format(auth.au_ops.au_flavor),
          end=("" if auth.au_flavor else "\n"))
    if auth.au_flavor:
        print(", pseudoflavor={}".format(auth.au_flavor))

    totals_events = {}
    total_events_stats = get_enum_tag_value("__NFSIOS_COUNTSMAX",
                                            "nfs_stat_eventcounters")
    totals_bytes = {}
    total_bytes_stats = get_enum_tag_value("__NFSIOS_BYTESMAX",
                                           "nfs_stat_bytecounters")
    totals_fscache = {}
    total_fscache_stats = get_enum_tag_value("__NFSIOS_FSCACHEMAX",
                                             "nfs_stat_fscachecounters")

    rpc_xprt_print_stats(nfss.client)

    percpu = get_per_cpu()
    first_cpu = 1
    for c in percpu.cpu.keys():
        io_stats = percpu.per_cpu_struct(c, nfss.io_stats, "nfs_iostats")

        for i in range(0, total_events_stats):
            if first_cpu:
                totals_events[i] = 0
            totals_events[i] += io_stats.events[i]

        for i in range(0, total_bytes_stats):
            if first_cpu:
                totals_bytes[i] = 0
            totals_bytes[i] += io_stats.bytes[i]

        if nfss.options & LOCAL_DEFINES["NFS_OPTION_FSCACHE"]:
            for i in range(0, total_fscache_stats):
                if first_cpu:
                    totals_fscache[i] = 0
                totals_fscache[i] += io_stats.fscache[i]
        first_cpu = 0

    print("events:")
    for i in range(0, total_events_stats):
        count_name = get_enum_string(i, "nfs_stat_eventcounters")
        print("\t{:12}: {}".format(count_name, totals_events[i]))

    print("bytes:")
    for i in range(0, total_bytes_stats):
        count_name = get_enum_string(i, "nfs_stat_bytecounters")
        print("\t{:12}: {}".format(count_name, totals_bytes[i]))

    if nfss.options & LOCAL_DEFINES["NFS_OPTION_FSCACHE"]:
        print("fscache:")
        for i in range(0, total_fscache_stats):
            count_name = get_enum_string(i, "nfs_stat_fscachecounters")
            print("\t{:12}: {}".format(count_name, totals_fscache[i]))

    # TODO: xprt counts, such as:  xprt: tcp 849 1 1 0 275 12 12 0 14 0 2 0 2

    show_rpc_clnt_iostats(nfss.client)



# vim: sw=4 ts=4 noexpandtab

def process_one_arg(args, v):
    if args.procmounts:
        show_vfsmnt(v)
    if args.procmountstats:
        show_nfss_stats(v)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--mounts", dest="procmounts",
                  action="store_true",
                  help="print equivalent of /proc/mounts for specified"
                        " mount(s). If there are no other options set,"
                        " --mounts is optional")
    parser.add_argument("--stats", dest="procmountstats",
                  action="store_true",
                  help="print equivalent of /proc/self/mountstats for "
                        "specified mount(s)")
    # TODO: decide how to specify mount points: fstype, vfsmount, "all", etc
    parser.add_argument('mount', help='- specify  mount/vfsmount addr '
                        ' or mountpoint name. If there are no positional'
                        ' arguments, print info for all NFS mounts', nargs='*')
    o = parser.parse_args()

    # If we do not have any options - just positional arguments - treat it
    # as --mounts

    if (o.procmountstats is False):
        o.procmounts = True
    mnts = o.mount

    vfs_list = []
    mnt2vfs = {}
    for v, s, fstype, d, m in getMount():
        if (fstype in ("nfs", "nfs4")):
            vfs_list.append(v)
            mnt2vfs[m] = v

    if (not mnts):
        mnts = vfs_list

    for sv in mnts:
        # If sv is an integer, this is vfs
        # If arg starts from '/', intepret it as a mountpoint (string)
        # Otherwise, try converting it to hex
        if (isinstance(sv, int)):
            v = sv
        elif (sv.startswith("/")):
            # Strip final '/' if any
            if (sv.endswith('/')):
                sv = sv[:-1]
            # Search for it in mountpoints
            if (sv in mnt2vfs):
                v = mnt2vfs[sv]
            else:
                print("  Nothing is mounted at {}".format(sv))
                continue
        else:
            v = int(sv, 16)
        if (o.procmounts):
             show_vfsmnt(v)
        if (o.procmountstats):
            show_nfss_stats(v)
