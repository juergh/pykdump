
# module LinuxDump.inet.proto
# Time-stamp: <08/12/10 15:37:19 alexs>

#
# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.
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

__doc__ = '''
This is a package providing generic access to INET protocol structures.
For example, a program willing to print or analyze TCP-connection info
can use this package to obtain the list of TCP structures of interest and
after that extract more info from them, as needed.
'''

import string, struct
import sys
import types
from stat import S_ISSOCK

from pykdump.API import *
from LinuxDump.inet import *

# Emulate sk_for_each - walk the hash-table of 'struct hlist_head' embedded in
# socket. Returns a list of 'struct sock' addresses

skc_node_off = -1
sock_V1 = (struct_size("struct sock_common") == -1)

debug = API_options.debug

def sk_for_each(head):
    # compute skc_node_off if needed
    global skc_node_off
    if (skc_node_off == -1):
        sock_info = getStructInfo("struct sock")
        sock_common_info = getStructInfo("struct sock_common")
        skc_node_off = sock_info["__sk_common"].offset + \
                       sock_common_info["skc_node"].offset

    addrs = readList(head, 0)
    # Now recompute addrs to point to 'struct sock' where head_list is embedded
    return [a - skc_node_off for a in addrs]



# Addresses/ports for AF_INET and AF_INET6

def formatIPv4(ip, port, printstar=True):
    if (printstar and port == 0):
        return ("%s:*" %(ntodots(ip))).ljust(27)
    else:
        return ("%s:%d" %(ntodots(ip), port)).ljust(27)


# crash formats addrs as
# 0:0:0:0:0:ffff:1071:2f2-22 0:0:0:0:0:ffff:ff4:c1fb-3949
#
# netstat as
#tcp6       0      0 ::ffff:16.113.2.242:22  ::ffff:15.244.193:39495 ESTABLISHED

def formatIPv6(ip, port, printstar=True):
    if (printstar and port == 0):
        return ("%s:*" %(ntodots6(ip))).ljust(27)
    else:
        return ("%s:%d" %(ntodots6(ip), port)).ljust(27)


# v4/v6 IP - family deduced from socket.
# We analyze the type of passed object, here is what is acceptable:
# - 'struct sock' (from 2.4 kernels and <= 2.6.10)
# - 'struct inet_sock' (from > 2.6.10)
# - structs derived from inet_sock (e.g. tcp_sock). All these structures
# have 'inet_sock' at offset 0


class IP_sock(object):
    def __init__(self, o, details=False):
	if (sock_V1):
	    s = o
	elif (o.isNamed("struct sock")):
            s = o.castTo("struct inet_sock")
	elif (o.isNamed("struct tcp_sock")):
	    s = o
	    if (s.protocol != 6):
		raise KeyError,str(o)+' incorrect protocol=%d' %  s.protocol
	elif (o.isNamed("struct udp_sock")):
	    s = o
	    if (s.protocol != 17):
		raise KeyError,str(o)+' incorrect protocol=%d' %  s.protocol
	elif (o.isNamed("struct raw_sock")):
	    s = o
	    if (s.protocol in (6,17)):
		raise KeyError,str(o)+' incorrect protocol=%d' %  s.protocol
	    
        else:
            s = o
	self.__casted_sock = s
        #print o, s
        self.left = self.right = ''
        self.family = family = s.family
        self.protocol = s.protocol
        self.sktype = s.type
        self.user_data = s.user_data
        self.state =  s.state   # Makes sense mainly for TCP
        
	if (family == P_FAMILIES.PF_INET):
	    self.src = s.Src
	    self.sport = ntohs(s.sport)
	    self.dst = s.Dst
	    self.dport = ntohs(s.dport)
        elif (family == P_FAMILIES.PF_INET6):
	    self.src = s.Src6
	    self.sport = ntohs(s.sport)
	    self.dst = s.Dst6
	    self.dport = ntohs(s.dport)
	    self.state =  s.state   # Makes sense mainly
        else:
            raise TypeError, "family=%d o=%s" % (family, str(o))
            
	# Protocol-specific details
	if (not details):
	    return
	# The following parameters make sense for most sockets
	self.rcvbuf = s.rcvbuf
	self.sndbuf = s.sndbuf
	self.rmem_alloc = s.rmem_alloc_counter
	self.wmem_alloc = s.wmem_alloc_counter

	if (self.protocol == 6):    # TCP
	    # Details are different for TCP in different states
	    if (self.state != tcpState.TCP_LISTEN \
		and self.state != tcpState.TCP_TIME_WAIT):
                self.Tcp = Bunch()
		self.rx_opt =  s.rx_opt
		self.topt = s.topt
                #self.Tcp.nonagle = s.Nonagle
	    elif (self.state == tcpState.TCP_LISTEN):
		self.sk_max_ack_backlog = s.max_ack_backlog
		self.sk_ack_backlog = s.ack_backlog
		self.l_opt= s.l_opt
		self.accept_queue = s.accept_queue

	elif (self.protocol == 17): # UDP
	    self.uopt = s.uopt
	elif (self.sktype == sockTypes.SOCK_RAW): # RAW (mostly ICMP)
	    pass


	if (not details):
	    return
	
    # For all unknown attrs, proxy to s
    def __getattr__(self, fname):
	return getattr(self.__casted_sock, fname)


    def __str__(self):
        #Local Address           Foreign Address
        #0.0.0.0:45959           0.0.0.0:*
        try:
            pname = PROTONAMES[self.protocol]
        except KeyError:
            pname = "%d" % self.protocol
        if (self.sktype == sockTypes.SOCK_RAW):
            pname = "raw"

        if (self.right == ''):
            if (self.protocol == 6):    # TCP
                self.right = ' ' + tcpState[self.state][4:]
            elif (self.protocol == 17 or pname == "raw"): # UDP, RAW
                # For UDP and RAW we use two states at this moment:
                # TCP_ESTABLISHED=1 when we have data in flight
                # TCP_CLOSED=7      for everything else
                if (self.state == tcpState.TCP_ESTABLISHED):
                    self.right = "ESTABLISHED"
                else:
                    self.right = "st=%d" % self.state
            else:
                self.right = "st=%d" % self.state

        if (self.family == P_FAMILIES.PF_INET6):
            pname += "6"
            if (self.left == ''):
                self.left = pname.ljust(5)
            return  self.left+ ' ' + \
                   formatIPv6(self.src, self.sport)+\
                   formatIPv6(self.dst, self.dport)+\
                   self.right

        else:
            # PF_INET
            if (self.left == ''):
                self.left = pname.ljust(5)

            return  self.left+ ' ' + \
                   formatIPv4(self.src, self.sport)+\
                   formatIPv4(self.dst, self.dport)+\
               self.right



class IP_conn_tw(IP_sock):
    def __init__(self, tw, details = False):
        # We do not call the base class constructor as most
        # things are different. We have tcp_tw_bucket or inet_timewait_sock
        # (they both have sock_common at offset 0) on 2.6, but not on 2.4
        # So it is difficult to check the protocol
        self.left = self.right = ''
        self.family = -1
        self.protocol = 6               # Only TCP at this moment
        self.sktype = -1                # This is really not a socket

        self.state = tw.State
        self.family = tw.Family

        self.sport = ntohs(tw.Sport)
        self.dport = ntohs(tw.Dport)

        if  (self.family == P_FAMILIES.PF_INET6):
            self.src = tw.Src6
            self.dst = tw.Dst6
        else:
            self.src = tw.Src
            self.dst = tw.Dst
            

        if (not details):
            return
        
        self.tw_timeout = tw.Timeout
        jiffies = readSymbol("jiffies")
        self.ttd = tw.Ttd - jiffies
        if (self.ttd < 0):
            self.ttd = 0

        return


# Format sockaddr_in to print

def format_sockaddr_in(sin):
    family = sin.sin_family
    port = ntohs(sin.sin_port)

    addr = sin.sin_addr
    
    if (family == P_FAMILIES.PF_INET):
        return "%s:%d" % (ntodots(addr.s_addr), port)
    else:
        raise TypeError, "family=%d o=%s" % (family, str(o))
        


# Convert inode to socket
def inode2socketaddr(inode):
    if (not S_ISSOCK(inode.i_mode)):
        return None
    if (sock_V1):
        return Addr(inode.u)
    else:
        return Addr(inode) - struct_size("struct socket")


def decodeSock(sock):
    if (sock_V1):
	family = sock.family
	# For old kernels prot is NULL for AF_UNIX
	if (sock.prot):
	    protoname = sock.prot.name
	else:
	    protoname = "UNIX"
	sktype = sock.type
    else:
	skcomm = sock.__sk_common
	family = skcomm.skc_family
	try:
	    protoname =  skcomm.skc_prot.Deref.name
	except KeyError:
	    try:
		protoname = sock.sk_prot.Deref.name
	    except IndexError:
		protoname= '???'
	    except crash.error:
		protoname='???'
	sktype = sock.sk_type
    if (family == P_FAMILIES.PF_INET or family == P_FAMILIES.PF_INET6):
	inet = True
    else:
	inet = False
    return family, sktype, protoname, inet

# ...........................................................................

# On 2.4 we use just 'struct sock' for everything. On 2.6 we use inet_sock,
# tcp_sock and so on. Structs definitions are present in newer 2.6 kernels
# but not on some older 2.6 ones.


def check_inet_sock():
    # Let us create inet_sock if needed. struct_exists() checks for real
    # definitions (in vmlinux), here we check for our cache
    try:
        getStructInfo("struct inet_sock")
        return
    except TypeError:
        pass

    aS = ArtStructInfo("struct inet_sock")
    aS.append("struct sock", "sk")
    if (symbol_exists("tcpv6_protocol") or 
        symbol_exists("secure_tcpv6_sequence_number")):
        if (debug):
            print "Adding struct ipv6_pinfo *pinet6;"
        aS.append("struct ipv6_pinfo *", "pinet6")
    iopti = getStructInfo("struct inet_opt")
    aS.inline(iopti)
    # print aS

    # tcp_sock is inet_sock followed by tcp_opt
    tas = ArtStructInfo("struct tcp_sock")
    tas.inline(aS)
    tas.append("struct tcp_opt", "tcp")
    #print tas

    # udp_sock is inet_sock followed by udp_opt
    uas = ArtStructInfo("struct udp_sock")
    uas.inline(aS)
    uas.append("struct udp_opt", "udp")
    #print uas

    # raw_sock is inet_sock followed by raw_opt
    ras = ArtStructInfo("struct raw_sock")
    ras.inline(aS)
    ras.append("struct raw_opt", "udp")
    #print ras



# Initialize INET_Stuff
def init_INET_Stuff():
    # 2.4 kernels do not have 'struct inet_sock' at all
    # Some older 2.6 have it, but it is not accessible from
    # vmcore for some reason
    if (not sock_V1):
        check_inet_sock()
    tcp_hashinfo = readSymbol('tcp_hashinfo')

    # On 2.4 and <=2.6.9 kernels we use names :
    #  __tcp_ehash, __tcp_bhash, __tcp_listening_hash
    # On 2.6.15:
    # ehash, bhash, listening_hash
    # On 2.6.22:
    # tcp_hashinfo is as table of inet_ehash_bucket, each bucket
    # has two chains: normal and tw
    #     struct inet_hashinfo {
    #        struct inet_ehash_bucket	*ehash;
    #        struct inet_bind_hashbucket	*bhash;
    # 	     int				bhash_size;
    # 	     unsigned int			ehash_size;
    # 	     struct hlist_head		listening_hash[INET_LHTABLE_SIZE];

    try:
	ehash_size = tcp_hashinfo.__tcp_ehash_size
	ehash_btype = tcp_hashinfo["__tcp_ehash"].basetype
	ehash_addr = tcp_hashinfo.__tcp_ehash

	tcp_listening_hash = tcp_hashinfo.__tcp_listening_hash
	tw_type = "struct tcp_tw_bucket"
    except KeyError:
	ehash_size = tcp_hashinfo.ehash_size
	ehash_btype = tcp_hashinfo["ehash"].basetype
	ehash_addr = tcp_hashinfo.ehash

	tcp_listening_hash = tcp_hashinfo.listening_hash
	tw_type = "struct tcp_timewait_sock"
    
    if (struct_size("struct sock_common") == -1):
	# 2.4
	sockname = "struct sock"
        Kernel24 = True
    else:
	# 2.6
	sockname = "struct inet_sock"
        Kernel24 = False
    eb_info = getStructInfo(ehash_btype)
    eb_size = eb_info.size
    
    chain_off = eb_info["chain"].offset
    chain_sz = eb_info["chain"].size

    try:
        tw_chain_off = eb_info["twchain"].offset
    except KeyError:
        tw_chain_off = -1

    try:
        UNIX_HASH_SIZE = whatis("unix_socket_table") - 1
    except:
	UNIX_HASH_SIZE = 256
	
    # Now copy locals to INET_Stuff
    INET_Stuff.__dict__.update(locals())

def init_PseudoAttrs():
    sn = "struct sock"
    structSetAttr(sn, "family", "__sk_common.skc_family")
    structSetAttr(sn, "protocol", "sk_protocol")
    structSetAttr(sn, "type", "sk_type")
    structSetAttr(sn, "Src", "rcv_saddr")
    structSetAttr(sn, "Dst", "daddr")
    structSetAttr(sn, "rmem_alloc_counter", "rmem_alloc.counter")
    structSetAttr(sn, "wmem_alloc_counter", "wmem_alloc.counter")
    structSetAttr(sn, "user_data", "sk_user_data")

    structSetAttr(sn, "rx_opt", "tp_pinfo.af_tcp")
    structSetAttr(sn, "topt", "tp_pinfo.af_tcp")
    structSetAttr(sn, "l_opt", "tp_pinfo.af_tcp.listen_opt")
    structSetAttr(sn, "accept_queue", "tp_pinfo.af_tcp.accept_queue")
    structSetAttr(sn, "uopt", "tp_pinfo.af_udp")
    structSetAttr(sn, "rcv_tstamp", "tp_pinfo.af_tcp.rcv_tstamp")
    structSetAttr(sn, "lsndtime", "tp_pinfo.af_tcp.lsndtime")
    structSetAttr(sn, "Socket", ["socket", "sk_socket"])

    sn = "struct inet_sock"
    extra = ["struct tcp_sock", "struct udp_sock", "struct raw_sock", 
                                "struct unix_sock"]
    structSetAttr(sn, "family", "sk.__sk_common.skc_family", extra)
    structSetAttr(sn, "protocol", ["sk_protocol","sk.sk_protocol"], extra)
    structSetAttr(sn, "type", ["sl_type", "sk.sk_type"], extra)
    structSetAttr(sn, "state", "sk.__sk_common.skc_state", extra)

    structSetAttr(sn, "Src", ["inet.rcv_saddr", "rcv_saddr"], extra)
    structSetAttr(sn, "Dst", ["inet.daddr", "daddr"], extra)
    structSetAttr(sn, "sport", ["inet.sport", "sport"], extra)
    structSetAttr(sn, "dport", ["inet.dport", "dport"], extra)

    structSetAttr(sn, "Src6", "pinet6.rcv_saddr.in6_u.u6_addr32", extra)
    structSetAttr(sn, "Dst6", "pinet6.daddr.in6_u.u6_addr32", extra)

    structSetAttr(sn, "rcvbuf", "sk.sk_rcvbuf", extra)
    structSetAttr(sn, "sndbuf", "sk.sk_sndbuf", extra)
    structSetAttr(sn, "rmem_alloc_counter", "sk.sk_rmem_alloc.counter",
                  extra)
    structSetAttr(sn, "wmem_alloc_counter", "sk.sk_wmem_alloc.counter",
                  extra)
    structSetAttr(sn, "user_data", "sk.sk_user_data",
                  extra)
    structSetAttr(sn, "Socket", "sk.sk_socket", extra)

    # TCP-specific
    sn = "struct tcp_sock"
    extra = ["struct inet_sock"]
    structSetAttr(sn, "ack_backlog",
                  ["sk.sk_ack_backlog",
                   "inet_conn.icsk_inet.sk.sk_ack_backlog"], extra)
    structSetAttr(sn, "max_ack_backlog", 
                  ["sk.sk_max_ack_backlog",
                   "inet_conn.icsk_inet.sk.sk_max_ack_backlog"], extra)
    structSetAttr(sn, "accept_queue",
                  ["inet_conn.icsk_accept_queue",
                   "tcp.accept_queue"], extra)

    structSetAttr(sn, "l_opt",
                  ["inet_conn.icsk_accept_queue.listen_opt",
                   "tcp.listen_opt"], extra)

    structSetAttr(sn, "rx_opt",
                  ["tcp", "rx_opt"], extra)
    structSetAttr(sn, "rcv_tstamp", 
                  ["tcp.rcv_tstamp", "rx_opt.rcv_tstamp"],
                    extra)
    structSetAttr(sn, "lsndtime", 
                  ["tcp.lsndtime", "rx_opt.lsndtime"],
                    extra)



    structSetAttr(sn, "Nonagle", "nonagle")
    #structSetAttr(sn, "rcv_tstamp", "rcv_tstamp")
    # This is used to access snd_wnd. mss and so on. Should be replaced
    # by separate pseudoattrs
    structSetAttr(sn, "topt", ["tcp", ""], extra)

    # UDP-specific
    sn = "struct udp_sock"
    structSetAttr(sn, "uopt", ["udp", ""], extra)


    # TIME_WAIT sockets

    # old-style
    sn = "struct tcp_tw_bucket"
    structSetAttr(sn, "State", ["__tw_common.skc_state", "state"])
    structSetAttr(sn, "Family", ["__tw_common.skc_family", "family"])
    structSetAttr(sn, "Src", ["tw_rcv_saddr", "rcv_saddr"])
    structSetAttr(sn, "Dst", ["tw_daddr", "daddr"])
    structSetAttr(sn, "Sport", ["tw_sport", "sport"])
    structSetAttr(sn, "Dport", ["tw_dport", "dport"])

    structSetAttr(sn, "Timeout", ["tw_timeout", "timeout"])
    structSetAttr(sn, "Ttd", ["tw_ttd", "ttd"])

    structSetAttr(sn, "Src6", "tw_v6_rcv_saddr.in6_u.u6_addr32")
    structSetAttr(sn, "Dst6", "tw_v6_daddr.in6_u.u6_addr32")


    # New-style
    sn = "struct tcp_timewait_sock"
    extra = ["struct inet_timewait_sock"]
    structSetAttr(sn, "State", "tw_sk.__tw_common.skc_state")
    structSetAttr(sn, "Family", "tw_sk.__tw_common.skc_family")
    structSetAttr(sn, "Src", "tw_sk.tw_rcv_saddr", extra)
    structSetAttr(sn, "Dst", "tw_sk.tw_daddr", extra)
    structSetAttr(sn, "Sport", "tw_sk.tw_sport", extra)
    structSetAttr(sn, "Dport", "tw_sk.tw_dport", extra)

    structSetAttr(sn, "Timeout", "tw_sk.tw_timeout")
    structSetAttr(sn, "Ttd", "tw_sk.tw_ttd")

    # Programmatic attrs
    def getSrc6(tw):
        iw = tw.castTo("struct inet_timewait_sock")
        ipv6_offset = iw.tw_ipv6_offset
        addr = Addr(iw) + iw.tw_ipv6_offset
        tw6 = readSU("struct inet6_timewait_sock", addr)
        src = tw6.tw_v6_rcv_saddr.in6_u.u6_addr32
        return src
    def getDst6(tw):
        iw = tw.castTo("struct inet_timewait_sock")
        ipv6_offset = iw.tw_ipv6_offset
        addr = Addr(iw) + iw.tw_ipv6_offset
        tw6 = readSU("struct inet6_timewait_sock", addr)
        dst = tw6.tw_v6_daddr.in6_u.u6_addr32
        return dst

    extra = ["struct inet_timewait_sock", "struct tcp_timewait_sock"]
    if (not structSetAttr("struct tcp6_timewait_sock", "Src6",
                      "tw_v6_rcv_saddr.in6_u.u6_addr32", extra)):
        structSetProcAttr(sn, "Src6", getSrc6)

    if (not structSetAttr("struct tcp6_timewait_sock", "Dst6",
                      "tw_v6_daddr.in6_u.u6_addr32", extra)):
        structSetProcAttr(sn, "Dst6", getDst6)
	
    # AF_UNIX
    
    sn = "struct socket"
    structSetAttr(sn, "Inode", "inode")     # For 2.4
    structSetAttr(sn, "Ino", "inode.i_ino")     # For 2.4
    
    # At this moment "struct socket_alloc" is defined as
    # struct socket_alloc {
    #   struct socket socket;
    #   struct inode vfs_inode;
    # }

    sn = "struct socket_alloc"
    extra = ["struct socket"]
    structSetAttr(sn, "Inode", "vfs_inode", extra)
    structSetAttr(sn, "Ino", "vfs_inode.i_ino", extra)
    
    sn = "struct sock"
    structSetAttr(sn, "Uaddr", "protinfo.af_unix.addr")

    sn = "struct unix_sock"
    structSetAttr(sn, "socket", "sk.sk_socket")
    structSetAttr(sn, "Uaddr", "addr")
    
    #Peer:
    #
    # #define unix_peer(sk) (unix_sk(sk)->peer)     2.6, unix_sock
    # #define unix_peer(sk) ((sk)->sk_pair)         2.6.5, unix_sock
    # #define unix_peer(sk) ((sk)->pair)            2.4, sock 
    
    def getPeer26(s):
	return s.peer.castTo("struct unix_sock")
    
    def getPeer26old(s):
	return s.sk.sk_pair.castTo("struct unix_sock")    
    
    if (not structSetAttr("struct sock", "Peer", "pair")):
        # 2.6
	sn = "struct unix_sock"
	if (member_size(sn, "peer") != -1):
	   structSetProcAttr(sn, "Peer", getPeer26)
	else:
	   structSetProcAttr(sn, "Peer", getPeer26old)

	
# TCP structures are quite different for 2.4 and 2.6 kernels, it makes sense to
# have two different versions of code

INET_Stuff = Bunch()
# Initialize TCP stuff
init_INET_Stuff()

init_PseudoAttrs()

def get_TCP_LISTEN():
    t = INET_Stuff
    if (t.Kernel24):
        # 2.4 
        # On 2.4 this list is of 'struct sock *' (2.4 kernels)
        for b in t.tcp_listening_hash:
            next = b
            while (next):
                s = readSU(t.sockname, next)
                next = s.next
                yield s
    else:
        for b in t.tcp_listening_hash:
            # hlist_head
            first = b.first
            if (first):
                for a in  sk_for_each(first):
                    s = readSU("struct tcp_sock", a)
                    yield s
 

def get_TCP_ESTABLISHED():
    # ESTABLISHED
    t = INET_Stuff
    if (t.Kernel24):
        # 2.4 
        # On 2.4 'struct sock' are linked directly by 'next' pointer in them
        for b in getFullBuckets(t.ehash_addr, t.eb_size, t.ehash_size, t.chain_off):
            next = b
            while (next):
                s = readSU(t.sockname, next)
                next = s.next
	    yield s
    else:
        # 2.6
        for b in getFullBuckets(t.ehash_addr, t.eb_size, t.ehash_size, t.chain_off):
            for a in sk_for_each(b):
                s = readSU("struct tcp_sock", a)
                yield s


# 
def get_TCP_TIMEWAIT():
    t = INET_Stuff
    if (t.Kernel24):
        # 2.4 
        # On 2.4 we really have 'struct tcp_tw_bucket *' table
        ehash_tw = long(t.ehash_addr) + t.eb_size * t.ehash_size
        for b in getFullBuckets(ehash_tw, t.eb_size, t.ehash_size, t.chain_off):
            next = b
            while (next):
                s = readSU('struct tcp_tw_bucket', next)
                next = s.next
                yield s
    else:
        # 2.6
        if (t.tw_chain_off != -1):
            # 2.6.22
            ehash_tw = t.ehash_addr
            chain_off = t.tw_chain_off
        else:
            ehash_tw = long(t.ehash_addr) + t.eb_size * t.ehash_size
            chain_off = t.chain_off
        for b in getFullBuckets(ehash_tw, t.eb_size, t.ehash_size, chain_off):
            for a in sk_for_each(b):
                tw = readSU(t.tw_type, a)
                yield tw

# ----------------- UDP ----------------------------


def get_UDP():
    if (INET_Stuff.Kernel24):
	# 2.4
	for b in readSymbol("udp_hash"):
	    next = b
	    while (next):
		s = readSU('struct sock', next)
		next = s.next
		yield s
	
    else:
	# 2.6
	for s in readSymbol("udp_hash"):
	    first = s.first
	    if (first):
		for a in  sk_for_each(first):
		    s = readSU("struct udp_sock", a)
		    yield s

# -------------------- RAW ------------------------------------------
def get_RAW():
    if (INET_Stuff.Kernel24):
	# 2.4
	for b in readSymbol("raw_v4_htable"):
	    next = b
	    while (next):
		s = readSU('struct sock', next)
		next = s.next
		yield s
	
    else:
	# 2.6
        #
        # 2.6.27
        try:
            table = readSymbol("raw_v4_hashinfo").ht
            # older
        except TypeError:
            table = readSymbol("raw_v4_htable")
	for s in table:
	    first = s.first
	    if (first):
		for a in  sk_for_each(first):
		    s = readSU("struct raw_sock", a)
		    yield s

def get_RAW6():
    if (INET_Stuff.Kernel24):
	# 2.4 - not implemented yet
        return

    elif (symbol_exists("raw_v6_hashinfo")):
        # 2.6.27
        raw_v6_hashinfo = readSU("struct raw_hashinfo",
                                 sym2addr("raw_v6_hashinfo"))
        table = raw_v6_hashinfo.ht
	for s in table:
	    first = s.first
	    if (first):
		for a in  sk_for_each(first):
		    s = readSU("struct inet_sock", a)
		    yield s

    else:
	# Older 2.6
        # Unfortunately, the default kernel does not have "raw_v6_htable"
        # definition (it's in ipv6 DLKM...). And we don't have
        # 'struct raw6_sock' either...
        addr = sym2addr("raw_v6_htable")
	# If addr ==0, there is no v6 support enabled
	if (addr == 0):
	    return
        # struct hlist_head raw_v6_htable[RAWV6_HTABLE_SIZE];
        # RAWV6_HTABLE_SIZE = 256, but try to obtain this programmatically
        si = whatis("inet_protos")
        RAWV6_HTABLE_SIZE = si.array
        #print "RAWV6_HTABLE_SIZE=", RAWV6_HTABLE_SIZE

        szhead = struct_size("struct hlist_head")
        for i in range(RAWV6_HTABLE_SIZE):
            s = readSU("struct hlist_head", addr+i*szhead)
	    first = s.first
	    if (first):
		for a in  sk_for_each(first):
                    # In reality we return 'raw6_sock', but it
                    # has 'inet_sock' as the first field (new 2.6) or
                    # inet_sock similar layout for old 2.6
		    s = readSU("struct inet_sock", a)
		    yield s
                    
# ------------------- AF_UNIX ---------------------------------------

# We pass 'struct unix_sock' for new kernels and just 
# 'struct sock' for old ones
def unix_sock(s):
    state = s.state
    path = ''
    ino = 0
    sk_socket = s.socket
    if (sk_socket):
	ino = sk_socket.Ino
	
    uaddr = s.Uaddr


    if (uaddr):
	try:
	    path =  uaddr.name.sun_path
	except crash.error:
	    path = "!Cannot read memory!"
	#
	if (uaddr.hash != INET_Stuff.UNIX_HASH_SIZE):
	    ulen = uaddr.len - 2
	    # ABSTRACT
	    path = '@' + path[1:ulen]
	    #path = path.split('\0')[0]
    return state, ino, path




def get_AF_UNIX():

    if (struct_size("struct unix_sock") == -1):
        # Old-style AF_UNIX sockets
        unix_socket_table = readSymbol("unix_socket_table")
        for b in unix_socket_table:
            next = b
            while (next):
		#print hexl(next)
                s = readSU('struct sock', next)
                next = s.next
		yield s
    else:
        # New-style AF_UNIX sockets, using hash buckets
        usocks_addrs = []
        # On those kernels where unix sockets are built as a module, we cannot find
        # symbolic info for unix_socket_table
        try:
            ust = whatis("unix_socket_table")
            unix_socket_table = readSymbol("unix_socket_table")
        except:
            descr = "struct hlist_head unix_socket_table[257];"
            print "We don't have symbolic access to unix_socket_table, assuming"
            print descr
            unix_socket_table = readSymbol("unix_socket_table", descr)
            #return

        sainfo = getStructInfo("struct socket_alloc")
        vfs_off = sainfo["vfs_inode"].offset - sainfo["socket"].offset
        #print "vfs_off=", vfs_off

        for s in unix_socket_table:
            first = s.first
            if (first):
                for e in sk_for_each(first):
                    s = readSU("struct unix_sock", e)
                    sk_socket = s.sk.sk_socket
                    if (sk_socket == 0):
                        continue
                    yield s


# Print the contents of accept_queue
def print_accept_queue(pstr):
    accept_queue = pstr.accept_queue
    syn_table = pstr.l_opt.syn_table
    print "    --- Accept Queue", accept_queue
    if (accept_queue.hasField("rskq_accept_head")):
        qhead = accept_queue.rskq_accept_head
    else:
        qhead = accept_queue
    if (qhead.hasField("dl_next")):
        for rq in readStructNext(qhead, "dl_next"):
            if (rq.hasField("af")):
                v4_req = rq.af.v4_req
                laddr = v4_req.loc_addr
                raddr = v4_req.rmt_addr
            else:
                inet_sock = rq.sk.castTo("struct inet_sock")
                laddr = inet_sock.rcv_saddr
                raddr = inet_sock.daddr
            print '\t  laddr=%s raddr=%s' % (ntodots(laddr), ntodots(raddr))
    # Now print syn_table. It can be either an explicitly-sized array, e.g.
    # 	struct open_request	*syn_table[TCP_SYNQ_HSIZE];
    # or zero-sized array with hashsize in nr_table_entries
    # 	struct open_request	*syn_table[0];

    if (type(syn_table) == type([])):
        entries = len(syn_table)
    else:
        entries = pstr.l_opt.nr_table_entries
    synq = []
    for i in range(entries):
        for rq in readStructNext(syn_table[i], "dl_next"):
            synq.append(rq)
    if (synq):
        print "    --- SYN-Queue"
        for rq in synq:
            if (rq.hasField("af")):
                v4_req = rq.af.v4_req
                laddr = v4_req.loc_addr
                raddr = v4_req.rmt_addr
            elif (rq.sk):
                inet_sock = rq.sk.castTo("struct inet_sock")
                laddr = inet_sock.rcv_saddr
                raddr = inet_sock.daddr
            elif (struct_exists('struct inet_request_sock')):
                irq = rq.castTo('struct inet_request_sock')
                laddr = irq.loc_addr
                raddr = irq.rmt_addr
            else:
                print "Don't know how to print synq for this kernel"
            print '\t  laddr=%-20s raddr=%-20s' % (ntodots(laddr), ntodots(raddr))
            

#  Protocol families
P_FAMILIES_c = '''
#define	PF_UNSPEC	0	/* Unspecified.  */
#define	PF_LOCAL	1	/* Local to host (pipes and file-domain).  */
#define	PF_UNIX		PF_LOCAL /* Old BSD name for PF_LOCAL.  */
#define	PF_FILE		PF_LOCAL /* Another non-standard name for PF_LOCAL.  */
#define	PF_INET		2	/* IP protocol family.  */
#define	PF_AX25		3	/* Amateur Radio AX.25.  */
#define	PF_IPX		4	/* Novell Internet Protocol.  */
#define	PF_APPLETALK	5	/* Appletalk DDP.  */
#define	PF_NETROM	6	/* Amateur radio NetROM.  */
#define	PF_BRIDGE	7	/* Multiprotocol bridge.  */
#define	PF_ATMPVC	8	/* ATM PVCs.  */
#define	PF_X25		9	/* Reserved for X.25 project.  */
#define	PF_INET6	10	/* IP version 6.  */
#define	PF_ROSE		11	/* Amateur Radio X.25 PLP.  */
#define	PF_DECnet	12	/* Reserved for DECnet project.  */
#define	PF_NETBEUI	13	/* Reserved for 802.2LLC project.  */
#define	PF_SECURITY	14	/* Security callback pseudo AF.  */
#define	PF_KEY		15	/* PF_KEY key management API.  */
#define	PF_NETLINK	16
#define	PF_ROUTE	PF_NETLINK /* Alias to emulate 4.4BSD.  */
#define	PF_PACKET	17	/* Packet family.  */
#define	PF_ASH		18	/* Ash.  */
#define	PF_ECONET	19	/* Acorn Econet.  */
#define	PF_ATMSVC	20	/* ATM SVCs.  */
#define	PF_SNA		22	/* Linux SNA Project */
#define	PF_IRDA		23	/* IRDA sockets.  */
#define	PF_PPPOX	24	/* PPPoX sockets.  */
#define	PF_WANPIPE	25	/* Wanpipe API sockets.  */
#define	PF_BLUETOOTH	31	/* Bluetooth sockets.  */
#define	PF_MAX		32	/* For now..  */
'''

P_FAMILIES = CDefine(P_FAMILIES_c)


tcp_state_c = '''
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING,	 /* now a valid state */

  TCP_MAX_STATES /* Leave at the end! */
};
'''

tcpState = CEnum(tcp_state_c)

sock_type_c = '''
enum sock_type {
	SOCK_STREAM	= 1,
	SOCK_DGRAM	= 2,
	SOCK_RAW	= 3,
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10
};
'''

sockTypes = CEnum(sock_type_c)

# Some common protocols

PROTONAMES = {
    1:  'icmp',
    2:  'igmp',
    6:  'tcp',
    17: 'udp',
    50: 'esp',
    51: 'ah',
    132: 'sctp'
    }

def protoName(proto):
    try:
        return PROTONAMES[proto]
    except KeyError:
        return "proto=%d" % proto


# Sk_buffs
# Can be used to print both sk_buff_head and sk_buff
__devhdrs = ["dev", "input_dev", "real_dev"]
def print_skbuff_head(skb, v = 0):
    if (skb.isNamed("struct sk_buff_head")):
	skb = skb.castTo("struct sk_buff")
	skblist = readStructNext(skb, "next", inchead = False)
    else:
	skblist = readStructNext(skb, "next")

    for skb in skblist:
	if (v > 0):
	   print skb, skb.sk
	# Check for corruption
	sk = skb.sk
	family = "n/a"
	if (sk):
	    family = sk.family
		
	if (family == P_FAMILIES.PF_INET):
	    isock = IP_sock(sk)
	    print "\t", isock

	elif (sk):
	    print "\tFamily:", family, skb
	else:
	    print WARNING, 'sk=NULL'
	    decode_skbuf(skb, v)
	devs = [skb.dev]
	# real_dev and input_dev do not exist anymore on newer kernels
	try:
	    inout =  skb.input_dev
	except KeyError:
	    input_dev = None
	devs.append(input_dev)
            
	try:
	    real_dev =  skb.real_dev
	except KeyError:
	    real_dev = None
	devs.append(real_dev)
	print "\t\t",
	for h, dev in zip(__devhdrs, devs):
	    if (dev):
		ndev = dev.name
	    else:
		ndev = '0x0'
	    print "%s=%s " %(h, ndev),
	print ''
	

# Generate a 1-liner based on L3 header and L4 header.
# Here protocol is ETH protocol, e.g.
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
# and nh and h are addresses of L3 and L4 headers
ETH_P_IP = 0x0800
def IP_oneliner(nh, h):
    iphdr = readSU("struct iphdr", nh)
    proto = iphdr.protocol
    saddr = iphdr.saddr
    daddr = iphdr.daddr
    ipversion = iphdr.version
    if (proto == 6):          #TCP
	tcphdr = readSU("struct tcphdr", h)
	sport = ntohs(tcphdr.source)
	dport = ntohs(tcphdr.dest)
	left = "tcp".ljust(5)
    return left + formatIPv4(saddr, sport) + formatIPv4(daddr, dport)

	
# Decode and print skbuf as well as we can, taking into account different
# fields
def decode_skbuf(addr, v = 0):
    skb = readSU("struct sk_buff", addr)
    nh = skb.nh.raw
    ETH_protocol = ntohs(skb.protocol)
    if (nh == 0):
	# Data contains our headers
	nh = skb.data
	if (ETH_protocol != ETH_P_IP):
	   print "Cannot decode protocol=%d" % ETH_protocol
	   return skb
	iphdr = readSU("struct iphdr", nh)
	hlen = 1 << iphdr.ihl
	h = long(iphdr) + hlen
    else:
	h = skb.h.raw

    if (v == 0):
	# 1-liner
	print IP_oneliner(nh, h)
	return skb
    if (v > 1):
	print " ===== Decoding", skb, "===="
 
    iph = decode_IP_header(nh, v)
    # Now check whether we can decode L4
    proto = iph.protocol
    if (h == 0):
	# Try to decode data
	print "Need to decode raw L4 data, is not implemented yet"
	return skb	
    if (proto == 6):
	# TCP
	print decode_TCP_header(h, v)
    return skb

# Decode and print IP header as received from network
def decode_IP_header(addr, v = 0):
    iphdr = readSU("struct iphdr", addr)
    frag = ntohs(iphdr.frag_off)
    flags = frag >> 13
    frag_off = frag & (0xffff >> 3)
    id = ntohs(iphdr.id)
    saddr = ntodots(iphdr.saddr)
    daddr = ntodots(iphdr.daddr)
    proto = iphdr.protocol
    print "IPv%d" % iphdr.version
    print "  tos=%d id=%d fl=%d frag=%d ttl=%d proto=%d saddr=%s daddr=%s" %\
        (iphdr.tos, id, flags, frag_off, iphdr.ttl, proto, saddr, daddr)
    return iphdr
    
# Decode and print TCP header as received from network
def decode_TCP_header(addr, v = 0):
    tcphdr = readSU("struct tcphdr", addr)
    sport = ntohs(tcphdr.source)
    dport = ntohs(tcphdr.dest)
    tcpstr = "TCP: sport=%d dport=%d" % (sport, dport)
    if (v < 1):
        return tcpstr
    else:
	flags = readU8(long(addr) + 12)
	return tcpstr + "\n" + decode_TCP_flags(flags)

__TCP_flags_template = '''
    Flags: 0x%02x (%s)
        %d... .... = Congestion Window Reduced (CWR): %s
        .%d.. .... = ECN-Echo: %s
        ..%d. .... = Urgent: %s
        ...%d .... = Acknowledgment: %s
        .... %d... = Push: %s
        .... .%d.. = Reset: %s
        .... ..%d. = Syn: %s
        .... ...%d = Fin: %s
'''
__TCP_flags_names = ('CWR', 'ECN', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN')
def decode_TCP_flags(flags):
    bits = [0] * 16
    fstr = []
    flags_copy = flags
    for i in range(8):
	f = (flags & 0x1)
	ind = 2 * (7-i)
	bits[ind] = f
	if (f):
	    fstr.append(__TCP_flags_names[7-i])
	    bits[ind+1] = "Set"
	else:
	    bits[ind+1] = "Not set"
	flags >>= 1
    fstr = string.join(fstr, ',')
    args = tuple([flags_copy, fstr] + bits)
    return __TCP_flags_template % args
	

