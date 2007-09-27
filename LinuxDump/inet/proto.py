# module LinuxDump.inet.proto
#
# Time-stamp: <07/09/27 15:35:24 alexs>
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

class IPv4_conn:
    def __init__(self, left='', right='', sock=None):
        # You can put here anything that needs to be printed, e.g. sock addr
        self.left = left
        self.right = right
        if (right):
            right = ' ' + right
        # We expect at least the following members:
        # src, sport, dst, dport
	if (sock):
	    self.src = sock.rcv_saddr
	    self.sport = ntohs(sock.sport)
	    self.dst = sock.daddr
	    self.dport = ntohs(sock.dport)

    def __str__(self):
        #Local Address           Foreign Address
        #0.0.0.0:45959           0.0.0.0:*
        return  self.left+ ' ' + \
               formatIPv4(self.src, self.sport)+\
               formatIPv4(self.dst, self.dport)+\
               self.right

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

# Extract src/dest/ports from 'inet_sock'
class IPv6_conn:
    def __init__(self, left='', right='', sock=None):
        # You can put here anything that needs to be printed, e.g. sock addr
        self.left = left
        self.right = right
        if (right):
            right = ' ' + right
            
        # We expect sock to be 'inet_sock' and PF_INET6
	if (sock):
            pinet6 = sock.Deref.pinet6
	    self.src = pinet6.rcv_saddr.in6_u.u6_addr32
            self.dst = pinet6.daddr.in6_u.u6_addr32

	    try:
	    	self.sport = ntohs(sock.sport)
	    	self.dport = ntohs(sock.dport)
	    except KeyError:
		sockopt = sock.inet
                self.sport = ntohs(sockopt.sport)
                self.dport = ntohs(sockopt.dport)


    def __str__(self):
        #Local Address           Foreign Address
        #0.0.0.0:45959           0.0.0.0:*
        return  self.left+ ' ' + \
               formatIPv6(self.src, self.sport)+\
               formatIPv6(self.dst, self.dport)+\
               self.right

# v4/v6 IP - family deduced from socket.
# We analyze the type of passed object, here is what is acceptable:
# - 'struct sock' (from 2.4 kernels)
# - 'struct inet_sock' (from 2.6)
# - structs derived from inet_sock (e.g. tcp_sock). All these structures
# have 'inet_sock' at offset 0

class IP_sock(object):
    def __init__(self, o, details=False):
        self.left = self.right = ''
        self.family = -1
        #if (o.isNamed("struct sock")):
	if (sock_V1):
            # -----------------2.4-------------------
            s = o
            self.family = family = s.family
            self.protocol = s.protocol
            self.sktype = s.type
            if (family == P_FAMILIES.PF_INET):
                self.src = s.rcv_saddr
                self.sport = ntohs(s.sport)
                self.dst = s.daddr
                self.dport = ntohs(s.dport)
                self.state =  s.state   # Makes sense mainly for TCP

            # Protocol-specific details
            if (not details):
                return

            # The following parameters make sense for most sockets
            self.rcvbuf = s.rcvbuf
            self.sndbuf = s.sndbuf
            self.rmem_alloc = s.rmem_alloc.counter
            self.wmem_alloc = s.wmem_alloc.counter

            if (self.protocol == 6):    # TCP
                # Details are different for TCP in different states
                if (self.state != tcpState.TCP_LISTEN \
                    and self.state != tcpState.TCP_TIME_WAIT):
                    self.rx_opt = self.topt = s.tp_pinfo.af_tcp
                elif (self.state == tcpState.TCP_LISTEN):
                    self.sk_max_ack_backlog = s.max_ack_backlog
                    self.sk_ack_backlog = s.ack_backlog
		    self.l_opt= Deref(s.tp_pinfo.af_tcp.listen_opt)
            elif (self.protocol == 17): # UDP
                self.uopt = s.tp_pinfo.af_udp
            elif (self.sktype == sockTypes.SOCK_RAW): # RAW (mostly ICMP)
                pass

        else:
            # ----------------2.6---------------------
            s = o.castTo("struct inet_sock")
            sock = o.castTo("struct sock")
            sk = s.sk
            #skc = sk.__getattr__("__sk_common")
            skc = sk.__sk_common
            self.family = family = skc.skc_family
            self.protocol = sock.sk_protocol
            self.sktype = sock.sk_type
            self.state = skc.skc_state  # Is mostly of interest for TCP
            try:
                sp= s.inet
            except KeyError:
                sp = s
            if (family == P_FAMILIES.PF_INET):
                self.src = sp.rcv_saddr
                self.sport = ntohs(sp.sport)
                self.dst = sp.daddr
                self.dport = ntohs(sp.dport)
            elif (family == P_FAMILIES.PF_INET6):
                pinet6 = Deref(s.pinet6)
                v =  pinet6.rcv_saddr.in6_u
                self.src = pinet6.rcv_saddr.in6_u.u6_addr32
                self.dst = pinet6.daddr.in6_u.u6_addr32

                self.sport = ntohs(sp.sport)
                self.dport = ntohs(sp.dport)

            else:
                return

            # Protocol-specific details
            if (not details):
                return
            
            # The following parameters make sense for most sockets
            self.rcvbuf = sk.sk_rcvbuf
            self.sndbuf = sk.sk_sndbuf
            self.rmem_alloc = sk.sk_rmem_alloc.counter
            self.wmem_alloc = sk.sk_wmem_alloc.counter

            if (self.protocol == 6):    # TCP
                # Details are different for TCP in different states
                if (self.state != tcpState.TCP_LISTEN \
                    and self.state != tcpState.TCP_TIME_WAIT):
                    self.rcvbuf = sk.sk_rcvbuf
                    self.sndbuf = sk.sk_sndbuf
                    self.topt = o
                    if (o.hasField("tcp")):
                        # Older 2.6, e.g. 2.6.9
                        self.rx_opt = self.topt = o.tcp
                    else:
                        # Newer 2.6, e.g. 2.6.15
                        self.rx_opt = o.rx_opt
                elif (self.state == tcpState.TCP_LISTEN):
		    if (struct_exists("struct inet_connection_sock")):
			csk = o.castTo("struct inet_connection_sock")
			accept_queue = csk.icsk_accept_queue
			l_opt = Deref(accept_queue.listen_opt)
		    else:
		        tcpsk = o.tcp
		        l_opt = Deref(tcpsk.listen_opt)
                    self.sk_max_ack_backlog = sk.sk_max_ack_backlog
                    self.sk_ack_backlog = sk.sk_ack_backlog
		    self.l_opt = l_opt
            elif (self.protocol == 17): # UDP
                if (o.hasField("udp")):
		    # Older 2.6, e.g. 2.6.9
                    self.uopt = o.udp
		else:
		    # Newer 2.6, e.g. 2.6.15
                    # UDP options are just fields in udp_sock
		    self.uopt = o

            elif (self.sktype == sockTypes.SOCK_RAW): # RAW (mostly ICMP)
                pass
                
                    


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

# A special case for TIME_WAIT sockets - they are not really sockets but
# rather some special structures

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
        if (tw.isNamed("struct tcp_tw_bucket")):
            # 2.4 and older 2.6 (<2.6.11) has 'struct tcp_tw_bucket'
            if (tw.hasField("__tw_common")):
                skc = tw.__tw_common
                self.state = skc.skc_state
                self.family = skc.skc_family
            else:
                skc = None
                self.state = tw.state
                self.family = tw.family

            if  (self.family == P_FAMILIES.PF_INET6):
                if (skc):
                    self.sport = ntohs(tw.tw_sport)
                    self.dport = ntohs(tw.tw_dport)
                    self.src = tw.tw_v6_rcv_saddr.in6_u.u6_addr32
                    self.dst = tw.tw_v6_daddr.in6_u.u6_addr32
                    self.tw_timeout = tw.tw_timeout
                    self.ttd = tw.tw_ttd

            else:
                if (skc):
                    self.src = tw.tw_rcv_saddr
                    self.sport = ntohs(tw.tw_sport)
                    self.dst = tw.tw_daddr
                    self.dport = ntohs(tw.tw_dport)
                    self.tw_timeout = tw.tw_timeout
                    self.ttd = tw.tw_ttd

                else:
                    self.src = tw.rcv_saddr
                    self.sport = ntohs(tw.sport)
                    self.dst = tw.daddr
                    self.dport = ntohs(tw.dport)
                    self.tw_timeout = tw.timeout
                    self.ttd = tw.ttd

            if (details):
                jiffies = readSymbol("jiffies")
                self.ttd = self.ttd - jiffies
                if (self.ttd < 0):
                    self.ttd = 0
        else:
            # This is newer 2.6, we have 'tcp_timewait_sock which is based on
            # inet_timewait_sock
            iw = tw.castTo("struct inet_timewait_sock")
            skc = iw.__tw_common
            self.state = skc.skc_state
            self.family = skc.skc_family
            prot = Deref(skc.skc_prot)
            if (self.family == P_FAMILIES.PF_INET6):
                # On 2.6.17 we have a generic inet6_timewait_sock, but on
                # 2.6.15 we have tcp6_timewait_sock
                try:
                    # Cast this to inet6_timewait_sock
                    ipv6_offset = iw.tw_ipv6_offset
                    # struct inet6_timewait_sock *tw6 = inet6_twsk((struct sock *)tw);
                    # (((u8 *)sk) + inet_twsk(sk)->tw_ipv6_offset)
                    addr = Addr(iw) + iw.tw_ipv6_offset
                    tw6 = readSU("struct inet6_timewait_sock", addr)
                except KeyError:
                    # tcp6_timewait_sock
                    tw6 = tw.castTo("struct tcp6_timewait_sock")
                self.sport = ntohs(iw.tw_sport)
                self.dport = ntohs(iw.tw_dport)
                self.src = tw6.tw_v6_rcv_saddr.in6_u.u6_addr32
                self.dst = tw6.tw_v6_daddr.in6_u.u6_addr32
            else:
                self.sport = ntohs(iw.tw_sport)
                self.dport = ntohs(iw.tw_dport)

                self.src = iw.tw_rcv_saddr
                self.dst = iw.tw_daddr


            if (details):
                jiffies = readSymbol("jiffies")
                self.tw_timeout = iw.tw_timeout
                self.ttd = iw.tw_ttd - jiffies


# Convert inode to socket
def inode2socketaddr(inode):
    if (not S_ISSOCK(inode.i_mode)):
        return None
    if (sock_V1):
        return Addr(inode.u)
    else:
        return Addr(inode) - struct_size("struct socket")

    

# Decode info for 'struct sock'
def olddecodeSock(sock):
    if (sock_V1):
	family = sock.family
	# For old kernels prot is NULL for AF_UNIX
	try:
	    protoname = sock.Deref.prot.name
	except IndexError:
	    protoname = "UNIX"
	sktype = sock.type
    else:
	skcomm = sock.__sk_common
	family = skcomm.skc_family
	try:
	    protoname =  skcomm.Deref.skc_prot.name
	except KeyError:
	    try:
		protoname = sock.Deref.sk_prot.name
	    except IndexError:
		protoname= '???'
	sktype = sock.sk_type
    if (family == P_FAMILIES.PF_INET or family == P_FAMILIES.PF_INET6):
	if (not sock_V1):
	    sock = sock.castTo("struct inet_sock")
	    try:
		sockopt= sock.inet
	    except KeyError:
		sockopt = sock
	else:
	    sockopt = sock
    else:
	sockopt = None
    return family, sktype, protoname, sock, sockopt

def decodeSock(sock):
    if (sock_V1):
	family = sock.family
	# For old kernels prot is NULL for AF_UNIX
	try:
	    protoname = sock.prot.Deref.name
	except IndexError:
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

# Check whether we have inet_sock
def check_inet_sock():
    # Let us create inet_sock if needed
    if (struct_size("struct inet_sock") == -1):
        as = ArtStructInfo("struct inet_sock")
        as.append("struct sock	  sk;")
        if (symbol_exists("tcpv6_protocol") and 
            symbol_exists("udpv6_protocol")):
            if (debug):
                print "Adding struct ipv6_pinfo *pinet6;"
            as.append("struct ipv6_pinfo *pinet6;")
        iopti = getStructInfo("struct inet_opt")
        as.append(iopti)
        # print as

        # tcp_sock is inet_sock followed by tcp_opt
        tas = ArtStructInfo("struct tcp_sock")
        tas.append(as)
        tas.append("struct tcp_opt tcp;")
        #print tas

        # udp_sock is inet_sock followed by udp_opt
        uas = ArtStructInfo("struct udp_sock")
        uas.append(as)
        uas.append("struct udp_opt udp;")
        #print uas
	
	# raw_sock is inet_sock followed by raw_opt
	ras = ArtStructInfo("struct raw_sock")
        ras.append(as)
        ras.append("struct raw_opt udp;")
	#print ras


# Initialize INET_Stuff
def init_INET_Stuff():
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

    
    # Now copy locals to INET_Stuff
    INET_Stuff.__dict__.update(locals())

# TCP structures are quite different for 2.4 and 2.6 kernels, it makes sense to
# have two different versions of code

INET_Stuff = Bunch()
# Initialize TCP stuff
init_INET_Stuff()

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
        ehash_tw = t.ehash_addr + t.eb_size * t.ehash_size
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
            ehash_tw = t.ehash_addr + t.eb_size * t.ehash_size
            chain_off = t.chain_off
        for b in getFullBuckets(ehash_tw, t.eb_size, t.ehash_size, chain_off):
            for a in sk_for_each(b):
                tw = readSU(t.tw_type, a)
                yield tw

# ----------------- UDP ----------------------------

def UDP():
    print '-------- UDP ----------'
    if (struct_size("struct sock_common") == -1):
        UDP_k24()
    else:
        UDP_k26()

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
	for s in readSymbol("raw_v4_htable"):
	    first = s.first
	    if (first):
		for a in  sk_for_each(first):
		    s = readSU("struct raw_sock", a)
		    yield s

def get_RAW6():
    if (INET_Stuff.Kernel24):
	# 2.4 - not implemented yet
        return
	
    else:
	# 2.6
        # Unfortunately, the default kernel does not have "raw_v6_htable"
        # definition (it's in ipv6 DLKM...). And we don't have
        # 'struct raw6_sock' either...
        addr = sym2addr("raw_v6_htable")
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

# Old kernels use different tables for AF_UNIX
def unix_sock_old():
    unix_socket_table = readSymbol("unix_socket_table")
    UNIX_HASH_SIZE = len(unix_socket_table) - 1
    for b in unix_socket_table:
        next = b
        while (next):
            s = readSU('struct sock', next)
            print hexl(next),
            addr = s.protinfo.af_unix.addr
            if (addr):
                uaddr = readSU("struct unix_address", addr)
                path =  uaddr.name.sun_path
                if (uaddr.hash != UNIX_HASH_SIZE):
                    # ABSTRACT
                    path = '@' + path[1:]
                print  path.split('\0')[0]
            else:
                print ''    
            next = s.next

def unix_sock():
    if (struct_size("struct unix_sock") == -1):
        unix_sock_old()
        return
    # Non-empty buckets
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

    UNIX_HASH_SIZE = len(unix_socket_table) - 1
    for s in unix_socket_table:
        first = s.first
        if (first):
            usocks_addrs +=  sk_for_each(first)

    sainfo = getStructInfo("struct socket_alloc")
    vfs_off = sainfo["vfs_inode"].offset - sainfo["socket"].offset
    #print "vfs_off=", vfs_off

    for e in usocks_addrs:
	s = readSU("struct unix_sock", e)
        sk_socket = s.sk.sk_socket
        if (sk_socket == 0):
            continue
        vfs_inode_addr = sk_socket + vfs_off
        vfs_inode = readSU("struct inode", vfs_inode_addr)
        ino = vfs_inode.i_ino
        print hexl(e), hexl(sk_socket), ino, 
        if (s.addr):
            #uaddr = readSU("struct unix_address", s.addr)
            uaddr = s.Deref.addr
            path =  uaddr.name.sun_path
            if (uaddr.hash != UNIX_HASH_SIZE):
                # ABSTRACT
                path = '@' + path[1:]
            print  path
            #print  s.GDBderef("->addr->name->sun_path")
        else:
            print ''


def get_AF_UNIX(details=False):
    if (struct_size("struct unix_sock") == -1):
        # Old-style AF_UNIX sockets
        unix_socket_table = readSymbol("unix_socket_table")
        UNIX_HASH_SIZE = len(unix_socket_table) - 1
        INET_Stuff.UNIX_HASH_SIZE = UNIX_HASH_SIZE
        for b in unix_socket_table:
            next = b
            while (next):
                s = readSU('struct sock', next)
                next = s.next
                if (details):
                    # We use TCP-states here: 1,7 an 10
                    state = s.state
                    path = ''
                    sk_socket = s.socket
                    if (socket):
                        #sk->socket->inode->i_ino
                        ino = s.socket.Deref.inode.Deref.i_ino
                    else:
                        ino = 0
                    addr = s.protinfo.af_unix.addr
                    if (addr):
                        uaddr = readSU("struct unix_address", addr)
                        path =  uaddr.name.sun_path
                        if (uaddr.hash != UNIX_HASH_SIZE):
                            # ABSTRACT
                            path = '@' + path[1:]
                            path =  path.split('\0')[0]
                    yield (s, state, ino, path)
                else:
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

        INET_Stuff.UNIX_HASH_SIZE = len(unix_socket_table) - 1
        UNIX_HASH_SIZE = len(unix_socket_table) - 1
        
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
                    # We use TCP-states
                    state = s.sk.__sk_common.skc_state
                    if (details):
                        path = ''
                        vfs_inode_addr = sk_socket + vfs_off
                        vfs_inode = readSU("struct inode", vfs_inode_addr)
                        ino = vfs_inode.i_ino
                        if (s.addr):
                            uaddr = Deref(s.addr)
                            path =  uaddr.name.sun_path
                            if (uaddr.hash != UNIX_HASH_SIZE):
                                # ABSTRACT
				path = '@' + path[1:]

                            path = path.split('\0')[0]
                        yield (s, state, ino, path)
                    else:
                        yield s


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
    51: 'ah'
    }
