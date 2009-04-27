#!/usr/bin/env python

# Time-stamp: <08/06/20 14:49:50 alexs>

# Copyright (C) 2006-2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2008 Hewlett-Packard Co., All rights reserved.

# Print info about connections and sockets 

from pykdump.API import *

# For INET stuff
from LinuxDump.inet import *
from LinuxDump.inet import proto, netdevice
#reload(proto)
from LinuxDump.inet.proto import format_sockaddr_in
     
loadModule("sctp")

# Two groups of state enums:

# For sk_state
#typedef enum {
	#SCTP_SS_CLOSED         = TCP_CLOSE,        7
	#SCTP_SS_LISTENING      = TCP_LISTEN,      10
	#SCTP_SS_ESTABLISHING   = TCP_SYN_SENT,     2
	#SCTP_SS_ESTABLISHED    = TCP_ESTABLISHED,  1
	#SCTP_SS_DISCONNECTING  = TCP_CLOSING,     11
#} sctp_sock_state_t;

# for assoc state
#/* SCTP state defines for internal state machine */
#typedef enum {

	#SCTP_STATE_EMPTY		= 0,
	#SCTP_STATE_CLOSED		= 1,
	#SCTP_STATE_COOKIE_WAIT		= 2,
	#SCTP_STATE_COOKIE_ECHOED	= 3,
	#SCTP_STATE_ESTABLISHED		= 4,
	#SCTP_STATE_SHUTDOWN_PENDING	= 5,
	#SCTP_STATE_SHUTDOWN_SENT	= 6,
	#SCTP_STATE_SHUTDOWN_RECEIVED	= 7,
	#SCTP_STATE_SHUTDOWN_ACK_SENT	= 8,

#} sctp_state_t;

# Remote addrs belonging to the sctp_association *assoc
def assoc_remaddrs(assoc):
    primary = assoc.peer.primary_addr
    primary_v4 = primary.v4.sin_addr.s_addr

    out = []
    for a in readList(assoc.peer.transport_addr_list, inchead = False):
	transport = container_of(a, "struct sctp_transport", "transports")
	ipaddr = transport.ipaddr
	v4 = ipaddr.v4
	addr = v4.sin_addr
	out.append("%s" % ntodots(addr.s_addr))

    return string.join(out, ' ')
    
# Local addrs belonging to the sctp_association *assoc
def assoc_locaddrs(epb):
    out = []
    for a in readList(epb.bind_addr.address_list, inchead = False):
	laddr = container_of(a, "struct sctp_sockaddr_entry", "list")
	ipaddr = laddr.a
	v4 = ipaddr.v4
	addr = v4.sin_addr
	out.append("%s" % ntodots(addr.s_addr))
    return string.join(out, ' ')
    
sctp_globals = readSymbol("sctp_globals")

ep_hashsize = sctp_globals.ep_hashsize
ep_hashtable = sctp_globals.ep_hashtable

assoc_hashsize = sctp_globals.assoc_hashsize
assoc_hashtable = sctp_globals.assoc_hashtable

# telco 2.0
#         for (epb = head->chain; epb; epb = epb->next) {
#                 assoc = sctp_assoc(epb);

for i in range(assoc_hashsize):
    epb = assoc_hashtable[i].chain
    if (not epb):
	continue
    

    print ""
    #print " ASSOC               SOCK   STY     SST ST HBKT ASSOC-ID UID LPORT  RPORT LADDRS <-> RADDRS"
    print " ASSOC               SOCK            SST ST LPORT RPORT LADDRS <-> RADDRS"
    #print "0xe00000409b996000 0xe0000040c2e4c080 10 4 51000 51000 10.249.54.1"
    for epb in readStructNext(epb, "next"):
	assoc = container_of(epb, "struct sctp_association", "base")
	sk = epb.sk
	state = sk.__sk_common.skc_state
	#print epb
	#if (long(assoc) != 0xe0000040c16a6000):
	#    continue
	print "%s %s" % (hexl(assoc),  hexl(sk)), state, assoc.state, \
	  epb.bind_addr.port, assoc.peer.port, assoc_locaddrs(epb) + '<->' + \
	  assoc_remaddrs(assoc)
	
	ep = assoc.ep
	print "\t ep=%s  refcnt=%d" %  (hexl(ep), ep.base.refcnt.counter)
	
	
# EndPoint table
for i in range(ep_hashsize):
    epb = ep_hashtable[i].chain
    if (not epb):
	continue
    print ""
    print " ENDPT                SOCK       STY SST LPORT   UID INODE LADDRS"
    #print "0xe000000127e9ad80 0xe0000040f5e86480 10 53000"
    for epb in readStructNext(epb, "next"):
	ep = container_of(epb, "struct sctp_endpoint", "base")
	sk = epb.sk
	state = sk.__sk_common.skc_state
	#print epb
	#if (long(assoc) != 0xe0000040c16a6000):
	#    continue
	print " %s %s" % (hexl(ep),  hexl(sk)), state, epb.bind_addr.port
        