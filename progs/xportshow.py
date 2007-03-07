#!/usr/bin/env python

# Time-stamp: <07/03/06 16:29:36 alexs>

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.

# Print info about connections and sockets 

from pykdump.API import *

# For INET stuff
from LinuxDump.inet import *
from LinuxDump.inet import proto, netdevice
from LinuxDump.inet.proto import tcpState, sockTypes, \
    IPv4_conn, IPv6_conn, IP_sock,  P_FAMILIES
from LinuxDump.inet.routing import print_fib

from LinuxDump.Tasks import TaskTable, taskFds

import string

debug = API_options.debug

sock_V1 = proto.sock_V1

details = False

print_listen = False
print_nolisten = True



def print_TCP_sock(o):
    pstr = IP_sock(o, details)
    print pstr
    tcp_state = pstr.state
    # Here we print things that are not kernel-dependent
    if (details):
        sfamily = P_FAMILIES.value2key(pstr.family)
        if (tcp_state != tcpState.TCP_LISTEN 
            and tcp_state != tcpState.TCP_TIME_WAIT):
            snd_wnd = pstr.topt.snd_wnd
            rcv_wnd = pstr.topt.rcv_wnd
            advmss = pstr.topt.advmss
            nonagle=pstr.topt.nonagle
            print "\twindows: rcv=%d, snd=%d  advmss=%d rcv_ws=%d snd_ws=%d" %\
                (rcv_wnd, snd_wnd, advmss,
                 pstr.rx_opt.rcv_wscale, pstr.rx_opt.snd_wscale)
            print "\tnonagle=%d sack_ok=%d tstamp_ok=%d" %\
                (nonagle, pstr.rx_opt.sack_ok, pstr.rx_opt.tstamp_ok)
	    print "\trx_queue=%d, tx_queue=%d" % (pstr.rmem_alloc,
                                                  pstr.wmem_alloc)
            print "\trcvbuf=%d, sndbuf=%d" % (pstr.rcvbuf, pstr.sndbuf)
        elif (tcp_state == tcpState.TCP_LISTEN):
            print "\t family=%s" % sfamily
	    print "\t backlog=%d(%d)" % (pstr.sk_ack_backlog,
                                         pstr.sk_max_ack_backlog)


# Print TCP info from TIMEWAIT buckets

# Print TCP info from TIMEWAIT buckets
def print_TCP_tw(tw):
    pstr = proto.IP_conn_tw(tw, details)
    print pstr
    if (details):
        print "\ttw_timeout=%d, ttd=%d" % (pstr.tw_timeout, pstr.ttd)
    

def print_TCP():
    # Some notes about printing the contents of TCP sockets
    # on 2.4 it is just 'sock' with extra unions pointing to TCP-specific
    # on 2.6 we have a generic inet_sock (for all INET protocols) and
    # tcp_sock for TCP. And tcp_sock is quite different for different 2.6.x
    # E.g. for 2.6.9
    # struct tcp_sock {
    #        struct sock       sk;
    # for 2.6.15
    # struct tcp_sock {
    #	/* inet_connection_sock has to be the first member of tcp_sock */
    #	struct inet_connection_sock	inet_conn;
    #...
    # struct inet_connection_sock {
    #	/* inet_sock has to be the first member! */
    #	struct inet_sock	  icsk_inet;
    #
    # As a result, the easiest way to print non-kernel specific info
    # is to cast all 2.6 tcp_sock to inet_sock (the headers say expicitly that
    # inet_sock should be the 1st member

    global jiffies
    
    
    # print LISTEN
    if (print_listen):
        for o in proto.get_TCP_LISTEN():
            if (details):
                print '-' * 78
                print o, '\t\tTCP'
            print_TCP_sock(o)

    if (not print_nolisten):
        return
    # Print ESTABLISHED TCP
    
    for o in proto.get_TCP_ESTABLISHED():
        if (details):
            print '-' * 78
            print o, '\t\tTCP'

        print_TCP_sock(o)
	
   
    # Print TIME_WAIT
    jiffies = readSymbol("jiffies")
    for tw in proto.get_TCP_TIMEWAIT():
        if (details):
            print '-' * 78
            print o, '\t\tTCP'
    
        print_TCP_tw(tw)

# print UDP

def print_UDP():
    for o in proto.get_UDP():
        pstr = IP_sock(o, details)
        # If we do not want LISTEN sockets only, ignore everything but
        # ESTABLISHED (there is no real LISTEN state for UDP)
        if (pstr.state == tcpState.TCP_ESTABLISHED):
            if (not print_nolisten): continue
        else:
            # LISTEN socket
            if (not print_listen): continue

        if (details):
            print '-' * 78
            print o, '\t\tUDP'
        print pstr
	if (details):
	    print "\trx_queue=%d, tx_queue=%d" % (pstr.rmem_alloc,
                                                  pstr.wmem_alloc)
	    print "\trcvbuf=%d, sndbuf=%d" % (pstr.rcvbuf, pstr.sndbuf)
            pending = pstr.uopt.pending
            corkflag = pstr.uopt.corkflag
            ulen = pstr.uopt.len
            print "\tpending=%d, corkflag=%d, len=%d" % (pending,
                                                         corkflag, ulen)

# print AF_UNIX

def print_UNIX():
    print "unix   State          I-node  Path"
    print "----------------------------------"
    for s, state, ino, path in proto.get_AF_UNIX(True):
        if (state == tcpState.TCP_LISTEN):
            if (not print_listen): continue
        else:
            if (not print_nolisten):
                continue
        if (details):
            print '-' * 78
            print s, '\t\tUnix'
           
        print "unix   %-12s   %-6d  %s" % (tcpState[state][4:],
                                           ino, path)

  

def print_RAW():
    for o in list(proto.get_RAW()) + list(proto.get_RAW6()):
        pstr = IP_sock(o, details)
        if (not print_listen and pstr.state != tcpState.TCP_ESTABLISHED):
            continue

        if (details):
            print '-' * 78
            print o, '\t\tRAW'
	print pstr
	if (details):
	    print "\trx_queue=%d, tx_queue=%d" % (pstr.rmem_alloc,
                                                  pstr.wmem_alloc)
	    print "\trcvbuf=%d, sndbuf=%d" % (pstr.rcvbuf, pstr.sndbuf)


# Print a summary of connections
def Summarize():

    print "TCP Connection Info"
    print "-------------------"
    counts = {}

    # LISTEN
    lqfull = 0                          # Listen Queue Full
    lqne = 0                            # Listen Queue Non-Empty
    for o in proto.get_TCP_LISTEN():
        pstr = IP_sock(o, True)
        counts[pstr.state] = counts.setdefault(pstr.state, 0) + 1
        if (pstr.sk_ack_backlog):
            lqne += 1
            if (pstr.sk_ack_backlog == pstr.sk_max_ack_backlog):
                lqfull += 1
    
    # ESTABLISHED TCP

    # How 'nonagle' is used on Linux: TCP_NODELAY sets 1
    #define TCP_NAGLE_OFF  1  /* Nagle's algo is disabled */
    #define TCP_NAGLE_CORK 2  /* Socket is corked	    */
    #define TCP_NAGLE_PUSH 4  /* Cork is overridden for already queued data */

    nodelay = 0
    w_rcv_closed = 0
    w_snd_closed = 0
    for o in proto.get_TCP_ESTABLISHED():
        pstr = IP_sock(o, True)
        counts[pstr.state] = counts.setdefault(pstr.state, 0) + 1
        nonagle=pstr.topt.nonagle
        if (nonagle == 1):
            nodelay += 1
        snd_wnd = pstr.topt.snd_wnd
        rcv_wnd = pstr.topt.rcv_wnd
        if (rcv_wnd == 0):
            w_rcv_closed += 1
        if (snd_wnd == 0):
            w_snd_closed += 1


	
   
    # TIME_WAIT
    jiffies = readSymbol("jiffies")
    for tw in proto.get_TCP_TIMEWAIT():
        pstr = proto.IP_conn_tw(tw, True)
        counts[pstr.state] = counts.setdefault(pstr.state, 0) + 1

    states = counts.keys()
    states.sort()
    for s in states:
        print "    %15s  %5d" % (tcpState[s][4:], counts[s])
    if (nodelay):
        print "\n\t\t\tNAGLE disabled (TCP_NODELAY): %5d" % nodelay

    if  (lqne or lqfull or w_rcv_closed or w_rcv_closed):
        print ""
        print "  Unusual Situations:"
    if (lqne):
        print "    Listen Queue Non-Empty:       %5d" % lqne
    if (lqfull):
        print "    Listen Queue Full:            %5d" % lqfull
    if (w_rcv_closed):
        print "    Receive Window Closed:        %5d" % w_rcv_closed
    if (w_snd_closed):
        print "    Send Window Closed:           %5d" % w_snd_closed


    print "\n\nUDP Connection Info"
    print "-------------------"
    count = rcvfull = sndfull = established = 0
    for o in proto.get_UDP():
        pstr = IP_sock(o, True)
        count += 1
        if (pstr.state == tcpState.TCP_ESTABLISHED):
            established += 1
        # Check whether buffers are full more than 50%
        if (pstr.rmem_alloc *100 >= pstr.rcvbuf * 75):
            rcvfull += 1
        if (pstr.wmem_alloc *100 >= pstr.sndbuf * 75):
            sndfull += 1
    print "  %d UDP sockets, %d in ESTABLISHED" % (count, established)
    if (rcvfull or sndfull):
        print "\tNote: buffer fill >=75%%  rcv=%d snd=%d" % (rcvfull, sndfull)


    print "\n\nUnix Connection Info"
    print "------------------------"

    counts = {}
    count = 0
    for s, state, ino, path in proto.get_AF_UNIX(True):
        counts[state] = counts.setdefault(state, 0) + 1
        count += 1
        
    states = counts.keys()
    states.sort()
    for s in states:
        print "    %15s  %5d" % (tcpState[s][4:], counts[s])

    print "\n\nRaw sockets info"
    print "--------------------"

    counts = {}
    for o in list(proto.get_RAW()) + list(proto.get_RAW6()):
         pstr = IP_sock(o, True)
         counts[state] = counts.setdefault(state, 0) + 1

    states = counts.keys()
    states.sort()

    for s in states:
        print "    %15s  %5d" % (tcpState[s][4:], counts[s])

    


   
    
def print_FragmentCache():
    pass

def print_dev_pack():
    ptype_all = readSymbol("ptype_all")
    #print "ptype_all=", ptype_all, "\n"
    # For 2.4 packet_type has next pointer, for 2.6 list_head is embedded
    newstyle = (whatis("ptype_base").ctype == "struct list_head")
    if (newstyle):
        offset = member_offset("struct packet_type", "list")
    else:
        offset = member_offset("struct packet_type", "next")


    print "--------ptype_all-------------------------------------------"
    if (newstyle):
        for pt in readSUListFromHead(Addr(ptype_all), "list",
                                     "struct packet_type"):
            print pt

            ptype = ntohs(pt.type)
            pdev = pt.dev
            pfunc = addr2sym(pt.func)
            print "\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc)
    else:
        # 2.4
        for pa in readList(ptype_all, offset):
            pt = readSU("struct packet_type", pa)
            print pt

            ptype = ntohs(pt.type)
            pdev = pt.dev
            pfunc = addr2sym(pt.func)
            print "\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc)


    print "\n--------ptype_base-------------------------------------------"
    bucket = 0
    for a in readSymbol("ptype_base"):
        if (newstyle):
            for pt in readSUListFromHead(Addr(a), "list", "struct packet_type"):
                print pt, " (bucket=%d)" % bucket

                ptype = ntohs(pt.type)
                pdev = pt.dev
                pfunc = addr2sym(pt.func)
                print "\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc)
        else:
            # 2.4
            if (a == 0):
                continue
            for pa in readList(a, offset):
                pt = readSU("struct packet_type", pa)
                print pt, " (bucket=%d)" % bucket
            
                ptype = ntohs(pt.type)
                pdev = pt.dev
                pfunc = addr2sym(pt.func)
                print "\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc)
        bucket += 1

            
        
def printTaskSockets(t):
    print " fd     file              socket"
    print " --     ----              ------"
    for fd, filep, dentry, inode in taskFds(t):
        socketaddr = proto.inode2socketaddr(inode)
        if (not socketaddr): continue
        print ("%3d  0x%-16x  0x%-16x" % (fd, filep, socketaddr)),
        # Find family/type of this socket
        socket = readSU("struct socket", socketaddr)
        sock = socket.Deref.sk
        if (sock_V1):
            family = sock.family
            protoname = sock.Deref.prot.name
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
        print " %-8s %-12s %-5s" % (P_FAMILIES.value2key(family),
                                 sockTypes[sktype], protoname)
        if (family == P_FAMILIES.PF_INET or family == P_FAMILIES.PF_INET6):
            if (not sock_V1):
                sock = sock.castTo("struct inet_sock")
		try:
	           sockopt= sock.inet
	        except KeyError:
	           sockopt = sock
	    else:
		sockopt = sock
            print IPv4_conn(left='\t', sock=sockopt)

def print_iface(if1="", details=False):

    # read device list starting from dev_base

    offset = member_offset("struct net_device", "next")
    dev_base = readSymbol("dev_base")
    for a in readList(dev_base, offset):
        dev = readSU("struct net_device", a)
        if (if1 == "" or if1 == dev.name):
            netdevice.print_If(dev, details)

# Print syctl info for net.
def print_sysctl():
    from LinuxDump import sysctl
    ctbl = sysctl.getCtlTables()
    names = ctbl.keys()
    names.sort()
    # Leave only those starting from 'net.'
    names = [n for n in names if n.find("net.") == 0]
    for n in names:
        cte = ctbl[n]
        print n.ljust(45), sysctl.getCtlData(cte)
    sys.exit(0)
        
if ( __name__ == '__main__'):
    import sys
    from optparse import OptionParser

    op =  OptionParser()

    op.add_option("-a", dest="All", default = 0,
                  action="store_true",
                  help="print all sockets")

    op.add_option("-v", dest="Verbose", default = 0,
                  action="store_true",
                  help="verbose output")

    op.add_option("-r", dest="Route", default = 0,
                  action="store_true",
                  help="print routing table")

    op.add_option("--program", dest="Program", default = "",
                  action="store",
                  help="print sockets for cmdname")
                 
    op.add_option("--pid", dest="Pid", default = -1,
                  action="store", type="int",
                  help="print sockets for PID")

    op.add_option("--new", dest="New", default = 0,
                  action="store_true",
                  help="Test new Routines")

    op.add_option("--summary", dest="Summary", default = 0,
                  action="store_true",
                  help="Print A Summary")

    op.add_option("-i", dest="Ifaces", default = 0,
                  action="store_true",
                  help="Print Interface Info")

    op.add_option("--interface", dest="If1", default = "",
                  action="store",
                  help="Limit output to the specified interface only")

    op.add_option("-l", "--listening", dest="Listen", default = 0,
                  action="store_true",
                  help="Print LISTEN sockets only")

    op.add_option("-t", "--tcp", dest="TCP", default = 0,
                  action="store_true",
                  help="Print TCP Info")

    op.add_option("-u", "--udp", dest="UDP", default = 0,
                  action="store_true",
                  help="Print UDP Info")

    op.add_option("-w", "--raw", dest="RAW", default = 0,
                  action="store_true",
                  help="Print RAW Info")

    op.add_option("-x", "--unix", dest="UNIX", default = 0,
                  action="store_true",
                  help="Print UNIX Info")

    op.add_option("--sysctl", dest="sysctl", default = 0,
                  action="store_true",
                  help="Print sysctl info for net.")

    op.add_option("--devpack", dest="devpack", default = 0,
                  action="store_true",
                  help="Print dev_pack info")

    (o, args) = op.parse_args()

    if (o.Verbose):
        details = True

    if (o.New):
        from LinuxDump.inet.netfilter import nf
        nf()
        sys.exit(0)
        pass
    # First, check for options that are not netstat-like. If any is present, do
    # do not do netstat stuff after them
    if (o.sysctl):
        print_sysctl()
        sys.exit(0)

    if (o.devpack):
        print_dev_pack()
        sys.exit(0)

    if (o.Route):
        print_fib()
        sys.exit(0)

    if (o.Ifaces):
        print_iface(o.If1, details)
        sys.exit(0)

    if (o.Summary):
        Summarize()
        sys.exit(0)

    if (o.Program):
        tt = TaskTable()
        task = tt.getByComm(o.Program)
        if (task):
            printTaskSockets(task)
        sys.exit(0)

    if (o.Pid != -1):
        tt = TaskTable()
        task = tt.getByPid(o.Pid)
        if (task):
            printTaskSockets(task)
        sys.exit(0)
            
    # Netstat-like options
    if (o.Listen):
        print_listen = True
        print_nolisten = False
    if (o.All):
        print_listen = True
    if (o.TCP or o.UDP or o.RAW or o.UNIX):
        if (o.TCP):
            print_TCP()
        if (o.UDP):
            print_UDP()
        if (o.RAW):
            print_RAW()
        if (o.UNIX):
            print_UNIX()
    else:
        if (o.All or o.Listen):
            print_TCP()
            print_UDP()
            print_RAW()
            print_UNIX()



from pykdump.wrapcrash import print_stats
print_stats()
