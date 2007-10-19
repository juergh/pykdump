#!/usr/bin/env python

# Time-stamp: <07/10/19 12:06:49 alexs>

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.

# Print info about connections and sockets 

from pykdump.API import *

# For INET stuff
from LinuxDump.inet import *
from LinuxDump.inet import proto, netdevice
from LinuxDump.inet.proto import tcpState, sockTypes, \
    IPv4_conn, IPv6_conn, IP_sock,  P_FAMILIES, decodeSock, print_accept_queue

from LinuxDump.Tasks import TaskTable

import string
from StringIO import StringIO

debug = API_options.debug

sock_V1 = proto.sock_V1

details = False

print_listen = False
print_nolisten = True

sport_filter = False
dport_filter = False
port_filter = False


def print_TCP_sock(o):
    pstr = IP_sock(o, details)
    if (port_filter):
	if (pstr.sport != port_filter and pstr.dport != port_filter):
	    return
    if (details):
        print '-' * 78
        print o, '\t\tTCP'
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
            l_opt = pstr.l_opt
	    print "\t max_qlen_log=%d qlen=%d qlen_young=%d" %\
		    (l_opt.max_qlen_log, l_opt.qlen, l_opt.qlen_young)
	    #printObject(l_opt)
            if (pstr.accept_queue):
                print_accept_queue(pstr)



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
            print_TCP_sock(o)

    if (not print_nolisten):
        return
    # Print ESTABLISHED TCP
    
    for o in proto.get_TCP_ESTABLISHED():
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
    tt = TaskTable()
    if (newstyle):
        for pt in readSUListFromHead(Addr(ptype_all), "list",
                                     "struct packet_type"):
            print pt

            ptype = ntohs(pt.type)
            pdev = pt.dev
            pfunc = addr2sym(pt.func)
            print "\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc)

            # for SOCK_PACKET and AF_PACKET we can find PID
            if (pt.af_packet_priv == 0):
                continue

            if (pfunc == 'packet_rcv' or pfunc == 'packet_rcv_spkt'):
                sock = readSU("struct sock", pt.af_packet_priv)
                socket = Deref(sock.sk_socket)
                filep = socket.file
                for t in tt.getByFile(filep):
                    print "\t    pid=%d, command=%s" %(t.pid, t.comm)
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


def testFiles(tasks):
    for t in tasks:
	fds = t.taskFds()
	continue
	for fd, filep, dentry, inode in t.taskFds():
	    pass
    

def printTaskSockets(t):
    prn = StringIO()
    threads = t.threads
    if (threads):
	nthreads = "  (%d threads)" % (len(threads) + 1)
    else:
	nthreads = ""
    print >>prn, "-----PID=%d  COMM=%s %s" % (t.pid, t.comm, nthreads)
    print >>prn, " fd     file              socket"
    print >>prn, " --     ----              ------"

    strue = False
    for fd, filep, dentry, inode in t.taskFds():
        socketaddr = proto.inode2socketaddr(inode)
        if (not socketaddr): continue

	socket = readSU("struct socket", socketaddr)
        #sock = socket.Deref.sk
	sock = Deref(socket.sk)
	family, sktype, protoname, inet = decodeSock(sock)


	if (inet):
	    ips = IP_sock(sock)

        # If we are not using port-filters, we print all families
	if (not port_filter):
	    strue = True
	
        print >>prn, ("%3d  0x%-16x  0x%-16x" % (fd, filep, socketaddr)),
        # Find family/type of this socket
	print >>prn, " %-8s %-12s %-5s" % (P_FAMILIES.value2key(family),
				    sockTypes[sktype], protoname)

        if (inet):
	    if (port_filter):
		if (ips.sport != port_filter and ips.dport != port_filter):
		    continue
	    print >>prn, "     ", ips
	    strue = True
	    
    print >>prn, ""
    if (strue):
	print prn.getvalue()
    prn.close()

def print_iface(if1="", details=False):
    for dev in netdevice.dev_base_list():
        if (if1 == "" or if1 == dev.name):
            netdevice.print_If(dev, details)

def get_net_sysctl():
    from LinuxDump import sysctl
    re_if = re.compile(r'^net\.ipv[46]\.\w+\.(eth\d+)\..*$')
    ctbl = sysctl.getCtlTables()
    names = ctbl.keys()
    names.sort()
    # Leave only those starting from 'net.'
    names = [n for n in names if n.find("net.") == 0]
    # Create a dictionary of those values that we can use as defaults
    # Some values are per interface, e.g.
    # net.ipv{4,6}.conf.eth0.*
    # net.ipv{4,6}.neigh.eth0.*
    dall = {}
    ddef = {}
    for n in names:
        cte = ctbl[n]
        vals = sysctl.getCtlData(cte)
        dall[n] = vals
        m = re_if.match(n)
        if (not m):
            ddef[n] = vals
    return (dall, ddef)
    
def print_sysctl():
    (dall, ddef) = get_net_sysctl()
    names = dall.keys()
    names.sort()

    for n in names:
        print n.ljust(45), dall[n]
    #pp.pprint(ddef)

# Print those values that are not equal to default ones
def print_sysctl_nodef():
    (dall, ddef) = get_net_sysctl()

    #pp.pprint(ddef)
    #return
    names = dall.keys()
    names.sort()


    default_vals = default_vals_24
    for n in names:
        if (not default_vals.has_key(n)):
            continue
        cval = dall[n]
        dval = default_vals[n]
        #print cval, dval
        nondef = False
        if (type(cval) == type([])):
            try:
                for c, d in zip(cval, dval):
                    if (c != d):
                        nondef = True
                        break
            except:
                nondef = True
        else:
            nondef = (cval != dval)
        if (nondef):
            print "[%s]  %s != default %s" %(n, repr(cval), repr(dval))
            nondef = False

def print_Stats():
    from LinuxDump.inet.snmpstats import SnmpTable, snmp4_tables
    for t in snmp4_tables:
	t = SnmpTable(t)
	print t

def print_Everything():
    nf()
    print_sysctl()
    print_dev_pack()
    print_fib()
    print_rt_hash()
    print_iface(o.If1, details)
    Summarize()
    print_Stats()
    print_TCP()
    print_UDP()
    print_RAW()
    print_UNIX()
    

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

    op.add_option("--netfilter", dest="Netfilter", default = 0,
                  action="store_true",
                  help="Print Netfilter Hooks")

    op.add_option("--summary", dest="Summary", default = 0,
                  action="store_true",
                  help="Print A Summary")
    
    op.add_option("-s", "--statistics", dest="Stats", default = 0,
                  action="store_true",
                  help="Print Statistics")

    op.add_option("-i", dest="Ifaces", default = 0,
                  action="store_true",
                  help="Print Interface Info")

    op.add_option("--interface", dest="If1", default = "",
                  action="store",
                  help="Limit output to the specified interface only")

    op.add_option("--sport", dest="sport", default = -1,
                  action="store", type="int",
                  help="Limit output to the specified sport")

    op.add_option("--dport", dest="dport", default = -1,
                  action="store", type="int",
                  help="Limit output to the specified dport")
    
    op.add_option("--port", dest="port", default = -1,
                  action="store", type="int",
                  help="Limit output to the specified port (src or dst)")

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

    op.add_option("--arp", dest="arp", default = 0,
                  action="store_true",
                  help="Print ARP & Neighbouring info")

    op.add_option("--rtcache", dest="rtcache", default = 0,
                  action="store_true",
                  help="Print the routing cache")

    op.add_option("--everything", dest="Everything", default = 0,
                  action="store_true",
                  help="Run all functions available - for developers")

    op.add_option("--profile", dest="Profile", default = 0,
                  action="store_true",
                  help="Run with profiler (for developers)")


    (o, args) = op.parse_args()

    if (o.Verbose):
        details = True

    if (o.Everything):
        from LinuxDump.inet.netfilter import nf
        from LinuxDump.inet import neighbour
        from LinuxDump.inet.routing import print_fib, print_rt_hash

        details = True

        print_Everything()
        sys.exit(0)

    if (o.Profile):
        from LinuxDump.inet.netfilter import nf
        from LinuxDump.inet import neighbour
        from LinuxDump.inet.routing import print_fib, print_rt_hash

        import cProfile

        details = True

        print_Everything()
        cProfile.run('print_Everything()')

        sys.exit(0)
        

        

    if (o.New):
        pass

    if (o.sport != -1):
	sport_filter = o.sport
    if (o.dport != -1):
	dport_filter = o.dport
    if (o.port != -1):
	port_filter = o.port

    if (o.Netfilter):
        from LinuxDump.inet.netfilter import nf
        nf()
        sys.exit(0)

    # First, check for options that are not netstat-like. If any is present, do
    # do not do netstat stuff after them
    if (o.sysctl):
        print_sysctl()
        sys.exit(0)

    if (o.devpack):
        print_dev_pack()
        sys.exit(0)

    if (o.arp):
        from LinuxDump.inet import neighbour
        neighbour.print_neighbour_info()
        sys.exit(0)

    if (o.Route):
        from LinuxDump.inet.routing import print_fib
        print_fib()
        sys.exit(0)

    if (o.rtcache):
        from LinuxDump.inet.routing import print_rt_hash
        print_rt_hash()
        sys.exit(0)

    if (o.arp):
        sys.exit(0)

    if (o.Ifaces):
        print_iface(o.If1, details)
        sys.exit(0)

    if (o.Summary):
        Summarize()
        sys.exit(0)

    if (o.Stats):
        print_Stats()
        sys.exit(0)

    if (o.Program):
        tt = TaskTable()
	if (o.Program == '*'):
	    tasks = tt.allTasks()
	    #testFiles(tasks)
	    #sys.exit(0)
	else:
	    tasks = tt.getByComm(o.Program)
        for task in  tasks:
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

