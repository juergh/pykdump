#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2013 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------


# Print info about connections and sockets 

# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function

__version__ = "0.8.2"


from pykdump.API import *

# For INET stuff
from LinuxDump.inet import *
from LinuxDump.inet import proto, netdevice
#reload(proto)
from LinuxDump.inet.proto import tcpState, sockTypes, \
     IP_sock,  P_FAMILIES, decodeSock, print_accept_queue,\
     print_skbuff_head, \
     decode_skbuf, decode_IP_header, decode_TCP_header

from LinuxDump.Tasks import TaskTable
from LinuxDump.inet import summary

import string

# Python2 vs Python3
_Pym = sys.version_info[0]
if (_Pym < 3):
    from StringIO import StringIO
else:
    from io import StringIO

debug = API_options.debug

sock_V1 = proto.sock_V1

details = 0         # Defines the level of verbosity

print_listen = False
print_nolisten = True

sport_filter = False
dport_filter = False
port_filter = False

# Print a list of sk_buff
def print_send_head(send_head):
    skblist = readStructNext(send_head, "next")
    if (not skblist):
        return
    print ("    send_head:")
    for skb in skblist:
        print ("\t", skb, skb.data_len)


def print_TCP_sock(o):
    try:
        pstr = IP_sock(o, details)
    except KeyError as msg:
        print (WARNING, msg)
        return
    jiffies = readSymbol("jiffies")
    if (port_filter):
        if (pstr.sport != port_filter and pstr.dport != port_filter):
            return
    if (details):
        print ('-' * 78)
        print (o, '\t\tTCP')
    print (pstr)
    tcp_state = pstr.state
    # Here we print things that are not kernel-dependent
    if (details):
        sfamily = P_FAMILIES.value2key(pstr.family)
        if (tcp_state != tcpState.TCP_LISTEN 
            and tcp_state != tcpState.TCP_TIME_WAIT):
            topt = pstr.topt
            snd_wnd = topt.snd_wnd
            rcv_wnd = topt.rcv_wnd
            advmss = topt.advmss
            #nonagle=pstr.Tcp.nonagle
            nonagle = topt.nonagle
            rx_queue = topt.rcv_nxt - topt.copied_seq
            tx_queue = topt.write_seq - topt.snd_una
            print ("\twindows: rcv=%d, snd=%d  advmss=%d rcv_ws=%d snd_ws=%d" %\
                (rcv_wnd, snd_wnd, advmss,
                 pstr.rx_opt.rcv_wscale, pstr.rx_opt.snd_wscale))
            print ("\tnonagle=%d sack_ok=%d tstamp_ok=%d" %\
                (nonagle, pstr.rx_opt.sack_ok, pstr.rx_opt.tstamp_ok))
            print ("\trmem_alloc=%d, wmem_alloc=%d" % (pstr.rmem_alloc,
                                                  pstr.wmem_alloc))
            print ("\trx_queue=%d, tx_queue=%d" % (rx_queue,
                                                  tx_queue))
            print ("\trcvbuf=%d, sndbuf=%d" % (pstr.rcvbuf, pstr.sndbuf))
            #print (pstr.rcv_tstamp, pstr.lsndtime)
            print ("\trcv_tstamp=%s, lsndtime=%s  ago" %\
                                       (j_delay(pstr.rcv_tstamp, jiffies),
                                        j_delay(pstr.lsndtime, jiffies)))

            if (details > 1):
                ss = o.castTo("struct sock")
                # Does not exist on 2.4 kernels
                try:
                    print_send_head(ss.sk_send_head)
                except KeyError:
                    pass
                
            # Extra details when there are retransmissions
            if (pstr.Retransmits):
                print("    -- Retransmissions --")
                print("       retransmits=%d, ca_state=%s" % (pstr.Retransmits, 
                        proto.TCP_CA_STATE[pstr.CA_state]))


        elif (tcp_state == tcpState.TCP_LISTEN):
            print ("\t family=%s" % sfamily)
            print ("\t backlog=%d(%d)" % (pstr.sk_ack_backlog,
                                         pstr.sk_max_ack_backlog))
            l_opt = pstr.l_opt
            print ("\t max_qlen_log=%d qlen=%d qlen_young=%d" %\
                    (l_opt.max_qlen_log, l_opt.qlen, l_opt.qlen_young))
            #printObject(l_opt)
            if (pstr.sk_ack_backlog):
                print_accept_queue(pstr)
        # For special sockets only
        # e.g. for NFS this is "struct svc_sock"
        # for RPC this is "struct rpc_xprt *"
        udaddr = pstr.user_data
        if (udaddr):
            print ("\t   |user_data|", hexl(udaddr),end='')
            decode_user_data(udaddr, long(o))


# Try to decode user_data

# struct svc_sock {
#       struct list_head        sk_ready;       /* list of ready sockets */
#       struct list_head        sk_list;        /* list of all sockets */
#       struct socket *         sk_sock;        /* berkeley socket layer */
#       struct sock *           sk_sk;          /* INET layer */
#         ...
# }

# On 2.6.9 and 2.4
# struct rpc_xprt {
#       struct socket *         sock;           /* BSD socket layer */
#       struct sock *           inet;           /* INET layer */

#       struct rpc_timeout      timeout;        /* timeout parms */
#       struct sockaddr_in      addr;           /* server address */
#       int                     prot;           /* IP protocol */
#         ...
# }

# On 2.6.22
# struct rpc_xprt {
#       struct kref             kref;           /* Reference count */
#       struct rpc_xprt_ops *   ops;            /* transport methods */

#       struct rpc_timeout      timeout;        /* timeout parms */
#       struct sockaddr_storage addr;           /* server address */
#       size_t                  addrlen;        /* size of server address */
#       int                     prot;           /* IP protocol */
#         ...
# }


# The 1st arg is user_data, the 2nd one 'struct sock *' pointer
#
# The best way to decode is to load symbolic modules info...but we are
# trying to do our best without it
def decode_user_data(addr, saddr):
    # Check whether this looks like svc_sock
    ptrsock = readPtr(addr + 4 * PTR_SIZE)
    ptrsk = readPtr(addr + 5 * PTR_SIZE)
    #print (hexl(ptrsock), hexl(ptrsk))
    if (ptrsk == saddr):
        # This is svc_sock
        print (" -> 'struct svc_sock'")
        return

    # Check whether this looks like 2.6.9 rpc_xprt
    ptrsk = readPtr(addr + PTR_SIZE)
    if (ptrsk == saddr):
        # This is 2.6.9 rpc_xptr
        print ("-> 'struct rpc_xprt'")
        return

    # On recent 2.6 kernels, we try to find the offset of sockaddr_storage

    
    offset = LONG_SIZE *2 + LONG_SIZE * 3 + INT_SIZE*2
    #print ("offset=", offset)
    saname = None
    for sname in ("struct __kernel_sockaddr_storage",
                  "struct sockaddr_storage"):
        if (struct_exists(sname)):
            saname = sname
            break
    sas = readSU(saname, addr + offset)
    addrlen = readLong(addr + offset + struct_size(sname))
    prot = readInt(addr + offset + struct_size(sname) + PTR_SIZE)
    #print (sas.ss_family, addrlen, prot)
    if (prot in (6, 17) and sas.ss_family in (2,10)):
        print ("-> 'struct rpc_xprt'")
        return
    print ('')


# Print TCP info from TIMEWAIT buckets

# Print TCP info from TIMEWAIT buckets
def print_TCP_tw(tw):
    pstr = proto.IP_conn_tw(tw, details)

    if (port_filter):
        if (pstr.sport != port_filter and pstr.dport != port_filter):
            return
    if (details):
        print ('-' * 78)
        print (tw, '\t\tTCP')
    
    
    print (pstr)
    if (details):
        print ("\ttw_timeout=%d, ttd=%d" % (pstr.tw_timeout, pstr.ttd))
    

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
    #   /* inet_connection_sock has to be the first member of tcp_sock */
    #   struct inet_connection_sock     inet_conn;
    #...
    # struct inet_connection_sock {
    #   /* inet_sock has to be the first member! */
    #   struct inet_sock          icsk_inet;
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
        print_TCP_tw(tw)

# print UDP

def print_UDP():
    count = 0
    for o in proto.get_UDP():
        count += 1
        pstr = IP_sock(o, details)
        # If we do not want LISTEN sockets only, ignore everything but
        # ESTABLISHED (there is no real LISTEN state for UDP)
        if (pstr.state == tcpState.TCP_ESTABLISHED):
            if (not print_nolisten): continue
        else:
            # LISTEN socket
            if (not print_listen): continue

        if (details):
            print ('-' * 78)
            print (o, '\t\tUDP')
        print (pstr)
        if (details):
            print ("\trx_queue=%d, tx_queue=%d" % (pstr.rmem_alloc,
                                                  pstr.wmem_alloc))
            print ("\trcvbuf=%d, sndbuf=%d" % (pstr.rcvbuf, pstr.sndbuf))
            pending = pstr.uopt.pending
            corkflag = pstr.uopt.corkflag
            ulen = pstr.uopt.len
            print ("\tpending=%d, corkflag=%d, len=%d" % (pending,
                                                         corkflag, ulen))
            # For special sockets only
            # e.g. for NFS this is "struct svc_sock"
            # for RPC this is "struct rpc_xprt *"
            udaddr = pstr.user_data
            if (udaddr):
                print ("\t   |user_data|", hexl(udaddr), end='')
                decode_user_data(udaddr, long(o))
    if (count == 0):
        print (WARNING, "Empty UDP-hash - dump is probably incomplete")

def tcp_state_name(state):
    # If the structure is corrupted, state will be bogus
    try:
        statename = tcpState[state][4:]
    except KeyError:
        statename = "|%d|" % state
    return statename
    
# print AF_UNIX

def print_UNIX():
    print ("unix   State          i_ino   Path")
    print ("----------------------------------")
    for s in proto.get_AF_UNIX():
        state, ino, path = proto.unix_sock(s)
        if (state == tcpState.TCP_LISTEN):
            if (not print_listen): continue
        else:
            if (not print_nolisten):
                continue
        if (details):
            print ('-' * 78)
            print (s, '\t\tUnix')
         
        statename = tcp_state_name(state)
        print ("unix   %-12s   %-6d  %s" % (statename, ino, path))
        if (details < 2):
            continue
        # Check whether we have a peer
        peer = s.Peer
        if (peer):
            state, ino, path = proto.unix_sock(peer)
            statename = tcp_state_name(state)
            print ("  Peer %-12s   %-6d  %s" % (statename, ino, path))

  

def print_RAW():
    for o in list(proto.get_RAW()) + list(proto.get_RAW6()):
        try:
            pstr = IP_sock(o, details)
        except KeyError as msg:
           print ("   Unexpected protocol in RAW table,", msg)
           continue
        if (not print_listen and pstr.state != tcpState.TCP_ESTABLISHED):
            continue

        if (details):
            print ('-' * 78)
            print (o, '\t\tRAW')
        print (pstr)
        if (details):
            print ("\trx_queue=%d, tx_queue=%d" % (pstr.rmem_alloc,
                                                  pstr.wmem_alloc))
            print ("\trcvbuf=%d, sndbuf=%d" % (pstr.rcvbuf, pstr.sndbuf))


    
def print_FragmentCache():
    pass

def print_dev_pack():
    ptype_all = readSymbol("ptype_all")
    #print ("ptype_all=", ptype_all, "\n")
    # For 2.4 packet_type has next pointer, for 2.6 list_head is embedded
    newstyle = (whatis("ptype_base").ctype == "struct list_head")
    if (newstyle):
        offset = member_offset("struct packet_type", "list")
    else:
        offset = member_offset("struct packet_type", "next")


    print ("--------ptype_all-------------------------------------------")
    tt = TaskTable()
    if (newstyle):
        for pt in readSUListFromHead(Addr(ptype_all), "list",
                                     "struct packet_type"):
            print (pt)

            ptype = ntohs(pt.type)
            pdev = pt.dev
            pfunc = addr2sym(pt.func)
            print ("\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc))

            # for SOCK_PACKET and AF_PACKET we can find PID
            if (pt.af_packet_priv == 0):
                continue

            if (pfunc == 'packet_rcv' or pfunc == 'packet_rcv_spkt'):
                sock = readSU("struct sock", pt.af_packet_priv)
                socket = Deref(sock.sk_socket)
                filep = socket.file
                for t in tt.getByFile(filep):
                    print ("\t    pid=%d, command=%s" %(t.pid, t.comm))
    else:
        # 2.4
        for pa in readList(ptype_all, offset):
            pt = readSU("struct packet_type", pa)
            print (pt)

            ptype = ntohs(pt.type)
            pdev = pt.dev
            pfunc = addr2sym(pt.func)
            print ("\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc))


    print ("\n--------ptype_base-------------------------------------------")
    bucket = 0
    for a in readSymbol("ptype_base"):
        if (newstyle):
            for pt in readSUListFromHead(Addr(a), "list", "struct packet_type"):
                print (pt, " (bucket=%d)" % bucket)

                ptype = ntohs(pt.type)
                pdev = pt.dev
                pfunc = addr2sym(pt.func)
                print ("\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc))
        else:
            # 2.4
            if (a == 0):
                continue
            for pa in readList(a, offset):
                pt = readSU("struct packet_type", pa)
                print (pt, " (bucket=%d)" % bucket)

                ptype = ntohs(pt.type)
                pdev = pt.dev
                pfunc = addr2sym(pt.func)
                print ("\ttype=0x%04x dev=0x%x func=%s" % (ptype, pdev, pfunc))
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
    print ("-----PID=%d  COMM=%s %s" % (t.pid, t.comm, nthreads), file=prn)
    print (" fd     file              socket", file=prn)
    print (" --     ----              ------", file=prn)

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
        
        print ("%3d  0x%-16x  0x%-16x" % (fd, filep, socketaddr), file=prn, end=' ')
        # Find family/type of this socket
        print (" %-8s %-12s %-5s" % (P_FAMILIES.value2key(family),
                                    sockTypes[sktype], protoname), file=prn)

        if (inet):
            if (port_filter):
                if (ips.sport != port_filter and ips.dport != port_filter):
                    continue
            print ("     ", ips, file=prn)
            strue = True
        if (details > 1 and family == P_FAMILIES.PF_FILE):
            # AF_UNIX. on 2.4 we have just 'struct sock',
            # on 2.6 'struct unix_sock'
            if (not sock_V1):
                sock = sock.castTo("struct unix_sock")
            hdr = "     +" + '-' * 65
            print (hdr, file=prn)
            print ("     |      state          i_ino   Path", file=prn)
            print (hdr, file=prn)
            for us, h in zip((sock, sock.Peer), ("sock", "peer")):
               if (us):
                    state, ino, path = proto.unix_sock(us)
                    statename = tcp_state_name(state)
                    print ("     |%s  %-12s   %-6d  %s" % (h,
                                                  statename, ino, path), file=prn)
                    sock = us.Socket
                        
                    if (h == "peer" and sock):
                        filep = sock.file
                        pids = tt.getByFile(filep)
                        print ("     |   ",filep, sock, file=prn)
                        for pid in pids:
                            print ("     |   ", pid, file=prn)
                    print (hdr, file=prn)
            
    print ("")
    if (strue):
        print (prn.getvalue())
    prn.close()

def print_iface(if1="", details=False):
    for dev in netdevice.dev_base_list():
        if (if1 == "" or if1 == dev.name):
            netdevice.print_If(dev, details)

def get_net_sysctl():
    from LinuxDump import sysctl
    re_if = re.compile(r'^net\.ipv[46]\.\w+\.(eth\d+)\..*$')
    ctbl = sysctl.getCtlTables()
    names = sorted(ctbl.keys())
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
        try:
            vals = sysctl.getCtlData(cte)
        except:
            vals = '(?)'
        dall[n] = vals
        m = re_if.match(n)
        if (not m):
            ddef[n] = vals
    return (dall, ddef)
    
def print_sysctl():
    try:
        (dall, ddef) = get_net_sysctl()
    except crash.error:
        print (WARNING, "cannot get sysctl tables")
        return
    names = sorted(dall.keys())

    for n in names:
        print (n.ljust(45), dall[n])
    #pp.pprint(ddef)

# Print those values that are not equal to default ones (not implemented yet)
def print_sysctl_nodef():
    (dall, ddef) = get_net_sysctl()

    #pp.pprint(ddef)
    #return
    names = sorted(dall.keys())


    default_vals = default_vals_24
    for n in names:
        if (not n in default_vals):
            continue
        cval = dall[n]
        dval = default_vals[n]
        #print (cval, dval)
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
            print ("[%s]  %s != default %s" %(n, repr(cval), repr(dval)))
            nondef = False

def print_Stats():
    from LinuxDump.inet.snmpstats import SnmpTable, snmp4_tables
    for t in snmp4_tables:
        t = SnmpTable(t)
        print (t)

def print_softnet_data(details):
    from LinuxDump import percpu
    addrs = percpu.get_cpu_var("softnet_data")
    for cpu, a in enumerate(addrs):
        sd = readSU("struct softnet_data", a)
        # Print the completion queue
        print (" --CPU=%d" % cpu)
        # Count entries in the queue, it starts from sk_buff_head
        off = member_offset("struct sk_buff_head", "next")
        nq = getListSize(sd.input_pkt_queue, off, 10000)
        print ("    ..input_pkt_queue has %d elements" % nq)
        if (details > 1):
            skbhead = sd.input_pkt_queue.castTo("struct sk_buff")
            for skb in readStructNext(skbhead, "next", inchead = False):
                print (skb)
                decode_skbuf(skb)
        
        print ("    ..Completion queue")
        print_skbuff_head(sd.completion_queue)
        
def print_Everything():
    print_listen = True
    nf()
    print_sysctl()
    print_dev_pack()
    print_fib()
    print_rt_hash()
    print_iface(o.If1, details)
    summary.TCPIP_Summarize()
    print_Stats()
    print_TCP()
    print_UDP()
    print_RAW()
    print_UNIX()
    

# Printing TCP delays relative to jiffies
# Compute delay between a given timestamp and jiffies
# Even though on 64-bit hosts jiffies is
# volatile long unsigned int jiffies;
# TCP code uses
# #define tcp_time_stamp                ((__u32)(jiffies))

def j_delay(ts, jiffies):
    v = (jiffies - ts) & INT_MASK
    if (v > INT_MAX):
        v = "n/a"
    elif (v > HZ*3600*10):
        v = "%d hours" % (v/HZ/3600)
    else:
        v = "%1.1f s" % (float(v)/HZ)
    return v

if ( __name__ == '__main__'):
    import sys
    
    __experimental ='PYKDUMPDEV'in  os.environ
    
    from optparse import OptionParser, OptionGroup, SUPPRESS_HELP

    def e_help(help):
        global __experimental
        if (__experimental):
            return help + " (experimental)"
        else:
            return SUPPRESS_HELP

    op =  OptionParser()
    

    op.add_option("-a", dest="All", default = 0,
                  action="store_true",
                  help="print all sockets")

    op.add_option("-v", dest="Verbose", default = 0,
                  action="count",
                  help="verbose output")

    op.add_option("-r", dest="Route", default = 0,
                  action="store_true",
                  help="Print routing table. Adding -v prints all"
                  " routing tables and policies")

    op.add_option("--program", dest="Program", default = "",
                  action="store",
                  help="print sockets for cmdname")
                 
    op.add_option("--pid", dest="Pid", default = -1,
                  action="store", type="int",
                  help="print sockets for PID")


    op.add_option("--netfilter", dest="Netfilter", default = 0,
                  action="store_true",
                  help="Print Netfilter Hooks")

    op.add_option("--softnet", dest="Softnet", default = 0,
                  action="store_true",
                  help="Print Softnet Queues")

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

    op.add_option("--decode", dest="Decode", default = None,
                  action="store",
                  help="Decode iph/th/uh")

    
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

    op.add_option("--skbuffhead", dest="Skbuffhead", default = -1,
                  action="store", type="int",
                  help="Print sk_buff_head")


    op.add_option("--version", dest="Version", default = 0,
                  action="store_true",
                  help="Print program version and exit")


    # Expertimental options, not ready for general usgae yet
    group = OptionGroup(op, "Experimental Options",
                    "Caution: this is work in progress, "
                    "not fully supported for all kernels yet.")

    group.add_option("--sport", dest="sport", default = -1,
                  action="store", type="int",
                  help="Limit output to the specified sport")

    group.add_option("--dport", dest="dport", default = -1,
                  action="store", type="int",
                  help="Limit output to the specified dport")

    group.add_option("--ipsec", dest="ipsec", default = 0,
                  action="store_true",
                  help="Print IPSEC stuff")

    op.add_option("--everything", dest="Everything", default = 0,
                  action="store_true",
                  help="Run all functions available for regression testing")

    group.add_option("--profile", dest="Profile", default = 0,
                  action="store_true",
                  help="Run with profiler")

    op.add_option_group(group)


    (o, args) = op.parse_args()

    verbose = details = o.Verbose
    #__experimental = O.experimental

    if (o.Version):
        print ("XPORTSHOW version %s" % (__version__))
        if (details):
            # Print C-module and API versions
            print("C-Module version: %s" %(crash.version))
        sys.exit(0)

    if (o.Everything):
        from LinuxDump.inet.netfilter import nf
        from LinuxDump.inet import neighbour
        from LinuxDump.inet.routing import print_fib, print_rt_hash

        details = 2

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

    if (o.Softnet):
        print_softnet_data(details)
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
        from LinuxDump.inet.routing import print_fib, print_fib_rules
        # In Verbose mode, print all routing tables and policy rules
        if (details):
            print_fib(True)
            print ("\n=== Policy Rules")
            print_fib_rules()
        else:
            print_fib()
        sys.exit(0)

    if (o.rtcache):
        from LinuxDump.inet.routing import print_rt_hash
        print_rt_hash()
        sys.exit(0)

    if (o.Skbuffhead != -1):
        skbhead = readSU("struct sk_buff_head",  o.Skbuffhead)
        print_skbuff_head(skbhead, details)
        sys.exit(0)

    if (o.ipsec):
        from LinuxDump.inet import ipsec
        ipsec.print_IPSEC()
        sys.exit(0)

    if (o.Ifaces):
        print_iface(o.If1, details)
        sys.exit(0)

    if (o.Summary):
        summary.TCPIP_Summarize()
        summary.IF_Summarize()
        sys.exit(0)

    if (o.Stats):
        print_Stats()
        sys.exit(0)

    if (o.Decode):
        for a in args:
            addr = int(a, 16)
            if (o.Decode == 'skb'):
                decode_skbuf(addr, details)
            elif (o.Decode == 'iph'):
                decode_IP_header(addr)
            elif (o.Decode == 'th'):
                decode_TCP_header(addr, details)
            else:
                print ("Cannot decode", o.Decode)
                sys.exit(1)
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
        task = tt.getByTid(o.Pid)

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

