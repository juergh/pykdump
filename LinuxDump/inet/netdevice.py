# module LinuxDump.inet.netdevice
#
# Time-stamp: <08/03/17 12:26:57 alexs>
#
# Copyright (C) 2006-2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2008 Hewlett-Packard Co., All rights reserved.
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
This is a package providing useful tables and functions for 'struct netdevice'
and related stuff.
'''
from pykdump.API import *
from LinuxDump.inet import *
from LinuxDump import percpu
from LinuxDump.inet.proto import print_skbuff_head
from StringIO import StringIO
import string

__IFF_FLAGS_c = '''
#define	IFF_UP		0x1		/* interface is up		*/
#define	IFF_BROADCAST	0x2		/* broadcast address valid	*/
#define	IFF_DEBUG	0x4		/* turn on debugging		*/
#define	IFF_LOOPBACK	0x8		/* is a loopback net		*/
#define	IFF_POINTOPOINT	0x10		/* interface is has p-p link	*/
#define	IFF_NOTRAILERS	0x20		/* avoid use of trailers	*/
#define	IFF_RUNNING	0x40		/* interface RFC2863 OPER_UP	*/
#define	IFF_NOARP	0x80		/* no ARP protocol		*/
#define	IFF_PROMISC	0x100		/* receive all packets		*/
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets*/

#define IFF_MASTER	0x400		/* master of a load balancer 	*/
#define IFF_SLAVE	0x800		/* slave of a load balancer	*/

#define IFF_MULTICAST	0x1000		/* Supports multicast		*/

#define IFF_PORTSEL	0x2000          /* can set media type		*/
#define IFF_AUTOMEDIA	0x4000		/* auto media select active	*/
#define IFF_DYNAMIC	0x8000		/* dialup device with changing addresses*/

#define IFF_LOWER_UP	0x10000		/* driver signals L1 up		*/
#define IFF_DORMANT	0x20000		/* driver signals dormant	*/
'''

IFF_FLAGS = CDefine(__IFF_FLAGS_c)

__ARP_HW_c = """
/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM	0		/* from KA9Q: NET/ROM pseudo	*/
#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/
#define	ARPHRD_EETHER	2		/* Experimental Ethernet	*/
#define	ARPHRD_AX25	3		/* AX.25 Level 2		*/
#define	ARPHRD_PRONET	4		/* PROnet token ring		*/
#define	ARPHRD_CHAOS	5		/* Chaosnet			*/
#define	ARPHRD_IEEE802	6		/* IEEE 802.2 Ethernet/TR/TB	*/
#define	ARPHRD_ARCNET	7		/* ARCnet			*/
#define	ARPHRD_APPLETLK	8		/* APPLEtalk			*/
#define ARPHRD_DLCI	15		/* Frame Relay DLCI		*/
#define ARPHRD_ATM	19		/* ATM 				*/
#define ARPHRD_METRICOM	23		/* Metricom STRIP (new IANA id)	*/
#define	ARPHRD_IEEE1394	24		/* IEEE 1394 IPv4 - RFC 2734	*/
#define ARPHRD_EUI64	27		/* EUI-64                       */
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* Dummy types for non ARP hardware */
#define ARPHRD_SLIP	256
#define ARPHRD_CSLIP	257
#define ARPHRD_SLIP6	258
#define ARPHRD_CSLIP6	259
#define ARPHRD_RSRVD	260		/* Notional KISS type 		*/
#define ARPHRD_ADAPT	264
#define ARPHRD_ROSE	270
#define ARPHRD_X25	271		/* CCITT X.25			*/
#define ARPHRD_HWX25	272		/* Boards with X.25 in firmware	*/
#define ARPHRD_PPP	512
#define ARPHRD_CISCO	513		/* Cisco HDLC	 		*/
#define ARPHRD_HDLC	ARPHRD_CISCO
#define ARPHRD_LAPB	516		/* LAPB				*/
#define ARPHRD_DDCMP    517		/* Digital's DDCMP protocol     */
#define ARPHRD_RAWHDLC	518		/* Raw HDLC			*/

#define ARPHRD_TUNNEL	768		/* IPIP tunnel			*/
#define ARPHRD_TUNNEL6	769		/* IP6IP6 tunnel       		*/
#define ARPHRD_FRAD	770             /* Frame Relay Access Device    */
#define ARPHRD_SKIP	771		/* SKIP vif			*/
#define ARPHRD_LOOPBACK	772		/* Loopback device		*/
#define ARPHRD_LOCALTLK 773		/* Localtalk device		*/
#define ARPHRD_FDDI	774		/* Fiber Distributed Data Interface */
#define ARPHRD_BIF      775             /* AP1000 BIF                   */
#define ARPHRD_SIT	776		/* sit0 device - IPv6-in-IPv4	*/
#define ARPHRD_IPDDP	777		/* IP over DDP tunneller	*/
#define ARPHRD_IPGRE	778		/* GRE over IP			*/
#define ARPHRD_PIMREG	779		/* PIMSM register interface	*/
#define ARPHRD_HIPPI	780		/* High Performance Parallel Interface */
#define ARPHRD_ASH	781		/* Nexus 64Mbps Ash		*/
#define ARPHRD_ECONET	782		/* Acorn Econet			*/
#define ARPHRD_IRDA 	783		/* Linux-IrDA			*/
/* ARP works differently on different FC media .. so  */
#define ARPHRD_FCPP	784		/* Point to point fibrechannel	*/
#define ARPHRD_FCAL	785		/* Fibrechannel arbitrated loop */
#define ARPHRD_FCPL	786		/* Fibrechannel public loop	*/
#define ARPHRD_FCFABRIC	787		/* Fibrechannel fabric		*/
	/* 787->799 reserved for fibrechannel media types */
#define ARPHRD_IEEE802_TR 800		/* Magic type ident for TR	*/
#define ARPHRD_IEEE80211 801		/* IEEE 802.11			*/
#define ARPHRD_IEEE80211_PRISM 802	/* IEEE 802.11 + Prism2 header  */
#define ARPHRD_IEEE80211_RADIOTAP 803	/* IEEE 802.11 + radiotap header */

#define ARPHRD_VOID	  0xFFFF	/* Void type, nothing is known */
#define ARPHRD_NONE	  0xFFFE	/* zero header length */
"""

ARP_HW = CDefine(__ARP_HW_c)

# From net/ipv6/addrconf.c:
#/*
# *	Configured unicast address hash table
# */
#static struct inet6_ifaddr		*inet6_addr_lst[IN6_ADDR_HSIZE];
__IN6_ADDR_HSIZE = 16


# Return the list of all non-empty 'inet6_ifaddr' structures. In each bucket
# we have structures linked by 'lst_next'

def get_inet6_ifaddr():
    ptrsz = sys_info.pointersize
    tableaddr = sym2addr('inet6_addr_lst')
    if (tableaddr == 0):
        return
    sn = "struct inet6_ifaddr"
    if (not struct_exists(sn)):
	print WARNING, "IPv6 structures definitions missing"
	return
    offset = member_offset(sn, "lst_next")
    for i in range(__IN6_ADDR_HSIZE):
        sa = readPtr(tableaddr + i * ptrsz)
        if (sa == 0):
            continue
        for pt in readList(sa, offset):
            #print i, hexl(pt)
            ifa = readSU("struct inet6_ifaddr", pt)
            #print ifa.addr
            #print "  ", ntodots6(ifa.addr), ifa.Deref.idev.Deref.dev.name
            yield ifa

            
            
        
DEVSTATE_c = '''
enum netdev_state_t
{
	__LINK_STATE_XOFF=0,
	__LINK_STATE_START,
	__LINK_STATE_PRESENT,
	__LINK_STATE_SCHED,
	__LINK_STATE_NOCARRIER,
	__LINK_STATE_RX_SCHED,
	__LINK_STATE_LINKWATCH_PENDING
};
'''
DEVSTATE = CEnum(DEVSTATE_c)


# dev->state consists of bits and enum really defines the bit position
def decodeDevState(state):
    # (name, val) is contained in DEVSTATE.vals
    prefix = "__LINK_STATE_"
    lpref= len(prefix)
    outstr = []
    for name, val in DEVSTATE.vals:
        if ((state >> val) & 1):
            outstr.append(name[lpref:])
    return "(" + string.join(outstr, '|') + ")"


__NETIF_FEATURES_c = '''
#define NETIF_F_SG		1	/* Scatter/gather IO. */
#define NETIF_F_IP_CSUM		2	/* Can checksum only TCP/UDP over IPv4. */
#define NETIF_F_NO_CSUM		4	/* Does not require checksum. F.e. loopack. */
#define NETIF_F_HW_CSUM		8	/* Can checksum all the packets. */
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packets */
#define NETIF_F_TSO		2048	/* Can offload TCP/IP segmentation */
#define NETIF_F_LLTX		4096	/* LockLess TX */
#define NETIF_F_UFO             8192    /* Can offload UDP Large Send*/
'''
NETIF_FEATURES = CDefine(__NETIF_FEATURES_c)

# Convert hwaddr (a list of bytes) to string
def hwaddr2str(ha, l):
    out = []
    for i in range(l):
        out.append("%02x" % ha[i])
    return string.join(out, ':')

# Print QDisc data if possible
def printQdisc(qdisc, verbosity):
    qdiscalign = 32
    enqueuename = addr2sym(qdisc.enqueue)
    dequeuename = addr2sym(qdisc.dequeue)
    qdiscaddr = Addr(qdisc)
    qdiscsz = len(qdisc)
    qlen = qdisc.q.qlen
    skbsz = struct_size("struct sk_buff_head")
    print "    ............................................................."
    print "    %s qlen=%d\n\tenqueue=<%s> dequeue=<%s>" % \
          (str(qdisc), qlen, enqueuename, dequeuename)
    try:
        stats = qdisc.qstats
        requeues = stats.requeues
    except KeyError:
        # Old kernels
        stats = qdisc.stats
        requeues = 0                    # They are really unavailable 
    print "\tqlen=%d backlog=%d drops=%d requeues=%d overlimits=%d" % \
          (stats.qlen, stats.backlog, stats.drops,
           requeues, stats.overlimits)
    if (enqueuename == "pfifo_fast_enqueue"):
	#print "\tqdisc.rate_est.bps", qdisc.rate_est.bps	
        # Should be aligned to 32 bytes
        if (qdisc.hasField("data")):
	    privaddr = long(qdisc.data)
	else:
            privaddr = (qdiscaddr + qdiscsz + qdiscalign-1)&(~(qdiscalign-1))
	# On 2.4 privaddr is computed as qdisc.data, 
	print "\t== Bands =="
        for band in range(3):
            addr = privaddr + skbsz * band
            sk_buff_head = readSU("struct sk_buff_head", addr)
            print "\t  sk_buff_head=0x%x len=%d" % (addr, sk_buff_head.qlen)
	    if (sk_buff_head.qlen > 0):
		if (verbosity > 0):
		    print_skbuff_head(sk_buff_head, verbosity - 1)
	


	
    

# Extract statistics from net_device (NIC/driver specific, for some cards only)
__genstats = '''
rx_packets
tx_packets
rx_bytes  
tx_bytes  
rx_errors 
tx_errors 
rx_dropped
tx_dropped
multicast 
collisions
rx_length_errors
rx_over_errors
rx_crc_errors
rx_frame_errors
rx_fifo_errors
rx_missed_errors
tx_aborted_errors
tx_carrier_errors
tx_fifo_errors
tx_heartbeat_errors
tx_window_errors

'''.split()


# Loopback stats - percpu on 2.6, generic net_device_stats on 2.4
# On 2.6.20 they have changed the algorithm again

def lb_get_stats(priv):
    # Per-cpu
    if (symbol_exists("per_cpu__pcpu_lstats")):
        # 2.6.20
        addrs = percpu.get_cpu_var("pcpu_lstats")
        out = []
        for a in addrs:
            lb_stats = readSU("struct pcpu_lstats", a)
            stats = Bunch()
            stats.tx_packets = stats.rx_packets = lb_stats.packets
            stats.tx_bytes = stats.rx_bytes = lb_stats.bytes
            out.append(stats)
        return out

    elif (symbol_exists("per_cpu__loopback_stats")):
        addrs = percpu.get_cpu_var("loopback_stats")
        out = []
        for a in addrs:
            stats = readSU("struct net_device_stats", a)
            out.append(stats)
        return out
    elif (symbol_exists("init_net")): # 2.6.24
        out = []
        for cpu in range(sys_info.CPUS):
            a =  percpu.percpu_ptr(priv, cpu)
            lb_stats = readSU("struct pcpu_lstats", a)
            stats = Bunch()
            stats.tx_packets = stats.rx_packets = lb_stats.packets
            stats.tx_bytes = stats.rx_bytes = lb_stats.bytes
            out.append(stats)
        return out

    stats = readSU("struct net_device_stats", priv)
    return stats
         

# tg3-specific
def get_stat64(val):
    low = val.low
    high = val.high
    #print "high=", high, "low=", low
    if (sys_info.pointersize == 4):
	return low
    return  (high << 32 | low)

tg3_warning = '''
    !!!INFO: to print tg3 stats you need to install debuginfo version
             of tg3 module
'''

def tg3_get_stats(priv):
    try:
        tg3 = readSU("struct tg3", priv)
    except TypeError:
        loadModule("tg3")
        try:
            tg3 = readSU("struct tg3", priv)
        except TypeError:
            print tg3_warning
            return None

    stats = tg3.net_stats
    old_stats = tg3.net_stats_prev
    if (debug):
        print "hw_stats=0x%x" % tg3.hw_stats
    hw_stats = Deref(tg3.hw_stats)
    if (hw_stats == 0):
	delModule("tg3")
        return old_stats

    stats.rx_packets = old_stats.rx_packets + \
                       get_stat64(hw_stats.rx_ucast_packets) + \
                       get_stat64(hw_stats.rx_bcast_packets) + \
                       get_stat64(hw_stats.rx_ucast_packets)

    stats.tx_packets = old_stats.tx_packets + \
                       get_stat64(hw_stats.tx_ucast_packets) + \
                       get_stat64(hw_stats.tx_bcast_packets) + \
                       get_stat64(hw_stats.tx_ucast_packets)

    stats.rx_bytes = old_stats.rx_bytes + \
                     get_stat64(hw_stats.rx_octets)
    stats.tx_bytes = old_stats.tx_bytes + \
                     get_stat64(hw_stats.tx_octets)

    stats.rx_errors = old_stats.rx_errors + \
                     get_stat64(hw_stats.rx_errors)
    stats.tx_errors = old_stats.tx_errors + \
                      get_stat64(hw_stats.tx_errors) + \
                      get_stat64(hw_stats.tx_mac_errors) + \
                      get_stat64(hw_stats.tx_carrier_sense_errors) +\
                      get_stat64(hw_stats.tx_discards)
    
    stats.multicast = old_stats.multicast + \
                      get_stat64(hw_stats.rx_mcast_packets) 

    stats.collisions = old_stats.collisions + \
                       get_stat64(hw_stats.tx_collisions)

    stats.rx_length_errors = old_stats.rx_length_errors + \
                             get_stat64(hw_stats.rx_frame_too_long_errors) + \
                             get_stat64(hw_stats.rx_undersize_packets)
    
    stats.rx_over_errors = old_stats.rx_over_errors + \
                           get_stat64(hw_stats.rxbds_empty)
    
    stats.rx_frame_errors = old_stats.rx_frame_errors + \
                            get_stat64(hw_stats.rx_align_errors)

    stats.tx_aborted_errors = old_stats.tx_aborted_errors + \
                              get_stat64(hw_stats.tx_discards)

    stats.tx_carrier_errors = old_stats.tx_carrier_errors + \
                              get_stat64(hw_stats.tx_carrier_sense_errors)

    # The next one is not accurate as in kernel we call
    # calc_crc_errors to update the counters
    stats.rx_crc_errors = old_stats.rx_crc_errors + \
                          get_stat64(hw_stats.rx_fcs_errors)
    
    stats.rx_missed_errors = old_stats.rx_missed_errors + \
                             get_stat64(hw_stats.rx_discards)
    delModule("tg3")
    return stats



def getStats(dev):
    func = addr2sym(dev.get_stats)
    priv = dev.priv
    devname = dev.name
    stats = None

    # The only reliable way to get private structures is to load modules
    # containing definitions. But for some simple cases we can try to
    # make a good guess
    if (func == 'nv_get_stats'):
        return
        # struct fe_priv - 'forcedeth' module
        off = struct_size("spinlock_t")
        # Pad to a pointer size
        if (off < sys_info.pointersize):
            off = sys_info.pointersize
        stats = readSU("struct net_device_stats", priv + off)
    elif (func == 'tg3_get_stats'):
        stats = tg3_get_stats(priv)
    elif (devname  == 'lo'):
        stats = lb_get_stats(priv)
    if (not stats):
        return None

    # Print net_device_stats. In some cases (e.g. loopback) we have percpu
    # stats
    rx = StringIO()
    tx = StringIO()

    if (devname == "lo" and type(stats) == type([])):
        cpu = 0
        for s in stats:
            print >>rx, "   --CPU", cpu
            print >>tx, ""
            cpu += 1
            #print dev, s
            for f in __genstats[:4]:
                if (f[0] == 'r' or f[0] == 'm'):
                    # RX
                    out = rx
                else:
                    #TX
                    out = tx
                print >>out, "    %-20s %d" % (f, getattr(s, f))
        left = rx.getvalue()
        right = tx.getvalue()
        rx.close()
        tx.close()
        print ""
        print "            RX                -= Stats =-            TX          "
        print "     -----------------------                ------------------------"
        print2columns(left, right)
        return

    for f in __genstats:
        if (not hasattr(stats, f)):
            continue
        if (f[0] == 'r' or f[0] == 'm'):
            # RX
            out = rx
        else:
            #TX
            out = tx
        print >>out, "    %-20s %d" % (f, getattr(stats,f))
    left = rx.getvalue()
    right = tx.getvalue()
    rx.close()
    tx.close()
    print ""
    print "            RX                -= Stats =-            TX          "
    print "     -----------------------                ------------------------"
    print2columns(left, right)
    


# Very new kernels (e.g. 2.6.24): init_net.dev_base_head
# New style: dev_base_head is 'struct list_head	dev_base_head;' and this is
# embedded in 'struct net_device' as
# 	struct list_head	dev_list;

# Old style: 'struct net_device *dev_base;'
# and we are linked by 'next', e.g. dev_base->next


try:
    __dev_base = readSymbol("dev_base")
    # read device list starting from dev_base
    __offset = member_offset("struct net_device", "next")
    def dev_base_list():
        return [readSU("struct net_device", a) \
                for a in readList(__dev_base, __offset)]
except TypeError:
    # 2.6.22 and later
    if (symbol_exists("init_net")):
        __dev_base_head = readSymbol("init_net").dev_base_head
    else:
        __dev_base_head = readSymbol("dev_base_head")
    def dev_base_list():
        return readSUListFromHead(Addr(__dev_base_head), "dev_list",
                                  "struct net_device")
    

# At this moment contains values 0-2, i.e. 3 bands
prio2band = readSymbol("prio2band")

HZ = float(sys_info.HZ)

# Does this u32 can be intepreted as 'number of significant netmask bits'
def snetmask(u32):
    # I. Find the first non-zero bit, starting from the right
    n = socket.ntohl(u32) & 0xffffffff
    for i in range(32):
        if (n & 0x1):
            # Now test whether all high bits are set
            if (n == (0xffffffff >> i)):
                return 32-i
            else:
                return -1
        n >>= 1
    return 0

def print_If(dev, details = 0):
    # Get the list of inet6-devices and put into a dict
    if6devs = {}
    for ifa in get_inet6_ifaddr():
        name = ifa.idev.Deref.dev.Deref.name
        if6devs.setdefault(name, []).append(ifa)

    devname = dev.name
    jiffies = readSymbol("jiffies")
    ipwithmask = ''
    print ('=' * 22 + " " +  devname + " " + str(dev) + "  " + '=' *46)[:78]
    #print ""
    ipm_list = []
    if (dev.ip_ptr):
        ip = readSU("struct in_device", dev.ip_ptr)
        # Get IP-addresses
        ifa_list = ip.ifa_list
        for ifa in readStructNext(ifa_list, "ifa_next"):
            mask = ifa.ifa_mask
            # Can our mask be represented in bitnumber-way?
            smask = snetmask(mask)
            ipmask =  ntodots(ifa.ifa_mask)
            ipaddr = ntodots(ifa.ifa_address)
            if (smask != -1):
                ipwithmask = "%s/%d" % (ipaddr, smask)
            else:
                ipwithmask = "%s/%s" % (ipaddr, ipmask)
            ipm_list.append((ipwithmask, ifa.ifa_label, ifa.ifa_flags))
        # The list may be empty in patologic cases
        try: 
            ipwithmask = ipm_list[0][0]
        except IndexError:
            pass

    last_rx = dev.last_rx
    trans_start = dev.trans_start
    flags = dbits2str(dev.flags, IFF_FLAGS)
    features = dbits2str(dev.features, NETIF_FEATURES, 8)
    # If this is Ethernet, print its MAC-address
    if (dev.type == ARP_HW.ARPHRD_ETHER):
        da = dev.dev_addr
        hwaddr = hwaddr2str(da, 6)
    else:
        hwaddr = ""
    arptype = ARP_HW.value2key(dev.type)[7:]
    print "%-6s  %18s  mtu=%-5d  %20s  %s" % (devname, ipwithmask, dev.mtu,
                                              hwaddr, arptype)
    for ipwithmask, ifalabel, ifaflags in ipm_list[1:]:
        if (ifalabel != devname):
            ipwithmask = "%-20s  %s" % (ipwithmask, ifalabel)
        print "  inet4 addr: %s" % ipwithmask
    if (if6devs.has_key(devname)):
        for ifa in if6devs[devname]:
            print "  inet6 addr: %s/%d" % (ntodots6(ifa.addr),
                                           ifa.prefix_len)

    print "    flags=<%s>" % flags
    if (features):
        print "    features=<%s>" % features

    # Bonding info
    try:
        master = Deref(dev.master)
        print "    master=%s" % master.name
    except IndexError:
        pass
    if (details < 1):
        return

    print "    LINK_STATE %3d %s" %(dev.state, decodeDevState(dev.state))
    print "    open=<%s>, stats=<%s> mtu=%d promisc=%d" % \
          (addr2sym(dev.open), addr2sym(dev.get_stats),
           dev.mtu, dev.promiscuity)
    if (dev.ip_ptr and last_rx <2*jiffies):
	# If device is up but never was used, both last_rx and 
	# trans_start are bogus (usually very big)
        print "    \tlast_rx %7.2f s ago" % ((jiffies - last_rx)/HZ)
        if (trans_start):
            print "    \ttrans_start %7.2f s ago" % \
                  ((jiffies - trans_start)/HZ)
    getStats(dev)
    printQdisc(dev.qdisc, details-1)
   
def print_Ifs(IF):
    for dev in dev_base_list():
        devname = dev.name
        if (IF and IF != devname):
            continue
        print_If(dev)

def printPerCPU():
    print "\n\n ===== Per-CPU Data ====="
    softnet_data = percpu.get_cpu_var("softnet_data")
    netdev_rx_stat = percpu.get_cpu_var("netdev_rx_stat")
    for cpu in range(sys_info.CPUS):
        sd = readSU("struct softnet_data", softnet_data[cpu])
        print "--CPU %d" % cpu
        print "\tinput_pkt_queue=0x%x qlen=%d" % \
            (Addr(sd.input_pkt_queue), sd.input_pkt_queue.qlen)
        netif_rx_stats = readSU("struct netif_rx_stats", netdev_rx_stat[cpu])
        print "\tnetif_rx_stats total=%d, dropped=%d" % \
            (netif_rx_stats.total, netif_rx_stats.dropped)
