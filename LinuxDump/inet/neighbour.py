# module LinuxDump.inet.neighbour
#
# Time-stamp: <13/07/29 15:58:21 alexs>
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2013 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
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


from __future__ import print_function

__doc__ = '''
This is a package providing useful tables and functions for neighbouring
layer.
'''

from pykdump.API import *
from LinuxDump.inet import *
from LinuxDump.inet.netdevice import hwaddr2str, ARP_HW
from .proto import P_FAMILIES, walk_skb, skb_shinfo

_NUD_c = '''
#define NUD_INCOMPLETE  0x01
#define NUD_REACHABLE   0x02
#define NUD_STALE       0x04
#define NUD_DELAY       0x08
#define NUD_PROBE       0x10
#define NUD_FAILED      0x20

/* Dummy states */
#define NUD_NOARP       0x40
#define NUD_PERMANENT   0x80
#define NUD_NONE        0x00
'''

NUD = CDefine(_NUD_c)


def print_neighbour_info(v = 0):
    neigh_tables = readSymbol("neigh_tables")
    
    for t in readStructNext(neigh_tables, "next"):
        print ("===",t, P_FAMILIES.value2key(t.family), addr2sym(Addr(t)))
        print_neighbour_table(t, v)
    

def print_neighbour_table(tbl, v = 0):
    # Kernel 3.0moved hash_buckets to struct neigh_hash_table *nht;
    if (tbl.hasField("nht")):
        nht = tbl.nht
    else:
        nht = tbl
    hash_buckets = nht.hash_buckets
    if (nht.hasField("hash_mask")):
        hashsize = nht.hash_mask + 1
    elif (nht.hasField("hash_shift")):
        hashsize = 1 << nht.hash_shift
    else:
        hashsize = len(hash_buckets)

    family = tbl.family
    print ("IP ADDRESS        HW TYPE    HW ADDRESS           DEVICE  STATE")
    print ("----------        -------    ----------           ------  -----")
    for i in range(hashsize):
        b = hash_buckets[i]
        if (b != 0):
            #print i, repr(Deref(b))
            for s in readStructNext(b, "next"):
                if (family == P_FAMILIES.PF_INET):
                    ip = ntodots(readU32(s.primary_key))
                elif (family == P_FAMILIES.PF_INET6):
                    ip = ntodots6(readSU("struct in6_addr", s.primary_key))
                else:
                    ip = '???'
                    
                nud_state = dbits2str(s.nud_state, NUD, 4)
                dev = Deref(s.dev)
                dev_type = dev.type
                dev_addr_len = dev.addr_len
                ha = s.ha
                arptype = ARP_HW.value2key(dev_type)[7:]
                print ("%-16s  %-10s %-20s %-7s %s" % \
                      (ip, arptype, hwaddr2str(ha, dev_addr_len),
                       dev.name, nud_state))
                if (v):
                    print("   {}  arp_queue_len={}".format(s, s.arp_queue.qlen))
                    if (v > 1 and s.arp_queue.qlen):
                        for skb in walk_skb(s.arp_queue):
                            print("\t{}\n\t\t{}".format(skb, skb_shinfo(skb)))
                    print('-' * 78)


    # Now for permanent entries (phash_buckets/pneigh_entry)
    phash_buckets = tbl.phash_buckets
    try:
        nb = len(phash_buckets)
    except TypeError:
        nb = 0xf                        # PNEIGH_HASHMASK
    # print (" ------ Permanent ----------", nb)
    printheader = True
    for i in range(nb):
        b = phash_buckets[i]
        if (b):
            for s in readStructNext(b, "next"):
                if (printheader):
                    printheader = False
                    #print "   ---Proxies:"
                dev = s.Deref.dev
                dev_type = dev.type
                dev_addr_len = dev.addr_len
                arptype = ARP_HW.value2key(dev_type)[7:]
                if (family == P_FAMILIES.PF_INET):
                    ip = ntodots(readU32(s.key))
                elif (family == P_FAMILIES.PF_INET6):
                    ip = ntodots6(readSU("struct in6_addr", s.key))
                else:
                    ip = '???'
                print ("%-16s  %-10s %-20s %-7s %s" % \
                      (ip, arptype, '',
                       dev.name, 'PROXY'))


    print ("")


