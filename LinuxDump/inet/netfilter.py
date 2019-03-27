# module LinuxDump.inet.netfilter
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2016 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
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
This is a package providing useful tables and functions for NETFILTER
and related stuff.
'''
from pykdump.API import *
from LinuxDump.inet import *
from LinuxDump import percpu
from LinuxDump.inet.proto import P_FAMILIES

import pprint
pp = pprint.PrettyPrinter(indent=4)

# struct nf_hook_ops
# {
#       struct list_head list;

#       /* User fills in from here down. */
#       nf_hookfn *hook;
#       struct module *owner;
#       int pf;
#       int hooknum;
#       /* Hooks are ordered in ascending priority. */
#       int priority;
# };

_NF_IP_HOOK_PRIORITIES_c = '''
enum nf_ip_hook_priorities {
        NF_IP_PRI_FIRST = INT_MIN,
        NF_IP_PRI_CONNTRACK_DEFRAG = -400,
        NF_IP_PRI_RAW = -300,
        NF_IP_PRI_SELINUX_FIRST = -225,
        NF_IP_PRI_CONNTRACK = -200,
        NF_IP_PRI_BRIDGE_SABOTAGE_FORWARD = -175,
        NF_IP_PRI_MANGLE = -150,
        NF_IP_PRI_NAT_DST = -100,
        NF_IP_PRI_BRIDGE_SABOTAGE_LOCAL_OUT = -50,
        NF_IP_PRI_FILTER = 0,
        NF_IP_PRI_NAT_SRC = 100,
        NF_IP_PRI_SELINUX_LAST = 225,
        NF_IP_PRI_CONNTRACK_HELPER = INT_MAX - 2,
        NF_IP_PRI_NAT_SEQ_ADJUST = INT_MAX - 1,
        NF_IP_PRI_CONNTRACK_CONFIRM = INT_MAX,
        NF_IP_PRI_LAST = INT_MAX,
};
'''

# Does not work with our current implementation of CEnum - it cannot
# process INT_MAX and INT_MIN
#NF_IP_HOOK_PRIORITIES = CEnum(_NF_IP_HOOK_PRIORITIES_c)

def nf():
    if (symbol_exists("nf_hooks")):
        symi = whatis("nf_hooks")
        NPROTO = symi.array[0]
        NF_MAX_HOOKS = symi.array[1]
        nf_hooks = readSymbol("nf_hooks")
    else:
        net_ns = get_ns_net()
        nf_hooks = net_ns.nf.hooks
        NPROTO, NF_MAX_HOOKS = len(nf_hooks), len(nf_hooks[0])
    offset = member_offset("struct nf_hook_ops", "list")
    print ("NPROTO=%d, NF_MAX_HOOKS=%d" % (NPROTO, NF_MAX_HOOKS))
    if (offset == -1):
        print("  Netfilter analysis not implemented for this kernel yet")
        return
    for np in range(NPROTO):
        headerprinted = False
        for nh in range(NF_MAX_HOOKS):
            nflist = nf_hooks[np][nh]
            hops = readList(Addr(nf_hooks[np][nh]), inchead=False)
            if (not hops):
                continue
            if (not headerprinted):
                print ("=====PROTO=", P_FAMILIES.value2key(np))
                headerprinted = True
            print ("   ", NF_HOOKS.value2key(nh))
            for h in hops:
                hops = readSU("struct nf_hook_ops", h-offset)
                hook = addr2sym(hops.hook)
                prio = hops.priority
                print ("\tprio=%d,  hook=%s" % (prio, hook))


_NF_HOOKS_c = '''
#define NF_IP_PRE_ROUTING       0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN          1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD           2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT         3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING      4
'''

NF_HOOKS = CDefine(_NF_HOOKS_c)
