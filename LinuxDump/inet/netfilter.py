# module LinuxDump.inet.netfilter
#
# Time-stamp: <07/03/07 12:30:02 alexs>
#
# Copyright (C) 2006-2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2007 Hewlett-Packard Co., All rights reserved.
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
# 	struct list_head list;

# 	/* User fills in from here down. */
# 	nf_hookfn *hook;
# 	struct module *owner;
# 	int pf;
# 	int hooknum;
# 	/* Hooks are ordered in ascending priority. */
# 	int priority;
# };

def nf():
    symi = whatis("nf_hooks")
    NPROTO = symi.array[0]
    NF_MAX_HOOKS = symi.array[1]
    offset = member_offset("struct nf_hook_ops", "list")
    nf_hooks = readSymbol("nf_hooks")
    print "NPROTO=%d, NF_MAX_HOOKS=%d" % (NPROTO, NF_MAX_HOOKS)
    for np in range(NPROTO):
        headerprinted = False
        for nh in range(NF_MAX_HOOKS):
            nflist = nf_hooks[np][nh]
            hops = readList(Addr(nf_hooks[np][nh]), inchead=False)
            if (not hops):
                continue
            if (not headerprinted):
                print "=====PROTO=", P_FAMILIES.value2key(np)
                headerprinted = True
            print "   ", NF_HOOKS.value2key(nh)
            for h in hops:
                hops = readSU("struct nf_hook_ops", h-offset)
                hook = addr2sym(hops.hook)
                prio = hops.priority
                print "\tprio=%d,  hook=%s" % (prio, hook)
                

_NF_HOOKS_c = '''
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4
'''

NF_HOOKS = CDefine(_NF_HOOKS_c)
