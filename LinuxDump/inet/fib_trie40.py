# -*- coding: utf-8 -*-
# module LinuxDump.inet.fib_trie40
#
#
# --------------------------------------------------------------------
# (C) Copyright 2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# FIB-TRIE stuff for kernel 4.2 (quite different from older kernels...)

from __future__ import print_function

from pykdump.API import *

from LinuxDump.inet import *
from LinuxDump.inet import routing as gen_rtn

debug = API_options.debug

# ------- FIB-TRIE stuff for new kernels ----------------------------------
#define KEYLENGTH       (8*sizeof(t_key))
#define KEY_MAX         ((t_key)~0)

#typedef unsigned int t_key;

#define IS_TRIE(n)      ((n)->pos >= KEYLENGTH)
#define IS_TNODE(n)     ((n)->bits)
#define IS_LEAF(n)      (!(n)->bits)

KEYLENGTH = 8 * struct_size("t_key")
KEY_MAX = -1

def IS_TRIE(n):
    return n.pos >= KEYLENGTH

def IS_TNODE(n):
    return n.bits

def IS_LEAF(n):
    return (not n.bits)

# static inline unsigned long get_index(t_key key, struct key_vector *kv)
# {
#       unsigned long index = key ^ kv->key;

#       if ((BITS_PER_LONG <= KEYLENGTH) && (KEYLENGTH == kv->pos))
#               return 0;

#       return index >> kv->pos;
# }

def get_index(key, kv):
    # print("   cindex:", key, kv)
    index = key ^ kv.key
    if (BITS_PER_LONG <= KEYLENGTH and KEYLENGTH == kv.pos):
        return 0
    return index >> kv.pos

#define get_child_rcu(tn, i) rcu_dereference_rtnl((tn)->tnode[i])
def get_child_rcu(tn, i):
    return tn.tnode[i]

#define node_parent_rcu(tn) rcu_dereference_rtnl(tn_info(tn)->parent)
def node_parent_rcu(tn):
    #print("  node_parent", tn, tn_info(tn))
    return tn_info(tn).parent

# static inline struct tnode *tn_info(struct key_vector *kv)
# {
#       return container_of(kv, struct tnode, kv[0]);
# }

def tn_info(kv):
    return container_of(kv, "struct tnode", "kv")

#print(KEYLENGTH, KEY_MAX)



# Note: we have kv[1] in the following definition
#struct trie {
#    struct key_vector kv[1];
#    struct trie_use_stats *stats;
#}

# PyKdump API is smart enough to work properly for
# kv[0], kv[1] etc. ot kv, kv+1, ...

# We turn it into a generator, so no we maintain both tn and key internally
def leaf_walk(tn):
    key = 0
    pn = tn
    while (True):
        (n, pn) = leaf_walk_rcu(pn, key)
        if (n):
            yield n
            key = n.key + 1
        else:
            return
            

def leaf_walk_rcu(tn, key):
    n = tn
    # do while
    while(True):
        #print("1st pass", n, key)
        pn = n
        # cindex = key ? get_index(key, pn) : 0;
        cindex = get_index(key, pn) if key else 0
        #print("  cindex", cindex, pn.bits)
        if (cindex >> pn.bits):
            break
        n = get_child_rcu(pn, cindex)
        cindex += 1
        if (not n):
            break
        if (IS_LEAF(n) and (n.key >= key)):
            # found
            return (n, pn)
        if (not IS_TNODE(n)):
            break

    #while (!IS_TRIE(pn)) {
    while(True):
        if (IS_TRIE(pn)):
            break
        #       if (cindex >= (1ul << pn->bits)) {
        #       t_key pkey = pn->key;

        #       pn = node_parent_rcu(pn);
        #       cindex = get_index(pkey, pn) + 1;
        #       continue;
        # }
        #print("2nd pass", pn, key)
        if (cindex >= 1 << pn.bits):
            pkey = pn.key
            pn = node_parent_rcu(pn)
            cindex = get_index(pkey, pn) + 1
            continue

        n = get_child_rcu(pn, cindex)
        cindex += 1
        if (not n):
            continue
        if (IS_LEAF(n)):
            # found
            return (n, pn)
        #/* Rescan start scanning in new node */
        pn = n
        cindex = 0
    return (None, pn)                # Root 

        

           
def process_one_kv(kv):
    prefix = htonl(kv.key)
    #print(kv, prefix)
    for fa in hlist_for_each_entry("struct fib_alias", kv.leaf, "fa_list") :
            b = Bunch()
            mask = gen_rtn.inet_make_mask(KEYLENGTH - fa.fa_slen)
            fi = fa.fa_info
            b.fa = fa           # To skip some entries later
            # First, fill-in fields from fib_info
            if (fi):
                #define fib_dev         fib_nh[0].nh_dev
                dev = fi.fib_nh[0].nh_dev
                if (dev):
                    b.dev = dev.name
                else:
                    b.dev = '*'
                b.gw = fi.fib_nh.nh_gw
                b.metric = fi.fib_priority
                b.mtu = 0
                fib_advmss = fi.fib_metrics[gen_rtn.RTAX.RTAX_ADVMSS-1]
                if (fib_advmss):
                    b.mtu =  fib_advmss + 40
            else:
                # fi = NULL
                b.flags = gen_rtn.fib_flags_trans(fa.fa_type, b.mask, 0)
                b.gw = 0
                b.metric = 0

            b.flags = gen_rtn.fib_flags_trans(fa.fa_type, mask, fi)
            b.dest = prefix
            b.mask = mask

            yield b

# get all entries from a table for kernels 3.0
def get_fib_entries_v40(table):
    t = readSU("struct trie", table.tb_data)
    tp = t.kv
    tb_id = table.tb_id

    for l in  leaf_walk(tp):
        for e in process_one_kv(l):
            fa = e.fa
            if (fa.fa_type in (gen_rtn.RTN.RTN_BROADCAST,
                               gen_rtn.RTN.RTN_MULTICAST)):
                continue
            if (fa.tb_id != tb_id):
                continue
            yield e


def fib_table_dump(tb):
    t = readSU("struct trie", tb.tb_data)
    print(t)
    tp = t.kv

    for l in  leaf_walk(tp):
        do_fib_print(process_one_kv(l))
        #for b in  process_one_kv(l):
        #    fib_print(b)

# --------end of FIB-TRIE--------------------------------------------------

