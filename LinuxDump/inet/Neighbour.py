#!/usr/bin/env python

# Time-stamp: <07/03/21 15:28:14 alexs>

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.

# Print info about connections and sockets 

from pykdump.API import *
from LinuxDump.inet import *

import sys

arp_tbl = readSymbol("arp_tbl")
hash_buckets = arp_tbl.hash_buckets

pt = hash_buckets.ptype

print repr(hash_buckets)

print arp_tbl.hash_mask

d1 = Deref(hash_buckets)
print repr(d1)

d2 = Deref(d1)
print repr(d2)

for i in range(arp_tbl.hash_mask):
    b = hash_buckets[i]
    if (b != 0):
        print i, repr(b)
        for s in readStructNext(b, "next"):
            pkey = s.primary_key
            print "\t", s, hexl(pkey), ntodots(readU32(pkey))


sys.exit(0)
for i in range(3):
    print "\n", "-"* 20, i

    for t in ("basetype", "ctype", "smarttype", "dim"):
        print  "%s: <%s>" % (t, getattr(pt, t))

    pp.pprint(pt)
    pt = pt.Deref()

