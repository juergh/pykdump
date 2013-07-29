#!/usr/bin/env python

# Time-stamp: <13/07/29 16:07:08 alexs>

# --------------------------------------------------------------------
# (C) Copyright 2006-2013 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------

# Print info about connections and sockets 

from pykdump.API import *
from LinuxDump import percpu

# Analyzing timer lists
__TIMER_MAGIC = 0x4b87ad6e
for cpu, a in  enumerate(percpu.get_cpu_var("tvec_bases")):
    s = readSU("struct tvec_t_base_s", a)
    print "---CPU#%d" % cpu, s
    # tv1-tv5 are arrays of list_heads
    for tvi in range(1,6):
	sn = "tv%d" % tvi
	tv = s.__getattr__(sn)
	print "  ", sn, tv
	for i, lh in enumerate(tv.vec):
	    lst, err = readBadList(lh, inchead = False, maxel=10000)
	    if (len(lst)):
	       print "\t", i, lh, len(lst)
	    if (err):
		print "\t  +++ %s.vec[%d]. lhaddr=0x%x" % (sn, i, long(lh)), err
		# Strip the bad element
		lst = lst[:-1]
	    # Print the list
	    for a in lst:
		tl = readSU("struct timer_list", a)
		if (tl.magic != __TIMER_MAGIC):
		    bm = "bad magic"
		else:
		    bm = addr2sym(tl.function)
		print "\t  ", tl, bm

