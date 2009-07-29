# -*- coding: latin-1 -*-
# Time-stamp: <09/05/01 09:52:02 alexs>
# module LinuxDump.Slab
#
# Time-stamp: <08/03/05 15:51:52 alexs>
#
# Copyright (C) 2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 008 Hewlett-Packard Co., All rights reserved.
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
This is a package providing generic access to SLAB-caches.
'''

from pykdump.API import *

import re

# Return a tuple of allocated and free lists
__re_alloc = re.compile(r'^\s+\[([a-f0-9]+)\]\s*$')
__re_free = re.compile(r'^\s+([a-f0-9]+)\s*(\(cpu.*cache\))?\s*$')
def get_slab_addrs(slabname):
    alloc = []
    free = []
    res = exec_crash_command("kmem -S %s" % slabname)
    if (len(res) == 0):
        raise KeyError, "no slab %s" % slabname
    for s in res.splitlines():
	m = __re_alloc.match(s)
	if (m):
	    alloc.append(int(m.group(1), 16))
	else:
	    m = __re_free.match(s)
	    if (m):
		free.append(int(m.group(1), 16))
    return (alloc, free)
	
