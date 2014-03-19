#!/usr/bin/env python
# -*- coding: utf-8 -*-
# module LinuxDump.Time
#
# --------------------------------------------------------------------
# (C) Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
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

from __future__ import print_function

__doc__ = '''
This is a package providing subroutines for time manipulation
'''

# Tasks and Pids

from pykdump.API import *

def j_delay(ts, jiffies):
    v = (jiffies - ts) & INT_MASK
    if (v > INT_MAX):
        v = "     n/a"
    elif (v > HZ*3600*20):
        v = ">20hours"
    else:
        v = "%8.2f s" % (float(v)/HZ)
    return v