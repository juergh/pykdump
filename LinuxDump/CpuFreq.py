#!/usr/bin/env python
# -*- coding: utf-8 -*-
# module LinuxDump.Tasks
#
# Copyright (C) 2006-2010 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2010 Hewlett-Packard Co., All rights reserved.
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
This is a package providing generic access to cpufreq
structures.
'''

# On older kernels the table is
# static struct cpufreq_policy *cpufreq_cpu_data[NR_CPUS]
#
# On newer ones this is per-cpu data

from pykdump.API import *

from LinuxDump import percpu

debug = API_options.debug

addr = sym2addr("cpufreq_cpu_data")

# struct cpufreq_policy *cpufreq_cpu_data[NR_CPUS]

# Fill-in the list
pointersize = sys_info.pointersize
cpufreq_cpu_data = []
for cpu in range(0, sys_info.CPUS):
    ptr = readPtr(addr + pointersize * cpu)
    p = readSU("struct cpufreq_policy", ptr)
    cpufreq_cpu_data.append(p)
    

def print_cpufreq():
    for p in cpufreq_cpu_data:
	print "  CPU=%d" % p.cpu, p, p.governor.name
	print "      Frequencies: min=%d max=%d cur=%d" % \
	    (p.min, p.max, p.cur)
