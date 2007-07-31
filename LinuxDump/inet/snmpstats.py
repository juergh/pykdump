# module LinuxDump.inet.snmpstats
#
# Time-stamp: <07/03/29 14:50:26 alexs>
#
# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.
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
This is a package providing generic access to SNMP NET statistics.
'''


import string, struct
import sys
import types
from StringIO import StringIO

from pykdump.API import *
from LinuxDump import  percpu


__cpus = sys_info.CPUS

# On 2.6 kernels we have definitions like
# static const struct snmp_mib snmp4_ipstats_list[] = {

snmp4_tables = ["ip_statistics", "icmp_statistics", "tcp_statistics",
                  "udp_statistics", "net_statistics"]

tabnames = {
            "ip_statistics"   : "snmp4_ipstats_list",
	    "icmp_statistics" : "snmp4_icmp_list",
	    "tcp_statistics"  : "snmp4_tcp_list",
	    "udp_statistics"  : "snmp4_udp_list",
	    "net_statistics"  : "snmp4_net_list"
	   } 

# We have similar names for IPv6 but they are defined in DLKM

# Data format on 2.4 and 2.6 is different.

# On 2.6 
# The data itself is declared as
# DECLARE_SNMP_STAT(struct tcp_mib, tcp_statistics);
#
# which expands to
#  type = struct tcp_mib {
#     long unsigned int mibs[15];
#  } *[2]

# #define TCP_INC_STATS(field)	SNMP_INC_STATS(tcp_statistics, field)

# #define SNMP_INC_STATS(mib, field) 	\
#	(per_cpu_ptr(mib[!in_softirq()], 
#         raw_smp_processor_id())->mibs[field]++)
	

class SnmpTable(dict):
    def __init__(self, tname):
        self.name = tname
        self.body = getSnmpTable(tname)
    def __str__(self):
	prn = StringIO()
        print >>prn, "\n", '-'*20, self.name, '-'*20, "\n"
	for f, sum in self.body:
	   print >>prn, "   %25s %20d" % (f, sum)
	out = prn.getvalue()
	prn.close()
	return out

def __getSnmpTable_26(tname):
    table = readSymbol(tname)
    snmpname = tabnames[tname]

    out = []
    for sn in readSymbol(snmpname):
	entry = sn.entry
	f = sn.name
        if (entry == 0): break
	
	sum = __getSnmpEntry(table, entry)
	out.append((f, sum))
    return out


	
def __getSnmpEntry(mib2, entry):
    sum = 0
    for cpu in range(__cpus):
	mib0 = Deref(percpu.percpu_ptr(mib2[0], cpu))
	mib1 = Deref(percpu.percpu_ptr(mib2[1], cpu))
	v0 = mib0.mibs[entry]
	v1 = mib1.mibs[entry]
	sum += (sLong(v0) + sLong(v1))
    return sum

# on 2.4 kernels SNMP-name isjust the fieldname in the struct, e.g.
#
# struct tcp_mib	tcp_statistics[NR_CPUS*2];
# which is laid out as [NR_CPUS][2]
#
# struct tcp_mib {
#    long unsigned int TcpRtoAlgorithm;
#    long unsigned int TcpRtoMin;
#    long unsigned int TcpRtoMax;

def __getSnmpTable_24(tname):
    table = readSymbol(tname)
    sinfo = table[0].PYT_sinfo
    stype = sinfo.stype
    fnames = [e['fname'] for e in sinfo.body][:-1]
    pref = tname.split('_')[0]
    # For all proto-specific tables (e.g. IP or TCP) the field names
    # in v2.4 have extra pref in the beginning of field names, compared
    # to those from v2.6
    if (pref != 'net'):
	preflen = len(pref)
    else:
	preflen = 0
    stats ={}
    out =[]
    for f in fnames:
	sum = 0
	for cpu in range(__cpus):
	    i0 = cpu*2
	    i1 = i0 + 1
	    v0 = sLong(getattr(table[i0], f))
	    v1 = sLong(getattr(table[i1], f))
	    sum += (v0 + v1)
	out.append((f[preflen:], sum))
    return out

if (symbol_exists("snmp4_tcp_list")):
    getSnmpTable = __getSnmpTable_26
else:
    getSnmpTable = __getSnmpTable_24