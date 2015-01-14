# module LinuxDump.inet.snmpstats
#
# Time-stamp: <2015-01-14 09:02:18 alexs>
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2014 Hewlett-Packard Development Company, L.P.
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
This is a package providing generic access to SNMP NET statistics.
'''


import string, struct
import sys
import types

# Python2 vs Python3
_Pym = sys.version_info[0]
if (_Pym < 3):
    from StringIO import StringIO
else:
    from io import StringIO

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

# #define TCP_INC_STATS(field)  SNMP_INC_STATS(tcp_statistics, field)

# #define SNMP_INC_STATS(mib, field)    \
#       (per_cpu_ptr(mib[!in_softirq()],
#         raw_smp_processor_id())->mibs[field]++)

class SnmpTable(dict):
    def __init__(self, tname):
        self.name = tname
        self.body = getSnmpTable(tname)
    def __str__(self):
        prn = StringIO()
        print("")
        print ('-'*20, self.name, '-'*20, "\n", file=prn)
        if (self.body):
            for f, sum in self.body:
                print ("   %25s %20d" % (f, sum), file=prn)
        else:
            print ("  not implemented yet", file=prn)
        out = prn.getvalue()
        prn.close()
        return out

def __getSnmpTable_26(tname):
    # On 2.6.27 the tables are in init_net
    if (symbol_exists("init_net")):
        net = get_nsproxy().net_ns
        mib = net.mib
        table = mib.__getattr__(tname)
    else:
        table = readSymbol(tname)
    snmpname = tabnames[tname]
    out = []
    if (not symbol_exists(snmpname)):
        return None
    #print("++", snmpname)
    for sn in readSymbol(snmpname):
        entry = sn.entry
        if (entry == 0): break
        f = sn.name
        sum = __getSnmpEntry(table, entry)
        # MaxConn field is signed, RFC 2012
        if (f == 'MaxConn'):
            sum = sLong(sum)
        out.append((f, sum))
    return out


# unsigned long snmp_fold_field(void __percpu *mib[], int offt)
# {
# 	unsigned long res = 0;
# 	int i;

# 	for_each_possible_cpu(i) {
# 		res += *(((unsigned long *) per_cpu_ptr(mib[0], i)) + offt);
# 		res += *(((unsigned long *) per_cpu_ptr(mib[1], i)) + offt);
# 	}
# 	return res;
# }

def X__getSnmpEntry(mib2, entry):
    sum = 0
    #print("mib2 {0x%x, 0x%x}" % (mib2[0], mib2[1]))
    for cpu in range(__cpus):
        mib0 = (percpu.percpu_ptr(long(mib2[0]), cpu))
        mib1 = (percpu.percpu_ptr(long(mib2[1]), cpu))
        #print("mib0=0x%x, entry=0x%x" % (mib0, entry))
        #print("mib1=0x%x, entry=0x%x" % (mib1, entry))
        v0 = readULong(mib0 + 8*entry)
        v1 = readULong(mib1 + 8*entry)
        #print("  entry=%d cpu=%d v0=%d v1=%d" % (entry, cpu, v0, v1))
        sum += v0 + v1
    #print ("++++sum=%d" %sum)
    return sum & LONG_MASK

if (struct_exists("struct netns_mib")):
    ti = getStructInfo("struct netns_mib")["tcp_statistics"].ti
    __snmp_array_sz = ti.elements
else:
    __snmp_array_sz = 2
    
def __getSnmpEntry(mib2, entry):
    sum = 0
    #print("mib2 {0x%x, 0x%x}" % (mib2[0], mib2[1]))
    for cpu in range(__cpus):
        for i in range(__snmp_array_sz):
            mib = Deref(percpu.percpu_ptr(mib2[i], cpu))
            v = mib.mibs[entry]
            sum += uLong(v)
    return sum & LONG_MASK

# on 2.4 kernels SNMP-name isjust the fieldname in the struct, e.g.
#
# struct tcp_mib        tcp_statistics[NR_CPUS*2];
# which is laid out as [NR_CPUS][2]
#
# struct tcp_mib {
#    long unsigned int TcpRtoAlgorithm;
#    long unsigned int TcpRtoMin;
#    long unsigned int TcpRtoMax;

def __getSnmpTable_24(tname):
    table = readSymbol(tname)
    # On SLES9 this is an array of tPtr, and they are really percpu_ptr.
    # Is not implemented yet
    if (isinstance(table[0], tPtr)):
        return None
    sinfo = table[0].PYT_sinfo
    #fnames = [e['fname'] for e in sinfo.body][:-1]
    fnames = sinfo.getFnames()[:-1]
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
