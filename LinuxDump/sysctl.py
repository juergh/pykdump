# module LinuxDump.sysctl
#
# Time-stamp: <07/02/01 15:14:30 alexs>
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
This is a package providing access to ctl_table trees used by 'sysctl'
The root table is 'root_table' and they are all of type 'struct ctl_table'
'''


import string, struct
import sys
import types

from pykdump.API import *


# This is the root ctl_table, most other tables can be reached by walking it
# But there are some non-standard ctl_tables (e.g. neigh_sysctl_template,
# addrconf_sysctl)  that are registered in a different way and should be
# processed separately. These additional tables are registered by calling
# register_sysctl_table() and can be found from
#
# static struct ctl_table_header root_table_header =
#	{ root_table, LIST_HEAD_INIT(root_table_header.ctl_entry) };



root_table = readSymbol("root_table")
root_table_header = readSymbol("root_table_header")

stype = root_table[0].PYT_symbol

# We put all found entries in a dcitionary - indexed by entry names, e.g.
# net.ipv6.conf.vmnet1.force_mld_version

__entries = {}

# Return a dict indexed by name (a la sysctl) and values, e.g.
# "net.ipv4.ip_forward".
def readCtlTable(root, parent = ''):
    #print "root=", root
    for ct in root:
        #print ct
        if (ct.ctl_name == 0): break
        if (ct.child):
            # This is a pointer to another table
            newroot = readSUArray(stype, ct.child)
            readCtlTable(newroot, parent + ct.procname + '.')
            continue
        # In some cases (e.g. neigh_sysctl_template) we copy the template
        # and then disable some table elements by setting
        # procname to NULL, e.g.
        # t->neigh_vars[12].procname = NULL;
        if (ct.procname != None):
            __entries[parent + ct.procname] =  ct


def getCtlTables():
    # Walk linked list of headers
    for ct in readSUListFromHead("root_table_header", "ctl_entry",
                                 "struct ctl_table_header", inchead=True):
        ctp = ct.ctl_table
        #print ct, hexl(ctp), ct.Deref.ctl_table.procname
        ctl_table = readSUArray(stype, ctp)
        #print '-' * 70
        readCtlTable(ctl_table)
    return __entries
    

# We assume that data points to an int, or array of ints
intsize = 4
def getCtlData(ct):
    maxlen = ct.maxlen
    if (maxlen == 0 or maxlen %intsize !=0):
        return "(?)"
    data = ct.data
    if (data == 0):
        return "(?)"
    out = []
    sz = maxlen/intsize
    if (sz == 1):
        return int(readU32(data))
    for i in range(sz):
        i = readU32(data)
        out.append(int(i))
        data += intsize
    return out
    
