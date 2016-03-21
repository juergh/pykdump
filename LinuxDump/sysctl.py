# module LinuxDump.sysctl
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2016 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
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

# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function

__doc__ = '''
This is a package providing access to ctl_table trees used by 'sysctl'
The root table is 'root_table' and they are all of type 'struct ctl_table'
'''


import string, struct
import sys
import types

from pykdump.API import *
from LinuxDump.Tasks import jiffies2ms


# This is the root ctl_table, most other tables can be reached by walking it
# But there are some non-standard ctl_tables (e.g. neigh_sysctl_template,
# addrconf_sysctl)  that are registered in a different way and should be
# processed separately. These additional tables are registered by calling
# register_sysctl_table() and can be found from
#
# static struct ctl_table_header root_table_header =
#       { root_table, LIST_HEAD_INIT(root_table_header.ctl_entry) };


# Some kernels have two completely unrelated root_table variables,
# both static. One for sysctl, another one for unwind.

if (len(sym2alladdr("root_table")) == 1):
    root_table = readSymbol("root_table")
    stype = root_table[0].PYT_symbol
    # Sometimes stype is returned as 'ctl_table', not 'struct ctl_table'
else:
    stype = "struct ctl_table"

try:
    root_table_header = readSymbol("root_table_header")
except:
    # Does not work on this kernel...
    root_table_header = None


# We put all found entries in a dcitionary - indexed by entry names, e.g.
# net.ipv6.conf.vmnet1.force_mld_version

__entries = {}

# Return a dict indexed by name (a la sysctl) and values, e.g.
# "net.ipv4.ip_forward".
def readCtlTable(root, parent = ''):
    #print "root=", root
    for ct in root:
        if (long(ct) == 0): break
        
        # The following was needed some time ago but does not work in 2.6.32
        # FIXME
        #if (ct.hasField("ctl_name")):
            #if(ct.ctl_name == 0):
                #break
        
        if (ct.procname == None):
            break

        if (ct.child):
            # This is a pointer to another table
            newroot = readSUArray(stype, ct.child)
            #print "   |", newroot, ct.child,  parent + ct.procname + '.'
            readCtlTable(newroot, parent + ct.procname + '.')
            continue
        # In some cases (e.g. neigh_sysctl_template) we copy the template
        # and then disable some table elements by setting
        # procname to NULL, e.g.
        # t->neigh_vars[12].procname = NULL;
        if (ct.procname and ct.procname[0] > chr(128)):
            continue
        if (ct.procname != None):
            __entries[str(parent + ct.procname)] =  ct


def getCtlTables():
    if (root_table_header == None):
        global nsproxy
        # Not supported on this kernel yet...
        rdir = readSymbol("sysctl_table_root").default_set.dir
        nsproxy = readSymbol("init_task").nsproxy
        process_subdir(rdir)
        return __entries
        
    # Walk linked list of headers
    for ct in readSUListFromHead("root_table_header", "ctl_entry",
                                 "struct ctl_table_header", inchead=True):
        ctp = ct.ctl_table
        if (not ctp.procname.isalnum()): continue
        # On new kernels we can exit because root is null
        try:
            if (not ct.root): break
        except KeyError:
            pass
        #print ct, hexl(ctp), ct.Deref.ctl_table.procname
        ctl_table = readSUArray(stype, ctp)
        #print '-' * 70
        readCtlTable(ctl_table)
    return __entries
    

# We assume that data points to an int, or array of ints
intsize = getSizeOf("int")
longsize = getSizeOf("long int")
HZ = sys_info.HZ

def getCtlData(ct):
    out = []
    maxlen = ct.maxlen
    phandler = addr2sym(ct.proc_handler)
    # Some special cases
    if (phandler == 'proc_dostring'):
        out = SmartString(readmem(ct.data, maxlen), ct.data, None)
        return out
    if (phandler == 'cdrom_sysctl_info'):
        idstr = SmartString(readmem(ct.data, maxlen), ct.data, None)
        for s in idstr.split("\n"):
            out.append("    " + s)
        # Strip whitespace from the 0th element
        # CD-ROM information, Id: cdrom.c 3.20 2003/12/17
        out[0] = out[0].strip()
        return "\n".join(out)
    if (maxlen == 0 or maxlen %intsize !=0):
        return "(?)"
    data = ct.data
    if (data == 0):
        return "(?)"
    if (phandler in ("proc_doulongvec_minmax", 
                     "dirty_background_bytes_handler", "dirty_bytes_handler",
                     "proc_ipc_doulongvec_minmax", "ipv4_tcp_mem")):
        sz = maxlen//longsize
        readsub = readULong
    else:
        sz = maxlen//intsize
        readsub = readUInt
    if (sz == 1):
        iv = int(readsub(data))
        if (phandler.find("jiffies") >= 0):
            # convert from jiffies to ms
            iv = iv//HZ
        return iv
    for i in range(sz):
        iv = int(readsub(data))
        if (phandler.find("jiffies") >= 0):
            # convert from jiffies to ms
            iv = iv//HZ
        out.append(iv)
        data += intsize
    # Arrays cane be huge - do not print more than 5 elements
    l = len(out)
    if (l > 5):
        out = out[:5] + ["... %d more elements" % (l-5)]
    return out
    

# -------- Kernel 3.5 and later implement /proc/sys in a different way
#  /proc/sys specific subroutines

from LinuxDump.trees import *
from stat import S_ISDIR, S_ISLNK

# node = struct rb_node
def first_usable_entry(node):
    while(node):
        ctl_node = container_of(node, "struct ctl_node", "node")
        #print(node, ctl_node)
        if(not ctl_node.header.unregistering):
            return ctl_node
        node = rb_next(node)
    return None


# ctdir = struct ctl_dir
def first_entry(ctdir):
    ctl_node = first_usable_entry(rb_first(ctdir.root))
    if (not ctl_node):
        return None
    head = ctl_node.header
    sz = len(ctl_node)
    ind =  (ctl_node-head.node)//sz
    #print("ctl_node=%d, head_node=%d, ctl_node - head->node=%d" % \
    #      (long(ctl_node), long(head.node), ind))
    
    
    entry = head.ctl_table[ind]
    return (entry, head)

# We do not walk it in the most efficient way as it is not needed
# for our purposes at this moment. We just use for_all_sysdir_entries
def find_entry(pdir, name):
    for entry, h in for_all_sysdir_entries(pdir):
        if (entry.procname == name):
            return entry, h
    return (None, None)

def find_subdir(pdir, name):
    entry, h = find_entry(pdir, name)
    if (not stat.S_ISDIR(entry.mode)):
        raise TypeError, "Incorrect mode " + name
    return container_of(h, "struct ctl_dir", "header")

def for_all_sysdir_entries(ctdir):
    ctl_node = first_usable_entry(rb_first(ctdir.root))
    while (ctl_node):
        head = ctl_node.header
        sz = len(ctl_node)
        ind =  (ctl_node-head.node)//sz
        ct = head.ctl_table[ind]
        yield ct, head
        
        ctl_node = first_usable_entry(rb_next(ctl_node.node))


# We gather all non-subdir entries here, indexed by key
__entries = {}

def process_subdir(subdir, parents = ''):
    for ct, h in for_all_sysdir_entries(subdir):
        fname = parents + ct.procname
        if(S_ISDIR(ct.mode)):
            newdir = container_of(h, "struct ctl_dir", "header")
            process_subdir(newdir, fname + '.')
        elif (S_ISLNK(ct.mode)):
            newdir = follow_symlink(h, ct, nsproxy)
            process_subdir(newdir, fname + '.')
        else:
            # A simple entry - add it to entries
            __entries[fname] = ct

def print_sysdir(sysdir, indent = 0):
    tindent = ' ' * indent
    for e, h in for_all_sysdir_entries(sysdir):
        print(tindent, e, e.procname)
        if(S_ISDIR(e.mode)):
            newdir = container_of(h, "struct ctl_dir", "header")
            print_sysdir(newdir, indent+4)
        elif (S_ISLNK(e.mode)):
            #print("!!!", e.procname)
            newdir = follow_symlink(h, e, nsproxy)
            print_sysdir(newdir, indent+4)

def follow_symlink(head, ct, namespaces):
    root = readSU("struct ctl_table_root", ct.data)
    lookup = addr2sym(root.lookup)
    if (lookup != "net_ctl_header_lookup"):
        raise TypeError, "Unknown lookup type"
    ctset = namespaces.net_ns.sysctls
    #print(root, ctset)
    return xlate_dir(ctset, head.parent)


__ERR_VALUE = uLong(-4095)

def xlate_dir(ctset, ctdir):
    if (not ctdir.header.parent):
        return ctset.dir
    parent = xlate_dir(ctset, ctdir.header.parent)
    if (long(parent) >= __ERR_VALUE):
        print("IS_ERR", parent)
        return parent
    procname = ctdir.header.ctl_table[0].procname
    return find_subdir(parent, procname)
