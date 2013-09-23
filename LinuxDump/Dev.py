# -*- coding: utf-8 -*-
# module LinuxDump.Dev
#
# Time-stamp: <13/07/29 16:14:16 alexs>
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2013 Hewlett-Packard Development Company, L.P.
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
This is a package providing generic access to block devices
'''

from pykdump.API import *
from LinuxDump.percpu import percpu_ptr

import re
import textwrap
from collections import namedtuple, defaultdict


# Decode dev_t
# major, minor = decode_devt(dev)
def decode_devt(dev):
    if (dev >>16):
        # New-style
        major = dev >> 20
        minor = dev ^ (major<<20)
    else:
        # Old-style
        major = dev >>8
        minor = dev & 0xff
    return (int(major), int(minor))

# ================= Block Device Tables =================

class BlkDev(object):
    def __init__(self, major, name, ops, bdevs):
        minors = sorted([m for m, bds in bdevs])
        self.major = major
        self.minors = minors
        self.name = name
        self.ops = ops
        self.opsname = addr2sym(self.ops)
        self.bdevs = bdevs
    def __str__(self):
        #prn = StringIO()
        return " %3d  %-11s   %x  <%s>" % \
              (self.major, self.name, self.ops, self.opsname)
    def shortstr(self):
        return "driver=%s, bdops=<%s>" % (self.name, self.opsname)



# This function returns a dictionary of (name, gendisk) keyed
# by major

@memoize_cond(CU_LIVE|CU_PYMOD)
def get_blkdevs():
    if (symbol_exists('all_bdevs')):
        return get_blkdevs_v2()
    else:
        return get_blkdevs_v1()

def get_blkdevs_v1():
    # static struct list_head bdev_hashtable[HASH_SIZE];
    # and heads are embedded in 'struct block_device'
    
    m_bdevs = {}
    out_bddev = {}      # a dict with bd_dev key
    for h in readSymbol("bdev_hashtable"):
        for s in readSUListFromHead(h, 'bd_hash',
             'struct block_device'):
            # We have one block_device structure per minor
            major, minor =  decode_devt(s.bd_dev)
            out_bddev[s.bd_dev] = s
            m_bdevs.setdefault(major, []).append((minor, s))
    
    pa = readSymbol('blkdevs')
    out = {}
    for major, s in enumerate(pa):
        if (not major in m_bdevs):
            continue
        bi = BlkDev(major, s.name, s.bdops, m_bdevs[major])
        out[major] = bi
    
    return out, out_bddev


def get_blkdevs_v2():
    # We want to group info per major, i.e. for each major we have
    # a list of all 'struct block_device' sorted by minor
    m_bdevs = defaultdict(list)
    out_bddev = {}      # a dict with bd_dev key
    for s in readSUListFromHead(sym2addr('all_bdevs'), 
           'bd_list', 'struct block_device'):
        major, minor =  decode_devt(s.bd_dev)
        out_bddev[s.bd_dev] = s
        m_bdevs[major].append((minor, s))
  
    # When we register a device, it can grab several major
    # numbers just in case - even if it does not need them
    # right now. See e.g. drivers/scsi/sd.c 
    # 'crash' prints all of them - but I think this is
    # a waste of time. For all practical purposes we are always
    # interested only in those devices that are physically
    # present (i.e. are in 'all_bdevs')
    out = {}
    for addr in readSymbol('major_names'):
        while(addr):
            s = Deref(addr)
            addr = s.next
            major = s.major
            if (not major in m_bdevs):
                #print ("major", major)
                continue
            bd = m_bdevs[major]
            # There are cases when device is registered but bd_disk=0
            # E.g. this happens when CD is not present in CD-ROM
            bd_disk = bd[0][1].bd_disk
            if (bd_disk):
               bdops = bd_disk.fops
               #print bd_disk.kobj.name
            else:
                bdops = 0
            out[major] = BlkDev(major, s.name, bdops, bd)
    return out, out_bddev

def print_blkdevs(v = 0):
    out, out_bddev = get_blkdevs()
    majors = sorted(out.keys())
    sep = '-' * 70
    if (v):
        print (sep)
    if (v > 1):
        devs = sorted(out_bddev.keys())
        for dev in devs:
            bd = out_bddev[dev]
            print (hexl(dev), bd)
            bd_holder = bd.bd_holder
            print (" ", bd.bd_openers, hexl(bd_holder))
            if (bd_holder):
                si = exec_gdb_command("x/i 0x%x" % bd_holder).rstrip()
                ss = exec_gdb_command("x/s 0x%x" % bd_holder).rstrip()
                print ("  ", si)
                print ("  ", ss)
    
    for major in majors:
        bi = out[major]
        #name, ops, bdevs = out[major]
        minors = bi.minors
        ops= bi.ops
        bdevs = bi.bdevs
        print (" %3d    %-14s   %x  <%s>" % \
              (major, bi.name, ops, addr2sym(ops)))
        if (v):
           print (textwrap.fill("\tMinors:" + str(minors), initial_indent=' ',
                  subsequent_indent=' ' *9))

           print ("\t", bdevs[0][1])

        if (v):
           print (sep)


# ================= Device-Mapper =======================
#
# To use these functions, you need a debuggable dm-mod loaded

#struct hash_cell {
    #struct list_head name_list;
    #struct list_head uuid_list;
    #char *name;
    #char *uuid;
    #struct mapped_device *md;
    #struct dm_table *new_map;
#}

def print_dm_devices(verbose = 0):
    sn = "struct hash_cell"
    # Check whether this struct info is present
    if (not struct_exists(sn)):
        loadModule("dm_mod")
    if (not struct_exists(sn)):
        print ("To decode DeviceMapper structures, you need a debuggable dm_mod")
        return
    nameb = readSymbol("_name_buckets")
    out = []
    off = member_offset(sn, "name_list")
    for b in nameb:
        for a in readListByHead(b):
            hc = readSU("struct hash_cell", a - off)
            out.append((hc.md.disk.first_minor, hc.name, hc.md.map))
    
    out.sort()      # sort on minor
    print (" ========== Devicemapper devices ============")
    for minor, name, dm in out:
        if (verbose):
           print ('-'*70)
        print ("%-40s  minor=%d" % (name, minor))
        if (verbose):
            print ("  ", dm)
            decode_dm_table(dm)

# Decode struct dm_table
#  list entries are embedded in
#struct dm_dev {
    #struct list_head list;
    #atomic_t count;
    #int mode;
    #struct block_device *bdev;
    #char name[16];
#}

def decode_dm_table(dm, verbose = 0):
    def round4k(s):
        return s/4096*4096
    devices = dm.devices   # This points to 'list' field in dm_dev
    # On newer kernels (e.g. 2.6.31)
    #
    # struct dm_dev_internal {
    #   struct list_head list;
    #   atomic_t count;
    #   struct dm_dev dm_dev;
    # }

    sn = "struct dm_dev"
    sn_i = "struct dm_dev_internal"
    off = member_offset(sn, "list")
    if (off == -1):
        off = member_offset(sn_i, "list") - member_offset(sn_i, "dm_dev")
    mtable, out_bddev = get_blkdevs()
    num_targets = dm.num_targets
    print (" -- %d targets" % num_targets)
    targets = dm.targets
    for nt in range(num_targets):
        target = targets + nt
        ttype = target.type
        t_begin = target.begin
        t_len = target.len
        t_end = t_begin + t_len - 1
        
        print ("  %d" % nt, target, ttype.name)
        print ("       | logical  sectors %d->%d" %(t_begin, t_end))
        if (ttype.name == "linear"):
            lc = readSU("struct linear_c", target.private)
            lc_begin = lc.start
            lc_end = lc.start + t_len -1
            print ("       | physical sectors %d->%d" %(lc_begin, lc_end))
            print ("       |    device used", lc.dev)
    
    print (" -- Block Devices Used By This Mapping")
    for a in readListByHead(devices):
        dmdev = readSU(sn, a - off)
        major, minor = decode_devt(dmdev.bdev.bd_dev)
        print ("     ", dmdev, "major=%-3d minor=%-3d" % (major, minor))
        print ("\t   ", mtable[major].shortstr())


# ================ gendisk stuff =============================
# Get the list of (dev, gendisk) sorted by dev

def get_gendisks():
    out = []
    # We do not process other gets yet (e.g. ata_probe)
    good_gets = sym2alladdr("exact_match")
    for pm in readSymbol("bdev_map").probes:
        for p in readStructNext(Deref(pm), "next"):
            data = p.data
            dev = p.dev
            if (data and long(p.get) in good_gets):
                #print '--', hexl(dev), p
                gd = readSU("struct gendisk", data)
                out.append((dev, gd))

    out.sort()
    return out

# Print disk statistics
def print_disk_stats(gd):
    ptr = gd.dkstats
    # gd.dkstats is a per-cpu pointer
    for cpu in range(sys_info.CPUS):
        pcpu = percpu_ptr(ptr, cpu)
        print ("  ", cpu, pcpu)
        #printObject(pcpu)
        
        
# Print gendisk structures with some checking.
# If v=0, print errors only
__re_good_diskname = re.compile(r'^[-\w:/]+$')
def print_gendisk(v = 1):
    try:
        gdlist = get_gendisks()
    except TypeError:
        if (v):
            print ("print_gendisk is not implemented for this kernel yet")
        return
    # To get block_device based on dev_t
    dummy, bd_devs = get_blkdevs()
    #
    for dev, gd in gdlist:
        if (v > 1):
            print ('#' * 50)
        disk_name = gd.disk_name
        # Check whether name is alphanum
        if (not __re_good_diskname.match(disk_name)):
            disk_name = '???'
        #kname = gd.kobj.name
        openname = None
        try:
            owner = gd.fops.owner
            badfops = False
        except crash.error:
            badfops = True
        
        try:
            openptr = gd.fops.open
            if (openptr):
                openname = addr2sym(openptr)
        except crash.error:
            pass
        
        if (v):
           print  ("  %12s dev=0x%x" % (disk_name, dev), gd, openname)
        if (badfops):
            print (ERROR, gd, "corrupted fops, disk_name=%s dev=0x%x"% \
                   (disk_name, dev))
        outparts = []
        # < 2.6.28
        # struct hd_struct **part;
        # 2.6.28
        #    struct disk_part_tbl *part_tbl;
        #    struct hd_struct part0;
        # and
        # struct disk_part_tbl {
        #     struct rcu_head rcu_head;
        #     int len;
        #     struct hd_struct *part[];
        #  };
        try:
            np = gd.part_tbl.len
            tbl =  gd.part_tbl.part
        except KeyError:
            np = gd.minors - 1
            tbl = gd.part
        for i in range(np):
            #print("tbl", repr(tbl))
            hd = tbl[i]
            #print("hd", repr(hd))
            try:
                if (hd and hd.Deref.nr_sects):
                    if (v):
                        print ("\t\t", i, Deref(hd))
            except crash.error:
                outparts.append(i)
                if (v):
                    print (ERROR, "corrupted", Deref(hd))
        if (outparts):
            print (ERROR, gd, "corrupted part list", outparts)
        
        if (v < 2):
            continue
        
        
