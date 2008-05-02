# module LinuxDump.Dev
#
# Time-stamp: <08/03/05 15:51:52 alexs>
#
# Copyright (C) 2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2008 Hewlett-Packard Co., All rights reserved.
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
This is a package providing generic access to block devices
'''

from pykdump.API import *

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
    for h in readSymbol("bdev_hashtable"):
	for s in readSUListFromHead(h, 'bd_hash',
	     'struct block_device'):
	    # We have one block_device structure per minor
	    major, minor =  decode_devt(s.bd_dev)
	    m_bdevs.setdefault(major, []).append((minor, s))
    
    pa = readSymbol('blkdevs')
    out = {}
    for major, s in enumerate(pa):
	if (not m_bdevs.has_key(major)):
	    continue
	out[major] = (s.name, s.bdops, m_bdevs[major])
    
    return out


def get_blkdevs_v2():
    # We need unique values only, so we use a dictionary to achieve this
    m_bdevs = {}
    for s in readSUListFromHead(sym2addr('all_bdevs'), 
	   'bd_list', 'struct block_device'):
	major, minor =  decode_devt(s.bd_dev)
	m_bdevs.setdefault(major, []).append((minor, s))
  
    # When we register a device, it can grab several major
    # numbers just in case - even if it does not need them
    # right now. See e.g. drivers/scsi/sd.c 
    # 'crash' prints all of them - but I think this is
    # a waste of time. For all practical purposes we are always
    # interested only in those devices that are physically
    # present (i.e. are in 'all_bdevs')
    out ={}
    for addr in readSymbol('major_names'):
        while(addr):
	    s = Deref(addr)
	    addr = s.next
	    major = s.major
            if (not m_bdevs.has_key(major)):
		continue
	    bd = m_bdevs[major]
	    # There are cases when device is registered but bd_disk=0
	    # E.g. this happens when CD is not present in CD-ROM
	    bd_disk = bd[0][1].bd_disk
	    if (bd_disk):
	       bdops = bd_disk.fops
	       print bd_disk.kobj.name
	    else:
		bdops = 0
            out[major] = (s.name, bdops, bd)
    return out

def print_blkdevs(v = 0):
    out = get_blkdevs()    
    majors = out.keys()
    majors.sort()
    for major in majors:
	name, ops, bdevs = out[major]
	minors = [m for m, bds in bdevs]
	minors.sort()
        print " %3d      %-11s   %x  <%s>" % \
              (major, name, ops, addr2sym(ops))
	if (v):
	   print "\tMinors:", minors
	   print "\t", bdevs[0][1]


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

def print_dm_devices():
    nameb = readSymbol("_name_buckets")
    out = []
    sn = "struct hash_cell"
    off = member_offset(sn, "name_list")
    for b in nameb:
	for a in readListByHead(b):
	    hc = readSU("struct hash_cell", a - off)
	    out.append((hc.md.disk.first_minor, hc.name, hc.md.map))
    
    out.sort()      # sort on minor
    for minor, name, dm in out:
	print "%-40s  minor=%d" % (name, minor)
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

def decode_dm_table(dm):
    devices = dm.devices   # This points to 'list' field in dm_dev
    sn = "struct dm_dev"
    off = member_offset(sn, "list")
    for a in readListByHead(devices):
	dmdev = readSU(sn, a - off)
	print "\t", dmdev.name, "\t", dmdev