#!/usr/bin/env python
# Time-stamp: <08/03/28 13:59:10 alexs>

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.

from pykdump.API import *

from LinuxDump.fs import *

import sys

def printdevs():
    #dump_chrdevs()
    #dump_blkdevs()
    dump_mounts()
    
def dump_mounts():
    for vfsmount, superblk, fstype, devname, mnt in getMount():
	superblock = readSU("struct super_block", superblk)
	s_bdev = superblock.s_bdev
	if (s_bdev):
	   print fstype, mnt, superblock.s_bdev.bd_disk
        

def dump_chrdevs():
    pa = readSymbol('chrdevs')
    print 'CHRDEV    NAME         OPERATIONS'

    # Depending on whether we have char_device_struct, we proceed
    # in a different way
    if (struct_exists('char_device_struct')):
        for addr in pa:
            while (addr):
                s = readSU('struct char_device_struct', addr)
                major = s.major
                name = s.name
                addr = s.next
                print "%3d       %-11s" % (major, name)
    else:
        for major, s in enumerate(pa):
            print repr(s)
            continue
            ops = s.fops
            if (ops == 0):
                continue
            name = s.name
            print " %3d      %-11s   %x  <%s>" % \
                  (major, name, ops, addr2sym(ops))

def dump_blkdevs():
    print '\nBLKDEV    NAME         OPERATIONS'
    if (symbol_exists('all_bdevs')):
        dump_blkdevs_v2()
    else:
        dump_blkdevs_v1()

def dump_blkdevs_v1():
    pa = readSymbol('blkdevs')
    for major, s in enumerate(pa):
        ops = s.bdops
        if (ops == 0):
            continue
        name = s.name
        print " %3d      %-11s   %x  <%s>" % \
              (major, name, ops, addr2sym(ops))
    
    
def dump_blkdevs_v2():
    # We need unique values only, so we use a dictionary to achieve this
    u = {}
    for s in readSUListFromHead(sym2addr('all_bdevs'), 'bd_list', 'struct block_device'):
        u[s.bd_disk] = 1
    
    # Get gendisk structures
    fops ={}
    for addr in u.keys():
        if (addr==0):
            print "ERROR: addr=0 in all_bdevs"
            continue
        s = readSU('struct gendisk', addr)
        fops[s.major] = s.fops

    for addr in readSymbol('major_names'):
        while(addr):
            s = readSU('struct blk_major_name', addr)
            if (fops.has_key(s.major)):
                fopsaddr = fops[s.major]
                sfops = '0x%x\t <%s>' % (fopsaddr, addr2sym(fopsaddr))
            else:
               sfops = ' (unknown)'
            # As 'name' is a chararray, we might need to strip after \0
            name = s.name#.split('\0')[0]
            print "%3d       %-11s  %-11s" % (s.major, name, sfops)
            addr = s.next


if ( __name__ == '__main__'):
    printdevs()

