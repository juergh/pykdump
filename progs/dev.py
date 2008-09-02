#!/usr/bin/env python
# Time-stamp: <08/03/28 13:59:10 alexs>

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.

from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump import Dev

import sys

def printdevs():
    #dump_chrdevs()
    dump_blkdevs()
    #dump_mounts()
    
def dump_mounts():
    for vfsmount, superblk, fstype, devname, mnt in getMount():
	superblock = readSU("struct super_block", superblk)
	#s_bdev = superblock.s_bdev
	#if (s_bdev):
	   #print fstype, mnt, superblock.s_bdev.bd_disk
        s_op = superblock.s_op
	print mnt
	if (s_op):
	    # Check whether all pointers are reasonable
	    print s_op

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



if ( __name__ == '__main__'):
    #Dev.print_blkdevs(1)
    print "Start"
    print "mod=<%s>" % exec_crash_command("mod")
    print "After"
    dump_mounts()

