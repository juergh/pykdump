#!/usr/bin/env python
#
#
# Copyright (C) 2007,2012 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007,2012 Hewlett-Packard Co., All rights reserved.
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
This is the parser for 'kmem' crash command output.
'''

import re
try:
    from pyparsing import *
except ImportError:
    from pykdump.pyparsing import *



# NODE N
# ZONE SkipTo(int) SkipTo(AREA) SkipTo("\n") Group(int + intl + Suppress(hex) + blocks + pages)

def actionToInt(s,l,t):
    return int(t[0], 0)

def actionToHex(s,l,t):
    return int(t[0], 16)

def stripQuotes( s, l, t ):
    return [ t[0].strip('"') ]

Cid = Word(alphas+"_", alphanums+"_")

dquote = Literal('"')

noprefix_hexval =  Word(hexnums).setParseAction(actionToHex)
hexval = Combine("0x" + Word(hexnums))
decval = Word(nums+'-', nums).setParseAction(actionToInt)
intval = hexval | decval
size = Word(nums, alphanums)
zname = Word(alphas, alphanums+"-_")


AREA = Group(decval + size + noprefix_hexval + decval + decval)
ZONE = Suppress("ZONE") +  Suppress(SkipTo("\n")) + intval + zname + \
       Suppress(SkipTo("PAGES", include=True)) + OneOrMore(AREA)
NODE = Suppress(Optional("NODE") + SkipTo("ZONE")) + OneOrMore(Group(ZONE))

text = '''
NODE
  0
ZONE  NAME        SIZE    FREE  MEM_MAP   START_PADDR  START_MAPNR
  0   DMA         4096    2926  c100002c       0            0
AREA    SIZE  FREE_AREA_STRUCT  BLOCKS  PAGES
  0       4k      c03abdd8           4      4
  1       8k      c03abde4           3      6
  2      16k      c03abdf0           5     20
  3      32k      c03abdfc           2     16
  4      64k      c03abe08           4     64
  5     128k      c03abe14           2     64
  6     256k      c03abe20           1     64
  7     512k      c03abe2c           1    128
  8    1024k      c03abe38           0      0
  9    2048k      c03abe44           1    512
 10    4096k      c03abe50           2   2048

ZONE  NAME        SIZE    FREE  MEM_MAP   START_PADDR  START_MAPNR
  1   Normal    225280   12698  c103c02c    1000000        4096
AREA    SIZE  FREE_AREA_STRUCT  BLOCKS  PAGES
  0       4k      c03ad0d8       12698  12698
  1       8k      c03ad0e4           0      0
  2      16k      c03ad0f0           0      0
  3      32k      c03ad0fc           0      0
  4      64k      c03ad108           0      0
  5     128k      c03ad114           0      0
  6     256k      c03ad120           0      0
  7     512k      c03ad12c           0      0
  8    1024k      c03ad138           0      0
  9    2048k      c03ad144           0      0
 10    4096k      c03ad150           0      0

ZONE  NAME        SIZE    FREE  MEM_MAP   START_PADDR  START_MAPNR
  2   HighMem   3948543  2252018  c1d2002c    38000000      229376
AREA    SIZE  FREE_AREA_STRUCT  BLOCKS  PAGES
  0       4k      c03ae3d8       11842  11842
  1       8k      c03ae3e4       90912 181824
  2      16k      c03ae3f0      106494 425976
  3      32k      c03ae3fc       69869 558952
  4      64k      c03ae408       32361 517776
  5     128k      c03ae414        7534 241088
  6     256k      c03ae420        2637 168768
  7     512k      c03ae42c         631  80768
  8    1024k      c03ae438         152  38912
  9    2048k      c03ae444          27  13824
 10    4096k      c03ae450          12  12288

nr_free_pages: 2267642  (verified)
'''

# One Node only at this moment
def parse_kmemf(text):
    return NODE.parseString(text).asList()

# Format and print info from parsed output

def print_Zone(zone):
    print ("\n   == Zone:%s ==" % zone[1])
    print ("")
    print ("AREA    SIZE  FREE_AREA_STRUCT     BLOCKS  PAGES")
    print ("----    ----  ------------------   ------  -----")
    for area, size, f, blocks, pages in zone[2:]:
        print ("%3d %8s  0x%016x    %5d  %5d" % (area, size, f, blocks, pages))

def check_kmemf(nodekmem):
    Normal = nodekmem[1]
    warn_8k = True
    warn_32k = True

    for area, size, f, blocks, pages in Normal[2:]:
        sizekb = int(size[:-1])
        if (sizekb >= 8 and blocks > 1):
            warn_8k = False
        if (sizekb >= 32 and blocks > 1):
            warn_32k = False
        #print "%2d  %6d %6d" % (area, sizekb, blocks)

    print (warn_8k, warn_32k)

# 'kmem -z' parser
'''
NODE: 0  ZONE: 0  ADDR: ffff81000001a000  NAME: "DMA"
  SIZE: 4096  PRESENT: 2623  MIN/LOW/HIGH: 3/3/4
  NR_ACTIVE: 0  NR_INACTIVE: 0  FREE: 2720
  VM_STAT:
          NR_ANON_PAGES: 0
         NR_FILE_MAPPED: 1
          NR_FILE_PAGES: 0
                NR_SLAB: 0
           NR_PAGETABLE: 0
          NR_FILE_DIRTY: 0
           NR_WRITEBACK: 0
        NR_UNSTABLE_NFS: 0
              NR_BOUNCE: 0
               NUMA_HIT: 1
              NUMA_MISS: 0
           NUMA_FOREIGN: 0
    NUMA_INTERLEAVE_HIT: 0
             NUMA_LOCAL: 1
             NUMA_OTHER: 0
  ALL_UNRECLAIMABLE: no  PAGES_SCANNED: 0  

NODE: 0  ZONE: 1  ADDR: ffff81000001ab00  NAME: "DMA32"
    ...

NODE: 0  ZONE: 3  ADDR: ffff81000001c100  NAME: "HighMem"
  [unpopulated]
'''
    
if ( __name__ == '__main__'):
    nodekmem = parse_kmemf(text)
    check_kmemf(nodekmem)
    print_Zone(nodekmem[1])
