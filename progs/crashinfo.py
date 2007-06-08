#!/usr/bin/env python

# Time-stamp: <07/06/08 13:37:19 alexs>

# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.

# 1st-pass dumpanalysis

from pykdump.API import *

import time, os

import pprint

all = open("bt1.out", "r").read()
#print all

from pykdump.BTstack import exec_bt
t0 = os.times()[0]

btsl = exec_bt('foreach bt')
#btsl = exec_bt(text = all)
t1 = os.times()[0]

print "%7.2f s to parse, %d entries" % (t1 - t0, len(btsl))

for bts in btsl:
    if bts.hasfunc('sys_select'):
        print bts
