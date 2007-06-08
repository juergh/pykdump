#!/usr/bin/env python

# Time-stamp: <07/06/08 11:43:03 alexs>

# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.

# 1st-pass dumpanalysis

from pykdump.API import *

import time, os

import pprint
pp = pprint.PrettyPrinter(indent=4)


spid = 'PID: 8440   TASK: f621e130  CPU: 3   COMMAND: "bash"'
sf1 = ' #0 [f7f0ff7c] smp_call_function_interrupt at c0116c4a'
sf2 = ' #7 [f2035f20] error_code (via page_fault) at c02d1ba9'

sall = '''PID: 0      TASK: c031ea80  CPU: 0   COMMAND: "swapper"
 #0 [c038ffa4] smp_call_function_interrupt at c0116c4a
 #1 [c038ffac] call_function_interrupt at c02d1ae9
    EAX: 00000000  EBX: c038f000  ECX: 00000000  EDX: 00000000  EBP: 0048c007
    DS:  007b      ESI: 00000000  ES:  007b      EDI: c03c4120
    CS:  0060      EIP: c01040e5  ERR: fffffffb  EFLAGS: 00000246
 #2 [c038ffe0] mwait_idle at c01040e5
 #3 [c038ffe8] cpu_idle at c010409b
'''

sall1 = '''PID: 0      TASK: c031ea80  CPU: 0   COMMAND: "swapper"
 #0 [c038ffa4] smp_call_function_interrupt at c0116c4a
 #1 [c038ffac] call_function_interrupt at c02d1ae9
 #2 [c038ffe0] mwait_idle at c01040e5
 #3 [c038ffe8] cpu_idle at c010409b
'''


#rc = PID_line.parseString(spid)
#print rc

#rc = FRAME_start.parseString(sf1)
#print rc

#rc = FRAME_start.parseString(sf2)
#print rc


#rc = PID.parseString(sall)
#pp.pprint(rc.asList())

all = open("bt1.out", "r").read()
#print all

from pykdump.BTstack import exec_bt
t0 = os.times()[0]

btsl = exec_bt('foreach bt')
#btsl = exec_bt(text = all)
t1 = os.times()[0]

print "%7.2f s to parse, %d entries" % (t1 - t0, len(btsl))

import re
for bts in btsl:
    if bts.hasfunc('auditf'):
        print bts
