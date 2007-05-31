#!/usr/bin/env python

# Time-stamp: <07/05/31 16:32:53 alexs>

# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.

# 1st-pass dumpanalysis

#from pykdump.API import *


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

all = open("bta.out", "r").read()

from pykdump.BTstack import exec_bt
rc = exec_bt('foreach bt')
#exec_bt(text = all)

