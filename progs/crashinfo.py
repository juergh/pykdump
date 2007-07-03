#!/usr/bin/env python
#
# First-pass dumpanalysis
#
# Time-stamp: <07/07/03 14:54:30 alexs>

# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.

# 1st-pass dumpanalysis

from pykdump.API import *
from LinuxDump.BTstack import exec_bt
from LinuxDump.kmem import parse_kmemf, print_Zone

import sys
from StringIO import StringIO
from optparse import OptionParser

WARNING = "+++WARNING+++"


# The type of the dump. We should check different things for real panic and
# dump created by sysrq_handle

Panic = True

# Parsed output of 'foreach bt' (this is rather time-consuming)
btsl = None

#print "%7.2f s to parse, %d entries" % (t1 - t0, len(btsl))

def printHeader(format, *args):
    if (len(args) > 0):
	text = format % args
    else:
	text = format
    lpad = (77-len(text))/2
    print "\n", '-' * lpad, text, '-' * lpad

def print_basics():
    print "         *** Crashinfo v0.1 ***"
    print ""
    if (quiet):
        return
    
    print exec_crash_command("sys")
    print ""

def check_mem():
    if (not quiet):
	printHeader("Memory Usage (kmem -i)")
        kmemi = exec_crash_command("kmem -i")
        print kmemi
        print ""

    # Checking for fragmentation (mostly useful on 32-bit systems)
    kmemf = exec_crash_command("kmem -f")
    node = parse_kmemf(kmemf)
    Normal = node[1]
    warn_8k = True
    warn_32k = True

    for area, size, f, blocks, pages in Normal[2:]:
        sizekb = int(size[:-1])
        if (sizekb >= 8 and blocks > 1):
            warn_8k = False
	    
	# 32Kb chunks are needs for loopback as it has high MTU
        if (sizekb == 32 and blocks > 1):
            warn_32k = False
        if (sizekb > 32 and blocks > 0):
            warn_32k = False

	#print "%2d  %6d %6d" % (area, sizekb, blocks)
    if (warn_8k or warn_32k):
        printHeader("Memory Fragmentation (kmem -f)")
    if (warn_8k):
        print WARNING, "fragmentation: 8Kb"
    if (warn_32k):
        print WARNING, "fragmentation: 32Kb"
    if (warn_8k or warn_32k):
        print_Zone(Normal)
    #pp.pprint(node)
    
# Check how the dump has been triggered
def dump_reason(btsl, dmesg):
    global Panic
    def test(l, t):
	if (len([bts for bts in l if bts.hasfunc(t)])):
	    return True
	else:
	    return False
    def ifnetdump(dmesg):
	re_netdump = re.compile('netdump activated', re.M)
	if (re_netdump.search(dmesg)):
	    return True
	else:
	    return False

    if (quiet):
        return
	
    printHeader("How This Dump Has Been Created")
    if (sys_info.livedump):
	print "Running on a live kernel"
        return
    func1 = re.compile('sysrq_handle|handle_sysrq|netconsole')
    trigger = re.compile('vfs_write|sys_write')
    kbd  = re.compile('keyboard_interrupt')
    netconsole = re.compile('netconsole')
    res = [bts for bts in btsl if bts.hasfunc(func1)]
    if (res):
	# Now check whether we used keyboard or sysrq-trigger
	print "Dump has been initiated: with sysrq"
	if (test(res, trigger)):
	    print "\t- programmatically (via sysrq-trigger)"
	elif (test(res, kbd)):
	    print "\t-via keyboard"
	elif (test(res, netconsole)):
	    print "\t- via netconsole"
	else:
	    print "\t- ???"
	if (test(res, "disk_dump")):
	    print "\t- using diskdump"
	elif (ifnetdump(dmesg)):
	    print "\t- using netdump"
	else:
	    print "\t- using unknown dump method"
	if (verbose):
	    for bts in res:
		print bts
	
      
def check_auditf():
    global btsl
    btsl = exec_bt('foreach bt')
    func1 = re.compile('auditf')
    func2 = re.compile('rwsem_down')
    res = [bts for bts in btsl if bts.hasfunc(func1, func2)]
    if (not res):
	return False
    print WARNING, "%d threads halted by auditd" % len(res)
    if (verbose):
	for bts in res:
	    print bts

def check_sysctl():
    from LinuxDump import sysctl
    ctbl = sysctl.getCtlTables()
    names = ctbl.keys()
    names.sort()

    for n in names:
        dall = sysctl.getCtlData(ctbl[n])
        print n.ljust(45), dall

def check_runqueues():
    from LinuxDump import percpu
    from LinuxDump.Tasks import TaskTable, Task, getRunQueues

    if (not quiet):
        printHeader("Scheduler Runqueues (per CPU)")
    rloffset = member_offset("struct task_struct", "run_list")
    # Whether all 
    RT_hang = True
    for cpu, rq in enumerate(getRunQueues()):
	RT_count = 0
	# Print Active
	active = rq.Deref.active
	if (not quiet):
	   print ' ---- CPU#%d ---  %s' % (cpu, str(rq))
	#print active
	#print active.queue
	for i, pq in enumerate(active.queue):
	    #print hexl(Addr(pq))
	    talist = readList(Addr(pq), inchead = False)
	    l = len(talist)
	    if (l and not quiet):
	       print "    prio=%-3d len=%d" % (i, l)
	    for ra in talist:
		ta = ra - rloffset
		ts = readSU("struct task_struct", ta)
		if (ts.policy != 0):
		    RT_count += 1
		if (verbose):
		    print "\tTASK_STRUCT=0x%x  policy=%d CMD=%s"\
		          %(ta, ts.policy, ts.comm)
	if (RT_count == 0):
	    RT_hang = False
	else:
	    print " %d Real-Time processes on this CPU" % RT_count
    if (RT_hang):
	print WARNING, "all CPUs are busy running Real-Time processes"
	
if (not sys_info.livedump):
    bta = exec_bt('bt -a')
else:
    bta = None

dmesg = exec_crash_command("log")


op =  OptionParser()

op.add_option("-v", dest="Verbose", default = 0,
		action="store_true",
		help="verbose output")

op.add_option("-q", dest="Quiet", default = 0,
		action="store_true",
		help="quiet mode - print warnings only")


op.add_option("--sysctl", dest="sysctl", default = 0,
		action="store_true",
		help="Print sysctl info.")

(o, args) = op.parse_args()


if (o.Verbose):
    verbose = 1
else:
    verbose =0

if (o.Quiet):
    quiet = 1
else:
    quiet =0


t1 = os.times()[0]

# Non-standard options (those that stop normal tests)
if (o.sysctl):
    check_sysctl()
    sys.exit(0)
    

print_basics()
dump_reason(bta, dmesg)
check_mem()
check_auditf()
check_runqueues()
