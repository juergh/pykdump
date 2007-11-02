#!/usr/bin/env python
#
# First-pass dumpanalysis
#
# Time-stamp: <07/10/26 11:22:27 alexs>

# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.

# 1st-pass dumpanalysis

from pykdump.API import *
from LinuxDump.BTstack import exec_bt, bt_summarize, bt_mergestacks
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
    for cpu, stack in enumerate(bta):
        print "      -- CPU#%d --" % cpu, stack
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
    if (len(node) < 2):
        # IA64 woth 2.6 kernels
	Normal = node[0]
    else:
        Normal = node[1]
    warn_8k = True
    warn_32k = True

    # We issue a warning if there is less than 2 blocks available.
    # We are interested in blocks up to 32Kb mainly
    for area, size, f, blocks, pages in Normal[2:]:
        sizekb = int(size[:-1])

        # 8-Kb chunks are needed for task_struct
        if (sizekb == 8 and blocks > 1):
            warn_8k = False
        if (sizekb > 8 and blocks > 0):
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
    elif (warn_32k):
        print WARNING, "fragmentation: 32Kb"

    if (warn_8k or warn_32k):
        print_Zone(Normal)
    #pp.pprint(node)
    
# Check how the dump has been triggered
def dump_reason(dmesg):
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
    func1 = 'sysrq_handle|handle_sysrq|netconsole'
    trigger = re.compile('vfs_write|sys_write')
    kbd  = re.compile('keyboard_interrupt')
    netconsole = re.compile('netconsole')
    res = [bts for bts in btat if bts.hasfunc(func1)]
    if (res):
	# Now check whether we used keyboard or sysrq-trigger
	print "Dump has been initiated: with sysrq"
	if (test(res, trigger)):
	    print "\t- programmatically (via sysrq-trigger)"
	elif (test(res, kbd)):
	    print "\t- via keyboard"
	elif (test(res, netconsole)):
	    print "\t- via netconsole"
	else:
	    print "\t- ???"
	if (test(btat, "disk_dump")):
	    print "\t- using diskdump"
	elif (ifnetdump(dmesg)):
	    print "\t- using netdump"
	else:
	    print "\t- using unknown dump method"
	if (verbose):
	    for bts in res:
		print bts
    else:
        # This seems to be a real panic - search for BUG/general protection
        res = [bts for bts in btat if bts.hasfunc('die')]
        if (res):
            print "Dump was triggered by kernel"
            if (test(res, "general_protection")):
                print "\t- General Protection Fault"
	
# Check Load Averages
def check_loadavg():
    avgf = []
    avgstr = sys_info["LOAD AVERAGE"]
    for avgs in avgstr.split(','):
	avgf.append(float(avgs))
    avg1, avg5, avg15 = avgf
    if (avg1 > 29 or avg5 > 29):
	print WARNING, "High Load Averages:", avgstr
    
def check_auditf():
    global btsl
    if (not btsl):
        btsl = exec_bt('foreach bt')
    func1 = 'auditf'
    func2 = 'rwsem_down'
    res = [bts for bts in btsl
           if bts.hasfunc(func1) and bts.hasfunc(func2)]
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

def check_network():
    import LinuxDump.inet.netdevice as netdevice
    offset = member_offset("struct net_device", "next")
    dev_base = readSymbol("dev_base")
    jiffies = readSymbol("jiffies")
    for a in readList(dev_base, offset):
        dev = readSU("struct net_device", a)
	if_up = dev.flags & netdevice.IFF_FLAGS.IFF_UP
	if (not if_up):  continue
	# Last RX and TX times in jiffies. Check this only for devices
	# that are UP
	last_rx = (jiffies - dev.last_rx)/HZ
        trans_start = (jiffies - dev.trans_start)/HZ
	print dev.name, last_rx, trans_start
 

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
	active = rq.active
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
    btat = exec_bt('bt -at')
else:
    bta = []
    btat = []

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

op.add_option("--ext3", dest="ext3", default = 0,
		action="store_true",
		help="Print EXT3 info.")

op.add_option("--filelock", dest="filelock", default = 0,
		action="store_true",
		help="Print filelock info.")

op.add_option("--stacksummary", dest="stacksummary", default = 0,
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

if (o.ext3):
    from LinuxDump.fs.ext3 import showExt3

    showExt3()
    sys.exit(0)

if (o.filelock):
    from LinuxDump.flock import print_locks

    print_locks()
    sys.exit(0)
if (o.stacksummary):
    from LinuxDump.Tasks import TaskTable
    if (not btsl):
        btsl = exec_bt('foreach bt')
	tt = TaskTable()
    #bt_summarize(btsl)
    bt_mergestacks(btsl, reverse=True, tt=tt)
    sys.exit(0)
    
HZ = sys_info.HZ

print_basics()
dump_reason(dmesg)
check_loadavg()
check_mem()
check_auditf()
check_runqueues()
#check_network()
