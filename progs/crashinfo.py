#!/usr/bin/env python
#
# First-pass dumpanalysis
#
# Time-stamp: <08/03/12 14:49:02 alexs>

# Copyright (C) 2007-2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007-2008 Hewlett-Packard Co., All rights reserved.

# 1st-pass dumpanalysis

from pykdump.API import *
from LinuxDump.BTstack import exec_bt, bt_summarize, bt_mergestacks
from LinuxDump.kmem import parse_kmemf, print_Zone
from LinuxDump.Tasks import TaskTable, Task, tasksSummary, getRunQueues
from LinuxDump.inet import summary
import LinuxDump.inet.netdevice as netdevice
from LinuxDump import percpu



from LinuxDump import percpu


import sys
from stat import *
from StringIO import StringIO
from optparse import OptionParser

WARNING = "+++WARNING+++"


# The type of the dump. We should check different things for real panic and
# dump created by sysrq_handle

Panic = True


# Parsed output of 'foreach bt' (this is rather time-consuming)
btsl = None
def get_btsl():
    global btsl
    if (not btsl):
        btsl = exec_bt('foreach bt')
    return btsl

Fast = False

tt = None
def get_tt():
    global tt
    if (not tt):
        tt = TaskTable()
    return tt

#print "%7.2f s to parse, %d entries" % (t1 - t0, len(btsl))

def printHeader(format, *args):
    if (len(args) > 0):
	text = format % args
    else:
	text = format
    tlen = len(text)
    lpad = (73-tlen)/2
    print ""
    uh = ' ' + ' '*lpad + '+' + '-'*(tlen+2) + '+'
    print uh
    print '>' + '-' * lpad + '| ' + text + ' |' +  '-' * lpad + '<'
    print uh
    print ""

def print_basics():
    print "         *** Crashinfo v0.2 ***"
    print ""
    if (not sys_info.livedump):
	# Check whether this is a partial dump and if yes,
	# compare the size of vmcore and RAM
	# If sizeof(vmcore) < 25% sizeof(RAM), print a warning
	dfile = sys_info.DUMPFILE
	if (dfile.find("PARTIAL DUMP") != -1):
	    dfile = dfile.split()[0]
	    # Convert memory to Mb
	    (im, sm) = sys_info.MEMORY.split()
	    ram = float(im)
	    if (sm == "GB"):
		ram *= 1024
	    # Get vmcore size
	    sz = os.stat(dfile)[ST_SIZE]/1024/1024
	    if (ram > sz *4):
	       print WARNING,
	       print "PARTIAL DUMP with size(vmcore) < 25% size(RAM)"
    if (quiet):
        return

    print exec_crash_command("sys")
    if (len(bta) > 0):
	printHeader("Per-cpu Stacks ('bt -a')")
    
	for cpu, stack in enumerate(bta):
	    print "      -- CPU#%d --" % cpu, stack
	    print ""

def print_dmesg():
    if (verbose):
        printHeader("dmesg buffer")
        print dmesg
    else:
        printHeader("Last 40 lines of dmesg buffer")
        print "\n".join(dmesg.splitlines()[-40:])
    
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
    res = [bts for bts in bta if bts.hasfunc(func1)]
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
	if (test(bta, "disk_dump")):
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
        res = [bts for bts in bta if bts.hasfunc('die')]
        if (res):
            print "Dump was triggered by kernel"
            if (test(res, "general_protection")):
                print "\t- General Protection Fault"
	
def stackSummary():
    btsl = get_btsl()
    tt = get_tt()
    #bt_summarize(btsl)
    bt_mergestacks(btsl, reverse=True, tt=tt)
    
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
    btsl = get_btsl()
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
    ctbl = sysctl.getCtlTables()
    names = ctbl.keys()
    names.sort()

    for n in names:
        dall = sysctl.getCtlData(ctbl[n])
        print n.ljust(45), dall

 
# Check whether active (bt -a) tasks are looping
def check_activetasks():

    tt = get_tt()
    basems = tt.basems
    for cpu, stack in enumerate(bta):
	pid = stack.pid
	mt = tt.getByTid(pid)
	ran_ms_ago = basems - mt.last_ran
	if (ran_ms_ago > 10 * 1000):
	    print ""
	    print WARNING, "possible looping, CPU=%d ran_ago=%d ms" \
	       % (cpu, ran_ms_ago)
	    print stack


# Check some frequently-used spinlocks

re_locks = re.compile(r'^\w+\s+\(D\)\s+(\w+)\s*$')
def check_spinlocks():
    sn = "spinlock_t"
    structSetAttr(sn, "slock", ["raw_lock.slock", "lock"])
    
    # Locks we are do not care to print
    ignore_locks = ("die_lock", "oops_lock")
    
    # BKL is implemented in a different way
    BKL = 1
    if (sym2addr("kernel_flag_cacheline") != 0):
	BKL = readSymbol("kernel_flag_cacheline").lock.slock
    if (BKL != 1):
	print WARNING, "BKL=%d" % BKL
   
    # Get a list of all global symbols (D) with the names like *_lock
    lock_list = []
    for l in exec_crash_command("sym -q _lock").splitlines():
	m = re_locks.match(l)
	#print "<%s>" % l, m
	if (m):
	    ln = m.group(1)
	    if (ln in ignore_locks):
		continue
	    lock_list.append(ln)
	    
    for ln in lock_list:
	# We cannot be sure that this is lock_t
	# (e.g.this can be rwlock_t)
	try:
	    lv = readSymbol(ln).slock
	    if (lv != 1):
		print WARNING, "Lock %s is held, lock=%d" % (ln, lv)
	except:
	    pass


def check_runqueues():

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
	

# Do some basic network subsystem check
def check_network():
    if (not quiet):
        printHeader("Network Status Summary")
    summary.TCPIP_Summarize(quiet)
    summary.IF_Summarize(quiet)

# The argument can be 'all' (all threads), integer (pid or tid) or
# syscall name 'e.g. select'
def decode_syscalls(arg):
    from LinuxDump.syscall import decode_Stacks
    # Check argumenttype and decide what to do
    try:
	pid = int(arg)
	bt = exec_bt('bt %d' % pid)
    except ValueError:
	# This is not an integer arg
	bt = exec_bt('foreach bt')
        # Leave only those that have the specified syscall
        def test(stack, bt):
            if (not stack.hasfunc(r"^(system_call|sysenter_entry)$")):
                return False
            if (arg =='all' or stack.hasfunc('sys_' + arg)):
                return True
            else:
                return False
        bt = [s for s in bt if test(s, arg)]
    decode_Stacks(bt)
 
    sys.exit(0)
    

# Decode keventd_wq

def decode_eventwq():
    keventd_wq = readSymbol("keventd_wq")

    # On older (e.g. 2.6.9) kernels we use
    # cwq = keventd_wq->cpu_wq + cpu;
    # On newer ones,
    # cwq = per_cpu_ptr(keventd_wq->cpu_wq, cpu);

    cpu_wq = keventd_wq.cpu_wq
    per_cpu = keventd_wq.hasField("freezeable")
    # CPU-specific 
    for cpu in range(0, sys_info.CPUS):
        if (per_cpu):
            cwq = percpu.percpu_ptr(cpu_wq, cpu)
        else:
            cwq = keventd_wq.cpu_wq[cpu]
	print " ----- CPU ", cpu, cwq
	# worklist is embedded in struct work_struct
	# as 'struct list_head entry'
	worklist = cwq.worklist
	print "\tworklist:"
	for e in readSUListFromHead(Addr(worklist), "entry",
	    "struct work_struct"):
	    print e
    return
    # print singleevent
    singleevent = readSymbol("singleevent")
    print ' --- singleevent', singleevent
    for e in readSUListFromHead(Addr(singleevent), "list",
	"struct lw_event"):
	try:
	    name = e.dev.name
	except crash.error:
	    name = "++BAD DEV++"
	print e, e.dev, name
	
    # print lweventlist
    lweventlist = readSymbol("lweventlist")
    print ' --- lweventlist', lweventlist
    for e in readSUListFromHead(Addr(lweventlist), "list",
	"struct lw_event"):
	print e, e.dev, e.dev.name
   
	
# Print args of most recent processes
def print_args5():
    tt = get_tt()
    # Most recent first
    out = []
    for t in tt.allThreads():
        out.append((- t.last_ran, t.pid, t))
        out.sort()
    for l, pid, t in out[:5]:
        mm = t.mm
        try:
            arg_start = mm.arg_start
            arg_end = mm.arg_end
        except crash.error:
            print pid, t.comm, "no user stack"
            continue
        s = readProcessMem(long(t.ts), arg_start, (arg_end - arg_start))
        print pid, t.comm, s



op =  OptionParser()

op.add_option("-v", dest="Verbose", default = 0,
		action="store_true",
		help="verbose output")

op.add_option("-q", dest="Quiet", default = 0,
		action="store_true",
		help="quiet mode - print warnings only")
		
op.add_option("--fast", dest="Fast", default = 0,
		action="store_true",
		help="Fast mode - do not run potentially slow tests")


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
		help="Print stacks (bt) categorized summary.")

op.add_option("--decodesyscalls", dest="decodesyscalls", default = "",
		action="store",
		help="Decode Syscalls on the Stack")

op.add_option("--keventd_wq", dest="eventwq", default = "",
		action="store_true",
		help="Decode keventd_wq")
(o, args) = op.parse_args()


if (o.Verbose):
    verbose = 1
else:
    verbose =0

if (o.Quiet):
    quiet = 1
else:
    quiet =0

if (o.Fast):
    Fast = True

t1 = os.times()[0]

# Non-standard options (those that stop normal tests)

if (o.sysctl):
    check_sysctl()
    sys.exit(0)

if (o.eventwq):
    decode_eventwq()
    sys.exit(0)

if (o.decodesyscalls):
    decode_syscalls(o.decodesyscalls)
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
    stackSummary()
    sys.exit(0)
    
HZ = sys_info.HZ

dmesg = exec_crash_command("log")

if (not sys_info.livedump):
    bta = exec_bt('bt -a')
else:
    bta = []

# If we reached this place, this means that no 'special' options are set
#
# There are 3 cases:
# 1. no options (delault). Print a compact summary suitable for quick triage
# 2. -q option. Print warnings only
# 3. -v option. Print a more detailed summary suitable for sending by email

print_basics()
dump_reason(dmesg)
check_loadavg()
if (not quiet):
    printHeader("Tasks Summary")
    threadcount = tasksSummary()

print_args5()
#check_activetasks()
check_spinlocks()
check_mem()

if (not Fast):
    check_auditf()
check_runqueues()
check_network()

# After this line we put all routines that can produce significant output
# We don't want to see hundreds of lines in the beginning!
if (not quiet):
    print_dmesg()
if (verbose):
    printHeader("A Summary Of Threads Stacks")
    stackSummary()

