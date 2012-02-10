#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# First-pass dumpanalysis
#
# Time-stamp: <12/02/10 13:58:06 alexs>

# Copyright (C) 2007-2009 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007-2009 Hewlett-Packard Co., All rights reserved.


# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function

# 1st-pass dumpanalysis
__version__ = "0.5.1"
__SVN_Id = "$Id$"

from pykdump.API import *

from LinuxDump import BTstack
from LinuxDump.BTstack import exec_bt, bt_summarize, bt_mergestacks
from LinuxDump.kmem import parse_kmemf, print_Zone
from LinuxDump.Tasks import TaskTable, Task, tasksSummary, getRunQueues,\
            TASK_STATE
from LinuxDump.inet import summary
import LinuxDump.inet.netdevice as netdevice
from LinuxDump import percpu, sysctl, Dev
from LinuxDump.Dev import print_dm_devices, print_gendisk

from LinuxDump import percpu


import sys
from stat import *
from StringIO import StringIO
from optparse import OptionParser


WARNING = "+++WARNING+++"


# The type of the dump. We should check different things for real panic and
# dump created by sysrq_handle

Panic = False
Fast = False

tt = None
def get_tt():
    global tt
    if (not tt):
        tt = TaskTable()
    return tt

#print ("%7.2f s to parse, %d entries" % (t1 - t0, len(btsl)))

def printHeader(format, *args, **kwargs):
    if (len(args) > 0):
	text = format % args
    else:
	text = format
    tlen = len(text)
    lpad = (73-tlen)/2
    print ("")
    if ("frame" in kwargs):
	uh = ' ' + ' '*lpad + '+' + '='*(tlen+2) + '+'
	print (uh)
	print (' ' + ' ' * lpad + '| ' + text + ' |')
	print (uh)
    else:	
	uh = ' ' + ' '*lpad + '+' + '-'*(tlen+2) + '+'
	print (uh)
	print ('>' + '-' * lpad + '| ' + text + ' |' +  '-' * lpad + '<')
	print (uh)
    print ("")

def print_basics():
    printHeader("*** Crashinfo v%s ***" % __version__, frame=1)
    print ("")
    if (not sys_info.livedump):
	# Check whether this is a partial dump and if yes,
	# compare the size of vmcore and RAM
	# If sizeof(vmcore) < 25% sizeof(RAM), print a warning
	dfile = sys_info.DUMPFILE
	# Convert memory to Mb
	(im, sm) = sys_info.MEMORY.split()
	ram = float(im)
	if (sm == "GB"):
	    ram *= 1024
	# Get vmcore size
	sz = os.stat(dfile.split()[0])[ST_SIZE]/1024/1024

        # When RH creates partial dumps, it says so
	# SLES can do this silently, so we can easily have just
	# a 14Mb vmcore on a system with 4GB of RAM...

	if (dfile.find("PARTIAL DUMP") != -1):
	    dfile = dfile.split()[0]
	    if (ram > sz *4):
	       print (WARNING, end=' ')
	       print ("PARTIAL DUMP with size(vmcore) < 25% size(RAM)")
	elif (ram > sz *10):
	    print (WARNING, end=' ')
	    print ("DUMP with size(vmcore) < 10% size(RAM)")

        # Check whether we can read modules table. In case of failure
        # the built-in 'mod' command prints
        # "mod: cannot access vmalloc'd module memory"
        # using error(FATAL,))
        #try:
            #exec_crash_command("mod")
        #except crash.error:
            #print (WARNING, "bad modules table.", end=' ')
            #print ("The dump is either corrupt or incomplete")
        
    if (quiet):
        return

    print (exec_crash_command("sys"))
    if (len(bta) > 0):
	printHeader("Per-cpu Stacks ('bt -a')")
    
	for cpu, stack in enumerate(bta):
	    print ("      -- CPU#%d --" % cpu, stack)
	    print ("")


def print_mount():
    printHeader("Mounted FS")
    print (exec_crash_command("mount"))

def print_dmesg():
    if (verbose):
        printHeader("dmesg buffer")
        print (dmesg)
    else:
        printHeader("Last 40 lines of dmesg buffer")
        print ("\n".join(dmesg.splitlines()[-40:]))
    
def check_mem():
    if (not quiet):
	printHeader("Memory Usage (kmem -i)")
        kmemi = exec_crash_command("kmem -i")
	if (kmemi):
            print (kmemi)
	else:
            # Timeout
	    print ("")

    # Checking for fragmentation (mostly useful on 32-bit systems)
    # In some patological cases this can be _very_ slow
    try:
	kmemf = exec_crash_command("kmem -f")
    except crash.error:
	kmemf = None
	print (WARNING, "Cannot Execute kmem -f")
    if (kmemf):
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
    
	    #print ("%2d  %6d %6d" % (area, sizekb, blocks))
	if (warn_8k or warn_32k):
	    printHeader("Memory Fragmentation (kmem -f)")
    
	if (warn_8k):
	    print (WARNING, "fragmentation: 8Kb")
	elif (warn_32k):
	    print (WARNING, "fragmentation: 32Kb")
    
	if (warn_8k or warn_32k):
	    print_Zone(Normal)
	#pp.pprint(node)
    else:
        # Timeout
        pass
	
    # Check whether NR_WRITEBACK is below vm_dirty_ratio
    try:
	kmemz = exec_crash_command("kmem -z")
	nr_writeback = 0
	for l in kmemz.splitlines():
	    spl = l.split(':')
	    if (len(spl) != 2): continue
	    k = spl[0].strip()
	    if (k != 'NR_WRITEBACK'): continue
	    v = int(spl[1].strip())
	    nr_writeback += v

	total_pages = readSymbol("totalram_pages")
	vm_dirty_ratio = readSymbol("vm_dirty_ratio")
	wr_ratio = float(nr_writeback)/total_pages*100
	if (wr_ratio > vm_dirty_ratio):
	    print (WARNING, end='') 
	    print (" NR_WRITEBACK/TOTALRAM=%5.2f%% > vm_dirty_ratio=%d%%" % \
		(wr_ratio, vm_dirty_ratio))
	elif (verbose):
	    print (" NR_WRITEBACK/TOTALRAM=%5.2f%%, vm_dirty_ratio=%d%%" % \
		(wr_ratio, vm_dirty_ratio))
    except crash.error:
	pass
    
    # Now check user-space memory. Print anything > 25% for thread group leaders
    tt = get_tt()
    for pid, ppid, cpu, task, st, pmem, vsz, rss, comm in parse_ps():
	if (pmem > 25.0 and tt.getByPid(pid)):
	    print (WARNING, "PID=%d CMD=%s uses %5.1f%% of total memory" %\
	       (pid, comm, pmem))
    
# Check how the dump has been triggered
def dump_reason(dmesg):
    global Panic
    def test(l, t):
	if (len([bts for bts in l if bts.hasfunc(t)])):
	    return True
	else:
	    return False
    def ifnetdump(dmesg):
	re_netdump = re.compile('netdump', re.M)
	if (re_netdump.search(dmesg)):
	    return True
	else:
	    return False

    if (not quiet):
        printHeader("How This Dump Has Been Created")
    if (sys_info.livedump):
	print ("Running on a live kernel")
        return
    func1 = 'sysrq_handle|handle_sysrq|netconsole'
    trigger = re.compile('vfs_write|sys_write')
    kbd  = re.compile('keyboard_interrupt')
    netconsole = re.compile('netconsole')
    die = re.compile('die')
    res = [bts for bts in bta if bts.hasfunc(func1)]
    if (res and not test(res, die)):
	if (quiet):
	    return
	# Now check whether we used keyboard or sysrq-trigger
	print ("Dump has been initiated: with sysrq")
	if (test(res, trigger)):
	    print ("\t- programmatically (via sysrq-trigger)")
	elif (test(res, kbd)):
	    print ("\t- via keyboard")
	elif (test(res, netconsole)):
	    print ("\t- via netconsole")
	else:
	    print ("\t- ???")
	if (test(bta, "disk_dump")):
	    print ("\t- using diskdump")
	elif (ifnetdump(dmesg)):
	    print ("\t- using netdump")
	else:
	    print ("\t- using unknown dump method")
	if (verbose):
	    for bts in res:
		print (bts)
    else:
        # This seems to be a real panic - search for BUG/general protection
        res = [bts for bts in bta if bts.hasfunc('die')]
        if (res):
	    Panic = True
	    if (quiet):
		return
            print ("Dump was triggered by kernel")
            if (test(res, "general_protection")):
                print ("\t- General Protection Fault")
	    m = re.search(r'^(.*Kernel BUG.*)$',dmesg, re.M)
	    if (m):
		print (m.group(1))
	    return
	
def stackSummary():
    btsl = exec_bt("foreach bt")
    #print_(memoize_cache())
    tt = get_tt()
    #bt_summarize(btsl)
    bt_mergestacks(btsl, reverse=True, tt=tt, verbose=verbose)
    
# Check Load Averages
def check_loadavg():
    avgf = []
    avgstr = sys_info["LOAD AVERAGE"]
    for avgs in avgstr.split(','):
	avgf.append(float(avgs))
    avg1, avg5, avg15 = avgf
    if (avg1 > 29 or avg5 > 29):
	print (WARNING, "High Load Averages:", avgstr)
    
def check_auditf():
    btsl = exec_bt("foreach bt")
    func1 = 'auditf'
    func2 = 'rwsem_down'
    res = [bts for bts in btsl
           if bts.hasfunc(func1) and bts.hasfunc(func2)]
    if (not res):
	return False
    print (WARNING, "%d threads halted by auditd" % len(res))
    if (verbose):
	for bts in res:
	    print (bts)

def check_sysctl():
    ctbl = sysctl.getCtlTables()
    names = ctbl.keys()
    names.sort()

    for n in names:
        dall = sysctl.getCtlData(ctbl[n])
        print (n.ljust(45), dall)

 
# Check whether active (bt -a) tasks are looping
def check_activetasks():

    tt = get_tt()
    basems = tt.basems
    for cpu, stack in enumerate(bta):
	pid = stack.pid
	mt = tt.getByTid(pid)
	ran_ms_ago = basems - mt.Last_ran
	if (ran_ms_ago > 10 * 1000):
	    print ("")
	    print (WARNING, "possible looping, CPU=%d ran_ago=%d ms" \
	       % (cpu, ran_ms_ago))
	    print (stack)


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
	print (WARNING, "BKL=%d" % BKL)
   
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
	    if ((ia64 == 1 and lv != 0) or (ia64 == 0 and lv <= 0)):
		print (WARNING, "Lock %s is held, lock=%d" % (ln, lv))
	except:
	    pass

# Get important global object from the symtable
re_bestguess = re.compile(r'^\w+\s+\([DB]\)\s([a-zA-Z]\w+)\s*$', re.I)
@memoize_cond(CU_LOAD)
def get_interesting_symbols():
    results = {}
    lines = memoize_cond(CU_LOAD)(exec_crash_command)("sym -l")
    for l in lines.splitlines():
	m = re_bestguess.match(l)
	if (m):
	    sym = m.group(1)
	    try:
		ctype = whatis(sym).ctype
		results.setdefault(ctype, []).append(sym)
	    except TypeError:
		pass
    # We are not really interested in funcs and integers types
    not_interested = ('(func)', '<data variable, no debug info>',
                    '__u32', '__u8', '__u16', '__u64', 
		    'char', 'int', 'long int',
		    'long unsigned int', 'short int', 'short unsigned int'
		    )
		    
    for k in results.keys():
	if (k in not_interested):
	    del results[k]
    return results


    
def get_important():
    results = get_interesting_symbols()

    if (verbose > 2):
	pp.pprint(results)
    # On older kernels, 'struct semaphore' has sleepers member, on newer ones
    # it is called 'count'we have a waitqueue (and count==0)
    ssn = "struct semaphore"
    if (member_offset(ssn, "sleepers") != -1):
        print (' -- semaphores with sleepers > 0 --')
        for n in results[ssn]:
            sem = readSymbol(n)
            sleepers = sem.sleepers
            if (sleepers):
               print (n, sem.sleepers)

        print (' -- semaphores with sleepers <= 0 --')
        for n in results[ssn]:
            sem = readSymbol(n)
            sleepers = sem.sleepers
            if (sleepers <= 0):
               print (n, sem.sleepers)

    srws = 'struct rw_semaphore'
    print (' -- rw_semaphores with count > 0 --')
    for n in results[srws]:
        addr = sym2addr(n)
        if (is_percpu_symbol(addr)):
            li = percpu.get_cpu_var(addr)
        else:
            li = [addr]

        for aa in li:
            sem = readSU(srws, aa)
            try:
               count = sem.count
            except KeyError:
                count = sem.activity
            if (count):
               print ("    ", n, count)

    print (' -- rw_semaphores with count <= 0 --')
    for n in results["struct rw_semaphore"]:
        addr = sym2addr(n)
        if (is_percpu_symbol(addr)):
            li = percpu.get_cpu_var(addr)
        else:
            li = [addr]

        for aa in li:
            sem = readSU(srws, aa)
        
            try:
               count = sem.count
            except KeyError:
                count = sem.activity
            if (count <= 0):
               print ("    ", n, count)
 	
    print (' -- Non-empty wait_queue_head --')
    for n in results["wait_queue_head_t"]:
	text = exec_crash_command("waitq %s" % n).strip()
	if (not re.match(r'^.*is empty$', text)):
	    print ("    ", n)
	    for l in text.splitlines():
		print ("\t", l)
	    
	#print (n)
 
    # Work queues (2.6) and task queues
    if ("struct work_struct" in results):
	off = member_offset("struct work_struct", "entry")
	print (' -- Non-empty struct work_struct --')
	for n in results["struct work_struct"]:
	    # per_cpu_xxx should be processed in a different way
            addr = sym2addr(n)
	    if (n.find("per_cpu") == 0 or is_percpu_symbol(addr)):
		continue
	    addr = sym2addr(n)
	    nel = getListSize(addr+off, 0, 1000000L)
	    if (nel):
	       print ("\t", n, nel)

    if ("struct tq_struct" in results):
	off = member_offset("struct tq_struct", "list")
	print (' -- Non-empty struct tq_struct --')
	for n in results["struct tq_struct"]:
	    # per_cpu_xxx should be processed in a different way
	    if (n.find("per_cpu") == 0):
		continue
	    addr = sym2addr(n)
	    try:
	       nel = getListSize(addr+off, 0, 1000000L) - 1
	    except crash.error:
		print (WARNING, "corrupted list", n)
		continue
	    if (nel):
	       print ("\t", n, nel)
    return
	    
    keys = results.keys()
    keys.sort()
    for k in keys:
	print  ('-----------', k, '-----------')
	results[k].sort()
	for v in results[k]:
	    print ('\t', v)

# Ordered Traversal of RB-tree (as represented by "struct rb_node")
def traverse_binary_tree(node):
    if (not node): return
    left = node.rb_left
    right = node.rb_right
    for nd in traverse_binary_tree(left):
        yield nd
    yield node
    for nd in traverse_binary_tree(right):
        yield nd

# Print CFS runqueue
def print_CFS_runqueue(rq):
    rb_node = rq.cfs.tasks_timeline.rb_node
    for node in traverse_binary_tree(rb_node):
        se = container_of(node, "struct sched_entity", "run_node")
        task = container_of(se, "struct task_struct", "se")
        print ("   ", task.pid, task.comm, se.sum_exec_runtime*1.e-9)

# Print RT-queue (new style)
def print_RT_runqueue(rq):
    # struct rt_rq
    rt = rq.rt
    prn = StringIO()
    RT_count = 0
    print ("  -- RT Queues ---", file=prn)
    for i, pq in enumerate(rt.active.queue):
        talist = readList(Addr(pq), inchead = False)
        l = len(talist)
        if (l):
            RT_count += 1
            print ("    prio=%-3d len=%d" % (i, l), file=prn)

    if (RT_count):
        print (prn.getvalue(),)
    prn.close()
    return RT_count

# Decode cpus_allowed
from crash import  mem2long

# cpumask_t can be declared as:
#struct {
    #long unsigned int bits[1];
#}
#
# or with 'mask' instead of 'bits'
def decode_cpus_allowed(cpus_allowed):
    try:
	bits = cpus_allowed.mask[0]
    except KeyError:
	bits = cpus_allowed.bits[0]
    out = []
    for i in range(sys_info.CPUS):
	if ((bits >> i) & 1):
	    out.append(i)
    return out
	

def check_runqueues():
    if (sys_info.kernel < "2.6.0"):
	return
    if (not quiet):
        printHeader("Scheduler Runqueues (per CPU)")
    rloffset = member_offset("struct task_struct", "run_list")
    # New kernels use CFS
    CFS = (member_offset("struct task_struct", "se") != -1)
    # Whether all 
    RT_hang = True
    for cpu, rq in enumerate(getRunQueues()):
	RT_count = 0
        print ("  ---+ CPU=%d %s ----" % (cpu, str(rq)))
	print ("     | CURRENT TASK %s, CMD=%s" % \
	       (rq.curr, rq.curr.comm))
        if (CFS):
            print_CFS_runqueue(rq)
            RT_count = print_RT_runqueue(rq)
        else:
            # Old scheduler
            # Print Active
            active = rq.Active
            #print (active)
            #print (active.queue)
	    timestamp_last_tick = rq.timestamp_last_tick
            for i, pq in enumerate(active.queue):
                #print (hexl(Addr(pq)))
		(talist, errmsg) = readBadList(Addr(pq), inchead = False)
		if (errmsg):
		    print (WARNING, "prio=%d" % i, errmsg, pq)
                l = len(talist)
                if (l and not quiet):
                   print ("    prio=%-3d len=%d" % (i, l))
                for ra in talist:
                    ta = ra - rloffset
                    ts = readSU("struct task_struct", ta)
		    try:
			policy = ts.policy
		    except Exception as e:
			print (WARNING, e)
			continue
                    if (ts.policy != 0):
                        RT_count += 1
                    if (verbose):
                        print ("\tTASK_STRUCT=0x%x  policy=%d CMD=%s PID=%s"\
                              %(ta, ts.policy, ts.comm, ts.pid))
		    if (verbose > 1):
			print ("\t\t (Timestamp - rq.timestamp_last_tick)=%4.2f s" %\
			      ((ts.timestamp - timestamp_last_tick)*1.e-9))
			print ("\t\t  CPUs allowed", ts.cpus_allowed, \
			     decode_cpus_allowed(ts.cpus_allowed))
	if (RT_count == 0):
	    RT_hang = False
	else:
	    print ("    %d Real-Time processes on this CPU" % RT_count)
    if (RT_hang):
	print (WARNING, "all CPUs are busy running Real-Time processes")
	

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
            if (not stack.hasfunc(r"^(system_call|sysenter_entry|ia64_ret_from_syscall|system_call_fastpath)$")):
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
    # If cpu_wq is not an array, this is per_cpu_ptr
    per_cpu = not isinstance(cpu_wq, list)
    # CPU-specific 
    for cpu in range(0, sys_info.CPUS):
        if (per_cpu):
            cwq = percpu.percpu_ptr(cpu_wq, cpu)
        else:
            cwq = keventd_wq.cpu_wq[cpu]
	print (" ----- CPU ", cpu, cwq)
	# worklist is embedded in struct work_struct
	# as 'struct list_head entry'
	worklist = cwq.worklist
	print ("\tworklist:")
	for e in readSUListFromHead(Addr(worklist), "entry",
	    "struct work_struct"):
	    print ("\t   ", e)
    return
    # print (singleevent)
    singleevent = readSymbol("singleevent")
    print (' --- singleevent', singleevent)
    for e in readSUListFromHead(Addr(singleevent), "list",
	"struct lw_event"):
	try:
	    name = e.dev.name
	except crash.error:
	    name = "++BAD DEV++"
	print (e, e.dev, name)
	
    # print (lweventlist)
    lweventlist = readSymbol("lweventlist")
    print (' --- lweventlist', lweventlist)
    for e in readSUListFromHead(Addr(lweventlist), "list",
	"struct lw_event"):
	print (e, e.dev, e.dev.name)
   
	
# Print args of most recent processes
def print_args5():
    printHeader("5 Most Recent Threads")
    print ("  PID  CMD                Age    ARGS")
    print ("-----  --------------   ------  ----------------------------")
    tt = get_tt()
    basems = tt.basems
    # Most recent first
    out = []
    for t in tt.allThreads():
        out.append((basems - t.Last_ran, t.pid, t))
	#print (t.pid, t.Last_ran)
    out.sort()
    for l, pid, t in out[:5]:
        mm = t.mm
        try:
            arg_start = mm.arg_start
            arg_end = mm.arg_end
	    s = readProcessMem(long(t.ts), arg_start, (arg_end - arg_start))
            # Replace nulls with spaces
	    s = s.replace('\0', ' ')
        except crash.error:
            s = "(no user stack)"
	spr = "%5d %-14s  %5d ms  %s" % (pid, t.comm, l, s)
	print (spr)
	if (len(spr) > 79):
	    print ("")

def __j_delay(ts, jiffies):
    v = (jiffies - ts) & INT_MASK
    if (v > INT_MAX):
        v = "     n/a"
    elif (v > HZ*3600*10):
        v = ">10hours"
    else:
        v = "%8.1f s" % (float(v)/HZ)
    return v


# ................................................................
# Tests for threads in UNINTERRUPTBLE state

# Here are some important cases:
# 1. We are doing sync/fsync and are stuck  (typically while committing
#     the journal)
# 2. Memory allocation - we are short on memory and are shrinking caches/zones
#    or waiting for swapper
# 3. We are waiting for NFS
#
# In general, if we have UN threads that did not run for a long time, this
# is highly suspicious


def check_UNINTERRUPTIBLE():
    tt = get_tt()
    basems = tt.basems
    bts = []
    count = 0
    for t in tt.allThreads():
	if (t.ts.state & TASK_STATE.TASK_UNINTERRUPTIBLE):
	    pid = t.pid
	    count += 1
	    # crash can miss some threads when there are pages missing
	    # and it will not do 'bt' in that case.
	    try:
		bts.append(exec_bt("bt %d" % pid)[0])
	    except:
		pass


    re_sync = 'sys_fsync'
    re_nfs = 'svc_process|nfsd_dispatch'
    re_journal = 'log_wait_commit|journal_commit_transaction'
    nfscount = 0
    jcount = 0
    bigtime = 30                # Cutoff for ran_s_ago
    oldbts = []
    for bt in bts:
	pid = bt.pid
        mt = tt.getByTid(pid)
        ran_ms_ago = basems - mt.Last_ran
	ran_s_ago = ran_ms_ago/1000
	if (ran_s_ago > bigtime):
	    oldbts.append((ran_s_ago, bt))
	if (verbose):
	    print (bt)
	    print ("\n   ......  last_ran %ds ago\n" % ran_s_ago)
	    print ('-' * 70)
	if ((bt.cmd == "syslogd" or bt.cmd == "syslog-ng") and 
		    ran_s_ago > bigtime):
	    print (WARNING, \
	       "syslogd is in UNINTERRUPTIBLE state, last_ran %ds ago"\
	           %ran_s_ago)
	if (bt.hasfunc(re_nfs) and ran_s_ago > bigtime):
	    nfscount += 1
	if (bt.hasfunc(re_journal)):
	    jcount += 1
	    
    
    # Print cummulative results
    if (nfscount):
	print (WARNING, \
	    "%d NFS processes in UNINTERRUPTIBLE state" % nfscount)
    if (jcount):
	print (WARNING, \
	    "%d processes in UNINTERRUPTIBLE state are committing journal" %\
	        jcount)
	        
    # Sort oldbts and print the last three stacks
    bts3 = sorted(oldbts)[-3:]
    if (bts3):
	print (WARNING, "three oldest UNINTERRUPTIBLE threads")
	for r, bt in bts3:
	    print ('   ... ran %ds ago' % r)
	    print (bt)

# ................................................................
#define RQ_INACTIVE		(-1)
#define RQ_ACTIVE		1
#define RQ_SCSI_BUSY		0xffff
#define RQ_SCSI_DONE		0xfffe
#define RQ_SCSI_DISCONNECTING	0xffe0

# On different kernels we have different fields. As we mainly use this
# function on pointers from slab/allocated, there can be bogus pointers
# Do not print them

def decode_request(rq):
    out = []
    out.append("    " + str(rq))
    # Do we have rq_status? If yes, is it reasonable?
    try:
        rq_status = rq.rq_status
	if (rq_status <= 0 or not rq_status in (1, 0xffff, 0xfffe, 0xffe0)):
	    return
	out.append("rq_status=0x%x" % rq_status)
    except KeyError:
	pass
    try:
	rq_dev = rq.rq_dev
	(major, minor) = decode_devt(rq_dev)
	out.append("rq_dev=0x%x major=%d minor=%d" % \
	   (rq.rq_dev, major, minor))
    except KeyError:
	pass
    

    try:
	# If cmd_len is too high, this is not a 
	# valid structure
	if (rq.cmd_len > 16):
	    return	
	rq_disk = rq.rq_disk
	if (not rq_disk):
	    return
	out.append("\n\tdisk_name=%s major=%d" % \
	   (rq_disk.disk_name,rq_disk.major))
    except KeyError:
	pass
    
    try:
	q = rq.q
	if (not q):
	    return
    except KeyError:
	pass
    try:
	in_flight = rq.q.in_flight
	cmd_flags = rq.cmd_flags
	ref_count = rq.ref_count

        # On recent kernels in_flight is an array with two elements,
        # one counter for sync and another one for non-sync
        try:
            in_flight = in_flight[0] + in_flight[1]
        except TypeError:
            pass
        if (in_flight == 0):
            return

	out.append("in_flight=%d, cmd_flags=0x%x, ref_count=%d" %\
	   (in_flight, cmd_flags, ref_count))
    except KeyError:
	pass
	
    ran_ago = __j_delay(rq.start_time, readSymbol("jiffies"))
    out.append("\n\tstarted %s ago" % ran_ago)
    return ", ".join(out)


# Decode struct rw_semaphore - waiting-list etc.

def decode_semaphore(semaddr):
    s = readSU("struct rw_semaphore", semaddr)
    print (s)
    #wait_list elements are embedded in struct rwsem_waiter
    wait_list = readSUListFromHead(Addr(s.wait_list), "list",
             "struct rwsem_waiter")
    out = []
    for w in wait_list:
	task = w.task
	out.append([task.pid, task.comm])
    # Sort on PID
    out.sort()
    for pid, comm in out:
	print ("\t%8d  %s" % (pid, comm))
    
# Decode struct mutex - waiting-list etc.

def decode_mutex(addr):
    s = readSU("struct mutex", addr)
    print (s)
    #wait_list elements are embedded in struct mutex_waiter
    wait_list = readSUListFromHead(Addr(s.wait_list), "list",
             "struct mutex_waiter")
    out = []
    for w in wait_list:
	task = w.task
	out.append([task.pid, task.comm])
    # Sort on PID
    out.sort()
    for pid, comm in out:
	print ("\t%8d  %s" % (pid, comm))
	
# WARNING: on some kernels (e.g. Ubuntu/Hardy, 2.6.24)
# blkdev_requests is mapped to a general slab.
# E.g. when struct request has size 188, it goes into "kmalloc-192"
# 

def print_blkreq(header = None):
    from LinuxDump.Slab import get_slab_addrs
    try:
        name = readSymbol("request_cachep").name
    except:
        name = "blkdev_requests"
    try:
        (alloc, free) = get_slab_addrs(name)
    except crash.error as val:
	print (val)
	return
    out = []
    lalloc = len(alloc)
    sfree = None
    for i, a in enumerate(alloc+free):
	rq = readSU("struct request", a)
        try:
            rqs = decode_request(rq)
	    if (rqs):
                if (a in alloc):
                    rqs = "+" + rqs
                else:
                    rqs = '-' + rqs
                if (sfree == None and i >= lalloc):
                    sfree = len(out)
		out.append(rqs)
        except crash.error:
            pass
    if (out):
	if (header):
	    print (header)
	else:
	   print (WARNING, "there are outstanding blk_dev requests")
        print (lalloc,len(free), sfree)
        # Insert alloc/free headers
        if (sfree == 0):
            # No alloc, just free
            print ("  ===== Free List")
        else:
            print ("  ===== Allocated List")
            if (sfree):
                out.insert(sfree, "  ===== Free List")
	print ("\n".join(out))
	
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
    return (major, minor)

# Find stacks with functions matching the specified pattern
def find_stacks(pattern):
    btsl = exec_bt("foreach bt")
    for bt in btsl:
	if (bt.hasfunc(pattern)):
	    print (bt)

# Parse (as reliably as possible)  output of 'ps' command
#    0      1    2      3      4    5       6      7     8
#   PID    PPID  CPU   TASK    ST  %MEM     VSZ    RSS  COMM
#>     0      0   0  c0324a80  RU   0.0       0      0  [swapper]
#   5758   6983   0  e30aa7b0  IN   0.1    8020   1900  httpd

def parse_ps():
    out = []
    for l in exec_crash_command('ps').splitlines()[1:]:
	spl = re.split("\s+", l[1:].strip())
	try:
	    # Convert integers
	    for i in (0, 1, 2, 6, 7):
		spl[i] = int(spl[i])
	    # hexadecimal
	    spl[3] = int(spl[3], 16)
	    # Floating-point
	    spl[5] = float(spl[5])
	    pid, ppid, cpu, task, st, pmem, vsz, rss = spl[:8]
	    comm = string.join(spl[8:])
	    out.append((pid, ppid, cpu, task, st, pmem, vsz, rss, comm))
	except:
	    print (WARNING, "cannot parse:", l)
    return out

# Compute the sum of all RSS memory used by applications. We cannot
# just some values from 'ps' output as it does not make difference between
# processes and threads. Hence, for multithreaded processes it reports
# the same memory multiple times

def user_space_memory_report():
    # Get processes/thread group leaders only
    
    tt = get_tt()
    rss_tot = pmem_tot = 0
    # Get processes/thread group leaders only
    for pid, ppid, cpu, task, st, pmem, vsz, rss, comm in parse_ps():
        if (tt.getByPid(pid)):
            rss_tot += rss
            pmem_tot += pmem
    print ("RSS_TOTAL=%d pages, %%mem=%7.1f" % (rss_tot, pmem_tot))

# Check for long (>nmin) chains of processes. E.g. custom script is looping and
# spawns more and more processes recursively
def longChainOfPids(tt, nmin):
    # Convert to tree structure, ignore pid=0
    # Each element is (ppid, [children]) tuple
    ptree = {}
    for t in tt.allThreads():
	pid = t.pid
	if (pid == 0):
	    continue
	# Thread pointers may get corrupted because of kernel bugs
	try:
	    ppid = t.parent.pid
	except crash.error:
	    print (ERROR, "corrupted", t)
	    continue
	
	if (not pid in ptree):
	    ptree[pid] = (ppid, [])
    
	ptree.setdefault(ppid, (t.parent.parent.pid, []))[1].append(pid)
    
    for pid, l in ptree.items():
	ppid, children = l
	if (not children):
	    # Check distance from the top
	    dist = 0
	    #print (pid)
	    chain = [pid]
	    while (ppid > 1):
		dist += 1
		ppid = ptree[ppid][0]
		if (dist < 10):
		    chain.insert(0, ppid)
		#print ("\t", ppid)
	    if (dist > nmin):
		print (WARNING, "a long chain of processes, N=%d, last pid=%d" % (dist, pid))
		print ("  Last 10 Processes in this chain")
		for i, pid in enumerate(chain):
		    comm = tt.getByPid(pid).comm
		    print ('  ', '  ' * i, pid, comm)
# ----------------------------------------------------------------------------

op =  OptionParser()

op.add_option("-v", dest="Verbose", default = 0,
		action="count",
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

op.add_option("--blkreq", dest="Blkreq", default = 0,
		action="store_true",
		help="Print Block I/O requests")

op.add_option("--blkdevs", dest="Blkdevs", default = 0,
		action="store_true",
		help="Print Block Devices Info")

op.add_option("--filelock", dest="filelock", default = 0,
		action="store_true",
		help="Print filelock info.")

op.add_option("--stacksummary", dest="stacksummary", default = 0,
		action="store_true",
		help="Print stacks (bt) categorized summary.")

op.add_option("--findstacks", dest="findstacks", default = "",
		action="store",
		help="Print stacks (bt) containing functions that match the provided pattern")

op.add_option("--decodesyscalls", dest="decodesyscalls", default = "",
		action="store",
		help="Decode Syscalls on the Stack")

op.add_option("--keventd_wq", dest="eventwq", default = "",
		action="store_true",
		help="Decode keventd_wq")

op.add_option("--lws", dest="Lws", default = "",
		action="store_true",
		help="Print Locks Waitqueues and Semaphores")		

op.add_option("--devmapper", dest="DM", default = "",
		action="store_true",
		help="Print DeviceMapper Tables")		

op.add_option("--runq", dest="Runq", default = "",
		action="store_true",
		help="Print Runqueus")

op.add_option("--semaphore", dest="Sema", default = 0,
		type="long", action="store",
		help="Print Semaphore info")

op.add_option("--mutex", dest="Mutex", default = 0,
		type="long", action="store",
		help="Print Mutex info")

op.add_option("--gendisk", dest="gendisk", default = "",
              action="store_true",
              help="Print gendisk structures")

op.add_option("--umem", dest="umem", default = "",
              action="store_true",
              help="Print User-space Memory Usage")
	
op.add_option("--ls", dest="ls", default = "",
		action="store",
		help="Emulate 'ls'. You can specify either dentry"
              " address or full pathname")

op.add_option("--version", dest="Version", default = 0,
              action="store_true",
              help="Print program version and exit")


(o, args) = op.parse_args()


verbose = o.Verbose

if (o.Version):
    print ("CRASHINFO version %s,  %s" % (__version__, __SVN_Id))
    if (verbose):
        # Print C-module and API versions
        print("C-Module version: %s" %(crash.version))
    sys.exit(0)


if (sys_info.machine == "ia64"):
    ia64 = 1
    #print ("This is IA64!")
else:
    ia64 = 0

if (o.Quiet):
    quiet = 1
else:
    quiet = 0

if (o.Fast):
    set_default_timeout(12)

t1 = os.times()[0]

# Non-standard options (those that stop normal tests)

if (o.Lws):
    get_important()
    sys.exit(0)
    
if (o.sysctl):
    check_sysctl()
    sys.exit(0)

if (o.findstacks):
    find_stacks(o.findstacks.strip('\'"'))
    sys.exit(0)

if (o.eventwq):
    decode_eventwq()
    sys.exit(0)

if (o.Blkreq):
    print_blkreq(" ---- Outstanding blk_dev Requests -----")
    sys.exit(0)
    
if (o.Blkdevs):
    Dev.print_blkdevs(verbose)
    sys.exit(0)
    
if (o.decodesyscalls):
    decode_syscalls(o.decodesyscalls)
    sys.exit(0)

if (o.Sema):
    decode_semaphore(o.Sema)
    sys.exit(0)

if (o.Mutex):
    decode_mutex(o.Mutex)
    sys.exit(0)

if (o.ext3):
    from LinuxDump.fs.ext3 import showExt3

    showExt3()
    sys.exit(0)

if (o.ext3):
    from LinuxDump.fs.ext3 import showExt3

    showExt3()
    sys.exit(0)

if (o.ls):
    from LinuxDump.fs.dcache import ls_pathname

    ls_pathname(o.ls, verbose)
    sys.exit(0)
    
if (o.stacksummary):
    stackSummary()
    sys.exit(0)
 
if (o.DM):
    print_dm_devices(verbose)
    sys.exit(0)

if (o.Runq):
    check_runqueues()
    sys.exit(0)

if (o.gendisk):
    print_gendisk(verbose)
    sys.exit(0)

if (o.umem):
    user_space_memory_report()
    sys.exit(0)
 


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
longChainOfPids(get_tt(), 20)
if (not quiet):
    printHeader("Tasks Summary")
    threadcount = tasksSummary()

if (not quiet):
    print_args5()
#check_activetasks()
check_spinlocks()
check_mem()

# Tests that make sense for non-panic situations
if (not Panic):
    print_blkreq()

# Check gendisk structures
print_gendisk(0)

check_UNINTERRUPTIBLE()
check_auditf()

try:
    check_runqueues()
except crash.error:
    print (WARNING, "cannot continue - the dump is probably incomplete", \
        "or corrupted")

try:	
    check_network()
except crash.error:
    print (WARNING, "cannot continue - the dump is probably incomplete", \
        "or corrupted")


# After this line we put all routines that can produce significant output
# We don't want to see hundreds of lines in the beginning!
if (not quiet):
    print_mount()
    print_dmesg()
if (verbose):
    printHeader("A Summary Of Threads Stacks")
    stackSummary()

