#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# First-pass dumpanalysis
#

# --------------------------------------------------------------------
# (C) Copyright 2006-2019 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------


# 1st-pass dumpanalysis
__version__ = "1.3.5"

from pykdump.API import *

from LinuxDump import BTstack
from LinuxDump.BTstack import (exec_bt, bt_summarize, bt_mergestacks,
                               fastSubroutineStacks, verifyFastSet)
from LinuxDump.kmem import parse_kmemf, print_Zone
from LinuxDump.Tasks import (TaskTable, Task, tasksSummary, getRunQueues,
            TASK_STATE, sched_clock2ms, decode_waitq)
from LinuxDump.Analysis import (check_possible_hang, check_saphana,
                                check_memory_pressure, check_hanging_nfsd,
                                print_wait_for_AF_UNIX)
from LinuxDump.inet import summary
import LinuxDump.inet.netdevice as netdevice
from LinuxDump import percpu, sysctl, Dev
from LinuxDump.KernLocks import (decode_mutex, spin_is_locked, decode_semaphore,
                                 decode_rwsemaphore)
from LinuxDump.Dev import (print_dm_devices, print_gendisk,
            get_blkreq_fromslab, print_request_slab, 
            print_request_queues, print_blk_cpu_done)
    
from LinuxDump import percpu
from LinuxDump.Time import j_delay

# For FS stuff
from LinuxDump.fs import *

# DLKM info
from LinuxDump.dlkm import lsmod


import sys
import re
from stat import *
from optparse import OptionParser
from collections import Counter
import textwrap
from io import StringIO
import itertools


# The type of the dump. We should check different things for real panic and
# dump created by sysrq_handle

Fast = False

def printHeader(format, *args, **kwargs):
    if (len(args) > 0):
        text = format % args
    else:
        text = format
    tlen = len(text)
    lpad = (73-tlen)//2
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
        # Get vmcore size - skip this test for split kdump
        if (not 'DUMPFILES' in sys_info):
            sz = os.stat(dfile.split()[0])[ST_SIZE]/1024/1024

            # When RH creates partial dumps, it says so
            # SLES can do this silently, so we can easily have just
            # a 14Mb vmcore on a system with 4GB of RAM...

            if (dfile.find("PARTIAL DUMP") != -1):
                dfile = dfile.split()[0]
                if (ram > sz *4):
                    pylog.warning("PARTIAL DUMP with size(vmcore) < 25% size(RAM)")
            elif (ram > sz *10):
                pylog.warning("DUMP with size(vmcore) < 10% size(RAM)")

        
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

def kmemi_parser(data):
    __re_l = re.compile(r'^([^\d]+)(\d+)\s+([\d.]+\s(?:.B)?)\s+(\d+%)?')
    # Put results into a dictionary, name:(total, percent)
    # For convenience, convert total to MB
    out = {}
    for l in data.splitlines()[1:]:
        l = l.rstrip()
        if (not l):
            continue
        m =  __re_l.match(l)
        #print (m.groups())
        #continue
        fname, pages, total, percent = m.groups()
        if (total):
            v, *suff = total.split()
            v = float(v)
            if (suff):
                suff = suff[0]
                if (suff == 'GB'):
                    v *= 1024
                elif (suff == 'KB'):
                    v /= 1024
                elif (suff == 'MB'):
                    pass
                else:
                    raise ValueError("Unknown suffix "+ l)
            
        fname = fname.strip()
        if (percent):
            percent = int(percent[:-1])
        out[fname] = (v, percent)
    return out
def analyze_kmem(d):
    # Analyse memory usage. We look at the following:
    # 1. SWAP usage
    # 2. Commit
    # 3. HUGE (total/free)
    totmem = d['TOTAL MEM'][0]
    free, freeper = d['FREE']
    tothuge = d['TOTAL HUGE'][0]
    hugefree, hugefreeper = d['HUGE FREE']
    totswap = d['TOTAL SWAP'][0]
    swapusedper = d['SWAP USED'][1]
    committedper = d['COMMITTED'][1]

    # Now some tests.
    #
    # If there is plenty of free memory, no need to do anything!
    if (freeper > 10):
        return
    
    # Is committed > 100?
    if (committedper > 100):
        pylog.warning("Commited {}%".format(committedper))
        
    # Did we reserve many huge pages but not really using them?
    if (tothuge > totmem/2 and hugefreeper > 30):
        pylog.warning("{:2.1f} GB of huge memory reserved but {}% of it is not used".\
            format(tothuge/1024, hugefreeper))
        
    # IF swap reserved is at least 20% of RAM, check how much is used
    if (totswap > totmem/5 and swapusedper > 15):
        pylog.warning("Significant swapping")
    
def check_mem():
    if (not quiet):
        printHeader("Memory Usage (kmem -i)")
        kmemi = memoize_cond(CU_LIVE | CU_TIMEOUT)(exec_crash_command_bg)("kmem -i")
        if (kmemi):
            print (kmemi)
            try:
                d = kmemi_parser(kmemi)
                analyze_kmem(d)
            except:
                # In case something goes wrong
                pass
        else:
            # Timeout
            print ("")

    # Checking for fragmentation (mostly useful on 32-bit systems)
    # In some patological cases this can be _very_ slow
    try:
        kmemf = memoize_cond(CU_LIVE | CU_TIMEOUT)(exec_crash_command_bg)("kmem -f")
    except crash.error:
        kmemf = None
        pylog.warning("Cannot Execute kmem -f")
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
            pylog.warning("fragmentation: 8Kb")
        elif (warn_32k):
            pylog.warning("fragmentation: 32Kb")
    
        if (warn_8k or warn_32k):
            print_Zone(Normal)
        #pp.pprint(node)
    else:
        # Timeout
        pass
        
    # Check whether NR_WRITEBACK is below vm_dirty_ratio
    try:
        kmemz = exec_crash_command_bg("kmem -V")
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
            pylog.warning(" NR_WRITEBACK/TOTALRAM=%5.2f%% > vm_dirty_ratio=%d%%" % \
                (wr_ratio, vm_dirty_ratio))
        elif (verbose):
            print (" NR_WRITEBACK/TOTALRAM=%5.2f%%, vm_dirty_ratio=%d%%" % \
                (wr_ratio, vm_dirty_ratio))
    except (crash.error, TypeError):
        pass
    
    # Check for kmem -s errors
    s  = memoize_cond(CU_LIVE | CU_TIMEOUT)(exec_crash_command_bg)("kmem -s")
    # Search for 'kmem: <slabname> ..."
    out = re.findall(r'^kmem: .+$', s, re.M)
    if (out):
        pylog.error("SLAB corruption")
        for s in out:
            print("  ", s)
    
    # Now check user-space memory. Print anything > 25% for thread group leaders
    tt = TaskTable()
    for pid, ppid, cpu, task, st, pmem, vsz, rss, comm in parse_ps():
        if (pmem > 25.0 and tt.getByPid(pid)):
            pylog.warning("PID=%d CMD=%s uses %5.1f%% of total memory" %\
               (pid, comm, pmem))
    
def dump_reason(dmesg):
    def search_dmesg(pattern):
        m = re.search(pattern,dmesg, re.M)
        if (m):
            return m.group(1)
        else:
            return None
    def print1(msg):
        print("   *** {} ***".format(msg))
    def print2(msg):
        if (msg):
            print("     {}".format(msg))

    if (sys_info.livedump):
        print1("Running on a live kernel")
        return

    bt = exec_bt("bt")[0]
    if (not quiet):
        printHeader("How This Dump Has Been Created")
    
    # Check for sysrq
    if (bt.hasfunc('sysrq_handle|handle_sysrq|netconsole')):
        print1("Dump has been initiated: with sysrq")
        if (bt.hasfunc('vfs_write|sys_write')):
            print2("programmatically (via sysrq-trigger)")
        elif (bt.hasfunc('keyboard_interrupt|kbd_event')):
            print2("via keyboard")
        else:
            print2("???")
        return
    
    # Check for Deadman timer
    if (bt.hasfunc("deadman_timer")):
       print1("Dump has been initiated: with SG Deadman Timer")
       DCache.tmp.SG_deadman_timer = True
       return
   
    # A real panic? (E.g. kernel bug)
    kbug_re = r'^.*(Kernel BUG.*|BUG: .*)$'
    if (bt.hasfunc("die|do_page_fault|__bad_area_nosemaphore|general_protection")):
        if (quiet):
            return
        print1("Dump was triggered by kernel")
        if (bt.hasfunc("general_protection")):
            print2("General Protection Fault")
            return
        s = search_dmesg(kbug_re)
        print2(s)
        if (s):
            return
        s = search_dmesg(r'^(Unable to handle kernel .*)$')
        if (s):
            print2(s)
            return
            
    if (bt.hasfunc("panic")):
        print1("Panic")
        # Now do tests, from more specific to less specific
        if (bt.hasfunc("fence")):
            s = search_dmesg(r'^(.*fencing.*)$')
            print2(s)
            return
        elif (bt.hasfunc("mce_panic")):
            print2("MCE")
            return
        elif (bt.hasfunc("hpwdt")):
            print2("hpwdt timeout")
            DCache.tmp.hpwdt = True
            return
        elif (bt.hasfunc("watchdog_timer")):
            print2("watchdog timer")
            return
        elif (bt.hasfunc("nmi_handle|do_nmi")):
            print2("Panic triggered by NMI")
            s = search_dmesg(r'^.*(NMI: .*)$')
            print2(s)
            return

        s = search_dmesg(kbug_re)
        if (s):
            print2(s)
            return
    elif (bt.hasfunc("nmi_handle|do_nmi")):
        s = search_dmesg(r'.*(NMI received .*)$')
        if (s):
            print2(s)
            return
        
        
    print2("Cannot identify the specific condition that triggered vmcore")


            

def stackSummary():
    btsl = exec_bt("foreach bt")
    #print_(memoize_cache())
    tt = TaskTable()
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
        pylog.warning("High Load Averages:", avgstr)
    
def check_auditf():
    btsl = exec_bt("foreach bt")
    func1 = 'auditf'
    func2 = 'rwsem_down'
    res = [bts for bts in btsl
           if bts.hasfunc(func1) and bts.hasfunc(func2)]
    if (not res):
        return False
    pylog.warning("%d threads halted by auditd" % len(res))
    if (verbose):
        for bts in res:
            print (bts)

def check_sysctl():
    ctbl = sysctl.getCtlTables()
    names = sorted(ctbl.keys())

    for n in names:
        ct = ctbl[n]
        if (verbose):
            if (verbose > 1):
                phandler = addr2sym(ct.proc_handler)
            else:
                phandler = ""
            print("-----", ct, "------", phandler)
        try:
            dall = sysctl.getCtlData(ct)
        except:
            dall = '(?)'
        print (n.ljust(20), dall)

 
# Check whether active (bt -a) tasks are looping
def check_activetasks():

    tt = TaskTable()
    basems = tt.basems
    for cpu, stack in enumerate(bta):
        pid = stack.pid
        mt = tt.getByTid(pid)
        ran_ms_ago = basems - mt.Last_ran
        if (ran_ms_ago > 10 * 1000):
            print ("")
            pylog.warning("possible looping, CPU=%d ran_ago=%d ms" \
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
        pylog.warning("BKL=%d" % BKL)
   
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
                pylog.warning("Lock %s is held, lock=%d" % (ln, lv))
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
                    
    for k in list(results.keys())[:]:
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
        # For some strange reasons, crash does not work properly for
        # some empty queues, e.g. 'waitq acpi_bus_event_queue'
        try:
            text = exec_crash_command("waitq %s" % n).strip()
        except crash.error:
            continue
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
            nel = getListSize(addr+off, 0, 1000000)
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
               nel = getListSize(addr+off, 0, 1000000) - 1
            except crash.error:
                pylog.warning("corrupted list", n)
                continue
            if (nel):
               print ("\t", n, nel)
    return
            
    keys = sorted(results.keys())
    for k in keys:
        print  ('-----------', k, '-----------')
        for v in sorted(results[k]):
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
    try:
        rb_node = rq.cfs.tasks_timeline.rb_node
    except KeyError:
        rb_node = rq.cfs.tasks_timeline.rb_root.rb_node

    for node in traverse_binary_tree(rb_node):
        se = container_of(node, "struct sched_entity", "run_node")
        task = container_of(se, "struct task_struct", "se")
        print ("    {} {} {:6.5f} ".format(task.pid, task.comm,
                                         se.sum_exec_runtime*1.e-9))

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
    locked_rqs = []
    tt = TaskTable()
    for cpu, rq in enumerate(getRunQueues()):
        RT_count = 0
        print ("  ---+ CPU=%d %s ----" % (cpu, str(rq)))
        print ("     | CURRENT TASK %s, CMD=%s" % \
               (rq.curr, rq.curr.comm))
        # Don't have time to implement this ofr old kernels
        try:
            if (spin_is_locked(rq.lock.raw_lock)):
                print("         This runqueue is locked")
                locked_rqs.append(cpu)
        except:
            pass
        if (CFS):
            print_CFS_runqueue(rq)
            RT_count = print_RT_runqueue(rq)
        else:
            # Old scheduler
            # Print Active
            active = rq.Active
            #print (active)
            #print (active.queue)
            expired = rq.Expired
            timestamp_last_tick = sched_clock2ms(rq.timestamp_last_tick)
            for qn, aeq in enumerate((active.queue, expired.queue)):
                if (qn == 0):
                    print("     ---ACTIVE---")
                else:
                    print("     ---EXPIRED---")
                for i, pq in enumerate(aeq):
                    #print (hexl(Addr(pq)))
                    (talist, errmsg) = readBadList(Addr(pq), inchead = False)
                    if (errmsg):
                        pylog.warning("prio=%d" % i, errmsg, pq)
                    l = len(talist)
                    if (l and not quiet):
                        print ("       prio=%-3d len=%d" % (i, l))
                    for ra in talist:
                        ta = ra - rloffset
                        ts = Task(readSU("struct task_struct", ta), tt)
                        try:
                            policy = ts.policy
                        except Exception as e:
                            pylog.warning(e)
                            continue
                        if (ts.policy != 0):
                            RT_count += 1
                        if (verbose):
                            print ("\t TASK_STRUCT=0x%x  policy=%d CMD=%s PID=%s"\
                                %(ta, ts.policy, ts.comm, ts.pid))
                        if (verbose > 1):
                            print ("\t\t (Timestamp - rq.timestamp_last_tick)=%4.2f s" %\
                                ((ts.Last_ran - timestamp_last_tick)*1.e-3))
                            print ("\t\t  CPUs allowed", ts.cpus_allowed, \
                                decode_cpus_allowed(ts.cpus_allowed))
        if (RT_count == 0):
            RT_hang = False
        else:
            print ("    %d Real-Time processes on this CPU" % RT_count)
    if (RT_hang):
        pylog.warning("all CPUs are busy running Real-Time processes")
    if (locked_rqs):
        s = textwrap.fill(str(locked_rqs)[1:-1],  width=40,
                          initial_indent=' ',
                          subsequent_indent = 8 * ' ')
        #pylog.warning("Runqueus on cpus {} are locked".format(s))
        print ('-' * 60)
        print(WARNING)
            
        print("Runqueus on cpus {} are locked".format(s))
        

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
    

# Get an array of CPU-workqueues
def __get_cpu_wqs(_wq):
    # On older (e.g. 2.6.9) kernels we use
    # cwq = keventd_wq->cpu_wq + cpu;
    # On newer ones,
    # cwq = per_cpu_ptr(keventd_wq->cpu_wq, cpu);

    cpu_wq = _wq.cpu_wq
    # If cpu_wq is not an array, this is per_cpu_ptr
    per_cpu = not isinstance(cpu_wq, list)
    # CPU-specific 
    out = []
    for cpu in range(0, sys_info.CPUS):
        if (per_cpu):
            cwq = percpu.percpu_ptr(cpu_wq, cpu)
        else:
            cwq = _wq.cpu_wq[cpu]
        out.append((cpu, cwq))
    return out
    
# 2.6.30:
#struct cpu_workqueue_struct {
    #spinlock_t lock;
    #struct list_head worklist;
    #wait_queue_head_t more_work;
    #struct work_struct *current_work;
    #struct workqueue_struct *wq;
    #struct task_struct *thread;
#}

# 2.6.18:
#struct cpu_workqueue_struct {
    #spinlock_t lock;
    #long int remove_sequence;
    #long int insert_sequence;
    #struct list_head worklist;
    #wait_queue_head_t more_work;
    #wait_queue_head_t work_done;
    #struct workqueue_struct *wq;
    #task_t *thread;
    #int run_depth;
#}

# Decode workqueue
    
def decode_wq(_wq):
    for cpu, cwq in __get_cpu_wqs(_wq):
        print (" ----- CPU ", cpu, cwq)

        # worklist is embedded in struct work_struct
        # as 'struct list_head entry'
        worklist = cwq.worklist
        print ("\tworklist:")
        for e in readSUListFromHead(Addr(worklist), "entry",
            "struct work_struct"):
            print ("\t   ", e, "func=<%s>" % (addr2sym(e.func)))
            #barr = container_of(long(e), "struct wq_barrier", "work")
            #print(barr)
        if (verbose < 1):
            continue
        
        # Checking which threads are waiting for this wq to be flushed
        # The only implemented test is for RHEL4,5. If we don't know how
        # to do this, just skip this test
        # On RHEL4,5 tasks are in work_done
        # On RHEL6 it uses completion events
        # on 3.x kernels it uses wq_flusher
        if (cwq.hasField("work_done")):
            # RHEL4,5
            lhead = cwq.work_done
            tasklist = decode_waitq(lhead.task_list)
        elif (cwq.hasField("worklist")):
            # RHEL6
            # Completion events. First, check whether we have any work
            if (worklist.next == worklist.prev and long(cwq.current_work) == 0):
                tasklist = []
            else:
                #print("   Workqueue is not empty, but cannot decode it for this kernel")
                #raise TypeError("unsupported kernel")
                tasklist = []
        else:
            #raise TypeError("unsupported kernel")
            tasklist = []

        if (tasklist):
            print("   .... tasks waiting for this workqueue to be flushed:")
            #print(exec_crash_command("waitq 0x%x" % long(lhead)))
            for task in tasklist:
                print("     pid=%7d   CMD=%s" % (task.pid, task.comm))            
    return


# This is basically the same as decode_wq() for events, printing warnings only
# I don't like to duplicate the code but until I find a better way,
# here it goes...
def check_event_workqueues():
    tt = TaskTable()
    basems = tt.basems
    _wq = readSymbol("keventd_wq")
    warning = False
    for cpu, cwq in __get_cpu_wqs(_wq):    
        worklist = cwq.worklist
        # This works for RHEL4,5 only
        try:
            lhead = cwq.work_done
        except:
            break
        tasklist = decode_waitq(lhead.task_list)            
        # Check whether there are tasks waiting longer than 1s
        maxdelta = 1000         # in ms
        for task in tasklist:
            if (basems - task.Last_ran > maxdelta):
                warning = True
                break
        if (warning): break
    if (warning):
        pylog.warning("there are tasks waiting for events workqueue flushed"
            "\n          +++ for longer than %d ms\n" % maxdelta,
            "          +++ Run 'crashinfo --kevent -v' to get more details")
                    
                
# Print args of most recent processes
def print_args5():
    printHeader("5 Most Recent Threads")
    print ("  PID  CMD                Age    ARGS")
    print ("-----  --------------   ------  ----------------------------")
    tt = TaskTable()
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
            s = str(s, 'latin1')
            s = s.replace('\0', ' ')
        except crash.error:
            s = "(no user stack)"
        spr = "%5d %-14s  %5d ms  %s" % (pid, t.comm, l, s)
        print (spr)
        if (len(spr) > 79):
            print ("")




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
    tt = TaskTable()
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

        if (bt.hasfunc(re_nfs) and ran_s_ago > bigtime):
            nfscount += 1
        if (bt.hasfunc(re_journal)):
            jcount += 1
            
    
    # Print cummulative results
    if (nfscount):
        pylog.warning("%d NFS processes in UNINTERRUPTIBLE state" % nfscount)
    if (jcount):
        pylog.warning("%d processes in UNINTERRUPTIBLE state are committing journal" %\
                jcount)
                
    # Sort oldbts and print the last three stacks
    bts3 = sorted(oldbts)[-3:]
    if (bts3):
        print("+++three oldest UNINTERRUPTIBLE threads")
        for r, bt in bts3:
            print ('   ... ran %ds ago' % r)
            print (bt)

# Check for frozen FS
def check_frozen_fs():
    once = TrueOnce(1)
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        sb = readSU("struct super_block", superblk)
        if (sb_frozen(sb)):
            if (not verbose):
                pylog.warning("There are frozen FS, rerun with '-v' to get a list")
                return
            else:
                if (once):
                    pylog.warning("There are frozen FS")
                    print("\n --- A list of FS in frozen state ---")
                print("    ---", sb)
                print("       ", fstype, devname, mnt)
                # Check for tasks waiting on our queues
                queues = []
                try:
                    q = sb.s_wait_unfrozen
                    n = "s_wait_unfrozen"
                    queues.append((q,n))
                except:
                    pass
                try:
                    q = sb.s_writers.wait
                    n = "s_writers.wait"
                    queues.append((q,n))
                except:
                    pass
                try:
                    q = sb.s_writers.wait_unfrozen
                    n = "s_writers.wait_unfrozen"
                    queues.append((q,n))
                except:
                    pass
                for q, qn in  queues:
                    tasks = decode_waitq(q)
                    if (not tasks):
                        continue
                    pids = {t.pid for t in tasks}
                    print("      PIDs waiting on {}".format(qn))
                    s = textwrap.fill(str(pids),  width=60,
                          initial_indent='         ',
                          subsequent_indent = 16 * ' ')
                    print(s)

        
# Print status of block requests ('struct request') found in different ways.
# If v=0, print a summary only

def print_blkreq(v=0):
    # Request Queues per block_device
    print_request_queues(v)
    
    # Waiting for softirq processing on blk_cpu_done
    print_blk_cpu_done(v)
    
    print_request_slab(v)


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
    for l in exec_crash_command_bg('ps').splitlines()[1:]:
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
            comm = ''.join(spl[8:])
            out.append((pid, ppid, cpu, task, st, pmem, vsz, rss, comm))
        except:
            pylog.warning("cannot parse:", l)
    return out

# Compute the sum of all RSS memory used by applications. We cannot
# just some values from 'ps' output as it does not make difference between
# processes and threads. Hence, for multithreaded processes it reports
# the same memory multiple times

def user_space_memory_report():
    # Get processes/thread group leaders only
    
    tt = TaskTable()
    rss_tot = pmem_tot = 0
    # Get processes/thread group leaders only
    for pid, ppid, cpu, task, st, pmem, vsz, rss, comm in parse_ps():
        if (tt.getByPid(pid)):
            rss_tot += rss
            pmem_tot += pmem
    print ("RSS_TOTAL=%d pages, %%mem=%7.1f" % (rss_tot, pmem_tot))


# Check pcufreq-related problems:
# 1. is module pcc_cpufreq being loaded
__cpufreq_warn1 = '''
The CPU frequency governor "pcc_cpufreq" is in use. This is known to not scale
well beyond 4 CPUs and can have a deleterious effect on system performance,
consider disabling it via BIOS "Collaborative_Power_Control" setting or switch
the performance profile from "ondemand" to "performance" whilst online using 
cpupower(1).  Check for high sys% cpu for kworker threads.

For maximum performance also adjust BIOS "HP_Power_Regulator" to "
HP Static High Performance Mode". Optionally set to "OS control"  if regulation from the OS is still desired.
'''
# 2. are there related spinlocks in user
def check_pcc_cpufreq(_funcpids):
    mods = lsmod()
    if ('pcc_cpufreq' in mods):
        pylog.warning_onexit(__cpufreq_warn1)
    pids =  _funcpids('pcc_cpufreq_target')
    verifyFastSet(pids, 'queued_spin_lock_slowpath')
    verifyFastSet(pids, 'pcc_cpufreq_target')

    if(pids):
        pylog.warning_onexit('possible pcc_cpufreq spinlock contention problems')


__cssd_warning = '''
The server was performing a lot of IO writeback, this starved some tasks
from running beyond the timeout threshold of the cssdmonitor.

Recommendations:
    * change IO scheduler to noop or deadline
    * tune the non-ratio writeback kernel tunables 
    * consider altering the cssdmonitor timeout period 

'''

# A test of Oracle's cssdagenttriggering panic
def check_cssdagent(_funcpids, v = 0):
    # Check whether we are doing sync/fsync
    funcnames = 'sync_supers|reiserfs_sync_fs|sys_sync|sys_fdatasync|sys_fsync'
    subpids = _funcpids(funcnames)
    if (len(subpids) < 100):
        verifyFastSet(subpids, funcnames)
    if (subpids):
        pylog.warning("Panic while we were doing sync on FS")
        # First 5 pids
        if (v):
            print("  ... For example ....")
            pidstr = " ".join([str(i) for i in sorted(list(subpids))[:5]])
            for p in exec_bt("bt {}".format(pidstr)):
                print(p)
    pstack = exec_bt('bt')[0]
    if (not pstack.hasfunc('write_sysrq_trigger') or not 
        pstack.cmd in ('cssdagent, cssdmonitor')):
        return
    pylog.warning_onexit("Panic has been triggered explicitly by Oracle RAC {}".\
        format(pstack.cmd))
    if (not subpids):
        return
    
    # Find the oldest blk request
    rqlist = get_blkreq_fromslab()
    if (len(rqlist) < 20):
        # It is normal to have some outstanding requests
        return
    oldest = rqlist[-1][0]/HZ
    if (oldest > 10):
        pylog.warning_onexit("Something's wrong with SAN, controller or DM, the oldest"
            " request\n    has been put on queue {:8.2f}s ago".format(oldest))
    else:
        pylog.warning_onexit(__cssd_warning)
    
                        
            

    


# Check for long (>nmin) chains of processes. E.g. custom script is looping and
# spawns more and more processes recursively
#
# We should differentiate between parent and real parent in relationship
# analysis. Process can be reparented temporarily by ptrace

def longChainOfPids(tt, nmin):
    ntoprint = 12
    nbeg = ntoprint//2
    nend = ntoprint - nbeg
    ntot = 0
    leafs = []
    pidparent = {}
    for t in tt.allThreads():
        ntot += 1
        pid = t.pid
        if (pid == 0):
            continue
        if (not t.hasChildren()):
            leafs.append(pid)
        try:
            ppid = t.Realparent.pid
        except crash.error:
            pylog.error("corrupted", t)
            continue
        #print("{} => {}".format(pid, ppid))
        pidparent[pid] = ppid
    #print("{} total, {} leafs".format(ntot, len(leafs)))

    # For each leaf, follow its parents
    for l in leafs:
        chain = [l]
        pid = l
        # If tables is corrupted, we might loop forever - do extra check
        knownpids = {l}
        
        while(pid is not None):
            pid = pidparent.get(pid, None)
            if (pid in knownpids):
                pylog.error("Corrupted task table - pid/ppid loop at"
                    " pid={}".format(pid))
                break
            # Do not follow until 0, just until pid=1 is good enough
            if (pid is 0):
                break
            chain.insert(0, pid)
            knownpids.add(pid)

        chainlength = len(chain)
        if (chainlength >= nmin):
            pylog.warning("a long chain of processes, N={}, last pid={}".\
                format(chainlength, l))
            
            if (chainlength <= ntoprint):
                it_toprint = chain
            else:
                it_toprint = itertools.chain(chain[:nbeg], chain[-nend:])
            nmiddle = chainlength - ntoprint
            i = 0
            for pid in it_toprint:
                comm = tt.getByTid(pid).comm
                if (i == nbeg and chainlength > ntoprint):
                    print ('   {}--- <{} threads not printed> ---'.\
                        format(' '*i, nmiddle))
                    i += 1
                print ('  ', ' ' * i, pid, comm)
                i += 1
 
                    
                    
#  ==== Detect stack corruption ======
_longsize = getSizeOf("long int")


def checkTaskStack(task):
    thread_info = readSU("struct thread_info", task.stack)
    thread_struct = task.thread
    sp0 = thread_struct.sp0
    sp  = thread_struct.sp
    sz = len(thread_info)
    end_of_ti = ALIGN(long(thread_info) + sz, 16)
    #print(thread_info, "{} bytes".format(sz))
    #print("sp0={:#x} sp={:#x}".format(sp0, sp))
    
    # Test 1 - check pointers
    if (not (sp <= sp0 and sp >= end_of_ti)):
        return("SP out of boundaries")
        
    # Test 2 - check N long after thread_info
    N = 0
    for i in range(N):
        addr = end_of_ti + i * _longsize
        data = readLong(addr)
        if (data):
            #print("i={} addr={:#x} data={:#x} ".format(i, addr, data))
            return ("Last {} bytes of stack are not empty".format(N * _longsize))
    
    # Test 3 - check whatis(thread_info.restart_block.fn)
    sym = addr2sym(thread_info.restart_block.fn)
    if(not sym):
        return "Bad threadinfo pointer, stack.restart_block.fn"
    wi = whatis(sym)
    if (wi.ti.stype != '(func)'):
        return "Bad threadinfo, stack.restart_block.fn does not point to a function"
        
    return False

# Check for stack corruption for all tasks
def checkAllStacks():
    tt = TaskTable()

    for t in tt.allThreads():
        task = t.ts
        rc = checkTaskStack(task)
        if (rc):
            pylog.error("Corrupted Stack Detected\n\t%s\n\t  %s" % (str(t), rc))

# Check SG-specific things
def check_SG():
    tmp = DCache.tmp
    if (tmp.SG_deadman_timer and tmp.tcp_max_retrans):
        pylog.warning_onexit(__SG_retrans)

__SG_retrans = '''
The panic appears to have been caused by the deadman driver. There are also 
significant TCP retransmissions. This could potentially indicate a networking
issue affecting cluster or package communications over one or more network interfaces. Review the TCP connections that were being retransmitted to
determine if there are more general networking issues and if cluster or other
communications could have been impacted leading to the panic. Note that
the issue may not be on this system a networking component or the remote
system may no longer be responding.

Run 'xportshow --retrans' to see all retransmissions
'''

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

op.add_option("--checkstacks", dest="checkstacks", default = "",
                action="store_true",
                help=" Check stacks of all threads for corruption")

op.add_option("--decodesyscalls", dest="decodesyscalls", default = "",
                action="store",
                help="Decode Syscalls on the Stack")

op.add_option("--keventd_wq", dest="eventwq", default = "",
                action="store_true",
                help="Decode keventd_wq")

op.add_option("--kblockd_wq", dest="kblockdwq", default = "",
                action="store_true",
                help="Decode kblockd_workqueue")
                
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
                help="Print 'struct semaphore' info")

op.add_option("--rwsemaphore", dest="RWSema", default = 0,
                type="long", action="store",
                help="Print 'struct rw_semaphore' info")                

op.add_option("--mutex", dest="Mutex", default = 0,
                type="long", action="store",
                help="Print Mutex info")

op.add_option("--umem", dest="umem", default = "",
              action="store_true",
              help="Print User-space Memory Usage")
        
op.add_option("--ls", dest="ls", default = "",
                action="store",
                help="Emulate 'ls'. You can specify either dentry"
              " address or full pathname")

op.add_option("--workqueues", dest="Workqueue", default = "",
                action="store_true",
                help="Print Workqueues - just for some kernels")

op.add_option("--radix_tree_element", dest="RdElement", nargs=2,
                metavar='root offset',
                help="Find and print a radix tree element")


op.add_option("--pci", dest="Pci", default = "",
                action="store_true",
                help="Print PCI Info")               


op.add_option("--version", dest="Version", default = 0,
              action="store_true",
              help="Print program version and exit")


(o, args) = op.parse_args()


verbose = o.Verbose

if (o.Version):
    print ("CRASHINFO version %s" % (__version__))
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

if (o.RdElement):
    from LinuxDump.trees import radix_tree_lookup_element
    root = int(o.RdElement[0], 16)
    offset = int(o.RdElement[1], 16)
    node, slot = radix_tree_lookup_element(root, offset)
    if (node is None):
        print("   Not found")
    else:
        print("  node={:#x}, slot={:#x}".format(node, slot))
    sys.exit(0)
  
if (o.Pci):
    from LinuxDump.pci import *
    print_PCI_devices(verbose)
    print_PCI_resources(verbose)
    sys.exit(0)

if (o.sysctl):
    check_sysctl()
    sys.exit(0)

if (o.findstacks):
    find_stacks(o.findstacks.strip('\'"'))
    sys.exit(0)

if (o.checkstacks):
    checkAllStacks()
    pylog.cleanup()
    sys.exit(0)

if (o.eventwq):
    try:
        _wq = readSymbol("keventd_wq")
        decode_wq(_wq)
    except TypeError:
        print("The command is not supported for this kernel")
    sys.exit(0)
    
if (o.kblockdwq):
    try:
        _wq = readSymbol("kblockd_workqueue")
        decode_wq(_wq)
    except TypeError:
        print("The command is not supported for this kernel")
    sys.exit(0)
    
if (o.Blkreq):
    if (verbose == 4):
        verbose = -1
    print_blkreq(verbose)
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

if (o.RWSema):
    decode_rwsemaphore(o.RWSema)
    sys.exit(0)    

if (o.Mutex):
    decode_mutex(o.Mutex)
    sys.exit(0)

if (o.Workqueue):
    try:
        from LinuxDump.WorkQueues import print_all_workqueues
    except:
        print("Workqueues analysis not implemented for this kernel")
        sys.exit(0)
    print_all_workqueues(verbose)
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

stacks_helper = fastSubroutineStacks()
_funcpids = stacks_helper.find_pids_byfuncname

print_basics()
dump_reason(dmesg)
check_loadavg()
longChainOfPids(TaskTable(), 20)

if (not quiet):
    printHeader("Tasks Summary")
    threadcount = tasksSummary()

if (not quiet):
    print_args5()
#check_activetasks()
#check_spinlocks()
check_mem()

# Tests that make sense for non-panic situations
print_blkreq(-1)

# Panics triggered by Oracle RAC
check_cssdagent(_funcpids, verbose)

# Check gendisk structures
print_gendisk(0)

check_UNINTERRUPTIBLE()
# The next test is very slow and I have never seen it to be useful
#check_auditf()

try:
    check_frozen_fs()
except:
    pylog.warning("Frozen FS test not implemented on this kernel")

try:
    check_runqueues()
except crash.error:
    pylog.warning("cannot continue - the dump is probably incomplete", \
        "or corrupted")

try:    
    check_network()
except crash.error:
    pylog.warning("cannot continue - the dump is probably incomplete "
            "or corrupted")

try:
    if (not sys_info.livedump):
        checkAllStacks()
except:
    # For those kernels where are test does not work
    pass

# Check RSS used
user_space_memory_report()

# Check pcc_cpufreq
check_pcc_cpufreq(_funcpids)

# Check hangs/memory pressure/SAP HANA stuff
_SAPHANA = check_saphana()
_p_hang = check_possible_hang()
if (_p_hang):
    pylog.warning("   Run 'hanginfo' to get more details")
_p_memory_pressure = check_memory_pressure(_funcpids)

_p_hanging_nfsd = check_hanging_nfsd(_funcpids)


if (_p_memory_pressure and _p_hanging_nfsd):
    pylog.warning("A host with hanging NFSD and memory pressure"
        "\n\tRun 'nfsshow' to see whether we have loopback NFS mount"
        "\n\tand if yes, see LWN article https://lwn.net/Articles/595652")

if (_SAPHANA == 2 and _p_hang and _p_memory_pressure):
    pylog.warning("This host is running SAP HANA and is under memory pressure"
        "\n\tMost probably, it is not properly tuned and this is the root cause"
        "\n\tof the hang"
        "\n\tRun 'hanginfo --saphana' for explanations and tuning suggestions")


# After this line we put all routines that can produce significant output
# We don't want to see hundreds of lines in the beginning!
if (not quiet):
    print_mount()
    print_dmesg()

print_wait_for_AF_UNIX(-1)

# Ad-hoc tests
from LinuxDump.specialcases import check_specialcases
check_specialcases()

if (verbose):
    printHeader("A Summary Of Threads Stacks")
    stackSummary()

check_SG()
