#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2018 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------
#  Analyze reasons why some tasks are hanging (TASK_UNINTERRUPTIBLE)


__version__ = "0.4.1"

import sys
import re

from pykdump.API import *
from LinuxDump.fs import *
from LinuxDump.Tasks import (TaskTable, Task, tasksSummary, ms2uptime, 
                             decode_tflags, decode_waitq, TASK_STATE)
from LinuxDump.BTstack import (exec_bt, bt_mergestacks, fastSubroutineStacks,
                               verifyFastSet)

from LinuxDump.Analysis import (print_wait_for_AF_UNIX, print_pidlist,
                                check_possible_hang,
                                check_saphana, check_memory_pressure,
                                get_tentative_arg)                                

from LinuxDump.Files import pidFiles
from LinuxDump.KernLocks import (decode_semaphore, get_rwsemaphore_tasks,
                                 get_mutex_waiters)
from pykdump.Misc import AA_Node

from collections import namedtuple, defaultdict

debug = API_options.debug

# Resource owners - that is, threads that own some mutex/sema etc. that
# other threads are waiting on

__resource_owners = set()
__resource_owner_extra = defaultdict(set)      # pids owned by us

def resource_owners_clear():
    __resource_owners.clear()
    __resource_owner_extra.clear()
    
def add_resource_pid(pid, extra = set()):
    __resource_owners.add(pid)
    __resource_owner_extra[pid] |= extra
    
# Debugging
def _print_wait_tree():
    print("\n+++ Debugging +++")
    print(__resource_owners)
    print("Extra:", __resource_owner_extra)

def print_wait_tree():
    __owners = __resource_owner_extra
    # Create a set of small branches
    branches = set()
    for top, children in __owners.items():
        # If it is an empty set, do nothing
        if (not children):
            continue
        top = AA_Node(top)
        branches.add(top)
        for c in children:
            leaf = AA_Node(c, top)
    # Now glue small branches together
    for b in branches:
        for bo in branches:
            if (bo == b):
                continue
            bo.glue(b)

    topbranches = {b for b in branches if b.parent is None}
    for b in topbranches:
        print('-'*78)
        #print(b)
        sys.stdout.flush()
        sys.stdout.buffer.write(str(b.HorTree()).encode("utf8"))
        #print(b.HorTree())
        print()
        sys.stdout.flush()


# Print header: what we are waiting for and number of pids
def print_header(msg, n = None):
    print("\n {:=^60}".format(" " + msg + " "))

# Get UNINTERRUPTIBLE tasks
# In reality, get STOPPED, TRACED, ZOMBIE, DEAD and WAKING etc too - 
# everygthing > 1
# Return a set of pids/tids
#@memoize_cond(CU_LIVE)
def getUNTasks():
    return {t.pid for t in T_table.allThreads() \
        if t.ts.state & TASK_STATE.TASK_UNINTERRUPTIBLE}

# Remove a list of pids from the provided dictionary
def remove_pidlist(pset, pids):
    pset -= set(pids)


# A test to check heuristically whether a pointer looks like mutex
# On RHEL6 and later
#struct mutex {
    #atomic_t count;
    #spinlock_t wait_lock;
    #struct list_head wait_list;
    #struct thread_info *owner;
#}

# On RHEL5, no 'owner'

# In some cases, owner=NULL
# We return:
# 0 - this is not a mutex
# 1 - this is a mutex with owner=NULL
# 2 - this is a mutex with owner
def if_mutexOK(addr):
    try:
        mutex = readSU("struct mutex", addr)
        wait_list = mutex.wait_list
        _next_wait_list = wait_list.next
        try:
            owner = mutex.Owner
        except KeyError:
            owner = None
        # Does counter look reasonable?
        counter = mutex.count.counter
        if (counter < -1000 or counter > 1000):
            return 0
        if (owner):
            _next_tasks = owner.tasks.next
        for i in range(5):
            _next_wait_list = _next_wait_list.next 
            if (owner and _next_tasks):
                _next_tasks = _next_tasks.next
        return 2 if owner else 1
    except:
        return 0


structSetAttr("struct mutex", "Owner", ["owner.task", "owner"])
# Try to classify the mutex and print its type and its owner
def print_mutex(mutex, pids = set()):
    mtype = ''
    if (long(mutex) == sym2addr("rtnl_mutex")):
        mtype = "rtnl_mutex"
    else:
        kmem_s = exec_crash_command("kmem -s {:#x}".format(mutex),
                                    1).splitlines()
        if (len(kmem_s) > 1):
            mtype = kmem_s[1].split()[1]
    # Try to get the owner
    if (mutex.hasField("owner") and mutex.owner):
        ownertask = mutex.Owner
        ownerpid = ownertask.pid
    else:
        ownertask = ''
    if (ownertask):
        add_resource_pid(ownerpid, pids)
        ownertask = "\n   Owner: pid={0.pid} cmd={0.comm}".format(ownertask)
    else:
        ownertask = "\n   No Owner"
    print("  -- {} {} {}".format(mutex, mtype, ownertask))
            
        

# stack data consists of lines like
#    ffff8b71e4a21558: 0000000000000082 ffff8b71e4a20010 
#    ffff8b71e4a21568: 0000000000011800 0000000000011800 

# For x86 (32 bits):
#    [RA: c06278ad  SP: e0ad1e28  FP: e0ad1e40  SIZE: 28]
#    e0ad1e28: ed826aec  ed826aec  d62354d0  ed826ae4  
#    e0ad1e38: 00000000  ed826a70  c06278ad  

# Convert it to an array of integers

def __stackdata2array(lines):
    arr = []
    for l in lines:
        l = l.strip()
        # For 32-bit x86, skip line starting with [
        if (l[0] == '['):
            continue
        for d in re.split(r'[:\s]+', l)[1:]:
            arr.append(int(d, 16))
    return arr


# Print backing_dev_info
def print_backing_dev_info(bdi):
    work_list = bdi.work_list
    lh = ListHead(work_list, "struct wb_writeback_work")
    task = bdi.wb.task
    print(" ------ {}, {} PID={}".format(
        str(bdi), task.comm, task.pid))
    for wb in lh.list:
        print(wb)
    print_bdi_writeback(bdi.wb)

# BDI wb_writeback
def print_bdi_writeback(wb):
    for inode in ListHead(wb.b_io.prev, 'struct inode').i_list:
        print(inode, inode.i_state, inode.i_mapping)

# To find possible mmap semaphore owners, we get a list of
# RU/UN threads that have this mmap_sem and have a credible
# subroutine on the stack
def get_sema_owners():
    tt = T_table
    out = defaultdict(list)
    goodpids = _funcpids("do_page_fault|do_page_fault")
    #goodpids = funcpids["do_page_fault"] | funcpids["dup_mm"]
    #print(goodpids)
    for t in tt.allThreads():
        if (not t.pid in goodpids):
            continue
        if (t.ts.state in (TASK_STATE.TASK_RUNNING, TASK_STATE.TASK_UNINTERRUPTIBLE)):
            out[t.mm.mmap_sem].append(t.pid)
    return out

# Print statistics for threads having a given subroutine on the stack
def summarize_subroutines(funcnames, title = None):
    subpids = _funcpids(funcnames)
    # funcnames are specified using | operator
    if (not subpids):
        return
    if (len(subpids) < 100):
        verifyFastSet(subpids, funcnames)
    if (not subpids):
        return
    d = defaultdict(int)
    total = 0
    for pid in subpids:
        t = T_table.getByTid(pid)
        d[t.state] += 1
        total += 1
    # Print
    if (title):
        header = "There are {} threads {}".format(total, title)
    else:
        header = "There are {} threads doing {}".format(total, funcnames)
    print_header(header)
    for k,v in d.items():
        print("  {:3d} in {}".format(v, k))
    print_pidlist(subpids, maxpids = _MAXPIDS, verbose = _VERBOSE,
                  sortbytime = _SORTBYTIME)


# Find all PIDs that match a give mm,mmap_sem address
def find_pids_mmap(addr):
    tt = T_table
    for t in tt.allThreads():
        if (long(t.mm.mmap_sem) == long(addr)):
            print(t.pid)

#
# ============= Check subroutines =======================
#
def check_mmap_sem(tasksrem):
    waiters = {}
    for addr in stacks_helper.alltaskaddrs:
        task = readSU("struct task_struct", addr)
        if (not task.mm or not task.mm.mmap_sem):
            continue
        s = task.mm.mmap_sem
        cmsg = "task={} mmap_sem={}".format(task, s)
        with MsgExtra(cmsg):
            wtasks = get_rwsemaphore_tasks(s)

        pids = [t.pid for t in wtasks]
        if (pids):
            waiters[s] = pids

    mmapsem_waiters = waiters
    possible_owners = get_sema_owners()
    if (mmapsem_waiters):
        print_header("Waiting on mmap semaphores")
        for sema, pids in mmapsem_waiters.items():
            print ("  --", sema)
            print_pidlist(pids, maxpids = _MAXPIDS, verbose = _VERBOSE,
                          sortbytime = _SORTBYTIME)
            powners = possible_owners.get(sema, None)
            if (powners):
                pid_set = set(pids)
                powners = set(powners)
                # Leave only those powners that are not in pids
                rem = powners - pid_set
                print("        Possible owners:", list(rem))
                for o in rem:
                    add_resource_pid(o)
            remove_pidlist(tasksrem, pids)

      

def check_inode_mutexes(tasksrem):
    goodpids = _funcpids(__mutexfunc +\
        "| __mutex_lock_killable_slowpath")
    inode_addrs = {}
    for pid in goodpids:
        finfo = pidFiles(pid).files
        for fd in finfo:
            fields = finfo[fd]
            inode_addr = fields[2]
            ftype = fields[3]
            path = fields[4]
            if (ftype not in ('REG', 'DIR', 'PIPE')):
                continue
    
            inode_addrs[inode_addr] = path
    
    #print(len(inode_addrs))
    waiters = {}
    for inodeaddr, v in inode_addrs.items():
        inode = readSU("struct inode", inodeaddr)
        #print(hex(inode), v)
        # 1: unlocked, 0: locked, negative: locked, possible waiters
        counter = inode.i_mutex.count.counter
        if (counter >= 0):
            continue
        mutex = inode.i_mutex
        print(mutex)
        wait_tasks = get_mutex_waiters(mutex)
        pids = [t.pid for t in wait_tasks]
        waiters[inode] = (v, pids)

    mutex_waiters = waiters
    if (mutex_waiters):
        print_header("Waiting on inode mutexes")
        for inode, (fn, pids) in mutex_waiters.items():
            print ("  --", inode, fn)
            print_mutex(inode.i_mutex, set(pids))
            print_pidlist(pids, maxpids = _MAXPIDS, verbose = _VERBOSE,
                          sortbytime = _SORTBYTIME)
            remove_pidlist(tasksrem, pids)


# Check cred_guard_mutex. 
# Older kernels: this is task.cred_guard_mutex
# Newer kernels: this is task.signal.cred_guard_mutex
structSetAttr("struct task_struct", "Cred_guard_mutex", 
              ["cred_guard_mutex", "signal.cred_guard_mutex"])

def check_cred_guard_mutex(task):
    gm = task.Cred_guard_mutex
    return gm
    
__mutexfunc = "__mutex_lock_slowpath"
def check_other_mutexes(tasksrem):
    #print(mutexlist)
    mutexlist = set()
    goodpids = _funcpids(__mutexfunc)
    for pid in tasksrem:
        if (not pid in goodpids):
        #if (not bt.hasfunc(__mutexfunc)):
            continue
        maddr = get_tentative_arg(pid, __mutexfunc, 0)
        #print("pid={} addr={:#x} OK={}".format(pid, maddr, if_mutexOK(maddr)))
        if (maddr and if_mutexOK(maddr)):
            mutex = readSU("struct mutex", maddr)
            mutexlist.add(mutex)
            #print("pid={}, mutex={}".format(pid, mutex))
            continue

    if (not mutexlist):
        return
    # Now print info about each found mutex
    once = TrueOnce(1)
    for mutex in mutexlist:
        try:
            owner = mutex.Owner
        except KeyError:
            owner = None
        # Sometimes we cannot get this mutex
        try:
            pids = [t.pid for t in get_mutex_waiters(mutex)]
        except:
            pylog.warning("Cannot get waiters for mutex {}".format(mutex))
            continue
        if (owner and not pids):
            continue
        if (once):
            print_header("Waiting on mutexes")
        print_mutex(mutex, set(pids))
        print_pidlist(pids, maxpids = _MAXPIDS, verbose = _VERBOSE,
                      sortbytime = _SORTBYTIME)
        remove_pidlist(tasksrem, pids)


def check_congestion_queues(tasksrem):
    # Congestion queues    
    for i, wqh in enumerate(readSymbol("congestion_wqh")):
        pids = []
        try:
            text = exec_crash_command("waitq 0x%x" % long(wqh)).strip()
        except crash.error:
            continue
        if (not re.match(r'^.*is empty$', text)):
            for l in text.splitlines():
                fields = l.split()
                pids.append(int(fields[1]))
    
        if (pids):
            if (i == 0):
                print(" ---- waiting on the read congestion queue ---")
            else:
                print(" ---- waiting on the write congestion queue ---")
            print_pidlist(pids, maxpids = _MAXPIDS, verbose = _VERBOSE,
                          sortbytime = _SORTBYTIME)
            remove_pidlist(tasksrem, pids)

# Check and print based on functions on the stack
def check_stack_and_print(funcname, tasksrem, txt = None):
    pids = _funcpids(funcname) & tasksrem
    verifyFastSet(pids, funcname)
    if (not pids):
        return
    if (txt is None):
        txt = funcname
    print_header("Waiting in {}".format(txt))
    print_pidlist(pids, maxpids = _MAXPIDS, verbose = _VERBOSE,
                  sortbytime = _SORTBYTIME)
    add_resource_pid(txt, set(pids))
    remove_pidlist(tasksrem, pids)


# kthread_create_list

def check_kthread_create_list(tasksrem):
    try:
        head = ListHead(readSymbol("kthread_create_list"),
                        "struct kthread_create_info")
    except TypeError:
        return
    tasks = []
    for create in head.list:
        tasks += decode_waitq(create.done.wait)

    pids_on_the_queue = [t.pid for t in tasks]
    
    # Check pids of processes having kthread_create_on_node
    extra = _funcpids("kthread_create_on_node")
    extra = list( extra - set(pids_on_the_queue))
    
    if (tasks):
        print_header("Waiting for kthreadd")
        print_pidlist(pids_on_the_queue, title="On the queue: ",
                      maxpids = _MAXPIDS, verbose = _VERBOSE,
                      sortbytime = _SORTBYTIME)
        if (extra):
            print("   Dequeued but not processed yet: {}".format(extra))
        remove_pidlist(tasksrem, pids_on_the_queue + extra)

 
# Check threads that have throttle_direct_reclaim
# They are waiting for kswapd
__tdr_func = "throttle_direct_reclaim"
def check_throttle_direct_reclaim(tasksrem):
    pids = _funcpids(__tdr_func)
    verifyFastSet(pids, __tdr_func)
    if (pids):
        print_header("Waiting for kswapd")
        print_pidlist(pids, maxpids = _MAXPIDS, verbose = _VERBOSE, 
                      sortbytime = _SORTBYTIME, statefilter = ('UN',))
        remove_pidlist(tasksrem, pids)
        

# Threads waiting on console_sem
def check_console_sem(tasksrem):
    console_sem_addr = sym2addr("console_sem")
    if (not console_sem_addr):
        return
    pidcomms = decode_semaphore(console_sem_addr, 0)
    if (pidcomms):
        print_header("Waiting on console_sem")
        for pid, comm in pidcomms:
            print ("\t{:8d}  {}".format(pid, comm))
    remove_pidlist(tasksrem, [pid for pid, comm in pidcomms])
    # Try to find a possible owner
    __testfunc = "__console_unlock"
    pids = _funcpids(__testfunc)
    verifyFastSet(pids, __testfunc)
    if (pids):
        print("    Possible owners: {}".format(pids))

__waitonbitfunc = "out_of_line_wait_on_bit"
def check_wait_on_bit(tasksrem):
    #print(mutexlist)
    mutexlist = set()
    goodpids = _funcpids(__mutexfunc)
    for pid in tasksrem:
        if (not pid in goodpids):
        #if (not bt.hasfunc(__mutexfunc)):
            continue

        
# ==============end of check subroutines=======================   
       

# Classify UNINTERRUPTIBLE threads
def classify_UN(v):
    # Reset owners
    resource_owners_clear()
    # We get a list of UN tasks
    tasksrem = getUNTasks()
    
    if (not tasksrem):
        print ("There are no UNINTERRUPTIBLE tasks")
        return

    print (" *** UNINTERRUPTIBLE threads, classified ***")

    # Now we are do a number of tests trying to classify the threads
    # Every time we succeed, we remove these threads from tasksrem
    check_stack_and_print('io_schedule', tasksrem)
    check_stack_and_print('btrfs_tree_read_lock', tasksrem)
    check_inode_mutexes(tasksrem)
    check_other_mutexes(tasksrem)
    check_mmap_sem(tasksrem)
    check_congestion_queues(tasksrem)
    check_kthread_create_list(tasksrem)
    check_throttle_direct_reclaim(tasksrem)
    check_console_sem(tasksrem)
    check_stack_and_print('schedule_timeout', tasksrem)
    check_stack_and_print('alloc_pages_slowpath', tasksrem)
    check_stack_and_print('nfs_idmap_id', tasksrem, "NFS idmapper")


    if (tasksrem):
        print ("\n\n ********  Non-classified UN Threads ********** {}"
            " in total".format(len(tasksrem)))
        # Print what remains
        btlist = []
        for pid in tasksrem:
            try:
                btlist.append(exec_bt("bt %d" % pid)[0])
            except IndexError:
                pylog.warning("Cannot get stack for PID={}".format(pid))
        #btlist = [exec_bt("bt %d" % pid)[0] for pid in tasksrem]
        bt_mergestacks(btlist, verbose=1)
    #print(un)
    # Print resource owners. We have two kinds: real pids and pseudo-owners,
    # such as "io_schedule"
    __real_owners = {x for x in __resource_owners if isinstance(x, int)}
    __pseudo_owners = __resource_owners - __real_owners
    if (__real_owners):
        print("\n*** Threads that own resources the other threads are"
            " waiting on ***")
        for pid in __real_owners:
            s = exec_bt("bt {}".format(pid))[0]
            print(s)
            print(__resource_owner_extra[pid])
    if (__pseudo_owners):
        print("\n*** System activities other threads are waiting for ***")
        for pid in __pseudo_owners:
            print("  --- Doing {} ---".format(pid))
            print(__resource_owner_extra[pid])
        

    # Are any of these owners looping in zone allocator?
    #_owners = zvm_pids & rem
    #if (_owners):
    #    print("        Looping in zone allocator:", list(_owners))
    return

    # The following code is not ready yet
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        sb = readSU("struct super_block", superblk)
        um = sb.s_umount
        if (um.count):
            print(devname, sb)
            bdi = sb.s_bdi
            if (bdi):
                print_backing_dev_info(bdi)
        #print(um.activity, um.wait_lock.raw_lock.slock, devname)


if ( __name__ == '__main__'):
    from optparse import OptionParser
    op =  OptionParser()

    op.add_option("-v", dest="Verbose", default = 0,
                action="count",
                help="verbose output")    

    op.add_option("--version", dest="Version", default = 0,
                  action="store_true",
                  help="Print program version and exit")

    op.add_option("--maxpids", dest="Maxpids", default = 10,
                  action="store", type='int',
                  help="Maximum number of PIDs to print")
    
    op.add_option("--sortbypid", dest="Sortbypid", default = 0,
                  action="store_true",
                  help="Sort by pid (the default is by ran_ago)")
    
    op.add_option("--syslogger", dest="Syslogger", default = 0,
                  action="store_true",
                  help="Print info about hangs on AF_UNIX sockets (such as used by syslogd")

    op.add_option("--tree", dest="Tree", default = 0,
                  action="store_true",
                  help="Print tree of resources owners  (experimental!)")

    op.add_option("--saphana", dest="Saphana", default = 0,
                  action="store_true",
                  help="Print recommendations for SAP HANA specific hangs")

    (o, args) = op.parse_args()
    
    v = _VERBOSE = o.Verbose
    _PRINT_TREE = o.Tree
    _MAXPIDS = o.Maxpids
    _SORTBYTIME = not o.Sortbypid
    T_table = TaskTable()
    _SAPHANA = check_saphana()
    
    if (o.Version):
        print ("HANGINFO version %s" % (__version__))
        sys.exit(0)

    if (o.Syslogger):
        print_wait_for_AF_UNIX(_VERBOSE)
        sys.exit(0)

    if (o.Saphana):
        try:
            from LinuxDump.SapHana import doSapHana
        except ImportError:
            def doSapHana():
                print("See https://www.suse.com/documentation/sles_for_sap_11/book_s4s/data/s4s_configuration.html")
        if _SAPHANA == 2:
            doSapHana()
        else:
            print("This host is _not_ running SAP HANA!")
        sys.exit(0)
       
    stacks_helper = fastSubroutineStacks()
    _funcpids = stacks_helper.find_pids_byfuncname
    


    classify_UN(v)

    summarize_subroutines("shrink_all_zones|shrink_zone",
                                 title='shrinking zone')
    summarize_subroutines("shrink_slab")
   
    summarize_subroutines("balance_dirty_pages")
    
    print("\n")
    print_wait_for_AF_UNIX(0)

    _p_hang = check_possible_hang()
    _p_memory_pressure = check_memory_pressure(_funcpids)
    
    if (_SAPHANA == 2 and _p_hang and _p_memory_pressure):
        pylog.warning("This host is running SAP HANA and is under memory pressure"
            "\n\tMost probably, it is not properly tuned and this is the root cause"
            "\n\tof the hang"
            "\n\tRun 'hanginfo --saphana' for explanations and tuning suggestions")
 
    if (_PRINT_TREE):
        #_print_wait_tree()
        print_wait_tree()
