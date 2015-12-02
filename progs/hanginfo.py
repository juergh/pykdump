#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------
#  Analyze reasons why some tasks are hanging (TASK_UNINTERRUPTIBLE)

# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function

__version__ = "0.3"

import sys
import re
import textwrap
import operator

from pykdump.API import *
from LinuxDump.fs import *

from pykdump.API import *
from pykdump.Generic import Bunch

from LinuxDump import percpu
from LinuxDump.Tasks import (TaskTable, Task, tasksSummary, ms2uptime, decode_tflags,
                             decode_waitq, TASK_STATE)
from LinuxDump.BTstack import (exec_bt, bt_mergestacks,
                               get_threads_subroutines, verifyFastSet)
from LinuxDump.inet import proto
from LinuxDump.Analysis import print_wait_for_AF_UNIX
from LinuxDump.Files import pidFiles

from collections import namedtuple, defaultdict

debug = API_options.debug

# Resource owners - that is, threads that own some mutex/sema etc. that
# other threads are waiting on

__resource_owners = set()

# Print header: what we are waiting for and number of pids
def print_header(msg, n = None):
    print("\n {:=^50}".format(" " + msg + " "))

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

# Print pidlist according to verbosity setting
def print_pidlist(pids):
    # Prepare a list of (ran_ms_ago, pid) list to sort them
    mlist = []
    for pid in pids:
        t = T_table.getByTid(pid)
        mlist.append((t.Ran_ago, pid))
    mlist = sorted(mlist)
    if (verbose):
        print("        PID     Ran ms ago")
        print("       -----   ------------")
        for ran_ms_ago, pid in mlist:
            print("    %8d  %10d" % (pid, ran_ms_ago))
    else:
        ran_y = mlist[0][0]
        ran_o = mlist[-1][0]
        spids = [p[1] for p in mlist]
        print("    Sorted pids (youngest first) [%d, %d] ms ago" % \
            (ran_y, ran_o))
        print(textwrap.fill(str(spids), initial_indent=' '*6, subsequent_indent=' ' *7))

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
        owner = mutex.Owner
        if (owner):
            _next_tasks = owner.tasks.next
        for i in range(5):
            _next_wait_list = _next_wait_list.next 
            if (owner):
                _next_tasks = _next_tasks.next
        return 2 if owner else 1
    except:
        return 0

# Get a list of pids waiting on mutex
def get_mutex_waiters(mutex):
    if (mutex.Owner and mutex.count.counter >= 0):
        return []
    wait_list = readSUListFromHead(Addr(mutex.wait_list), "list",
            "struct mutex_waiter")
    return [w.task.pid for w in wait_list]

structSetAttr("struct mutex", "Owner", ["owner.task", "owner"])
# Try to classify the mutex and print its type and its owner
def print_mutex(mutex):
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
        __resource_owners.add(ownerpid)
        ownertask = "\n   Owner: pid={0.pid} cmd={0.comm}".format(ownertask)
    else:
        ownertask = "\n   No Owner"
    print("  -- {} {} {}".format(mutex, mtype, ownertask))
            
        

# stack data consists of lines like
#    ffff8b71e4a21558: 0000000000000082 ffff8b71e4a20010 
#    ffff8b71e4a21568: 0000000000011800 0000000000011800 

# Convert it to an array of integers

def __stackdata2array(lines):
    arr = []
    for l in lines:
        for d in re.split(r'[:\s]+', l.strip())[1:]:
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
    goodpids = funcpids["do_page_fault"] | funcpids["dup_mm"]
    #print(goodpids)
    for t in tt.allThreads():
        if (not t.pid in goodpids):
            continue
        if (t.ts.state in (TASK_STATE.TASK_RUNNING, TASK_STATE.TASK_UNINTERRUPTIBLE)):
            out[t.mm.mmap_sem].append(t.pid)
    return out

# Print statistics for threads trying to srhink zones. 
__shrinkfunc = "shrink_all_zones"
def find_shrinkzones():
    shrinkpids = funcpids[__shrinkfunc] | funcpids["shrink_zone"]
    # we do not need to be 100% sure, this is just for information
    #verifyFastSet(shrinkpids, __shrinkfunc)
    if (not shrinkpids):
        return
    d = defaultdict(int)
    total = 0
    for pid in shrinkpids:
        t = T_table.getByTid(pid)
        d[t.state] += 1
        total += 1
    # Print
    print_header(" There are {} threads shrinking zone".format(total))
    for k,v in d.items():
        print("  {:3d} in {}".format(v, k))


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
    for addr in alltaskaddrs:
        task = readSU("struct task_struct", addr)
        if (not task.mm or not task.mm.mmap_sem):
            continue
        s = task.mm.mmap_sem
        #wait_list elements are embedded in struct rwsem_waiter
        wait_list = readSUListFromHead(Addr(s.wait_list), "list",
                "struct rwsem_waiter")
        pids = [w.task.pid for w in wait_list]
        if (pids):
            waiters[s] = pids

    mmapsem_waiters = waiters
    possible_owners = get_sema_owners()
    if (mmapsem_waiters):
        print_header("Waiting on mmap semaphores")
        for sema, pids in mmapsem_waiters.items():
            print ("  --", sema)
            print_pidlist(pids)
            powners = possible_owners.get(sema, None)
            if (powners):
                pid_set = set(pids)
                powners = set(powners)
                # Leave only those powners that are not in pids
                rem = powners - pid_set
                print("        Possible owners:", list(rem))
                for o in rem:
                    __resource_owners.add(o)
            remove_pidlist(tasksrem, pids)

      

def check_inode_mutexes(tasksrem):
    goodpids = funcpids[__mutexfunc] | \
        funcpids["__mutex_lock_killable_slowpath"]
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
        wait_list = readSUListFromHead(Addr(mutex.wait_list), "list",
             "struct mutex_waiter")
        pids = [w.task.pid for w in wait_list]
        waiters[inode] = (v, pids)

    mutex_waiters = waiters
    if (mutex_waiters):
        print_header("Waiting on inode mutexes")
        for inode, (fn, pids) in mutex_waiters.items():
            print ("  --", inode, fn)
            print_mutex(inode.i_mutex)
            print_pidlist(pids)
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
    goodpids = funcpids[__mutexfunc]
    for pid in tasksrem:
        if (not pid in goodpids):
        #if (not bt.hasfunc(__mutexfunc)):
            continue
        #print(bt)
        b1 = exec_bt("bt -f {}".format(pid))[0]
        for f in b1.frames:
            if (f.func.find(__mutexfunc) != -1):
                addrs = __stackdata2array(f.data)
                l_addrs = len(addrs)
                for pos in range(6,9):
                    if (pos >= l_addrs):
                        continue
                    maddr = addrs[pos]
                    if (if_mutexOK(maddr)):
                        mutex = readSU("struct mutex", maddr)
                        mutexlist.add(mutex)
                        continue

    if (not mutexlist):
        return
    # Now print info about each found mutex
    once = TrueOnce(1)
    for mutex in mutexlist:
        owner = mutex.Owner
        pids = get_mutex_waiters(mutex)
        if (owner and not pids):
            continue
        if (once):
            print_header("Waiting on mutexes")
        print_mutex(mutex)
        print_pidlist(pids)
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
                print(textwrap.fill(str(pids), initial_indent=' '*3, subsequent_indent=' ' *4))
                remove_pidlist(tasksrem, pids)

# Check and print based on functions on the stack
def check_stack_and_print(funcname, tasksrem):
    pids = funcpids[funcname] & tasksrem
    verifyFastSet(pids, funcname)
    if (not pids):
        return
    print_header("Waiting in {}".format(funcname))
    print_pidlist(pids)
    remove_pidlist(tasksrem, pids)


# ==============end of check subroutines=======================   
       

# Classify UNINTERRUPTIBLE threads
def classify_UN(v):
    # Reset owners
    __resource_owners.clear()
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
    # Print resource owners
    if (__resource_owners):
        print("\n*** Threads that own resources the other threads are"
            " waiting on ***")
        for pid in __resource_owners:
            s = exec_bt("bt {}".format(pid))[0]
            print(s)
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

    op.add_option("--syslogger", dest="Syslogger", default = 0,
                  action="store_true",
                  help="Print info about hangs on AF_UNIX sockets (such as used by syslogd")

    (o, args) = op.parse_args()
    
    v = verbose = o.Verbose
    T_table = TaskTable()
    if (o.Version):
        print ("HANGINFO version %s" % (__version__))
        sys.exit(0)
        
    if (o.Syslogger):
        print_wait_for_AF_UNIX(verbose)
        sys.exit(0)
     
    funcpids, functasks, alltaskaddrs  = get_threads_subroutines()
    #find_shrinkzones()
    #for pid in funcsMatch(funcpids, r'^io_schedule'):
    #    print(pid)
    
    #sys.exit(0)    
    zvm_pids = set(funcpids[__shrinkfunc])

    #find_pids_mmap(0xffff8b1b7c858ee0)
    #sys.exit(0)
    classify_UN(v)
    find_shrinkzones()
    
    print("\n")
    print_wait_for_AF_UNIX(0)

