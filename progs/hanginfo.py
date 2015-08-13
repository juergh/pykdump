#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2015 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------
#  Analyze reasons why some tasks are hanging (TASK_UNINTERRUPTIBLE)

# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function

__version__ = "0.2"

import sys
import textwrap
import operator

from pykdump.API import *
from LinuxDump.fs import *

from pykdump.API import *
from pykdump.Generic import Bunch

from LinuxDump import percpu
from LinuxDump.Tasks import TaskTable, Task, tasksSummary, ms2uptime, decode_tflags, decode_waitq
from LinuxDump.BTstack import exec_bt, bt_summarize, bt_mergestacks
from LinuxDump.inet import proto
from LinuxDump.Analysis import print_wait_for_AF_UNIX

from collections import namedtuple, defaultdict

debug = API_options.debug

#@memoize_cond(CU_LIVE)
def getUNTasks():
    basems = None
    #quit()
    tt = TaskTable()
    if (debug):
        print ("Basems", tt.basems, "Uptime:",  ms2uptime(tt.basems))
    

    out = []
    basems = tt.basems
    

    # Most recent first
    for t in tt.allThreads():
        out.append((basems - t.Last_ran, t.pid, t))
    out.sort()

    outUN = {}
    #print (" PID          CMD       CPU   Ran ms ago   STATE")
    #print ("--------   ------------  --  ------------- -----")

    for ran_ms_ago, pid, t in out:
        sstate = t.state[5:7]
        if (sstate != 'UN'):
            continue
        
        b = Bunch()
        b.ran_ms_ago = ran_ms_ago
        bt = exec_bt("bt %d" % pid)[0]
        b.bt = bt
        outUN[pid] = b
    return outUN

# Print pidlist according to verbosity setting
def print_pidlist(pids, tasksref):
    # Prepare a list of (ran_ms_ago, pid) list to sort them
    mlist = []
    for pid in pids:
        b = tasksref[pid]
        mlist.append((b.ran_ms_ago, pid))
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
        
def check_all_tasks():
    lines = memoize_cond(CU_LIVE)(exec_crash_command)("ps")
    waiters = {}
    for l in lines.splitlines()[1:]:
        fields = l[1:].split()
        task = readSU("struct task_struct", int(fields[3], 16))
        if (not task.mm or not task.mm.mmap_sem):
            continue
        s = task.mm.mmap_sem
        #wait_list elements are embedded in struct rwsem_waiter
        wait_list = readSUListFromHead(Addr(s.wait_list), "list",
                "struct rwsem_waiter")
        pids = [w.task.pid for w in wait_list]
        if (pids):
            waiters[s] = pids
    return waiters
        

def check_all_files():
    lines = memoize_cond(CU_LIVE)(exec_crash_command)("foreach files")
    inode_addrs = {}
    for l in lines.splitlines():
        fields = l.split()
        if (len(fields) < 5 or fields[4] != 'REG'):
            continue
        if (len(fields) == 5):
            fields.append("")

        inode_addrs[int(fields[3], 16)] = fields[5]
    
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

    return waiters

# A test to check heuristically whether a pointer looks like mutex
# On RHEL6 and later
#struct mutex {
    #atomic_t count;
    #spinlock_t wait_lock;
    #struct list_head wait_list;
    #struct thread_info *owner;
#}

# On RHEL5, no 'owner'

def if_mutexOK(addr):
    try:
        mutex = readSU("struct mutex", addr)
        wait_list = mutex.wait_list
        owner = mutex.Owner
        _next_wait_list = wait_list.next
        _next_tasks = owner.tasks.next
        for i in range(5):
            _next_wait_list = _next_wait_list.next 
            _next_tasks = _next_tasks.next
        return True
    except:
        return False

__mutexfunc = "__mutex_lock_slowpath"
def check_mutex_lock(tasksref, tasksrem):
    mutexlist = set()
    for pid in sorted(tasksref.keys()):
        bt = tasksref[pid].bt
        frames = bt.frames
        if (not bt.hasfunc(__mutexfunc)):
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
                        mutexlist.add(readSU("struct mutex", maddr))
                        continue

    if (not mutexlist):
        return
    # Now print info about each found mutex
    print(" === Waiting on mutexes =========")
    for mutex in mutexlist:
        pids = get_mutex_waiters(mutex)
        if (not pids):
            continue
        print_mutex(mutex)
        print_pidlist(pids, tasksref)
        remove_pidlist(tasksrem, pids)


# Get a list of pids waiting on mutex
def get_mutex_waiters(mutex):
    if (mutex.count.counter >= 0):
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
    else:
        ownertask = ''
    if (ownertask):
        ownertask = "\n   Owner: pid={0.pid} cmd={0.comm}".format(ownertask)
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

# Remove a list of pids from the provided dictionary

def remove_pidlist(tdict, pids):
    for pid in pids:
        try:
            del tdict[pid]
        except KeyError:
            pass
    
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
        

# Classify UNINTERRUPTIBLE threads
def classify_UN(v):
    # This is a reference list - we do not touch it
    tasksref = getUNTasks()
    
    # And this is a copy - we will be removing from it pids if we understand
    # what they are waiting for. In the end, only those pids that cannot be
    # categorized will be left here
    tasksrem = tasksref.copy()

    if (not tasksref):
        print ("There are no UNINTERRUPTIBLE tasks")
        return

    print (" *** UNINTERRUPTIBLE threads, classified ***")
    # Fin mutexes we are waiting on
    # Stage one - analyze global structures
    mutex_waiters = check_all_files()
    if (mutex_waiters):
        print(" === Waiting on inode mutexes ==========")
        for inode, (fn, pids) in mutex_waiters.items():
            print ("  --", inode, fn)
            print_mutex(inode.i_mutex)
            print_pidlist(pids, tasksref)
            remove_pidlist(tasksrem, pids)

    check_mutex_lock(tasksref, tasksrem)
   
    mmapsem_waiters = check_all_tasks()
    if (mmapsem_waiters):
        print(" === Waiting on mmap sempahores =========")
        for sema, pids in mmapsem_waiters.items():
            print ("  --", sema)
            print_pidlist(pids, tasksref)
            remove_pidlist(tasksrem, pids)

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
        
    un = tasksrem
    if (not un):
        return

    print ("\n\n ********  Non-classified UN Threads **********")
    
    # Print what remains
    btlist = [b.bt for b in un.values()]
    bt_mergestacks(btlist, verbose=1)
    #print(un)
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
    if (o.Version):
        print ("HANGINFO version %s" % (__version__))
        sys.exit(0)
        
    if (o.Syslogger):
        print_wait_for_AF_UNIX(verbose)
        sys.exit(0)
        
    classify_UN(v)
    
    print("\n")
    print_wait_for_AF_UNIX(0)

