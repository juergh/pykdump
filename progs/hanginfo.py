#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Time-stamp: <12/03/08 15:58:15 alexs>

# Copyright (C) 2010-2012 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2010-2012 Hewlett-Packard Co., All rights reserved.

#  Analyze reasons why some tasks are hanging (TASK_UNINTERRUPTIBLE)

# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function

__version__ = "0.1"

import sys
import textwrap

from pykdump.API import *
from LinuxDump.fs import *

from pykdump.API import *
from pykdump.Generic import Bunch

from LinuxDump import percpu
from LinuxDump.Tasks import TaskTable, Task, tasksSummary, ms2uptime, decode_tflags
from LinuxDump.BTstack import exec_bt, bt_summarize, bt_mergestacks

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
        continue
        tgid = t.tgid
        if (pid != tgid):
            print ("!!!", pid, tgid)
            pid_s =  "  %5d" % pid
        else:
            pid_s =  " %5d " % pid
        
        print ("%s %15s %2d %15d  %s" \
                        % (pid_s, t.comm,  t.cpu,
                            int(ran_ms_ago), sstate))

        bt = exec_bt("bt %d" % pid)
        print (bt[0])
        print(" ....................................................................")
  
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
        


# Remove a list of pids from the provided dictionary

def remove_pidlist(tdict, pids):
    for pid in pids:
        try:
            del tdict[pid]
        except KeyError:
            pass
    

if ( __name__ == '__main__'):
    from optparse import OptionParser
    op =  OptionParser()

    op.add_option("-v", dest="Verbose", default = 0,
                action="count",
                help="verbose output")    

    op.add_option("--version", dest="Version", default = 0,
                  action="store_true",
                  help="Print program version and exit")

    
    (o, args) = op.parse_args()
    
    verbose = o.Verbose
    if (o.Version):
        print ("HANGINFO version %s" % (__version__))
        sys.exit(0)

    # This is a reference list - we do not touch it
    tasksref = getUNTasks()
    
    # And this is a copy - we will be removing from it pids if we understand
    # what they are waiting for. In the end, only those pids that cannot be
    # categorized will be left here
    tasksrem = tasksref.copy()

    if (not tasksref):
        print ("There are no UNINTERRUPTIBLE tasks, nothing to analyze!")
        sys.exit(0)

    print (" *** UNINTERRUPTIBLE threads, classified ***")
    # Stage one - analyze global structures
    mutex_waiters = check_all_files()
    if (mutex_waiters):
        print(" === Waiting on inode mutexes ==========")
        for inode, (fn, pids) in mutex_waiters.items():
            print ("  --", inode, fn)
            print_pidlist(pids, tasksref)
            remove_pidlist(tasksrem, pids)

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
        sys.exit(0)

    print ("\n\n ********  Non-classified UN Threads **********")
    
    # Print what remains
    btlist = [b.bt for b in un.values()]
    bt_mergestacks(btlist, verbose=1)
    #print(un)
    sys.exit(0)
    for vfsmount, superblk, fstype, devname, mnt in getMount():
        sb = readSU("struct super_block", superblk)
        um = sb.s_umount
        print(um.activity, um.wait_lock.raw_lock.slock, devname)