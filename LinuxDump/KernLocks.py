# -*- coding: utf-8 -*-
#
# Interpreting different kernel locking-related structures:
#  spinlocks, mutexes etc.
#

# --------------------------------------------------------------------
# (C) Copyright 2006-2017 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------


from pykdump.API import *
from .Tasks import decode_waitq

__TICKET_SHIFT = 16

def ticket_spin_is_locked(lock):
    tmp = lock.slock
    return (((tmp >> __TICKET_SHIFT) ^ tmp) & ((1 << __TICKET_SHIFT) - 1))

spin_is_locked = ticket_spin_is_locked

# Decode struct mutex - waiting-list etc.

def decode_mutex(addr):
    s = readSU("struct mutex", addr)
    print (" {!s:-^40}".format(s))
    #wait_list elements are embedded in struct mutex_waiter
    wait_list = readSUListFromHead(Addr(s.wait_list), "list",
             "struct mutex_waiter", inchead=True)
    out = []
    for w in wait_list:
        task = w.task
        if (task):
            out.append([task.pid, task.comm])
        else:
            out.append([0, '<bad task!!!>'])
            pylog.error("corrupted wait_list for {}".\
                format(s))
    # Sort on PID
    out.sort()
    if (out):
        print("    Waiters on this mutex:")
    for pid, comm in out:
        print ("\t%8d  %s" % (pid, comm))
    
    # Check whether we can find an owner
    if (not s.hasField("owner") or not s.owner):
        return
    
    try:
        ownertask = s.owner.task
    except:
        ownertask = s.owner
    print("    Owner of this mutex: pid={0.pid} cmd={0.comm}".format(ownertask))


# Decode 'struct semaphore'
# If there are tasks on waitlist, print them
# Return list of (pid, comm) or empty list
def decode_semaphore(semaddr, v=1):
    s = readSU("struct semaphore", semaddr)
    task_list = PY_select(
        '[w.task for w in readSUListFromHead(Addr(s.wait_list), "list",'
            '"struct semaphore_waiter")]',
        'decode_waitq(s.wait)'
        )

    out = sorted([(task.pid, task.comm) for task in task_list])
    if (v == 0):
        return out
    print (s)
    for pid, comm in out:
        print ("\t{:8d}  {}".format(pid, comm))
    return out
        
# Decode struct rw_semaphore - waiting-list etc.
def decode_rwsemaphore(semaddr):
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
