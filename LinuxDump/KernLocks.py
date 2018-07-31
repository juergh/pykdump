# -*- coding: utf-8 -*-
#
# Interpreting different kernel locking-related structures:
#  spinlocks, mutexes etc.
#

# --------------------------------------------------------------------
# (C) Copyright 2006-2018 Hewlett Packard Enterprise Development LP
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

# ****** Decode wait_list as used by mutex and rw_semaphore ******
# Normally we have wait_list:
#    struct list_head wait_list;
# But on some kernels (RHEL7.5) in rw_semaphore:
#     struct slist_head wait_list;
#     struct slist_head {
#         struct list_head *next;



# We pass StructResult of either 'list_head' or 'slist_head' type
def __get_mrw_wait_list(wait_list, inchead = False):
    # If we have 'prev' field, this is normal 'list_head'
    if (wait_list.hasField('prev')):
        # list_head
        addrs = readList(Addr(wait_list), inchead = inchead)
    else:
        # slist_head
        ptr = wait_list.next
        # Now read list_head and include its head
        addrs = readList(ptr)
        # IF last addr is equal to ptr, this is really an empty list!
        if (addrs[-1] == ptr):
            addrs = []
    return addrs
    

# Decode struct mutex - waiting-list etc.

__mutex_waiter = "struct mutex_waiter"
__mutex_w_offset = getStructInfo(__mutex_waiter)["list"].offset
# Get mutex waiters
def get_mutex_waiters(addr):
    s = readSU("struct mutex", addr)
    # Two different cases:
    # 'struct list_head wait_list' - we should not include the head itself
    # 'struct list_head *wait_list' - we should include the list head
    #
    # This logic should be moved into Generic or wrapcrash
    isPtr = s.PYT_sinfo['wait_list'].ti.ptrlev  # None or 1
    inchead = True if isPtr else False
    wait_list = s.wait_list
    out = []
    for a in __get_mrw_wait_list(s.wait_list, inchead = inchead):
        w = readSU(__mutex_waiter, a - __mutex_w_offset)
        out.append(w.task)
    return out

    

def decode_mutex(addr):
    s = readSU("struct mutex", addr)
    print (" {!s:-^40}".format(s))
    out = []
    for task in get_mutex_waiters(s):
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
        

# This is ugly, we should add a better way of getting field type info
__rws_waiter = "struct rwsem_waiter"
__rwsw_offset = getStructInfo(__rws_waiter)["list"].offset


# Get rw_semaphore tasks
def get_rwsemaphore_tasks(semaddr):
    s = readSU("struct rw_semaphore", semaddr)
    out = []
    for a in __get_mrw_wait_list(s.wait_list, inchead = False):
        w = readSU(__rws_waiter, a - __rwsw_offset)
        out.append(w.task)
    return out

def decode_rwsemaphore(semaddr):
    s = readSU("struct rw_semaphore", semaddr)
    print (s)
    out = []
    for task in get_rwsemaphore_tasks(s):
        out.append([task.pid, task.comm])
    # Sort on PID
    out.sort()
    for pid, comm in out:
        print ("\t%8d  %s" % (pid, comm))
