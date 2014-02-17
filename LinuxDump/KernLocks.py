# -*- coding: utf-8 -*-
#
# Interpreting different kernel locking-related structures:
#  spinlocks, mutexes etc.
#

# --------------------------------------------------------------------
# (C) Copyright 2006-2013 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------

# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function


from pykdump.API import *

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
             "struct mutex_waiter")
    out = []
    for w in wait_list:
        task = w.task
        out.append([task.pid, task.comm])
    # Sort on PID
    out.sort()
    if (out):
        print("    Waiters on this mutex:")
    for pid, comm in out:
        print ("\t%8d  %s" % (pid, comm))
    
    # Check whether we can find an owner
    if (not s.hasField("owner") or not s.owner):
        return
    
    ownertask = s.owner.task
    print("    Owner of this mutex: pid={0.pid} cmd={0.comm}".format(ownertask))