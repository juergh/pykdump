#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Workqueues stuff

# --------------------------------------------------------------------
# (C) Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------


# To facilitate migration to Python-3, we use future statements/builtins
from __future__ import print_function

import sys
from collections import namedtuple, defaultdict
import textwrap
from textwrap import TextWrapper

from pykdump.API import *
from LinuxDump import Dev, percpu

from LinuxDump.idr import idr_for_each

# Workqueues are implemented in very different ways on different kernels.
# Here we are talking about CMWQ only, but even that code on different kernels
# is different
#
#  WARNING: working, but not thoroughly tested yet!
#
# Works on kernels: 2.6.32, 3.0.76, 3.11.0, 3.13.0, 3.16.0


# If these enums are unavailable, this is not CMWQ

WORK_CPU_UNBOUND = enumerator_value("WORK_CPU_UNBOUND")
WORK_CPU_NONE = enumerator_value("WORK_CPU_NONE")
WQ_UNBOUND = enumerator_value("WQ_UNBOUND")
NR_CPUS = WORK_CPU_UNBOUND              # Can be huge, much bigger
					#than number of real CPUs

# cpumask operations - this should be really moved to another module
#struct cpumask {
#    unsigned long bits[64];
#}
#
# In each word, the first bit is 0x1.

cpu_possible_mask = readSymbol("cpu_possible_mask")

def for_all_cpus():
    return cpumask_to_cpulist(cpu_possible_mask)


def cpumask_to_cpulist(cpumask):
    try:
        bits = cpumask.mask
    except KeyError:
        bits = cpumask.bits

    out = []
    for i in range(sys_info.CPUS):
        if (i % BITS_PER_LONG == 0):
            word = bits[i // BITS_PER_LONG]

        if (word & 1):
            out.append(i)
        word >>= 1
    return out

__numa_node = sym2addr("numa_node")
def cpu_to_node(cpu):
    ptr = percpu.percpu_ptr(__numa_node, cpu)
    return readInt(ptr)

# Should be moved to API or wrapcrash - we need it in many places
#
# Check whether list_head is empty.
def LH_isempty(lh):
    return Addr(lh) == lh.next

#  Decode wait_queue_head_t - similar to 'waitq' crash command.
# Returns a list of 'struct task_struct'
structSetAttr("struct __wait_queue", "Task", ["task", "private"])
def decode_waitq(wq):
    # 2.4 used to have 'struct __wait_queue'
    # 2.6 has 'wait_queue_head_t' = 'struct __wait_queue_head'
    out = []
    for l in ListHead(wq.task_list, "struct __wait_queue").task_list:
        task = readSU("struct task_struct", l.Task)
        out.append(task)
    return out

# Print WQ-header - common in many places
def WQ_header(wq, okprint = True):
    if (okprint):
        print('   {:-^25}   {}'.format(wq.name, str(wq)))


# ========================================================================
#
# Kernels 2.6.X implementation - no pools
#
# ========================================================================

#struct cpu_workqueue_struct {
    #spinlock_t lock;
    #struct list_head worklist;
    #wait_queue_head_t more_work;
    #struct work_struct *current_work;
    #struct workqueue_struct *wq;
    #struct task_struct *thread;
#}


# Each wq creates one thread per CPU. If there are many CPUs (> 100), printing
# everything output huge. So verbosity levels are like that:
#
#   0 - just a summary - print how many work_structs are queued per
#       each workqueue (sum all CPUs)
#   1 - the same, but with per-CPU stats
#   2 - print everything, even for empty queues
def print_wq_simple_details(wq, v=0):
    once = TrueOnce(1)
    totalwork = 0

    for cpu, cwq in __get_cpu_wqs(wq):
        worklist = cwq.worklist
        nwork = getListSize(worklist, 0, 1000000)  # Up to a million
        if (nwork):
            totalwork += nwork
        # If there is some work, print WQ header
        if (nwork):
            WQ_header(wq, once)
        # For v=0 we are interested in cummulative stats only
        if (v == 0):
            continue
        # For v=1 we are interested per-CPU stats and tasks as well, but only
        # for non-empty queues
        if (v == 1 and not nwork):
            continue

        WQ_header(wq, once)
        comm = cwq.thread.comm
        print ("     -- CPU {:3d} {} {}".format(cpu, cwq, comm))

        # worklist is embedded in struct work_struct
        # as 'struct list_head entry'

        if (not nwork):
            continue

        print ("\tworklist:")
        for e in readSUListFromHead(Addr(worklist), "entry",
            "struct work_struct"):
            print ("\t   ", e, "func=<%s>" % (addr2sym(e.func)))

        for t in decode_waitq(cwq.more_work):
            print(t)

    # Print cummulative number of queued tasks for this wq
    if (totalwork):
        WQ_header(wq, once)
        print("    *** total for all CPUs: {} work requests".format(totalwork))

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


# ========================================================================
#
# Kernels 3.0.X implementation - we use GCWs, struct global_cwq
#
# ========================================================================



def get_gcwq(cpu):
    if (cpu != WORK_CPU_UNBOUND):
        return percpu.percpu_ptr(__global_cwq, cpu)
    else:
        return readSymbol("unbound_global_cwq")

# Get all CWQs of a given workqueue_struct
def get_cwqs(wq):
    if (wq.flags & WQ_UNBOUND):
        yield wq.cpu_wq.pcpu.gcwq
        return

    out = []
    for cpu in for_all_cpus():
        cwq = percpu.percpu_ptr(wq.cpu_wq.pcpu, cpu)
        yield cwq.gcwq


def print_wq_gcwq_details(wq, v=0):
    once = TrueOnce(1)
    if (v > 0):
        WQ_header(wq)

    for gcwq in get_cwqs(wq):
        nr_idle = gcwq.nr_idle
        nr_workers = gcwq.nr_workers
        if (nr_idle != nr_workers or v > 1):
            if (once and v == 0):
                WQ_header(wq)
            print("     {}  nr_workers={} nr_idle={}".format(gcwq, nr_workers, nr_idle))


# ========================================================================
#
# Kernels 3.13 - instead of gcwq we have pwq, struct pool_workqueue
# We insert work on pwq
#
# ========================================================================


# This gets PWQ used by a given WQ and specific CPU.
# They are not necessarily unique for different CPUs.
def get_pwq(wq, cpu):
    if (not (wq.flags & WQ_UNBOUND)):
        pwq = percpu.percpu_ptr(wq.cpu_pwqs, cpu)
    else:
        node = cpu_to_node(cpu)
        #pwq = unbound_pwq_by_node(wq, cpu_to_node(cpu));
        pwq = wq.numa_pwq_tbl[node]
    return pwq

# This gets all PWQs used by this WQ
def for_each_pwq(wq):
    for pwq in ListHead(wq.pwqs, "struct pool_workqueue").pwqs_node:
        yield pwq

#struct work_struct {
    #atomic_long_t data;
    #struct list_head entry;
    #work_func_t func;
#}

# By default (v=0) print active queues only
def print_wq_pwq_details(wq, v =0):
    once = TrueOnce(1)
    if (v > 0):
        WQ_header(wq)
    for pwq in for_each_pwq(wq):
        delayed_works = pwq.delayed_works
        ldelayed=getListSize(Addr(delayed_works), 0, 100000)
        # Print active only by default
        if (pwq.nr_active == 0 and v < 1):
            continue
        if (once and v == 0):
            WQ_header(wq)

        pool = pwq.pool
        nr_workers = pool.nr_workers
        nr_idle = pool.nr_idle
        if (nr_idle == nr_workers and v < 2):
            continue

        print("  {} active={} delayed={}".format(pwq, pwq.nr_active,

                                                    ldelayed))
        print("   {} nr_workers={} nr_idle={}".format(pool, nr_workers, nr_idle))
        print_worker_pool(pool, v)


# On 3.13:
#define for_each_pool_worker(worker, wi, pool)	\
#	idr_for_each_entry(&(pool)->worker_idr, (worker), (wi))

def for_each_pool_worker_idr(pool):
    for _id, idr in idr_for_each(pool.worker_idr):
        worker = readSU("struct worker", idr)
        yield worker

# On 3.16:
#define for_each_pool_worker(worker, pool) \
#	list_for_each_entry((worker), &(pool)->workers, node)

def for_each_pool_worker_list(pool):
    for worker in ListHead(pool.workers, "struct worker").node:
        yield worker

# Print worker_pool
def print_worker_pool(pool, v):
    for worker in for_each_pool_worker(pool):
        # If v < 2, print only those that have non-idle
        current_func = worker.current_func
        if (current_func):
            current_func = addr2sym(current_func)
        else:
            current_func = ""
        if (current_func or v > 0):
            print ("      {}  {} {}".format(worker, worker.task.comm, current_func))
            if (current_func == "bdi_writeback_workfn"):
                print_bdi_writeback_workfn(worker.current_work)

# Decode and print data for <bdi_writeback_workfn>
def print_bdi_writeback_workfn(work):
    # to_delayed_work(work)
    # container_of(work, struct delayed_work, work);
    delayed_work = container_of(work, "struct delayed_work", "work")
    wb = container_of(delayed_work, "struct bdi_writeback", "dwork")
    bdi = wb.bdi
    print("       -- Decoding work for func=bdi_writeback_workfn")
    print("         ",wb)
    print("         ",bdi)



# ========================================================================
#
# Top-level subroutines that call kernel-specific stuff as needed
#
# ========================================================================

# A global list of all workqueues
def print_all_workqueues(v=0):
    #list_for_each_entry(wq, &workqueues, list)
    if (v == 0):
        print (" {!s:-^70}".format("WorkQueues - Active only"))
    else:
        print (" {!s:-^70}".format("All WorkQueues"))

    for wq in ListHead(sym2addr("workqueues"), "struct workqueue_struct").list:
        #print(wq, wq.name)
        print_wq_details(wq, v)



# Print work on the worklist
def print_worklist(worklist):
    lh = ListHead(worklist, "struct work_struct")

    for w in lh.entry:
        func = addr2sym(w.func)
        print("   ", func)

# .............................................................................
#
# Detection of kernel features
if (symbol_exists("global_cwq")):
    # Older 3.X kernels - gcwq
    print_wq_details = print_wq_gcwq_details
elif (struct_exists("struct pool_workqueue")):
    # Newer 3.X - pools of workers
    print_wq_details = print_wq_pwq_details
    # we iterate pool workers are either by idr or by list
    if (member_size("struct worker_pool", "workers") != -1):
        for_each_pool_worker = for_each_pool_worker_list
    elif (member_size("struct worker_pool", "worker_idr") != -1):
        for_each_pool_worker = for_each_pool_worker_idr
    else:
        raise TypeError("unsupported kernel")
elif (member_size("struct workqueue_struct", "cpu_wq") != -1):
    # 2.6 kernel
    print_wq_details = print_wq_simple_details
else:
    raise TypeError("unsupported kernel")

# .............................................................................

if ( __name__ == '__main__'):
    print_all_workqueues(1)
    #sys.exit(0)
    sys.exit(0)
    for cpu in for_all_cpus() + [WORK_CPU_UNBOUND]:
        if (cpu == WORK_CPU_UNBOUND):
            print("\n--Unbound")
        gcwq = get_gcwq(cpu)
        worklist = gcwq.worklist
        print(gcwq, getListSize(Addr(worklist), 0, 1000))
        print_worklist(worklist)
