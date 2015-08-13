#!/usr/bin/env python
# -*- coding: utf-8 -*-
# module LinuxDump.Tasks
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2014 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

from __future__ import print_function

__doc__ = '''
This is a package providing generic access to 'struct task_struct'
and scheduler.
'''

# Tasks and Pids

from pykdump.API import *
from pykdump.Misc import EmbeddedFrames

from LinuxDump import percpu

from collections import defaultdict
import textwrap
from textwrap import TextWrapper


debug = API_options.debug

_PIDTYPE = EnumInfo("enum pid_type")
pointersize = sys_info.pointersize


# We have a global variable 'struct task_struct init_task;',
# loop using 'struct list_head tasks;' field
# For 2.4 'union task_union init_task_union;'
try:
    init_task = readSymbol('init_task')
    init_task_saddr = Addr(init_task.tasks)
except:
    init_task = readSymbol("init_task_union") #c03f2000
    init_task_saddr = Addr(init_task.task.tasks)

structSetAttr("struct task_struct", "_Last_ran",
              ["last_run", "timestamp", "last_ran",
               "sched_info.last_arrival"])
class Task:
    # We start from 'struct task_struct'
    def __init__(self, ts, ttable):
        self.ts = ts
        self.ttable = ttable
    # -- Get the timestamp when last ran by scheduler, converted to ms --
    # We use the same algorithm as 'crash' does
    def __get_last_ran(self):
        return sched_clock2ms(self.ts._Last_ran)
    Last_ran = property(__get_last_ran)

    # -- Get CPU --
    def __get_cpu(self):
        ts = self.ts
        if (ts.hasField("cpu")):
            return ts.cpu
        elif (ts.hasField("stack")):
              thread_info = readSU("struct thread_info", self.ts.stack)
              return thread_info.cpu
        else:
            return  self.ts.Deref.thread_info.cpu
    cpu = property(__get_cpu)

    # -- Get Task State in a symbolic format --
    def __get_state(self):
        try:
            st = task_state2str(self.ts.state)
        except:
            st = '??'
            pylog.error('corrupted task ', self.ts)
        return st
    state = property(__get_state)

    # -- Get all threads belonging to our tgid --
    def __get_threads_fast(self):
        saddr = Addr(self.ts) + Task.tgoffset
        threads = []
        for a in readList(saddr, maxel=200000, inchead = False):
            addr = a-Task.tgoffset
            # Can we read from this addr?
            # This can be due to corruption or missing pages
            try:
                readInt(addr)
                threads.append(Task(readSU("struct task_struct", addr), self))
            except crash.error:
                pylog.warning(" missing page for PID={}".format(self.pid))
                threads = []
        return threads
    def __get_threads_fast_265(self):
        return self.__get_threads_fast()[:-1]
    def __get_threads_fast_24(self):
        return self.ttable.pids[self.pid][1:]
    def __get_threads(self):
        tgoffset = member_offset("struct task_struct", "thread_group")
        fast_method = Task.__get_threads_fast
        if (tgoffset != -1):
            # New 2.6
            Task.tgoffset = tgoffset
        elif (sys_info.kernel < "2.6.0"):
            # 2.4 - threads are processes
            fast_method = Task.__get_threads_fast_24
        else:
            # Older 2.6. We have either
            # struct pid      pids[PIDTYPE_MAX];
            # then we need pids[PIDTYPE_TGID].pid_list
            #
            # Or, we have
            # struct pid_link pids[PIDTYPE_MAX];
            # then we need pids[PIDTYPE_TGID].pid.task_list

            si = getStructInfo("struct task_struct")
            sn = si["pids"].ti.stype
            if (sn == "struct pid"):
                pl_off = member_offset(sn, "pid_list")
            elif (sn == "struct pid_link"):
                #pl_off = member_offset(sn, "pid") + \
                #          member_offset("struct pid", "task_list")
                pl_off = member_offset(sn, "pid_chain")
                fast_method = Task.__get_threads_fast_265
            else:
                raise TypeError("Don't know how to find threads")

            pl_off += struct_size(sn)
            #print sn, "pl_off=", pl_off
            Task.tgoffset = member_offset("struct task_struct", "pids") + \
                           pl_off
            #print "tgoffset=", Task.tgoffset
        Task.threads = property(fast_method)
        return self.threads

    threads = property(__get_threads)

    # PID-namespace related stuff
    def task_get_pid(self):
        # task->pids[PIDTYPE_PID].pid;
        return self.ts.pids[_PIDTYPE.PIDTYPE_PID].pid
    def task_ns(self):
        # ns = pid->numbers[pid->level].ns
        pid = self.task_get_pid()
        return pid.numbers[pid.level].ns

    # Delegate all unknown attributes access to self.ts
    def __getattr__(self, attr):
        return getattr(self.ts, attr)

    def __repr__(self):
        return "PID=%d <struct task_struct 0x%x> CMD=%s" % (self.ts.pid,
                                                     Addr(self.ts),
                                                     self.ts.comm)

    __str__ = __repr__

    def __nonzero__(self):
        return True

    # Get fds from 'task_struct'
    def taskFds(self, short = False):
        out = []
        task = self
        if (task.files):
            files = Deref(task.files)
            try:
                # 2.6
                fdt = Deref(files.fdt)
                fd = fdt.fd
                max_fds = fdt.max_fds
                open_fds = fdt.open_fds
            except KeyError:
                # 2.4
                fd = files.fd
                max_fds = files.max_fds
                open_fds = files.open_fds
                # print open_fds
            if (max_fds):
               fileparray = readmem(open_fds, struct_size("fd_set"))
            for i in range(max_fds):
                if (FD_ISSET(i, fileparray)):
                    filep = readPtr(fd + pointersize * i)
                else:
                    filep = None
                if (filep):
                    #print FD_ISSET(i, fileparray)
                    if (short):
                        out.append(filep)
                        continue

                    sfile = readSU("struct file", filep)
                    # On 2.6.20 f_dentry is really f_path.dentry
                    try:
                        dentry = Deref(sfile.f_dentry)
                    except KeyError:
                        dentry = Deref(sfile.f_path.dentry)
                    inode = Deref(dentry.d_inode)
                    out.append((i, filep, dentry, inode))
        return out
    # Get children
    def taskChildren(self):
        clist = readSUListFromHead(self.ts.children, "sibling",
                                  "struct task_struct")
        return [Task(c, self.ttable) for c in clist]

class _TaskTable:
    def __init__(self):
        tt = readSUListFromHead(init_task_saddr,
                                'tasks',
                                'struct task_struct',
                                inchead = True, maxel=200000)

        # On 2.4, we have in this list both thread group leaders
        # and threads. Leave only tg leaders, attach threads to
        # self.pids dictionary
        pids_d = {}

        self.tt = []
        self.comms = defaultdict(list)
        pidnamespaces = defaultdict(list)

        for t in tt:
            # In case we get a corrupted list
            try:
                pid = t.pid
                tgid = t.tgid
            except:
                pylog.warning("corrupted task-list")
                break
            task = Task(t, self)
            if (not pid in pids_d):
                pids_d[pid] = []
            if (pid == tgid):
                self.tt.append(task)
                try:
                    pidns = task.task_ns()
                    if (pidns.level):
                        pidnamespaces[pidns].append(task)
                except:
                    # Old kernels or corrupted task_struct
                    pass
                pids_d[pid].insert(0, task)
            else:
                pids_d[tgid].append(task)

            self.comms[t.comm].append(task)

        self.pids = pids_d
        self.pidnamespaces = pidnamespaces

        # A dict of all threads - we compute only if needed
        self.tids = {}

        self.filepids = {}
        self.toffset = member_offset("struct task_struct", "thread_group")

        # On a live kernel we need to get jiffies after getting threads info
        if (sys_info.livedump):
            self.__init_tids()

        self.basems = get_schedclockbase()

        # File objects cache
        self.files_cache = {}

    # Fill-in all tids
    def __init_tids(self):
        if (self.tids):
            return
        out = {}
        for mt in self.tt:
            out[mt.pid] = mt
            for t in mt.threads:
                # If it is corrupted, report and reparent to 1
                try:
                    out[t.pid] = t
                except:
                    pylog.error("corrupted thread", hexl(t))

        tids = sorted(out.keys())       # sort by tids
        self.tids = out
        self.allthreads = [out[tid] for  tid in tids]
    # Get all tasks
    def allTasks(self):
        return self.tt

    # Get all threads
    def allThreads(self):
        self.__init_tids()
        return self.allthreads

    # get task by pid
    def getByPid(self, pid):
        try:
            return self.pids[pid][0]
        except KeyError:
            return None
    # get thread by tid
    def getByTid(self, tid):
        self.__init_tids()
        try:
            return self.tids[tid]
        except KeyError:
            return None

    # get task by comm
    def getByComm(self, comm):
        try:
            return self.comms[comm]
        except KeyError:
            return []

    # get task by 'struct file *' pointer. As there can be several
    # processes sharing the same file, we return a list
    def getByFile(self, filep):
        if (len(self.filepids) == 0):
            for t in self.tt:
                for fp in t.taskFds(True):
                    self.filepids.setdefault(fp, []).append(t)

        try:
            return self.filepids[filep]
        except KeyError:
            return []


@memoize_cond(CU_LIVE |CU_PYMOD)
def TaskTable():
    return _TaskTable()


# On AMD64 we use RDTSC to measure times for scheduler
#static unsigned int cyc2ns_scale;
#define CYC2NS_SCALE_FACTOR 10 /* 2^10, carefully chosen */
#
#static inline unsigned long long cycles_2_ns(unsigned long long cyc)
#{
#        return (cyc * cyc2ns_scale) >> CYC2NS_SCALE_FACTOR;
#}


TASK_STATE_c_26 = '''
#define TASK_RUNNING            0
#define TASK_INTERRUPTIBLE      1
#define TASK_UNINTERRUPTIBLE    2
#define TASK_STOPPED            4
#define TASK_TRACED             8
#define EXIT_ZOMBIE             16
#define EXIT_DEAD               32
#define TASK_NONINTERACTIVE     64
'''

TASK_STATE_c_24 = '''
#define TASK_RUNNING            0
#define TASK_INTERRUPTIBLE      1
#define TASK_UNINTERRUPTIBLE    2
#define TASK_STOPPED            4
#define TASK_ZOMBIE             8
#define TASK_DEAD               16
'''

TASK_STATE_24 = CDefine(TASK_STATE_c_24)
TASK_STATE_26 = CDefine(TASK_STATE_c_26)
TASK_STATE = TASK_STATE_26

# Return a symbolic representation of task state
def task_state2str(state):
    if (state == TASK_STATE.TASK_RUNNING):
        return "TASK_RUNNING"

    out = ""
    for name, val in TASK_STATE.items():
        if (val and (state & val)):
            if (out == ""):
                out = name
            else:
                out += "|" + name
    return out


def jiffies2ms(jiffies):
    if (symbol_exists("jiffies_64")):
        #print "++", jiffies,
        # We have really passed jiffies_64
        if (sys_info.kernel >= "2.6.0"):
            wrapped = jiffies & long(0xffffffff00000000)
            #print "wrapped=", hex(wrapped), "HZ=", HZ
            if (wrapped):
                wrapped -= 0x100000000
                jiffies &= 0x00000000ffffffff
                jiffies |= wrapped
            else:
                # We don't have unsigned ints in Python so make this negative
                jiffies -= 2<<31

            jiffies += 300*HZ
    return jiffies*1000/HZ


# Here we want to convert time as reported by sched_clock() to ms. The kernel
# function sched_clock is very different on different platforms, e.g.

# 2.6.15/i386 - we usually return jiffies_64 converted to ns
# unsigned long long sched_clock(void)
# {
#       return (unsigned long long)jiffies_64 * (1000000000 / HZ);
# }
# But if use_tsc == 1, we are using TSC ! (not done yet)

# 2.6.15/amd64
# we return TSC converted to ns

# This is 2.6 clock using jiffies instead of TSC
def sched_clock2ms_26_jiffies(val):
    return jiffies2ms(val * HZ/1000000000)

# If we are using TSC, the timestamps are already in ns
def sched_clock2ms_26_tsc(val):
    return val/1000000.

# 2.4.X - no special sched_clock, we use just 'jiffies'
def sched_clock2ms_24(val):
    # We use plain jiffies
    return val*1000./HZ

def ms2uptime(ms):
    total = ms/1000
    days = total/(3600*24)
    total = total%(3600*24)

    hh = total/3600
    total = total%3600

    mm = total/60
    ss = total%60

    if (days):
        return "%d days, %02d:%02d:%02d" % (days, hh, mm, ss)
    else:
        return "%02d:%02d:%02d" % (hh, mm, ss)

def get_uptime():
    return ms2uptime(jiffie_clock_base())


# Find the current TSC value (we cannot really obtain the current one, just
# the last value saved recently). We convert it to milliseconds

def tsc_clock_base():
    recent = 0
    for cpu in range(sys_info.CPUS):
        rq = readSU(rqtype, sys_info.runqueues_addrs[cpu])
        #print rq, rq.Timestamp
        if (rq.Timestamp > recent):
            recent = rq.Timestamp
#     try:
#         recent = rq_cpu0.timestamp_last_tick
#     except KeyError:
#         recent = rq_cpu0.most_recent_timestamp
    return  sched_clock2ms(recent)


# Find the current jiffies/jiffies_64 value. We convert it to milliseconds
def jiffie_clock_base():
    try:
        jiffies =  readSymbol("jiffies_64")
        #print "jiffies_64=", jiffies
    except TypeError:
        jiffies = readSymbol("jiffies")
    return jiffies2ms(jiffies)


# Read runqueues
def getRunQueues():
    rqs = [readSU(rqtype, rqa) for rqa in runqueues_addrs]
    return rqs


# -------- Initializations done after dump is accessible ------

# Make a local copy of HZ for easier access
HZ = sys_info.HZ
# On 2.6 sched_clock() always returns time in ns even though it
# can obtain it in different ways


# Check whether we are using jiffies or tsc for sched_clock.
# Recent kernels use struct rq with most_recent_timestamp field
# Older 2.6 kernels do not have it, but those using TSC define __vxtime
if (symbol_exists("sched_clock")):
    if (debug):
        print ("Using sched_clock")
    # last_ran is in ns, derived from TSC
    get_schedclockbase = tsc_clock_base
    sched_clock2ms = sched_clock2ms_26_tsc
else:
    # last_ran is in ticks, derived from jiffies
    if (debug):
        print ("Using jiffies for clock base")
    get_schedclockbase = jiffie_clock_base

    if (sys_info.kernel >= "2.6.0"):
        sched_clock2ms = sched_clock2ms_26_jiffies
    else:
        sched_clock2ms = sched_clock2ms_24

runqueues_addrs = percpu.get_cpu_var("runqueues")
sys_info.runqueues_addrs = runqueues_addrs

# Older 2.6 use 'struct runqueue', newer ones 'struct rq'
rqtype = percpu.get_cpu_var_type('runqueues')
structSetAttr(rqtype, "Timestamp",
              ["timestamp_last_tick", "most_recent_timestamp",
               "tick_timestamp", "clock"])
structSetAttr(rqtype, "Active", ["active", "dflt_lrq.active"])
structSetAttr(rqtype, "Expired", ["expired", "dflt_lrq.active"])

__sts = "struct task_struct"

# New kernels have potentially different 'cred' and 'real_cred' and as a result
# two copies of 'struct user_struct'. By default, we'll use 'real_cred'

# task_struct::real_cred then refers to the objective and apparent
# real subjective credentials of a task, as perceived by the other tasks
# in the system.

# task_struct::cred then refers to the effective subjective credentials of
# a task, as used by that task when it's actually running. These are not
# visible to the other tasks in the system.


structSetAttr(__sts, "Uid", ["uid", "real_cred.uid.val", "real_cred.uid"])
structSetAttr(__sts, "User", ["user", "real_cred.user"])

# Print tasks summary and return the total number of threads
try:
    init_nsproxy =  readSymbol("init_nsproxy")
except:
    init_nsproxy = None

def tasksSummary():
    tt = TaskTable()
    threadcount = 0
    basems = tt.basems
    counts = {}
    d_counts = {}
    acounts = [0, 0, 0]
    def update_acounts(v):
        if (v <= 1):
            acounts[0] += 1
        if (v <= 5):
            acounts[1] += 1
        if (v <= 60):
            acounts[2] += 1

    n_of_ns_pids = 0
    for mt in tt.allTasks():
        #print mt.pid, mt.comm, mt.state
        state = mt.state
        comm = mt.comm
        counts[state] = counts.setdefault(state, 0) + 1
        d_counts[(comm, state)] = d_counts.setdefault((comm, state), 0) + 1
        update_acounts((basems - mt.Last_ran)/1000)
        threadcount += 1
        # Check whether we are running in our own namespace
        if (init_nsproxy):
            nsproxy = mt.ts.nsproxy
            # Do not report zombies here (they have nsproxy=NULL)
            if (nsproxy and nsproxy != init_nsproxy):
                n_of_ns_pids += 1
        for t in mt.threads:
            #print "\t", t.pid, t.state
            state = t.state
            counts[state] = counts.setdefault(state, 0) + 1
            d_counts[(comm, state)] = d_counts.setdefault((comm, state), 0)+1
            update_acounts((basems - t.Last_ran)/1000)
            threadcount += 1
    print ("Number of Threads That Ran Recently")
    print ("-----------------------------------")
    print ("   last second   %5d" % acounts[0])
    print ("   last     5s   %5d" % acounts[1])
    print ("   last    60s   %5d" % acounts[2])
    print ("")
    print (" ----- Total Numbers of Threads per State ------")
    for k,v in counts.items():
        print ("  %-40s  %4d" %  (k, v))
    print ("")
    # Check whether there are any PID-namespaces. If yes, issue a warning
    if (tt.pidnamespaces or n_of_ns_pids):
        pylog.warning("There are %d threads running in their own namespaces\n"
                      "\tUse 'taskinfo --ns' to get more details" % n_of_ns_pids)

    return threadcount
    print ("       === # of Threads Sorted by CMD+State ===")
    print ("CMD               State                                 Threads")
    print ("--------------- ------------------                      -------")
    keys = sorted(d_counts.keys())
    for k in keys:
        v = d_counts[k]
        comm, state = k
        print ("%-15s %-40s  %4d" % (comm, state, v))
    return threadcount


# IOCTX list of the task

def get_ioctx_list(task):
    # struct kioctx
    head = task.mm.ioctx_list
    return readStructNext(head, "next")


# SLES10
__TIF_SLES10 = '''
#define TIF_SYSCALL_TRACE       0       /* syscall trace active */
#define TIF_NOTIFY_RESUME       1       /* resumption notification requested */
#define TIF_SIGPENDING          2       /* signal pending */
#define TIF_NEED_RESCHED        3       /* rescheduling necessary */
#define TIF_SINGLESTEP          4       /* reenable singlestep on user return*/
#define TIF_IRET                5       /* force IRET */
#define TIF_SYSCALL_AUDIT       7       /* syscall auditing active */
#define TIF_SECCOMP             8       /* secure computing */
#define TIF_RESTORE_SIGMASK     9       /* restore signal mask in do_signal */
#define TIF_POLLING_NRFLAG      16      /* true if poll_idle() is polling TIF_NEED_RESCHED */
#define TIF_IA32                17      /* 32bit process */
#define TIF_FORK                18      /* ret_from_fork */
#define TIF_ABI_PENDING         19
#define TIF_MEMDIE              20
#define TIF_PTRACE_NOTIFY       21      /* self-induced ptrace notification */
'''

# RHEL5
__TIF_RHEL5 = '''
#define TIF_SYSCALL_TRACE       0       /* syscall trace active */
#define TIF_NOTIFY_RESUME       1       /* resumption notification requested */
#define TIF_SIGPENDING          2       /* signal pending */
#define TIF_NEED_RESCHED        3       /* rescheduling necessary */
#define TIF_SINGLESTEP          4       /* reenable singlestep on user return*/
#define TIF_IRET                5       /* force IRET */
#define TIF_SYSCALL_AUDIT       7       /* syscall auditing active */
#define TIF_SECCOMP             8       /* secure computing */
#define TIF_RESTORE_SIGMASK     9       /* restore signal mask in do_signal */
/* 16 free */
#define TIF_IA32                17      /* 32bit process */
#define TIF_FORK                18      /* ret_from_fork */
#define TIF_MEMDIE              20
#define TIF_FORCED_TF           21      /* true if TF in eflags artificially */
'''

# RHEL6
__TIF_RHEL6_c = '''
 #define TIF_SYSCALL_TRACE       0       /* syscall trace active */
 #define TIF_NOTIFY_RESUME       1       /* callback before returning to user */
 #define TIF_SIGPENDING          2       /* signal pending */
 #define TIF_NEED_RESCHED        3       /* rescheduling necessary */
 #define TIF_SINGLESTEP          4       /* reenable singlestep on user return*/
 #define TIF_IRET                5       /* force IRET */
 #define TIF_SYSCALL_EMU         6       /* syscall emulation active */
 #define TIF_SYSCALL_AUDIT       7       /* syscall auditing active */
 #define TIF_SECCOMP             8       /* secure computing */
 #define TIF_MCE_NOTIFY          10      /* notify userspace of an MCE */
 #define TIF_USER_RETURN_NOTIFY  11      /* notify kernel of userspace return */
 #define TIF_NOTSC               16      /* TSC is not accessible in userland */
 #define TIF_IA32                17      /* 32bit process */
 #define TIF_FORK                18      /* ret_from_fork */
 #define TIF_MEMDIE              20
 #define TIF_DEBUG               21      /* uses debug registers */
 #define TIF_IO_BITMAP           22      /* uses I/O bitmap */
 #define TIF_FREEZE              23      /* is freezing for suspend */
 #define TIF_FORCED_TF           24      /* true if TF in eflags artificially */
 #define TIF_BLOCKSTEP           25      /* set when we want DEBUGCTLMSR_BTF */
 #define TIF_LAZY_MMU_UPDATES    27      /* task is updating the mmu lazily */
 #define TIF_SYSCALL_TRACEPOINT  28      /* syscall tracepoint instrumentation */
 '''

__TIF_RHEL6 = CDefine(__TIF_RHEL6_c)
# Decode flags
def decode_tflags(flags, offset = 0):
    offset = ' ' * offset
    for i in range(32):
        if (flags & 1):
            v = __TIF_RHEL6.value2key(i)
            print(offset, "bit %d" %i, v)
        flags = (flags >> 1)

# Print info about namespaces being used

def print_namespaces_info(tt, v = 0):
    if (not init_nsproxy):
        return
    once = TrueOnce(1)
    # Group all tasks ny nsproxy they use
    tdict = defaultdict(list)
    for t in tt.allTasks():
        nsproxy = t.ts.nsproxy
        tdict[nsproxy].append(t)
    # We are not interested in init_nsproxy - a default NS
    del tdict[init_nsproxy]
    if(not tdict):
        return

    print("  {:*^60}".format("Non-standard Namespaces"))
    net_ns_set = set()          # A set of net that have PID owners
    net_ns_set.add(init_nsproxy.net_ns)
    once = TrueOnce(1)
    for nsproxy, tlist in tdict.items():
        if (once):
            print("    {:~^58}".format("Namespaces Associated with PID"))
        print("      {!s:.^50}".format(nsproxy))
        # On some kernels nsproxy can be NULL (bad - there were fixes)
        if (nsproxy):
            nslist = []
            for na in ("uts_ns", "ipc_ns", "mnt_ns",  "net_ns"):
                if (getattr(nsproxy, na) != getattr(init_nsproxy, na)):
                    nslist.append(na)
                net_ns_set.add(nsproxy.net_ns)
            print("     ", nslist)
        for t in tlist:
            print("\t", t)

    net_namespace_list = readSymbol("net_namespace_list")
    nslist = readSUListFromHead(Addr(net_namespace_list), "list",
                                "struct net")
    once = TrueOnce(1)
    for net in nslist:
        if (not net in net_ns_set):
            if(once):
                print("    {:~^58}".format("NET_NS without any task"))
            print("    ", net)

    if (tt.pidnamespaces):
        print("\n   *** PID Namespace Info ***")
        print_pid_namespaces(tt, v)


# Print info abour PID-namespaces
def print_pid_namespaces(tt, v = 0):
    def get_nspids(t, v):
        tspid = t.task_get_pid()
        out = []
        for l in range(tspid.level + 1):
            upid = tspid.numbers[l]
            out.append(str(upid.nr))

        if (v > 0):
            return out[0] + "[" + ",".join(out[1:]) + "]"
        else:
            return out[0]
    # Frames indexed by ns
    frames = {}

    for ns, tasks in tt.pidnamespaces.items():
        fr = EmbeddedFrames(str(ns))
        frames[ns] = fr
        out = []
        for task in tasks:
            nspids = get_nspids(task, v)
            out.append("PID={} CMD={}".format(nspids, task.comm))
            threads = []
            for thread in task.threads:
                nspids = get_nspids(thread, v)
                threads.append(nspids)
            if (len(threads) > 0):
                sthreads = "Threads: " + " ".join(threads)
                sthreads = textwrap.wrap(sthreads, width=70,
                                         initial_indent=4 * ' ',
                                         subsequent_indent = 8 * ' ')
                out += sthreads
        fr.addText("\n".join(out))

    for ns, fr in frames.items():
        parent = ns.parent
        if (parent in frames):
            pfr = frames[parent]
            pfr.addFrame(fr)

    # Now print only level-1 frames
    for ns, fr in frames.items():
        if (ns.level == 1):
            print(fr)

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

if ( __name__ == '__main__'):
    tt = TaskTable()
    t = tt.getByComm("kicker")
    for t in tt.tt:
        print (t.comm, t.pid)
        #threads = tt.getThreads(t)



