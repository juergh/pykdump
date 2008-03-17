#!/usr/bin/env python
# -*- coding: latin-1 -*-
# Time-stamp: <08/03/17 12:24:33 alexs>
# module LinuxDump.Tasks
#
# Time-stamp: <08/03/05 15:51:52 alexs>
#
# Copyright (C) 2006-2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2008 Hewlett-Packard Co., All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

__doc__ = '''
This is a package providing generic access to 'struct task_struct'
and scheduler.
'''

# Tasks and Pids

from pykdump.API import *

from LinuxDump import percpu


PIDTYPE_c = '''
enum pid_type
{
	PIDTYPE_PID,
	PIDTYPE_TGID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX
};
'''

PIDTYPE_26_c = '''
enum pid_type
{
	PIDTYPE_PID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX
};
'''

PIDTYPE = CEnum(PIDTYPE_c)
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
        ts = self.ts
        if (ts.hasField('last_run')):
            return sched_clock2ms(ts.last_run)
	elif (ts.hasField('timestamp')):
	    return sched_clock2ms(ts.timestamp)
        elif (ts.hasField('last_ran')):
            return sched_clock2ms(ts.last_ran)
        else:
            return None
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
        return task_state2str(self.ts.state)
    state = property(__get_state)

    # -- Get all threads belonging to our tgid --
    def __get_threads_fast(self):
        saddr = Addr(self.ts) + Task.tgoffset
        threads = []
        for a in readList(saddr, inchead = False):
            threads.append(Task(readSU("struct task_struct", a-Task.tgoffset), self))
        return threads
    
    def __get_threads(self):
        tgoffset = member_offset("struct task_struct", "thread_group")
        if (tgoffset != -1):
            # New 2.6
            Task.tgoffset = tgoffset
        elif (struct_exists("struct pid_link")):
            # 2.4 - threads are processes
            return self.ttable.pids[self.pid][1:]
        else:
            # Older 2.6
            Task.tgoffset = member_offset("struct task_struct", "pids") + \
                            struct_size("struct pid") + \
                            member_offset("struct pid", "pid_list")
        Task.threads = property(Task.__get_threads_fast)
        return self.threads
        
    threads = property(__get_threads)

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

		    sfile = readSU("struct file", filep)
		    # On 2.6.20 f_dentry is really f_path.dentry
		    try:
			dentry = Deref(sfile.f_dentry)
		    except KeyError:
			dentry = Deref(sfile.f_path.dentry)
		    inode = Deref(dentry.d_inode)
		    out.append((i, filep, dentry, inode))
	return out



class TaskTable:
    def __init__(self):
        tt = readSUListFromHead(init_task_saddr,
                                'tasks',
                                'struct task_struct',
                                inchead = True, maxel=100000)

        # On 2.4, we have in this list both thread group leaders
        # and threads. Leave only tg leaders, attach threads to
        # self.pids dictionary
        pids_d = {}

        self.tt = []
	self.comms = {}
	
        for t in tt:
            pid = t.pid
            tgid = t.tgid
            task = Task(t, self)
            if (not pids_d.has_key(pid)):
                pids_d[pid] = []
            if (pid == tgid):
                self.tt.append(task)
                pids_d[pid].insert(0, task)
            else:
                pids_d[tgid].append(task)
		
	    self.comms.setdefault(t.comm, []).append(task)

        self.pids = pids_d
	
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
		out[t.pid] = t

        tids = out.keys()
	tids.sort()    # sort by tids
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
 




# On AMD64 we use RDTSC to measure times for scheduler
#static unsigned int cyc2ns_scale;
#define CYC2NS_SCALE_FACTOR 10 /* 2^10, carefully chosen */
#
#static inline unsigned long long cycles_2_ns(unsigned long long cyc)
#{
#        return (cyc * cyc2ns_scale) >> CYC2NS_SCALE_FACTOR;
#}

def cycles_2_ns(cyc):
    cyc2ns_scale = readSymbol("cyc2ns_scale")
    return (cyc * cyc2ns_scale) >> 10

TASK_STATE_c_26 = '''
#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define TASK_STOPPED		4
#define TASK_TRACED		8
#define EXIT_ZOMBIE		16
#define EXIT_DEAD		32
#define TASK_NONINTERACTIVE	64
'''

TASK_STATE_c_24 = '''
#define TASK_RUNNING		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE	2
#define TASK_STOPPED		4
#define TASK_ZOMBIE		8
#define TASK_DEAD		16
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
            wrapped = jiffies & 0xffffffff00000000L
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
# 	return (unsigned long long)jiffies_64 * (1000000000 / HZ);
# }
# But if use_tsc == 1, we are using TSC ! (not done yet)

# 2.6.15/amd64
# we return TSC converted to ns

# This is 2.6 clock using jiffies instead of TSC
def sched_clock2ms_26_jiffies(val):
    return jiffies2ms(val * HZ/1000000000.)

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
    #vx = readSymbol("__vxtime")
    #return cycles_2_ns(vx.last_tsc)/1000000
    rq_cpu0 = readSU(rqtype, sys_info.runqueues_addrs[0])
    recent = rq_cpu0.Timestamp
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
if (struct_exists("struct rq") or symbol_exists("__vxtime")):
    if (debug):
        print "Using TSC for sched_clock"
    # last_ran is in ns, derived from TSC
    cyc2ns_scale = readSymbol("cyc2ns_scale")
    get_schedclockbase = tsc_clock_base
    sched_clock2ms = sched_clock2ms_26_tsc
else:
    # last_ran is in ticks, derived from jiffies
    if (debug):
        print "Using jiffies for clock base"
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
               "tick_timestamp"])

# Print tasks summary and return the total number of threads

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
	   
    for mt in tt.allTasks():
	#print mt.pid, mt.comm, mt.state
	state = mt.state
	comm = mt.comm
	counts[state] = counts.setdefault(state, 0) + 1
	d_counts[(comm, state)] = d_counts.setdefault((comm, state), 0) + 1
	update_acounts((basems - mt.Last_ran)/1000)
	threadcount += 1
	for t in mt.threads:
	    #print "\t", t.pid, t.state
	    state = t.state
	    counts[state] = counts.setdefault(state, 0) + 1
	    d_counts[(comm, state)] = d_counts.setdefault((comm, state), 0)+1
	    update_acounts((basems - t.Last_ran)/1000)
	    threadcount += 1
    print "Number of Threads That Ran Recently"
    print "-----------------------------------"
    print "   last second   %5d" % acounts[0]
    print "   last     5s   %5d" % acounts[1]
    print "   last    60s   %5d" % acounts[2]
    print ""
    print " ----- Total Numbers of Threads per State ------"
    for k,v in counts.items():
	print "  %-40s  %4d" %  (k, v)
    print ""
    return threadcount
    print "       === # of Threads Sorted by CMD+State ==="
    print "CMD               State                                 Threads"
    print "--------------- ------------------                      -------"
    keys = d_counts.keys()
    keys.sort()
    for k in keys:
	v = d_counts[k]
	comm, state = k
	print "%-15s %-40s  %4d" % (comm, state, v)
    return threadcount

if ( __name__ == '__main__'):
    tt = TaskTable()
    t = tt.getByComm("kicker")
    for t in tt.tt:
        print t.comm, t.pid
        #threads = tt.getThreads(t)
            


