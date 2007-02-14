#!/usr/bin/env python

from pykdump.API import *

from LinuxDump import percpu

debug = API_options.debug

class Task:
    # We start from 'struct task_struct'
    def __init__(self, ts):
        self.ts = ts
    # -- Get the timestamp when last ran by scheduler, converted to ms --
    def __get_last_ran(self):
        ts = self.ts
        if (ts.hasField('last_ran')):
            return sched_clock2ms(ts.last_ran)
        elif (ts.hasField('last_run')):
            return sched_clock2ms(ts.last_run)
        else:
            return None
    last_ran = property(__get_last_ran)

    # -- Get CPU --
    def __get_cpu(self):
        ts = self.ts
        if (ts.hasField("cpu")):
            return ts.cpu
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
        for a in readList(saddr):
            threads.append(Task(readSU("struct task_struct", a-Task.tgoffset)))
        return threads
    
    def __get_threads(self):
        if (struct_exists("struct pid_link")):
            return [self]
            Task.tgoffset = member_offset("struct task_struct", "pids") + \
                            struct_size("struct pid_link") + \
                            member_offset("struct pid_link", "pid_chain")
        else:
            Task.tgoffset = member_offset("struct task_struct", "pids") + \
                            struct_size("struct pid") + \
                            member_offset("struct pid", "pid_list")
            Task.threads = property(Task.__get_threads_fast)
        return self.threads
        
    threads = property(__get_threads)

    # Delegate all unknown attributes access to self.ts
    def __getattr__(self, attr):
        return self.ts.__getattr__(attr)
            
        
def printTasks():
    basems = get_schedclockbase()
    if (debug):
        print "Basems", basems, "Uptime:",  ms2uptime(basems)
    #quit()
    for task in readSUListFromHead(init_task_saddr, 'tasks',
                                   'struct task_struct',
                                   inchead = True):
        task = Task(task)
        for i, t in enumerate(task.threads):
            last_ran_ms = t.last_ran
            if (i > 0):
                print "\t",
            print t.pid, t.comm, '\t', t.cpu, '\t', \
                  basems-last_ran_ms, \
                  t.state
        


    print get_schedclockbase() - basems
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
        # We have really passed jiffies_64
        if (sys_info.kernel >= "2.6.0"):
            wrapped = jiffies & 0xffffffff00000000
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
    return jiffies2ms(val * HZ/1000000000)

# If we are using TSC, the timestamps are already in ns
def sched_clock2ms_26_tsc(val):
    return val/1000000

# 2.4.X - no special sched_clock, we use just 'jiffies'
def sched_clock2ms_24(val):
    # We use plain jiffies
    return val*1000/HZ

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
    rq_cpu0 = readSU("struct runqueue", sys_info.runqueues_addrs[0])
    return  sched_clock2ms(rq_cpu0.timestamp_last_tick)


# Find the current jiffies/jiffies_64 value. We convert it to milliseconds
def jiffie_clock_base():
    try:
        jiffies =  readSymbol("jiffies_64")
        print "jiffies_64=", jiffies
    except TypeError:
        jiffies = readSymbol("jiffies")
    return jiffies2ms(jiffies)



  

# -------- Initializations done after dump is accessible ------

# Make a local copy of HZ for easier access
HZ = sys_info.HZ
# On 2.6 sched_clock() always returns time in ns even though it
# can obtain it in different ways


# Check whether we are using jiffies or tsc for sched_clock.
if (symbol_exists("__vxtime")):
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

# We have a global variable 'struct task_struct init_task;',
# loop using 'struct list_head tasks;' field
# For 2.4 'union task_union init_task_union;'
try:
    init_task = readSymbol('init_task')
    init_task_saddr = Addr(init_task.tasks)
except:
    init_task = readSymbol("init_task_union") #c03f2000
    init_task_saddr = Addr(init_task.task.tasks)
    TASK_STATE = TASK_STATE_24


if ( __name__ == '__main__'):
    print "sys.argv=", sys.argv

    printTasks()

