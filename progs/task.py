#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pykdump.API import *

from LinuxDump import percpu
from LinuxDump.Tasks import TaskTable, Task, tasksSummary, ms2uptime

debug = API_options.debug

# The following is for x86/x86_64
__RLIMIT_c_def = '''
#define RLIMIT_CPU		0	/* CPU time in sec */
#define RLIMIT_FSIZE		1	/* Maximum filesize */
#define RLIMIT_DATA		2	/* max data size */
#define RLIMIT_STACK		3	/* max stack size */
#define RLIMIT_CORE		4	/* max core file size */
#define RLIMIT_RSS		5	/* max resident set size */
#define RLIMIT_NPROC		6	/* max number of processes */
#define RLIMIT_NOFILE		7	/* max number of open files */
#define RLIMIT_MEMLOCK		8	/* max locked-in-memory address space */
#define RLIMIT_AS		9	/* address space limit */

#define RLIMIT_LOCKS		10	/* maximum file locks held */
#define RLIMIT_SIGPENDING	11	/* max number of pending signals */
#define RLIMIT_MSGQUEUE		12	/* maximum bytes in POSIX mqueues */
#define RLIMIT_NICE		13	/* max nice prio allowed to raise to
					   0-39 for nice level 19 .. -20 */
#define RLIMIT_RTPRIO		14	/* maximum realtime priority */
#define RLIMIT_RTTIME		15	/* timeout for RT tasks in us */
#define RLIM_NLIMITS		16
'''
__RLIMIT = CDefine(__RLIMIT_c_def)

# convert limit to a string as appropriate

def __rlim2str(v):
    if (v == LONG_MASK):
        return "INFINITY"
    else:
        return "%d" % v
    

def printTaskDetails(t):
    print "----", t.pid, t.comm
    parent = t.parent
    real_parent = t.real_parent
    if (t.parent):
        print "   -- Parent:", parent.pid, parent.comm
        if (real_parent != parent):
            print "   -- Real Parent:", real_parent.pid, real_parent.comm

    children = t.taskChildren()
    if (children):
        print "   -- Children:"
        for c in children:
            print "\t", c.pid, c.comm

    # Stuff from 'struct signal_struct"
    signal = t.signal

    # Do we belong to a thread group and are we the leader?
    threads = t.threads
    if (threads):
        live = signal.live.counter
        print "   -- Threads Info (%d threads, %d live)" % \
              (len(threads)+1, live)
        if (t.pid == t.tgid):
            print "\tI am the leader of a thread group"
        else:
            print "\tWe belong to a thread group with tgid=%d" % t.tgid
    # Rlimits
    print "   -- Rlimits:"
    for i, r in enumerate(signal.rlim):
        s = __RLIMIT.value2key(i)
        print"\t%02d (%s) cur=%s max=%s" % (i, s,
                                            __rlim2str(r.rlim_cur),
                                            __rlim2str(r.rlim_max))

def find_and_print(pid):
    tt = TaskTable()
    # if pid > INT_MAX, let us treat it as addr of 'struct task_struct'
    if (pid > INT_MAX):
        # Do we have this pid in tt?
        t = readSU("struct task_struct", pid)
        if (not tt.getByTid(t.pid)):
            print "Bogus addr"
            return
        t = Task(t, tt)
    else:
        t = tt.getByTid(pid)
    if (t):
        printTaskDetails(t)
    else:
        print "There is no task with pid=", pid


def printTasks(reverse = False):
    basems = None
    #quit()
    tt = TaskTable()
    if (debug):
        print "Basems", tt.basems, "Uptime:",  ms2uptime(tt.basems)
    

    out = []
    basems = tt.basems
    
    if (not reverse):
	# Natural order (task followed by its threads)
	for mt in tt.allTasks():
	    out.append((basems - mt.Last_ran, mt.pid, mt))
	    for t in mt.threads:
		#print "    struct thread_info 0x%x" % long(t)
		out.append((basems - t.Last_ran, t.pid, t))
	print '==== Tasks in PID order, grouped by Thread Group leader =='
    else:
    # Most recent first
	for t in tt.allThreads():
	    out.append((basems - t.Last_ran, t.pid, t))
	out.sort()
	print '==== Tasks in reverse order, scheduled recently first   =='

    print " PID          CMD       CPU   Ran ms ago   STATE"
    print "--------    -----------  --  ------------- -----"

    for ran_ms_ago, pid, t in out:
	sstate = t.state[5:7]
	if (taskstates_filter and not (sstate in taskstates_filter)):
	    continue
        
	tgid = t.tgid
	if (pid != tgid):
	    pid_s =  "  %5d" % pid
	    tgid_s = "  (tgid=%d)" % tgid
	else:
	    pid_s =  " %5d " % pid
	    tgid_s = ""

	RLIMIT_NPROC = 6
	rlimit = t.signal.rlim[RLIMIT_NPROC].rlim_cur
	pcount = t.user.processes.counter
	uid = t.user.uid
	if (pcount > rlimit - 20):
	    print ' OOO', rlimit, pcount, "uid=%d" % uid
	else:
	    print '    ', rlimit, pcount, "uid=%d" % uid
	print " %05d %s %15s %2d %15d  %s %s" \
		    % (pcount, pid_s, t.comm,  t.cpu,
			int(ran_ms_ago), sstate, tgid_s)


taskstates_filter=None

if ( __name__ == '__main__'):
    from optparse import OptionParser
    op =  OptionParser()

    op.add_option("-v", dest="Verbose", default = 0,
		action="store_true",
		help="verbose output")
    
    op.add_option("--summary", dest="Summary", default = 0,
		action="store_true",
		help="Summary")
    
    op.add_option("--pidinfo", dest="Pidinfo", default = 0,
		action="store", type="int",
		help="Display details for a given PID")

    op.add_option("--taskfilter", dest="Taskfilter", default = None,
		action="store",
		help="A list of 2-letter task states to print, e.g. UN")

    op.add_option("-r", "--reverse", dest="Reverse", default = 0,
                    action="store_true",
                    help="Reverse order while sorting")
    (o, args) = op.parse_args()
    
    if (o.Taskfilter):
        taskstates_filter = re.split("\s*,\s*", o.Taskfilter)
	
    if (o.Reverse):
	printTasks(reverse=True)
    elif (o.Summary):
	tasksSummary()
    elif (o.Pidinfo):
        find_and_print(o.Pidinfo)
    else:
        printTasks()

