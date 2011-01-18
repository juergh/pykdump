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
    sstate = t.state[5:7]
    print "---- %5d(%s) %s %s" % (t.pid, sstate, str(t.ts), t.comm)
    parent = t.parent
    if (t.hasField("real_parent")):
	real_parent = t.real_parent
    else:
	real_parent = parent
    if (parent):
        print "   -- Parent:", parent.pid, parent.comm
        if (real_parent != parent):
            print "   -- Real Parent:", real_parent.pid, real_parent.comm

    children = t.taskChildren()
    if (children):
        print "   -- Children: %d" % len(children)
        if (verbose):
	    for c in children:
		print "\t", c.pid, c.comm

    # Stuff from 'struct signal_struct"
    signal = t.signal

    # Do we belong to a thread group and are we the leader?
    threads = t.threads
    if (threads):
	try:
	    live = ', %d live' % signal.live.counter
	except:
	    # RHEL3
	    live = ''
        print "   -- Threads Info (%d threads%s)" % \
              (len(threads)+1, live)
        if (t.pid == t.tgid):
            print "\tI am the leader of a thread group"
            # Print all threads in verbose mode
            if (verbose):
                tids = [t.pid for t in threads]
                print "\tThreads:", tids
        else:
            print "\tWe belong to a thread group with tgid=%d" % t.tgid
    # Credentials
    #

    if (t.hasField('cred')):
        if (t.cred != t.real_cred):
            job = [('cred', t.cred), ('real_cred', t.real_cred)]
        else:
            job = [('Credentials', t.cred)]
    else:
        job = [('Credentials', t)]

    for jh, c in job:
        print "   --", jh
        print "\t  uid=%-5d   gid=%-5d" % (c.uid, c.gid)
        print "\t suid=%-5d  sgid=%-5d" % (c.suid, c.sgid)
        print "\t euid=%-5d  egid=%-5d" % (c.euid, c.egid)
        print "\tfsuid=%-5d fsgid=%-5d" % (c.fsuid, c.fsgid)
        u = c.user
        print "     --user_struct", u
        if (u.hasField("sigpending")):
	    extra = " sigpending=%d" % u.sigpending.counter
	else:
	    extra = ""
        print "\t  processes=%d files=%d%s" % \
              (u.processes.counter, u.files.counter, extra)
	if (c.hasField("group_info")):
	    g = c.group_info
	    ngroups = g.ngroups
	    small_block = g.small_block
	else:
	    ngroups = t.ngroups
	    small_block = t.groups
	    g = ""
        print "     --group_info", g
	            # Print only if we do not have more than NGROUPS_SMALL
        if (ngroups <= len(small_block)):
            out = []
            for i in range(ngroups):
                out.append(str(small_block[i]))
            print "     ", out
                
            

        
    # for EXIT_DEAD processes, it does not make sense to continue
    if (sstate == 'DE'):
	return
    # Rlimits
    print "   -- Rlimits:"
    # On RHEL4 rlim is in task_struct, on later kernels in signal
    if t.hasField("rlim"):
	rlim = t.rlim
    else:
	rlim = signal.rlim
    for i, r in enumerate(rlim):
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
    print "--------   ------------  --  ------------- -----"

    for ran_ms_ago, pid, t in out:
	sstate = t.state[5:7]
	if (taskstates_filter and not (sstate in taskstates_filter)):
	    continue
        
	tgid = t.tgid
	if (pid != tgid):
	    pid_s =  "  %5d" % pid
	    extra = " (tgid=%d)" % tgid
	else:
	    pid_s =  " %5d " % pid
	    extra = ""
        uid = t.Uid
        extra = "%13s UID=%d" % (extra, uid)

	#RLIMIT_NPROC = 6
	#rlimit = t.signal.rlim[RLIMIT_NPROC].rlim_cur
	#pcount = t.user.processes.counter
	uid = t.Uid
	#if (pcount > rlimit - 20):
	#    print ' OOO', rlimit, pcount, "uid=%d" % uid
	#else:
	#    print '    ', rlimit, pcount, "uid=%d" % uid
	print "%s %15s %2d %15d  %s %s" \
		    % (pid_s, t.comm,  t.cpu,
			int(ran_ms_ago), sstate, extra)

# Emulate pstree

__STEP = 4

# A recursive thingy

# Sort children by comm
def __getcomm(t):
    return t.comm

def __t_str(t):
    return "%s(%d)" % (t.comm, t.pid)

def walk_children(t, top = False):
    parent_s = __t_str(t)
    if (not top):
        parent_s = '-' + parent_s
    sorted_c = sorted(t.taskChildren(), key=__getcomm)
    # If this task has threads, treat them as special children
    # printing something like 2*[{udisks-daemon}]
    # We print threads _only if we are the group leader
    if (t.pid == t.tgid):
	threads = t.threads
    else:
	threads = 0
    if (threads):
        lt = len(threads)
        if (lt > 1):
            st = "-%d*[{%s}]" % (lt, t.comm)
        else:
            st ="-{%s}" % t.comm
        sorted_c.append(st)
    
    newl = len(sorted_c)
    last = newl - 1
    if (newl == 0):
        yield parent_s

    padding = ' ' * (len(parent_s) + 1)
    p_blank = padding + ' '
    p_end =  padding + '`'

    for i, c in enumerate(sorted_c):
	if (i == last):
	    if (newl == 1):
		sc = padding + ' '
	    else:
		sc = p_end
	else:
	    sc = padding + '|'
	
        if (i == 0):
            if (newl == 1):
                s = parent_s + "--"
            else:
                s = parent_s + "-+"
            ll = len(s)
        else:
	    s = sc
        # If we have threads and c is the last element, it is a preformatted
        # string rather than a task
        if (i == last and threads):
            yield s + c
        else:
            for s1 in walk_children(c):
                yield  s + s1
                if (sc == p_end):
		    s = p_blank
		else:
		    s = sc



            
def pstree(pid = 1):
    tt = TaskTable()
    init = tt.getByPid(pid)
    for s in walk_children(init, top = True):
        print s
        
taskstates_filter=None
verbose = 0

if ( __name__ == '__main__'):
    from optparse import OptionParser
    op =  OptionParser()

    op.add_option("-v", dest="Verbose", default = 0,
		action="count",
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

    op.add_option("--pstree", dest="Pstree", default = False,
		action="store_true",
		help="Emulate user-space 'pstree' output")

    op.add_option("-r", "--reverse", dest="Reverse", default = 0,
                    action="store_true",
                    help="Reverse order while sorting")
    (o, args) = op.parse_args()
    
    verbose = o.Verbose

    if (o.Taskfilter):
        taskstates_filter = re.split("\s*,\s*", o.Taskfilter)

    if (o.Reverse):
	printTasks(reverse=True)
    elif (o.Summary):
	tasksSummary()
    elif (o.Pstree):
	if (o.Pidinfo):
	    pstree(o.Pidinfo)
	else:
	    pstree()
    elif (o.Pidinfo):
        find_and_print(o.Pidinfo)
    else:
        printTasks()

