#!/usr/bin/env python

from pykdump.API import *

from LinuxDump import percpu
from LinuxDump.Tasks import TaskTable, Task, tasksSummary

debug = API_options.debug




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
		out.append((basems - t.last_ran, t.pid, t))
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
        
	tgid = t.tgid
	if (pid != tgid):
	    pid_s =  "  %5d" % pid
	    tgid_s = "  (tgid=%d)" % tgid
	else:
	    pid_s =  " %5d " % pid
	    tgid_s = ""

	print " %s %15s %2d %15d  %s %s" \
		    % (pid_s, t.comm,  t.cpu,
			ran_ms_ago, sstate, tgid_s)


if ( __name__ == '__main__'):
    from optparse import OptionParser
    op =  OptionParser()

    op.add_option("-v", dest="Verbose", default = 0,
		action="store_true",
		help="verbose output")
    
    op.add_option("--summary", dest="Summary", default = 0,
		action="store_true",
		help="Summary")

    op.add_option("-r", "--reverse", dest="Reverse", default = 0,
                    action="store_true",
                    help="Reverse order while sorting")
    (o, args) = op.parse_args()
    
    if (o.Reverse):
	printTasks(reverse=True)
    elif (o.Summary):
	tasksSummary()
    else:
        printTasks()

