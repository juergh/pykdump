#!/usr/bin/env python

from pykdump.API import *

from LinuxDump import percpu
from LinuxDump.Tasks import TaskTable, Task

debug = API_options.debug

            
        
def printTasks():
    basems = None
    #quit()
    tt = TaskTable()
    if (debug):
        print "Basems", tt.basems, "Uptime:",  ms2uptime(tt.basems)
    for task in tt.tt:
        # This is a process
        t = Task(task)
        last_ran_ms = t.last_ran
        print "%5d   %15s %2d %10d %s" % (t.pid, t.comm,  t.cpu,
                                        tt.basems-last_ran_ms, t.state)

        for t in tt.getThreads(task):
            # This is a thread - no need to print command name again
            t = Task(t)
            last_ran_ms = t.last_ran
            print "  %5d %15s %2d %10d %s" % (t.pid, t.comm,  t.cpu,
                                            tt.basems-last_ran_ms, t.state)
            if (debug):
                print "\tlast_ran_ms", last_ran_ms 
        


    #print get_schedclockbase() - basems


if ( __name__ == '__main__'):
    printTasks()

