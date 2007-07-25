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
    for mt in tt.allTasks():
        last_ran_ms = mt.last_ran
        print "%5d   %15s %2d %10d %s" % (mt.pid, mt.comm,  mt.cpu,
                                        tt.basems-last_ran_ms, mt.state)

        for t in mt.threads:
            # This is a thread - no need to print command name again
            last_ran_ms = t.last_ran
            print "  %5d %15s %2d %10d %s" % (t.pid, t.comm,  t.cpu,
                                            tt.basems-last_ran_ms, t.state)
            if (debug):
                print "\tlast_ran_ms", last_ran_ms 
	#print mt.tgid
        


    #print get_schedclockbase() - basems


if ( __name__ == '__main__'):
    printTasks()

