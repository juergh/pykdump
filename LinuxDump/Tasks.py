#!/usr/bin/env python
# -*- coding: latin-1 -*-
# Time-stamp: <07/03/16 14:27:40 alexs>

# Tasks and Pids

from pykdump.API import *

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


class TaskTable:
    def __init__(self):
        self.tt =  readSUListFromHead(init_task_saddr, 'tasks',
                                 'struct task_struct',
                                 inchead = True, maxel=100000)
        self.pids = {}
        self.comms = {}
        self.filepids = {}
        self.toffset = member_offset("struct task_struct", "thread_group")

    # Get threads for task
    def getThreads(self, ts):
        if (self.toffset == -1):
            return []
        saddr = Addr(ts) + self.toffset
        
        threads = readSUListFromHead(saddr, "thread_group",
                                     "struct task_struct")
        return threads
    
    # Initialize dicts
    def __init_dicts(self):
        for t in self.tt:
            self.pids[t.pid] = t
            self.comms.setdefault(t.comm, []).append(t)
    # get task by pid
    def getByPid(self, pid):
        if (len(self.pids) == 0):
            self.__init_dicts()
        try:
            return self.pids[pid]
        except KeyError:
            return None
                
    # get task by comm
    def getByComm(self, comm):
        if (len(self.pids) == 0):
            self.__init_dicts()
        try:
            return self.comms[comm]
        except KeyError:
            return []
        
    # get task by 'struct file *' pointer. As there can be several
    # processes sharing the same file, we return a list
    def getByFile(self, filep):
        if (len(self.filepids) == 0):
            for t in self.tt:
                for fp in taskFds(t, True):
                    self.filepids.setdefault(fp, []).append(t)

        try:
            return self.filepids[filep]
        except KeyError:
            return []
        
            
            
# Get fds from 'task_struct'
def taskFds(task, short = False):
    out = []
    if (task.files):
        files = task.Deref.files
        try:
            fdt = files.Deref.fdt
            fd = fdt.fd
            max_fds = fdt.max_fds
        except KeyError:
            fd = files.fd
            max_fds = files.max_fds
        for i in range(max_fds):
            filep = readPtr(fd + pointersize * i)
            if (filep):
                if (short):
                    out.append(filep)
                    continue
                sfile = readSU("struct file", filep)
                dentry = sfile.Deref.f_dentry
                inode = dentry.Deref.d_inode
                out.append((i, filep, dentry, inode))
    return out



if ( __name__ == '__main__'):
    tt = TaskTable()
    t = tt.getByComm("kicker")
    for t in tt.tt:
        print t.comm, t.pid
        #threads = tt.getThreads(t)
            


