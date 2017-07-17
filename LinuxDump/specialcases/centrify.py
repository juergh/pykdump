# Copyright notice string
__copyright__ = """\
(C) Copyright 2017 Hewlett Packard Enterprise Development LP
Author: Alex Sidorenko <asid@hpe.com>
"""

__txt = '''
WARNING: adclient (from Centrify) appears to be core dumping and abrt-hook-ccpp
may be stuck trying to talk to adclient. If the system has been reported as hung
and you plan on elevating a case please read the following solution article
for RHEL before doing so:

https://access.redhat.com/solutions/1575493
'''

from pykdump.API import *
from LinuxDump.Tasks import (TaskTable, TASK_STATE)
from LinuxDump.BTstack import (exec_bt)

from LinuxDump.inet.proto import (decodeSock, unix_sock)

# Test:
#if a dump matches the following:

#1. There are tasks called adclient and at least one has an UN state
#2. At least one has a stack trace containing do_coredump
#3. The first character of core_pattern is a '|' character
#4. There is also a abrt-hook-ccpp process running
#5. abrt-hook-ccpp has AF_UNIX socket and either it or its peer path starts
#                from "/var/centrifydc/daemon"

def do_check():
    tt = TaskTable()
    has_do_coredump = False
    has_UN = False
    for task in tt.getThreadsByComm('adclient'):
        pid = task.pid
        stack = exec_bt("bt {}".format(task.pid))[0]
        if (stack.hasfunc('do_coredump')):
            has_do_coredump = True
        if( task.ts.state & TASK_STATE.TASK_UNINTERRUPTIBLE):
            has_UN = True
        if (has_do_coredump and has_UN):
            break
    else:
        return

    # After some commands issued, GDB returns incorrect type for this -
    # 'char core_pattern[];' instead of ' char core_pattern[CORENAME_MAX_SIZE]'
    addr = sym2addr("core_pattern")
    core_pattern = SmartString(readmem(addr,1), addr, None) 
    #core_pattern = readSymbol("core_pattern")
    if (not core_pattern.startswith("|")):
            return
    abrt_hook = tt.getByComm('abrt-hook-ccpp')
    
    if (not abrt_hook):
        return

    __daemon = "/var/centrifydc/daemon"
    for sock in abrt_hook[0].get_task_socks():
        family, sktype, protoname, inet = decodeSock(sock)
        if (protoname == 'UNIX'):
            sock = sock.castTo("struct unix_sock")
            state, ino, s_path = unix_sock(sock)
            p_state, p_ino, p_path = unix_sock(sock.Peer)
            for path in (s_path, p_path):
                if (path.startswith(__daemon)):
                    pylog.info(__txt)
