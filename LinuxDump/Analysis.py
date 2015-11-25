# !/usr/bin/env python
# -*- coding: utf-8 -*-
# module LinuxDump.Analysis
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
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
This is a package providing subroutines to analyse processes interdependicies,
locks etc. These subroutines can be used in different top-level programs
'''

import operator
from pykdump.API import *

from LinuxDump.inet import proto
from LinuxDump.Tasks import TaskTable, decode_waitq

# Print processes waiting for UNIX sockets (usuallu syslog /dev/log)
def print_wait_for_AF_UNIX(v=0):
    tt = TaskTable()
    basems = tt.basems
    
    # Part I - find all Unix sockets with peers
    peers_dict = defaultdict(list)              # peer-> (task, sock) list
    socks_dict = defaultdict(list)              # sock-> owners
    for t in tt.allTasks():
        once = TrueOnce(1)
        try:
            task_fds = t.taskFds()
        except crash.error:
            # page excluded
            continue
        last_ran = float(basems - t.Last_ran)/1000
        for fd, filep, dentry, inode in task_fds:
            socketaddr = proto.inode2socketaddr(inode)
            if (not socketaddr): continue

            socket = readSU("struct socket", socketaddr)
            sock = Deref(socket.sk)
            family, sktype, protoname, inet = proto.decodeSock(sock)
            if (family != proto.P_FAMILIES.PF_FILE):
                continue
    
            # AF_UNIX. on 2.4 we have just 'struct sock',
            # on 2.6 'struct unix_sock'
            if (not proto.sock_V1):
                sock = sock.castTo("struct unix_sock")

            #u_sock = readSU("struct unix_sock", 0xffff81073a7c3180)
            state, ino, path = proto.unix_sock(sock)
            socks_dict[sock].append((last_ran, t))
            # Check whether we have a peer
            peer = sock.Peer
            if (peer):
                peers_dict[peer].append((t, sock))
            
    # Part II - look at all peers
    nonempty_tasklist = []
    for peer, lst in peers_dict.items():
        state, ino, path = proto.unix_sock(peer)
        #if (path != "/dev/log"):
        #    continue
        #sleep = peer.sk.sk_sleep
        try:
            waitq = peer.peer_wait
        except:
            waitq = peer.peer_wq.wait
        tasklist = decode_waitq(waitq)
        if (tasklist):
            owners = sorted(socks_dict[peer])
            last_ran, t = owners[0]
            pids = [tt.pid for tt in tasklist]
            state, ino, path = proto.unix_sock(peer)
             # if last_ran is greater than this, issue a warning
            __max_time = 5
            if (v < 1 and last_ran < __max_time):
                continue
            if (v < 1 and path == "/dev/log"):
                # Just issue warnings
                msg = ("A problem with syslog daemon <{}> pid={} state={}\n"
                    "       It ran {:5.2f}s ago and {} processes"
                    " are waiting for it"
                     "".format(t.comm, t.pid,
                                                t.state[5:7], last_ran,
                                                len(tasklist)))
                if (v < 0):
                    msg += ("\n       Run 'hanginfo --syslogger -v' to get"
                                " more details")
                if (t.pid in pids):
                    msg += ("\n       Task pid={} CMD={} is waiting for"
                    " its own socket".format(t.pid, t.comm))
 
                pylog.warning(msg)
                if (v < 0):
                    return
                        
            print(" -- Socket we wait for: {} {}".format(peer, path))
            print("   Youngest process with this socket <{}> pid={}({}) ran "
                "{:5.2f}s ago".format(t.comm, t.pid, t.state[5:7], last_ran))
            print("   ...  {} tasks waiting for this socket".format(len(tasklist)))
            if (v > 0):
                for task in sorted(tasklist, key=operator.attrgetter('pid')):
                    print("     pid=%7d   CMD=%s" % (task.pid, task.comm))

    #if (once):
    #    print("--pid={} comm={} ran {:5.2f}s ago".format(t.pid, t.comm, last_ran))
