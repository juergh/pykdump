#!/usr/bin/env python

# Time-stamp: <12/06/19 11:32:20 alexs>

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.

from __future__ import print_function

import sys
import os, select, socket, struct, time, functools

from signal import *
import threading

import SocketServer


from pykdump.API import *
from pykdump.remote import Records, Discovery

# Dummy replacement of crash
#import crash
#from crash import exec_crash_command_bg2


def exec_remote(cmd, fsend, mplexid):
    timeout = crash.default_timeout
    (fd, pid) = exec_crash_command_bg2(cmd)
    running_pids[mplexid] = pid
    print (" ==<%s> started pid=%d========" % (cmd, pid))
    fsend(mplexid, 2, "<%s> started" % cmd)

    readable = [fd]
    out = []
    bt = time.time()
    # Send a status update one per 2s
    update_period = 1
    last_update = bt
    while(True):
        # A special case: background command closed fd before exiting
        try:
            ready, _, _ = select.select(readable, [], [], 0.2)
        except select.error as v:
            print("select fd=%d" % fd, str(v))
            break
        ct = time.time()
        if (ct - last_update >= update_period):
            last_update = ct
            msg ="<%s> running for %5.1f s" % (cmd, ct - bt)
            fsend(mplexid, 2, msg)
        if (ct - bt > timeout):
            print(crash.WARNING,
                  "<%s> failed to complete within the timeout=%-2.1fs" \
                  % (cmd, timeout))
            os.kill(pid, 15)
            break
        if (not ready):
            continue
        #print (" ->read")
        s = os.read(fd, 1000)
        #print (" <-read")
        if (not s):
            break
        #print(s, end='')
        #print("sending %d bytes" % len(s))
        fsend(mplexid, 0, s)
        out.append(s)

    (pid, status) = os.waitpid(pid, 0)
    del running_pids[mplexid]

    print (" ==============", pid)

    msg = ""
    if (os.WIFEXITED(status)):
        ecode = os.WEXITSTATUS(status)
        if (True or ecode):
            msg = "ExitCode=%d" % ecode
    elif (os.WIFSIGNALED(status)):
        if (os.WCOREDUMP(status)):
            msg = "Core Dumped"
        else:
            msg = "Signal %d" % os.WTERMSIG(status)
    print (msg)
    fsend(mplexid, 1, msg)
    return

class MyServer(SocketServer.TCPServer):
    allow_reuse_address = 1
    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

        


        
class MyTCPHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """
    #
    def __init__(self, request, client_address, server):
        self.rec = Records.Records(self.rechandler)
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        # self.request is the TCP socket connected to the client
        while(True):
            # We need an extra loop to guarantee that we have read the whole
            # record
            data = self.request.recv(1024)
            #print ("Got %d bytes from %s" % \
            #       (len(data), self.client_address[0]))            
            # If we received 0 bytes, this means the other side
            # has closed the connection
            ldata = len(data)
            if (ldata == 0):
                self.server.server_close()
                return
            self.rec.feedData(data)
 
            # just send back the same data, but upper-cased
    def rechandler(self, data, c1, c2):
        # c2 is a type of command
        # 0 - execute PyKdump
        # 1 - kill thread if it is still running
        if (c2 == 0):
            #csender = functools.partial(self.sender, c1)
            print ("Calling exec_remote", data, c1, c2)
            t = threading.Thread(target=exec_remote, args=[data, self.sender, c1])
            t.start()
            #exec_remote(data, self.sender, c1)
        elif (c2 == 1):
            # Kill the instance if it is still running
            kill_mplexid(c1)
            
    # This arguments order is needed for currying
    def sender(self, c1, c2, data):
        msg = self.rec.packRecord(data, c1, c2)
        with Tlock:
            # Use sendall() instead of send() - we need complete messages
            self.request.sendall(msg)

# Kill PyKdump process used by mplexid
def kill_mplexid(mplexid):
    def killer():
        # GDB processes SIGTERM and exits cleanly, so using it will not 
        # produce a warning. Let us use signal 16
        for sig in (16, 9):
            if (not mplexid in running_pids):
                return
            pid = running_pids[mplexid]
            print("Killing", pid, sig)
            os.kill(pid, sig)
            time.sleep(5)
    t = threading.Thread(target=killer)
    t.start()
            

if __name__ == "__main__":
    HOST, PORT = "", 9999

    # find an unused TCP port in this range
    portrange = range(2000,2500)
    # Create the server, binding to localhost on p
    for port in portrange:
        try:
            server = MyServer((HOST, port), MyTCPHandler)
            break
        except socket.error:
            pass

    print ("Listening on TCP port", port)
    username = os.environ['USER']
    cwd = os.getcwd()
    Discovery.register(port, (username, cwd))
    #Discovery._get_info("\0test")
    
    # Threads-related stuff
    Tlock = threading.Lock()                    # TCP send lock
    main_thread = threading.currentThread()
    running_pids = {}                           # key=mplexid

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    try: 
        server.serve_forever() 
    except KeyboardInterrupt:
        print ("^C detected")
        pass
    except (socket.error, select.error):
        # SIGINT processing is special in crash/GDB environment
        pass
    finally: 
        print ("server_close()" )
        server.server_close() 
        Discovery.unregister(port)
        print ("bye")

        
