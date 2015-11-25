#! /usr/bin/env python

# --------------------------------------------------------------------
# (C) Copyright 2006-2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------


from __future__ import print_function

import os, sys
import socket, time
from signal import *

import SocketServer
import threading

import cPickle as pickle

import crash

_pathname = '\0' + "remotecrash"

# TCP port
TCP_PORT = 10000

# From http://www.noah.org/wiki/Daemonize_Python
def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null', leavefds=[]):

    '''This forks the current process into a daemon. The stdin, stdout, and
    stderr arguments are file names that will be opened and be used to replace
    the standard file descriptors in sys.stdin, sys.stdout, and sys.stderr.
    These arguments are optional and default to /dev/null. Note that stderr is
    opened unbuffered, so if it shares a file with stdout then interleaved
    output may not appear in the order that you expect. '''

    # Do first fork.
    try: 
        pid = os.fork() 
        if pid > 0:
            #print("1st pid", pid)
            os.wait()     # Avoid zombie
            os._exit(0)   # Exit first parent.
    except OSError, e: 
        sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
        os._exit(1)

    # Decouple from parent environment.
    os.chdir("/") 
    os.umask(0) 
    os.setsid() 

    # Do second fork.
    try: 
        pid = os.fork() 
        if pid > 0:
            #print("2nd pid", pid)
            os._exit(0)   # Exit second parent.
    except OSError, e: 
        sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
        os._exit(1)

    # Now I am a daemon!
    # Change my name
    crash.setprocname("PyKdump")
    maxfd = 40
    for fd in range(3, maxfd):
        if (fd in leavefds):
            continue
        try:
            os.close(fd)
        except OSError:   # ERROR, fd wasn't open to begin with (ignored)
            pass
     # Redirect standard file descriptors.
    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

# A dictionary with stores values
_data = {}

def start_if_needed(id): 
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    #print("start_if_needed")
    try:
        s.bind(id)
    except socket.error, val:
        # Already running
        return
    # Become a daemon
    #print("Starting a daemon")
    sys.stdout.flush()
    if (os.fork() == 0):
        leavefds = [s.fileno()]
        #print("Daemonizing")
        daemonize('/dev/null','/tmp/daemon.log','/tmp/daemon.log', leavefds)
    else:
        # We continue with our process
        #signal(SIGCHLD, SIG_IGN)
        os.wait()
        return
    # Start TCP server
    t = threading.Thread(target=start_tcp_server)
    #t.daemon = True
    t.start()
    # Loop forever. This is a local AF_UNIX server
    while (True):
        data, addr = p = s.recvfrom(1024)
        req = pickle.loads(data)
        cmd = req[0]
        key = req[1]
        print(str(req))
        sys.stdout.flush()
        resp = None
        # Dictionary is thread-safe, no need to protect
        if (cmd == 0):
            # Query
            if (key in _data):
                resp = _data[key]
            else:
                resp = None
        elif (cmd == 1):
            # Register/store
            val = req[2]
            _data[key] = val
        elif (cmd == 2):
            # Unregister/delete
            try:
                del _data[key]
                resp = True
            except KeyError:
                resp = False
                
        presp = pickle.dumps(resp)
        s.sendto(presp, addr)

# TCP server
#class MyServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
class MyServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):    
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
    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024)
        # If we received 0 bytes, this means the other side
        # has closed the connection
        ldata = len(self.data)
        if (ldata == 0):
            #self.server.server_close()
            return
        # Send the whole registration table.
        table = pickle.dumps(_data)
        self.request.sendall(table)
        return



def start_tcp_server():
    server = MyServer(('', TCP_PORT), MyTCPHandler)
    server.serve_forever()
    #try:
    #    server.serve_forever()
    #except socket.error:
    #    pass

# --------------- Client-side subroutines-------------------------------------------

# Send a message and get response
# I. Fork a daemon if needed
# II. Prepare a temporary socket for communicating with it.
# III. Send request and return daemon's response
def _get_info(msg):
    start_if_needed(_pathname)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    # We need to create a temporary name and bind to it
    while(True):
        rndname = '\0' + os.urandom(20)
        try:
            s.bind(rndname)
            break
        except socket.error, val:
            pass
    s.connect(_pathname)
    pmsg = pickle.dumps(msg)
    s.send(pmsg)
    data, addr = s.recvfrom(4096)
    return pickle.loads(data)

def query(key):
    a = _get_info((0,key))
    print ("Received", a)

# 
def register(key, val):
    a = _get_info((1, key, val))
    print ("Received", a)

def unregister(key):
    a = _get_info((2, key))
    print ("Received", a)
    

if __name__ == "__main__":
    import getopt
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'r:u:q:t')
    except getopt.GetoptError:
        # print help information and exit:
        #usage()
        sys.exit(2)

    #start_tcp_server()
    #sys.exit(0)
    __TCP = False
    for o, a in optlist:
        if o == '-r':
            # Register
            #print((a, args[0]))
            register(a, args[0])
        elif o == '-u':
            # Unregister
            unregister(a)
        elif o == '-q':
            # query
            query(a)

