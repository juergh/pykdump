#
# Code that decides whether we are embedded or driving crash externally
# All other modules should use this one and never PTY/crashmodule directly
#
# Time-stamp: <07/07/03 12:27:48 alexs>
#

import sys, os, stat, errno, time
import re
import atexit
#import pykdump.pexpect as pexpect
import pexpect
import tempfile
        
import popen2
import threading


# GLobals used my this module

child = None
dumpid = None
waitstr = None

# FIFO creation/removal

fifoname = "PYT_fifo"

_tempdir = None

def PYT_mkfifo():
    global fifoname,  _tempdir
    _tempdir = tempfile.mkdtemp("pycrash")
    fifoname = _tempdir + "/" + fifoname
    try:
        os.mkfifo(fifoname)
    except OSError, (err, errstr):
        if (err == errno.EEXIST):
            # Check whether it's FIFO and writable
            st_mode = os.stat(fifoname)[0]
            if (not stat.S_ISFIFO(st_mode)):
                print "FATAL: %s is not a FIFO" % fifoname
                fifoname = None             # To prevent cleanup
                sys.exit(1)
        else:
            print "FATAL: cannot mkfifo %s in the current directory" % fifoname
            fifoname = None             # To prevent cleanup
            sys.exit(1)

def PYT_fifo_cleanup():
    try:
        if (fifoname):
            os.unlink(fifoname)
        os.rmdir(_tempdir)
    except:
        pass

# ------------- Pexpect version -------------------------

def pexpectCleanup():
    global child
    child.sendline('quit')
    child.sendeof()
    time.sleep(0.1)
    child.close()
    PYT_fifo_cleanup()


def openPTY(args, crash = 'crash'):
    global child, dumpid, waitstr
    argslist = args.split()
    if (os.uname()[-1] == 'ia64'):
	nocrashrc = ['--no_crashrc'] 
    else:
	nocrashrc = ['--no_crashrc']
    child = pexpect.spawn(crash, nocrashrc +argslist)
    #print crash , nocrashrc +argslist
    import re
    waitstr = re.compile(r'crash.*> ')
    try:
        child.expect(waitstr)
    except:
        # To prevent an error message while destroying spawn
        child.spawn = None
        return False
    # Skip everything till 'KERNEL'
    info = child.before.splitlines()
    for n, l in enumerate(info):
        if (l.find('KERNEL') != -1):
            info = info[n:]
            break

    # Initial settings
    child.delaybeforesend = 0
    child.sendline('set scroll off')
    #child.setecho(0)
    child.expect(waitstr)

    child.sendline('gdb set width 300')
    child.expect(waitstr)

    #waitstr = "\n" + waitstr

    # We need to create FIFO
    PYT_mkfifo()
    atexit.register(pexpectCleanup)
    return info



def PTYgetOutput(command):
    #print "--->", command
    child.sendline(command)
    #self.child.expect(command)
    child.expect(waitstr)
    # The command we send is echoed, so we don't want the 1st line
    res = child.before.strip().split("\n", 1)
    #print res
    # Beware: according to pyexpect documentation, we might see CR-LF
    # from pty even on Unix!
    #print "Sent <%s> got <%s>" % (command, res)
    if (len(res) > 1):
        return res[1].replace('\r', '')
    else:
        return ""

def PTYsendLine(command):
    child.sendline(command)
    
def PTYwait():
    child.wait()

crasheof_re = re.compile(r'^crash.*> quit\s*$')
def PTYinteract():
    # Skip the 1st line - it echoes command we've sent
    child.expect("\n")
    l = child.before.replace('\r', '')
    #
    while (True):
        child.expect("\n")
        l = child.before.replace('\r', '')
        if (not crasheof_re.match(l)):
            print l

def Cbreak():
    import tty, termios, os
    fd = child.child_fd
    print "fd=", os.isatty(fd), fd
    new = termios.tcgetattr(fd)
    print new[0]
    new[0] = new[0] | termios.ICRNL
    #print new[0]
    #termios.tcsetattr(fd, tty.TCSADRAIN, new)
    termios.tcsetattr(fd, tty.TCSANOW, new)
    #sys.exit(0)
    

# -------------- Pipe2 version ---------------------

from StringIO import StringIO
import os, fcntl, select

# Pipe2
p2r = None
p2w = None
p2marker = '--%^hnKhgk-'
p2text = ""
p2ev = threading.Event()

def p2Cleanup():
    global p2r, p2w, p2mt
    p2w.write("quit\n")
    p2w.flush()
    p2mt.join()
    p2r.close()
    p2w.close()
    PYT_fifo_cleanup()

# Read lines, one at at time, and print them
def tRead(r):
    global p2text, p2ev, p2marker
    print "tRead started"
    out = ""
    rfd = r.fileno()
    fcntl.fcntl(rfd, fcntl.F_SETFL, os.O_NONBLOCK)
    while(True):
        select.select((rfd,), (), ())
        l = os.read(rfd,6000)
        if (len(l) == 0):
            break
        out += l
        ind = out.find(p2marker)
        if (ind != -1):
            p2text = out[:ind]
            p2ev.set()
            #print "  +++ Text Ready +++"
            #print p2text
            out = ""

  

def openPipe2(args, crash = 'crash'):
    PYT_mkfifo()
    global p2r, p2w, p2mt, p2marker
    (p2r, p2w) = popen2.popen2(crash + ' ' + args)
    p2mt = threading.Thread(target=tRead, args=(p2r,))
    p2mt.start()
    atexit.register(p2Cleanup)
    p2getOutput('set scroll off')
    return True

    
def p2getOutput(command):
    global p2w, p2ev, p2text, p2marker
    p2ev.clear()
    if (command):
        p2w.write(command + "\n")
    p2w.write("echo " + p2marker + "\n")
    p2w.flush()
    #print " ... Sending and waiting ..."
    p2ev.wait()
    #print " ... Wakeup ..."
    return p2text

def p2sendLine(cmd):
    print cmd + "\n"
    p2w.write(cmd + "\n")
    p2w.flush()

def p2interact():
    pass

# Issue a GDB command and return the output

def exec_gdb_command(cmd):
    # Do some basic checks
    rstr = getOutput("gdb " + cmd)
    if (rstr.find("=") != -1):
        return rstr
    else:
        return None

mode = "PTY"
#mode = "P2"

try:
    import python
except ImportError:
    if (mode == "PTY"):
        #print "+++Using PTY version+++"
        getOutput = PTYgetOutput
        openDump = openPTY
        sendLine = PTYsendLine
        interact = PTYinteract
	wait = PTYwait
    elif (mode == "P2"):
        print "+++Using Pipe2 version+++"
        getOutput = p2getOutput
        openDump = openPipe2
        sendLine = p2sendLine
        interact = p2interact
