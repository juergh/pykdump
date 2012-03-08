#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2007-2010 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007-2010 Hewlett-Packard Co., All rights reserved.
#
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
This is a module for working with stack traces/frames as obtained
from 'bt' command. At this moment we are just parsing results (text) obtained
by running 'bt', later we might switch to something better.
'''

try:
    import crash
    from pykdump.API import *
except ImportError:
    pass



import string, re
import time, os, sys

# 5.1.0 started to show modules, e.g.
 #3 [ffff8102d6551d50] nlm_lookup_host at ffffffff88639781 [lockd]

# While 5.0.9 and earlier:
 #3 [ffff8102d6551d50] nlm_lookup_host at ffffffff88639781

# This class is for one thread only. Crash output says 'pid' even though
# in reality this is LWP

class BTStack:
    __regexps = {}
    def __init__(self):
        pass
    def __repr__(self):
        out = ["\nPID=%d  CPU=%d CMD=%s" % (self.pid, self.cpu, self.cmd)]
        for f in self.frames:
            out.append(str(f))
        return string.join(out, "\n")

    # A simplified repr - just functions on the stack
    def simplerepr(self):
        out =[]
        for f in self.frames:
            out.append(str(f.simplerepr()))
        return string.join(out, "\n")

    # Do we have this function on stack?
    # 'func' is either a string, or compiled regexp
    # If this is a string, we compile it and add to a table of precompiled
    # regexps
    # We can supply multiple func arguments, in this case the stack should
    # have all of them (logical AND)
    def oldhasfunc(self,  *funcs, **kwargs):
        try:
            reverse = kwargs['reverse']
        except KeyError:
            reverse = False

        negate = False
        res = {}
        n = len(funcs)
        frames = self.frames[:]
        if (reverse):
            frames.reverse()
        for f in frames:
            for t in funcs:
                if (type(t) == type("")):
                    if (t[0] == '!'):
                        t = t[1:]
                        negate = True
                    # Check whether we need to compile it
                    try:
                        tc = BTStack.__regexps[t]
                    except KeyError:
                        tc = re.compile(t)
                        BTStack.__regexps[t] = tc
                else:
                    tc = t
                # A regexp
                m1 = tc.search(f.func)
                m2 = tc.search(f.via)

                # A special case
                if (negate and not m1):
                    return f.func
                if (m1 and not negate):
                    if (n == 1):
                        return m1.group(0)
                    res[t] = m1.group(0)
                elif (m2 and not negate):
                    if (n == 1):
                        return m2.group(0)
                    res[t] = m2.group(0)
        if (len(res) == n):
            return True
        else:
            return False

    # Returns False or (framenum, func) tuple
    def hasfunc(self,  func, reverse = False):
        if (reverse):
            try:
                frames = self.rframes
            except AttributeError:
                frames = self.frames[:]
                frames.reverse
                self.rframes = frames
        else:
            frames = self.frames

        # Check whether we need to compile it
        try:
            tc = BTStack.__regexps[func]
        except KeyError:
            tc = re.compile(func)
            BTStack.__regexps[func] = tc

        for nf, f in enumerate(frames):
            # A regexp
            m1 = tc.search(f.func)
            if (m1):
                return (nf, m1.group(0))

            m2 = tc.search(f.via)
            if (m2):
                return (nf, m2.group(0))

        return False


    # A simple signature - to identify stacks that have the same
    # functions chain (not taking offsets into account)
    def getSimpleSignature(self):
        out = []
        for f in self.frames:
            out.append(f.func)
        return string.join(out,"/")

    # A full signature - to identify stacks that have the same
    # functions chain and offsets (this usually is seen when many
    # threads are hanging waiting for the same condition/resource)
    def getFullSignature(self):
        out = []
        for f in self.frames:
            out.append(repr(f))
        return string.join(out,"\n")
        
        
class BTFrame:
    def __init__(self):
        pass
    def __repr__(self):
        if (self.data):
            datalen = len(string.join(self.data))
            data = ', %d bytes of data' % datalen
        else:
            data = ''
        if (self.via):
            via = " , (via %s)" % self.via
        else:
            via = ''
        if (self.offset !=-1):
            return "  #%-2d  %s+0x%x%s%s" % \
                   (self.level, self.func, self.offset, data, via)
        else:
            # From text file - no real offset
            return "  #%-2d  %s 0x%x%s%s" % \
                   (self.level, self.func, self.addr, data, via)
    def simplerepr(self):
        return  "  #%-2d  %s" %  (self.level, self.func)


import pprint
pp = pprint.PrettyPrinter(indent=4)

    

# Prepare a summary of sleeping threads


def stack_categorize(e, descr):
    out = [e.frames[0].func, e.frames[-1].func]
    m =  e.hasfunc(descr[0], reverse = True)
    if (not m):
        return False
    out.append(m)
    for subc in descr[1:-1]:
        m = e.hasfunc(subc)
        if (m):
            out.append(m[1])
        else:
            out.append('?')
    return tuple(out)


_d_socket = ['sys_socketcall', 'accept|recv', 'tcp|udp|unix']
_d_fswrite = ['sys_write', '^[^_]*_write']
_d_fsopen = ['sys_open', 'vfs_create', '^[^_]+_create']
_d_pipe = ['pipe_\w+']
_d_exit = ['do_exit', 'wait_for_completion']
_d_selpoll = ['sys_poll|sys_select']
_d_futex = ['sys_futex', 'futex_wait|get_futex_key|do_futex']
_d_wait = ['^sys_wait.*$']
_d_catchall = ['^.*$']

_d_kthread = ['kernel_thread_helper',
              'ksoftirqd|context_thread|migration_task|kswapd|bdflush' +
              '|kupdate|md_thread|.+KBUILD_BASENAME']

_d_kthread = ['kernel_thread_helper']
_d_syscall = ['sys_.+']

_d_all = [_d_socket, 
          _d_fswrite, _d_fsopen,
          _d_pipe, _d_futex, _d_wait,
          _d_exit, _d_kthread, _d_syscall, _d_catchall]


def bt_summarize(btlist):
    bt_sched = []
    bt_others =[]


    out = {}
    bt_un = []
    for e in btlist:
        # FS-stuff
        
        for d in _d_all:
            m = stack_categorize(e, d)
            if (m):
                out[m] = out.setdefault(m, 0) + 1
                break
        if (not m):
            bt_un.append(e)

    keys = out.keys()
    keys.sort()

    # Group by top, bot
    ctop = cbot = None
    for k in keys:
        top = k[0]
        bot = k[1]
        if (top != ctop):
            print ("  =====", top)
            ctop = top
        if (bot != cbot):
            print (" \t=====", bot)
            cbot = bot
        print ("\t\t", k[2:], out[k])

    for f in bt_un:
        print (f)

    

# A parser using regular expressions only - no pyparsing
# PID: 0      TASK: c55c10b0  CPU: 1   COMMAND: "swapper"
re_pid = re.compile(r'^PID:\s+(\d+)\s+TASK:\s+([\da-f]+)\s+' +
                    'CPU:\s(\d+)\s+COMMAND:\s+"([^"]+)".*$')

# Frame start can have one of four forms:
# #0 [c038ffa4] smp_call_function_interrupt at c0116c4a
# #7 [f2035f20] error_code (via page_fault) at c02d1ba9
# #9 [103edef1f80] tracesys at ffffffff8011045a (via system_call)
# (active)
#
# and there can be space in [] like  #0 [ c7bfe28] schedule at 21249c3
# 5.1.0 started to show modules, e.g.
 #3 [ffff8102d6551d50] nlm_lookup_host at ffffffff88639781 [lockd]

# In IA64:
#  #0 [BSP:e00000038dbb1458] netconsole_netdump at a000000000de7d40

#                         frame                  faddr        func        addr          [mod]
re_f1 = re.compile(r'\s*(?:#\d+)?\s+\[(?:BSP:)?([\da-f]+)\]\s+(.+)\sat\s([\da-f]+)(\s+\[[-\w]+\])?(\s+\*)?$')
# The 1st line of 'bt -t' stacks
#       START: disk_dump at f8aa6d6e
re_f1_t = re.compile(r'\s*(START:)\s+([\w.]+)\sat\s([\da-f]+)$')

re_via = re.compile(r'(\S+)\s+\(via\s+([^)]+)\)$')


# Regex to remove (via funcname)
re_rmvia = re.compile(r'\s*\(via\s+([^)]+)\)')

@memoize_cond(CU_LIVE | CU_PYMOD | CU_TIMEOUT)
def exec_bt(crashcmd = None, text = None):
    #print "Doing exec_bt('%s')" % crashcmd
    btslist = []
    # Debugging
    if (crashcmd != None):
        # Execute a crash command...
        text = memoize_cond(CU_LIVE | CU_TIMEOUT)(exec_crash_command)(crashcmd)
        #print "Got results from crash", crashcmd
        if (not text):
            # Got timeout
            return btslist


    # Split text into one-thread chunks
    for s in text.split("\n\n"):
        #print '-' * 50
        #print s
        # The first line is PID-line, after that we have frames-list
        lines = s.splitlines()
        pidline = lines[0]
        #print pidline
        m = re_pid.match(pidline)
        if (not m):
            continue
        pid = int(m.group(1))
        addr = int(m.group(2), 16)
        cpu = int(m.group(3))
        cmd = m.group(4)

        bts = BTStack()
        bts.pid = pid
        bts.cmd = cmd
        bts.addr = addr
        bts.cpu = cpu
        bts.frames = []

        #print "%d 0x%x %d <%s>" % (pid, addr, cpu, cmd)
        f = None
        level = 0
        for fl in lines[1:]:
            # Before doing anything else, remove (via funcname) and remember it
            m = re_rmvia.search(fl)
            if (m):
                fls = re_rmvia.sub('', fl)
                viafunc = m.group(1)
            else:
                viafunc = ''
                fls = fl
            m = (re_f1.match(fls) or re_f1_t.match(fls))
            #print '-- <%s>' % fls, m, viafunc

            if (m):
                f = BTFrame()
                f.level = level
                level += 1
                f.func = m.group(2)
                # For 'bt -at' we can have START instead of frameaddr
                try:
                    f.frame = int(m.group(1), 16)
                except ValueError:
                    f.frame = None
                
                f.via = viafunc

                # If we have a pattern like 'error_code (via page_fault)'
                # it makes more sense to use 'via' func as a name
                f.addr = int(m.group(3), 16)
                f.module = m.group(4)
                if (crashcmd):
                    # Real dump environment
                    f.offset = f.addr - sym2addr(f.func)
                else:
                    f.offset = -1       # Debugging
                f.data = []
                bts.frames.append(f)
            elif (f != None):
                f.data.append(fl)

        btslist.append(bts)
    return btslist


# Merge similar stacks and print them. If TaskTable is available,
# add timing info
def bt_mergestacks(btlist, precise = False, 
        count = 1, reverse=False, tt=None, verbose=0):
    # Leave only those frames that have CMD=mss.1

    if (tt):
        basems = tt.basems
    smap = {}
    for i, s in enumerate(btlist):
        if (precise):
            sig =  s.getFullSignature()
        else:
            sig =  s.getSimpleSignature()
        smap.setdefault(sig, []).append(i)

    sorted = []
    for k, val in smap.items():
        nel = len(val)
        if (nel < count): continue
        sorted.append([nel, val])

    sorted.sort()
    if (reverse):
        sorted.reverse()

    for nel, val in sorted:
        # Count programs with the same name
        cmds = {}
        sch_young = None
        sch_old = None

        pidlist = []
        for i in val:
            p = btlist[i]
            pid = p.pid
            pidlist.append(pid)
            if (tt):
                task = tt.getByTid(pid)
                if (not task):
                    continue
                ran_ms_ago = basems - task.Last_ran
                if (sch_old == None or ran_ms_ago > sch_old):
                    sch_old = ran_ms_ago
                    pid_old = pid
                if (sch_young == None or ran_ms_ago < sch_young):
                    sch_young = ran_ms_ago
                    pid_young = pid
            cmds[p.cmd] = cmds.setdefault(p.cmd, 0) + 1
        print ("\n------- %d stacks like that: ----------" % nel)
        cmdnames = cmds.keys()
        cmdnames.sort()
        if (precise):
            print (p)
        else:
            print (p.simplerepr())
        if (tt and sch_young != None and sch_old != None):
            print ("    youngest=%ds(pid=%d), oldest=%ds(pid=%d)" % \
               (sch_young/1000, pid_young,  sch_old/1000, pid_old))
        print ("\n   ........................")
        for cmd in cmdnames:
            print ("     %-30s %d times" % (cmd, cmds[cmd]))
        if (verbose):
            # Print PIDs
            pidlist.sort()
            print ("\n   ... PIDs ...",)
            for i, pid in enumerate(pidlist):
                if (i%10 == 0):
                    print ("\n    ",)
                print (str(pid).rjust(6), end='')
            print ("")

    

# This module can be useful as a standalone program for parsing
# text files created from crash
if ( __name__ == '__main__'):
    from optparse import OptionParser
    op =  OptionParser()

    op.add_option("-v", dest="Verbose", default = 0,
                    action="store_true",
                    help="verbose output")

    op.add_option("-r", "--reverse", dest="Reverse", default = 0,
                    action="store_true",
                    help="Reverse order while sorting")

    op.add_option("--summary", dest="Summary", default = 0,
                    action="store_true",
                    help="Print a summary")

    op.add_option("-p", "--precise", dest="Precise", default = 0,
                    action="store_true",
                    help="Precise stack matching, both func and offset")

    op.add_option("-c", "--count", dest="Count", default = 1,
                  action="store", type="int",
                  help="Print only stacks that have >= count copies")

    op.add_option("-q", dest="Quiet", default = 0,
                    action="store_true",
                    help="quiet mode - print warnings only")


    (o, args) = op.parse_args()


    if (o.Verbose):
        verbose = 1
    else:
        verbose =0
    
    fname = args[0]
    count = o.Count
    reverse = o.Reverse
    precise = o.Precise
    
    #text = open("/home/alexs/cu/Vxfs/bt.out", "r").read()
    text = open(fname, "r").read()

    btlist = exec_bt(text=text)

    if (o.Summary):
        bt_summarize(btlist)
        sys.exit(0)
            

    bt_mergestacks(btlist, precise=precise, count=count, reverse=reverse)
