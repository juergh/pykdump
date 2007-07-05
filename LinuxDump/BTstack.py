#!/usr/bin/env python
#
# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.
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

__doc__ = '''
This is a module for working with stack traces/frames as obtained
from 'bt' command. At this moment we are just parsing results (text) obtained
by running 'bt', later we might switch to something better.
'''


from pykdump.API import *

import string
import time, os

try:
    from pyparsing import *
except ImportError:
    from pykdump.pyparsing import *

# Parsing results of 'bt' command
# For each process it has the folliwng structure:
#
# PID-line
# Frame-sections
#
# Each frame-section starts from something like
#   #2 [f2035de4] freeze_other_cpus at f8aa6b9f
# optionally followed by registers/stack/frame contents

def actionToInt(s,l,t):
    return int(t[0], 0)

def actionToHex(s,l,t):
    return int(t[0], 16)

def stripQuotes( s, l, t ):
    return [ t[0].strip('"') ]

Cid = Word(alphas+"_", alphanums+"_")

dquote = Literal('"')

noprefix_hexval =  Word(hexnums).setParseAction(actionToHex)
hexval = Combine("0x" + Word(hexnums))
decval = Word(nums+'-', nums).setParseAction(actionToInt)
intval = hexval | decval

dqstring = dblQuotedString.setParseAction(stripQuotes)


PID_line = Suppress("PID:") + decval.setResultsName("PID") + \
           Suppress("TASK:") + noprefix_hexval + \
           Suppress("CPU:") + decval + \
           Suppress("COMMAND:") + dqstring #+ lineEnd

FRAME_start = Suppress("#") + intval + \
              Suppress("[") + noprefix_hexval + Suppress("]") + Cid + \
              Optional("(via" +  SkipTo(")", include=True)).suppress() + \
              Suppress("at") + noprefix_hexval

FRAME_start = Regex("\s*#(\d+)\s+\[([^\]]+)\] .+$", re.M)
FRAME_empty = Suppress('(active)')

REG_context = Suppress(SkipTo(Literal('#') | Literal("PID")))
#REG_context = Regex("  \s+[^#]+$", re.M)
FRAME = (FRAME_start | FRAME_empty) + Optional(REG_context)

#FRAME = FRAME_start + ZeroOrMore(REG_context)

PID = PID_line + Group(OneOrMore(Group(FRAME)))
PIDs = OneOrMore(Group(PID))

# This class is for one thread only. Crash output says 'pid' even though
# in reality this is LWP

class BTStack:
    def __init__(self):
        pass
    def __repr__(self):
        out = ["\nPID=%d  CMD=%s" % (self.pid, self.cmd)]
        for f in self.frames:
            out.append(str(f))
        return string.join(out, "\n")
    # Do we have this function on stack?
    # 'func' is either a string (exact match), or compiled regexp
    # We can supply multiple func arguments, in this case the stack should
    # have all of them (logical AND)
    def hasfunc(self,  *funcs):
	res = {}
        for f in self.frames:
	    for t in funcs:
		if (type(t) == type("")):
		    # An exact match
		    if (t == f.func or t == f.via):
			res[t] = 1
		else:
		    # A regexp
                    if (t.search(f.func) or t.search(f.via)):
			res[t] = 1
        if (len(res) == len(funcs)):
	    return True
	else:
            return False
        
        
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
        return "  #%-2d  %s+0x%x%s%s" % \
               (self.level, self.func, self.offset, data, via)


import pprint
pp = pprint.PrettyPrinter(indent=4)


def exec_bt_pyparsing(cmd = None, text = None):
    # Debugging
    if (cmd != None):
        # Execute a crash command...
        text = exec_crash_command(cmd)
        #print text

    t0 = os.times()[0]
    res =  PIDs.parseString(text).asList()
    t1 = os.times()[0]

    pp.pprint(res)
    print "%7.2f s to parse" % (t1 - t0)
    return

    for pid, task, cpu, cmd, finfo in PIDs.parseString(text).asList():
        bts = BTStack()
        bts.pid = pid
        bts.cmd = cmd
        bts.frames = []
        if (len(finfo[0]) == 0):
            continue
        for level, fp, func, addr in finfo:
            f = BTFrame()
            f.level = level
            f.func = func
            f.addr = addr
            f.offset = addr - sym2addr(func)
            bts.frames.append(f)
        pp.pprint(bts)
    

# A parser using regular expressions only - no pyparsing
# PID: 0      TASK: c55c10b0  CPU: 1   COMMAND: "swapper"
re_pid = re.compile(r'^PID:\s+(\d+)\s+TASK:\s+([\da-f]+)\s+' +
                    'CPU:\s(\d+)\s+COMMAND:\s+"([^"]+)".*$')

# Frame start can have one of three forms:
#  #0 [c038ffa4] smp_call_function_interrupt at c0116c4a
# #7 [f2035f20] error_code (via page_fault) at c02d1ba9
# (active)

# In IA64:
#  #0 [BSP:e00000038dbb1458] netconsole_netdump at a000000000de7d40


re_f1 = re.compile(r'\s*#(\d+)\s+\[(?:BSP:)?([\da-f]+)\]\s+(.+)\sat\s([\da-f]+)$')
re_via = re.compile(r'(\S+)\s+\(via\s+([^)]+)\)$')

def exec_bt(cmd = None, text = None):
    # Debugging
    if (cmd != None):
        # Execute a crash command...
        text = exec_crash_command(cmd)
        #print "Got results from crash"


    # Split text into one-thread chunks
    btslist = []
    for s in text.split("\n\n"):
        #print '-' * 50
        #print s
        # The first line is PID-line, after that we have frames-list
        lines = s.splitlines()
        pidline = lines[0]
        #print pidline
        m = re_pid.match(pidline)
        pid = int(m.group(1))
        addr = int(m.group(2), 16)
        cpu = int(m.group(3))
        cmd = m.group(4)

        bts = BTStack()
        bts.pid = pid
        bts.cmd = cmd
        bts.frames = []

        #print "%d 0x%x %d <%s>" % (pid, addr, cpu, cmd)
        f = None
        for fl in lines[1:]:
            m = re_f1.match(fl)
            #print '--', fl
            if (m):
                f = BTFrame()
                f.level = int(m.group(1))
                f.func = m.group(3)
                viam = re_via.match(f.func)
                if (viam):
                    f.via = viam.group(2)
                    f.func = viam.group(1)
                else:
                    f.via = ''
                # If we have a pattern like 'error_code (via page_fault)'
                # it makes more sense to use 'via' func as a name
                f.addr = int(m.group(4), 16)
                f.offset = f.addr - sym2addr(f.func)
                f.data = []
                bts.frames.append(f)
            elif (f != None):
                f.data.append(fl)

        btslist.append(bts)
    return btslist


