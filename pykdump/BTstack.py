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

import string

from pyparsing import *
import pyparsing as pyp

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

noprefix_hexval =  Word(pyp.hexnums).setParseAction(actionToHex)
hexval = Combine("0x" + Word(pyp.hexnums))
decval = Word(pyp.nums+'-', pyp.nums).setParseAction(actionToInt)
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

FRAME_empty = Suppress('(active)')

REG_context = Suppress(SkipTo(Literal('#') | Literal("PID")))
FRAME = (FRAME_start | FRAME_empty) + Optional(REG_context)

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
        
        
class BTFrame:
    def __init__(self):
        pass
    def __repr__(self):
        return "  #%-2d  %35s  0x%08x" % (self.level, self.func, self.addr)


import pprint
pp = pprint.PrettyPrinter(indent=4)


def exec_bt(cmd = None, text = None):
    # Debugging
    if (cmd != None):
        # Execute a crash command...
        from pykdump.API import *
        text = exec_crash_command(cmd)
        #print text
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
            bts.frames.append(f)
        pp.pprint(bts)
    
