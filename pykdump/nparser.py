#!/usr/bin/env python

# Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.
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
This is a parser for processing strings obtained from running crash commands
Its main purpose is to obtain symbolic information about struct/union
definitions. This module contains newer implementation of some functions, more
efficient than those in 'tparser.py' (an old parser module).
Both these modules should be eventually replaced with direct interface to GDB
'''

import sys
import string, re
import pprint
import atexit

pp = pprint.PrettyPrinter(indent=4)

from Generic import FieldInfo, hexl, Bunch

import pyparsing as pyp
from pyparsing import *
#pyp.ParserElement.enablePackrat()


# A special class to be used with attibutes
class Attr:
    def __init__(self, name, val):
        self.name = name
        self.val = val
    def __repr__(self):
        return "<%s:%s>" % (self.name, str(self.val))

# ........... Actions .................................................
def actionStar(s,loc, toks):
    return Attr("star", toks[0])

def actionArray(s,loc, toks):
    return Attr("array", int(toks[0],0))

def actionFunc(s,loc, toks):
    return  [Attr("func", True)] + toks.asList()

def actionBitfield(s,loc, toks):
    return  Attr("bitfield", int(toks[0],0))

def actionEnumvals(s,loc, toks):
    return Attr("enumvals", toks.asList())

def actionBegSU(s, loc, toks):
    return Attr("begsu", toks.asList())

def actionEndSU(s, loc, toks):
    return Attr("endsu", toks.asList())

def actionBegtype(s, loc, toks):
    return toks[0].split()

Integer  = Word( nums )

lsqb = Literal("[").suppress()
rsqb = Literal("]").suppress()
lpar = Literal("(").suppress()
rpar = Literal(")").suppress()
Lbracket = Suppress("{")
Rbracket = Suppress("}")
eqsign = Suppress("=")
pars = CharsNotIn("()")
Stars = Word("*").setParseAction(actionStar)

Array = lsqb + Integer + rsqb
Array.setParseAction(actionArray)
Cid = Word(alphas+"_", alphanums+"_")
EndSimple = Literal(";").suppress()
dStruct = Literal("struct")
dEnum = Literal("enum")
dUnion = Literal("union")
bitfield = (Suppress(":") + Integer).setParseAction(actionBitfield)

# The beginning of type - everything Cid-like
begtype = Regex(r'[a-zA-Z0-9_ ]+')
begtype.setParseAction(actionBegtype)

# Function-like
fbody = lpar + Suppress("*") + Cid + rpar + SkipTo(EndSimple, False).suppress()
fbody.setParseAction(actionFunc)


s1 = begtype + Optional(Stars) + Optional(Cid|fbody) + Optional(Array|bitfield) + \
     EndSimple

s2 = OneOrMore(Cid) + Optional(Stars) + Optional(Cid) + Optional(Array) + \
     Optional(bitfield) + EndSimple

f1 = begtype + Optional(Stars) + lpar + Suppress("*") + Cid + rpar + \
     SkipTo(EndSimple).copy().suppress()

f2 = OneOrMore(Cid) + Optional(Stars) + lpar + Suppress("*") + Cid + rpar + \
     SkipTo(EndSimple).copy().suppress()

f1.setParseAction(actionFunc)

# crash/GDB does not show multiple nested structs/unions properly, e.g.
#     union {
#        struct {...} vm_set;
#        struct prio_tree_node prio_tree_node;
#    } shared;
incomplete =  dStruct + Literal("{...}") + Cid + EndSimple;

enumvals =  (Lbracket + delimitedList(Cid) + Rbracket).setParseAction(actionEnumvals)
e1 = dEnum + Optional(Cid) + enumvals + Optional(Cid) + EndSimple

begsu = (dUnion|dStruct) + Optional(Cid) + Lbracket
begsu.setParseAction(actionBegSU)
endsu = Rbracket + Optional(Stars) + Optional(Cid) + Optional(EndSimple)
endsu.setParseAction(actionEndSU)

new1 = (s1|e1|incomplete|begsu|endsu)

# Convert result of new1 to FieldInfo
def newToFieldInfo(l):
    l = l.asList()
    f = FieldInfo()
    tandi = []
    for a in l:
        if (isinstance(a, Attr)):
            f[a.name] = a.val
        else:
            tandi.append(a)
    f.type = tandi[:-1]
    f.fname = tandi[-1]
    return f
    

def parseStruct(lines):
    out = []
    f = None
    while (lines):
        l = lines.pop(0)
        #print l,
        p = new1.parseString(l)
        a = p[0]
        if (isinstance(a, Attr) and a.name == "begsu"):
            #print "  ++begsu:", a.val
            f = parseStruct(lines)
            f.type = a.val
            out.append(f)
        elif (isinstance(a, Attr) and a.name == "endsu"):
            f = FieldInfo()
            #print "  --endsu:", a.val
            if (a.val):
                f.fname = a.val[0]
            f.body = out
            return f
        else:
            out.append(newToFieldInfo(p))
    return out

def GDBStructInfo(text):
    lines = text.splitlines()
    lines[0] = lines[0].split("=")[1]
    pres = parseStruct(lines)[0]
    #print pres
    stype = string.join(pres["type"])
    size = 0
    body = pres["body"]
    return stype, size, body

# --------- Main for testing purposes ------------
if __name__ == '__main__':
    import os, time
    t_start = os.times()[0]
    t_starta = time.time()
    def cleanup():
        print "Execution took %6.2fs (real) %6.2fs (CPU)" % (time.time() - t_starta,
                                                             os.times()[0] - t_start)

    from tparser import GDBfullStmt, OneStatement

    atexit.register(cleanup)

    #print new1.parseString("struct hlist_node name_hlist;")
    #print new1.parseString("char name[16];")
    #print new1.parseString("void *ax25_ptr;")
    #print new1.parseString("struct net_device_stats *(*get_stats)(struct net_device *);")
    #tstr = open("sk_buff.out", 'r').read()
    #pp.pprint(GDBfullStmt.parseString(tstr).asList())
    #sys.exit(0)


    names = ("net_device.out", "sk_buff.out", "sock.out", "fib_table.out")

    def testold():
        for fn in names:
            tstr = open(fn, 'r').read()
            for i in range(1):
                pp.pprint(GDBfullStmt.parseString(tstr).asList())
                print len(GDBfullStmt.parseString(tstr))


    def testnew():
        for fn in names:
            tstr = open(fn, 'r').read()
            for i in range(1):
                lines = tstr.splitlines()

                lines[0] = lines[0].split("=")[1]
                #lines[-1] = lines[-1].strip() + "dummy;\n"
                pp.pprint(parseStruct(lines))
                print len(parseStruct(lines))

    #import hotshot, hotshot.stats
    #prof = hotshot.Profile("dev.prof")
    #prof.runcall(testnew)
    #stats = hotshot.stats.load("dev.prof")
    #stats.strip_dirs()

    #stats.sort_stats('cumulative', 'calls')
    #stats.print_stats(20)

    if (len (sys.argv) > 1 and sys.argv[1] == '-o'):
        testold()
    else:
        testnew()
    sys.exit(0)

    # A simple one-liner test
    #tstr =  open("sk_buff.out", 'r').read()
    tstr =  open("net_device.out", 'r').read()
    for i in range(1):
        #print len(GDBfullStmt.parseString(tstr))
        #pp.pprint(GDBfullStmt.parseString(tstr).asList())
        #continue
        lines = tstr.splitlines()
    
        lines[0] = lines[0].split("=")[1]
        lines[-1] = lines[-1].strip() + "dummy;\n"
        pp.pprint(parseStruct(lines))
        #print len(parseStruct(lines))
