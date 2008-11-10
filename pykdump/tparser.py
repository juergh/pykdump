#!/usr/bin/env python
#
# Copyright (C) 2006-2008 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2008 Hewlett-Packard Co., All rights reserved.
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
This is a parser for processing C-like declarations.
Its main purpose is to substitute real info in case when this info is
for some reason unavailable in vmlinux or modules.o
'''

import sys
import string, re
import pprint
import atexit

import types

pp = pprint.PrettyPrinter(indent=4)

from Generic import hexl, Bunch

FieldInfo = Bunch

import pyparsing as pyp
from pyparsing import *

# ........... Actions .................................................


def actionToInt(s,l,t):
    return int(t[0], 0)

def actionToHex(s,l,t):
    return int(t[0], 16)

# ........... Literals ................................................

lsqb = Literal("[").suppress()
rsqb = Literal("]").suppress()
lpar = Literal("(").suppress()
rpar = Literal(")").suppress()
eqsign = Suppress("=")

dEnum = Literal("enum")
EndSimple = Literal(";").suppress()

Integer  = Word( nums )
Cid = Word(alphas+"_", alphanums+"_")



# .......................................................................
hexval = Combine("0x" + Word(pyp.hexnums)).setParseAction(actionToInt)
decval = Word(pyp.nums+'-', pyp.nums).setParseAction(actionToInt)
intval = hexval | decval
Lbracket = Suppress("{")
Rbracket = Suppress("}")

# .............. A special aid for converting C-enum declarations to Python )
enumval = Group(Cid + Optional(Suppress('=') + intval))
enumline =  enumval + Suppress(',')
lastenumline = enumval
enumlines = ZeroOrMore(enumline) + lastenumline
Cenumdecl =  Suppress(dEnum) +  Suppress(Optional(Cid)) + \
            Lbracket + enumlines + Rbracket + Optional(Cid) + EndSimple
Cenumdecl.ignore(cStyleComment)
# .............. A special aid for converting C #define block to Python ......

defineStmt = Suppress("#define")+ \
             Group(Cid + (Cid|intval))
#defineStmt.ignore(cStyleComment)	     
defineBlock = OneOrMore(defineStmt).ignore(cStyleComment)


# Convert a string with C-enum declaration to class attributes

class CEnum(object):
    def __init__(self, cdecl):
        tp = Cenumdecl.parseString(cdecl).asList()
        i = 0
        self.vals = []                  # For printing
        self.lookup = {}                # For lookup
        for val in tp:
            name = val[0]
            if (len(val) == 2):
                i = val[1]
            self.vals.append((name, i))
            self.lookup[i] = name
            self.__dict__[name] = i
            i += 1
    def __getitem__(self, name):
        return self.lookup[name]
    def __str__(self):
        return str(self.vals)
    def __len__(self):
        return len(self.vals)

# Convert a string with C #define declarations to class attributes

class CDefine(dict):
    def __init__(self, cdecl):
        d = {}
        dict.__init__(self, d)
        self.__dict__.update(d)
        self.__reversedict = {}
        tp = defineBlock.parseString(cdecl).asList()
        for (name, val) in tp:
            if (type(val) == type('')):
                # This string should already be in a dictionary
                val = self.__getitem__(val)
            self.__setitem__(name, val)
    def __setitem__(self, name, value):
        dict.__setitem__(self, name, value)
        object.__setattr__(self, name, value)
        self.__reversedict[value] = name
    # Find and return a key based on value
    # Makes sense if we have 1-1 mapping
    def oldvalue2key(self, value):
	for k,v in self.items():
	    if (v == value):
		return k
	return None
    def value2key(self, value):
        try:
            return self.__reversedict[value]
        except:
            return None



# Parsing simple C struct/union defintions
def concatNoSpace(s, loc, toks):
    return string.join(toks, '')

def concatWithSpace(s, loc, toks):
    return string.join(toks, ' ').strip()

def replaceFargs(s, loc, toks):
    return '()'

Specifier = Cid + NotAny(Word(';['))
Array = '[' + Integer + ']'
Arrays = ZeroOrMore(Array).setParseAction(concatNoSpace)
Stars = ZeroOrMore('*').setParseAction(concatNoSpace)
semiColon = Suppress(';')

npars = CharsNotIn("()")
balancedParens = Forward()
balancedParens << "(" + Optional(npars) + \
               Optional(balancedParens) + Optional(npars) + ")"

balancedParens.setParseAction(replaceFargs)

Specifiers = OneOrMore(Specifier)


Nonfunc = (Specifiers + Stars).setParseAction(concatWithSpace) + \
          Group(Cid) + Arrays + semiColon

Funcptr = (Specifiers + (Literal('(') + '*').setParseAction(concatNoSpace)).setParseAction(concatWithSpace) \
          + Group(Cid)  \
          + (')' + balancedParens + Arrays).setParseAction(concatNoSpace) \
          + semiColon

stmt1 = Nonfunc | Funcptr
stmt1.ignore(cStyleComment)

SUhead = Literal('struct') | Literal('union')
suDef = (SUhead + Cid).setParseAction(concatWithSpace) \
        + Lbracket + OneOrMore(Group(stmt1)) + Rbracket \
        + Optional(';').suppress()


# Parse an SU definition, return
# [suname, [(ftype, fname), ...]]

def parseSUDef(s):
  rc = suDef.parseString(s).asList()
  sname = rc[0]
  out = []

  for flist in rc[1:]:
      # Process the list to extract fieldname
      out1 = []
      fn = None
      for t in flist:
          if (type(t) == type([])):
              fn = t[0]
          else:
              out1.append(t)
          tn = string.join(out1, '')
      out.append((tn, fn))
  return (sname, out )

    

__test_defs = '''
/* A comment */
#define RTF_UP          0x0001          /* route usable                 */
#define RTF_GATEWAY     0x0002          /* destination is a gateway     */
#define RTF_HOST        0x0004          /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008          /* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010          /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020          /* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040          /* specific MTU for this route  */
#define RTF_MSS         RTF_MTU         /* Compatibility :-(            */
#define RTF_WINDOW      0x0080          /* per route window clamping    */
#define RTF_IRTT        0x0100          /* Initial round trip time      */
#define RTF_REJECT      0x0200          /* Reject route                 */
'''

__test_enum_1 = '''
        enum aa {NETREG_UNINITIALIZED, NETREG_REGISTERING, NETREG_REGISTERED,
   NETREG_UNREGISTERING, NETREG_UNREGISTERED, NETREG_RELEASED} reg_state; 
'''

__test_enum_2 = '''
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING,   /* now a valid state */

  TCP_MAX_STATES /* Leave at the end! */
};
'''

__test_struct = '''
struct OneTwo{
  unsigned long ul;
  long int ula[2];
  struct net_device *dev; /* first - usefull for panic debug */
  int *ia[32];
  unsigned char  **ia3[32][5];
  void (*func1)(int, long);
  void ( * func2 ) ( int, long);
  void (*func3)(int, long) [2][3];
 };
'''

# --------- Main for testing purposes ------------
if __name__ == '__main__':
    import os, time
    t_start = os.times()[0]
    t_starta = time.time()
    def cleanup():
        print "Execution took %6.2fs (real) %6.2fs (CPU)" % (time.time() - t_starta,
                                                         os.times()[0] - t_start)
    atexit.register(cleanup)

    print CDefine(__test_defs)
    print CEnum(__test_enum_1)
    print CEnum(__test_enum_2)
    pp.pprint(parseSUDef(__test_struct))
