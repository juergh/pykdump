#!/usr/bin/env python
#
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
definitions. This is the first version, some functions are now obsolete and
replaced by those in 'nparser.py' (a new parser module).
Both these modules should be eventually replaced with direct interface to GDB
'''

import sys
import string, re
import pprint
import atexit

import types

pp = pprint.PrettyPrinter(indent=4)

from Generic import hexl, Bunch

FieldInfo = Bunch

test = '''
        union {
            __u32 rcvisn;
            void (*destructor)(struct sk_buff *);
            struct tcphdr *th;
            struct udphdr *uh;
            struct icmphdr *icmph;
            struct igmphdr *igmph;
            struct iphdr *ipiph;
 [40]       struct ipv6hdr *ipv6h;
            unsigned char *raw;
            union {
              struct tcp_v4_open_req v4_req;
              struct tcp_v6_open_req v6_req;
 [36]       } af;
    } h;
'''

test2 = '''
struct open_request {
    __u32 rcvisn;
    __u32 snt_isn;
    __u16 rmt_port;
    __u16 mss;
    __u8 retrans;
    __u8 __pad;
    __u16 snd_wscale : 4;
    __u16 rcv_wscale : 4;
    __u16 tstamp_ok : 1;
    __u16 sack_ok : 1;
    __u16 wscale_ok : 1;
    __u16 ecn_ok : 1;
    __u16 acked : 1;
    __u32 window_clamp;
    __u32 rcv_wnd;
    __u32 ts_recent;
  } af;
'''

test3 = '''
        enum aa {NETREG_UNINITIALIZED, NETREG_REGISTERING, NETREG_REGISTERED, 
   NETREG_UNREGISTERING, NETREG_UNREGISTERED, NETREG_RELEASED} reg_state; [352]
'''

test4 = "enum foo_bar goo;"

test5 = '''
chrdevs = $16 =
 {0x0, 0xf7c0aee0, 0x0, 0x0, 0xf7de6640, 0xf7de6720, 0xf77443c0,
  0x0, 0x0, 0x0, 0x0, 0x0}
'''

test6 = '''
  next = 0x0,
  major = 0x1,


  baseminor = 0x0,
  minorct = 0x100,
  name = 0xc02e2c4b "mem",
  fops = 0x0,
  cdev = 0xf7f4f380,
    rb_parent = 0x0, 
    rb_color = 0, 
    rb_right = 0x0, 
    rb_left = 0x100100  
'''

test7 = '''
struct vm_area_struct {
  vm_mm = 0x0,
  vm_start = 0
}
'''

test8 = '''
  vm_rb = {
    rb_parent = 0x0, 
    rb_color = 0, 
    rb_right = 0x0, 
    rb_left = 0x100100
  }
'''

RTN_c = '''
enum
{
	RTN_UNSPEC,
	RTN_UNICAST,		/* Gateway or direct route	*/
	RTN_LOCAL = 16,		/* Accept locally		*/
	RTN_BROADCAST,		/* Accept locally as broadcast,
				   send as broadcast */
	RTN_ANYCAST,		/* Accept locally as broadcast,
				   but send as unicast */
	RTN_MULTICAST,		/* Multicast route		*/
	RTN_BLACKHOLE,		/* Drop				*/
	RTN_UNREACHABLE,	/* Destination is unreachable   */
	RTN_PROHIBIT,		/* Administratively prohibited	*/
	RTN_THROW,		/* Not in this table		*/
	RTN_NAT,		/* Translate this address	*/
	RTN_XRESOLVE,		/* Use external resolver	*/
	__RTN_MAX = 17
};
'''
RTN_defs = '''
#define	RTF_UP		0x0001		/* route usable		  	*/
#define	RTF_GATEWAY	0x0002		/* destination is a gateway	*/
#define	RTF_HOST	0x0004		/* host entry (net otherwise)	*/
#define RTF_REINSTATE	0x0008		/* reinstate route after tmout	*/
#define	RTF_DYNAMIC	0x0010		/* created dyn. (by redirect)	*/
#define	RTF_MODIFIED	0x0020		/* modified dyn. (by redirect)	*/
#define RTF_MTU		0x0040		/* specific MTU for this route	*/
#define RTF_MSS		RTF_MTU		/* Compatibility :-(		*/
#define RTF_WINDOW	0x0080		/* per route window clamping	*/
#define RTF_IRTT	0x0100		/* Initial round trip time	*/
#define RTF_REJECT	0x0200		/* Reject route			*/
'''


# Offsets are output by crash at the left side and make lexing very tricky as
# offset can be in the middle of our tokens, e.g.
#
#         enum {NETREG_UNINITIALIZED, NETREG_REGISTERING, NETREG_REGISTERED,
#  [352] NETREG_UNREGISTERING, NETREG_UNREGISTERED, NETREG_RELEASED} reg_state;
#
# So we transform the strings moving offsets to the right, after ;

re_offset = re.compile(r'^\s*(\[\d+\])\s+(.+)$', re.M)


def preprocess(instr):
    #print instr
    # Remove ^M if any
    #instr = instr.replace('\r', '')
    out = re_offset.sub(r'\2\1', instr)
    return out



import pyparsing as pyp
from pyparsing import *
#pyp.ParserElement.enablePackrat()

# ............ Auxiliary Functions ....................................

# Flatten the results list using dotnames, e.g.

def flattenSresult(inres, topname = ""):
    outres = []
    # Each list element is a list of 2 or elements: name, value, optvalue
    # The 1st one is name, the 2nd one value. Value can be a list, too
    for el in inres:
	#print el
	key = el[0]
	val = el[1]
	# We have several cases. If val is a list, we either have an array
	# value, or a struct value. For struct, we have a list of lists
        if (type(val) == type([]) and len(el) == 2 and type(val[0]) == type([])):
	    outres += flattenSresult(val, topname + key + ".")
        else:
	    el[0] = topname + key
            outres.append(el)
    #print "--", topname, "--", outres
    return outres
        
        

def StructInfo(text):
    out = preprocess(text)
    res = fullStmt.parseString(out)
    pres = res.asList()[0]
    #print pres
    stype = string.join(pres["type"])
    size = pres["size"]
    body = pres["body"]
    return stype, size, body

def GDBStructInfo(text):
    out = preprocess(text)
    res = GDBfullStmt.parseString(out)
    pres = res.asList()[0]
    #print pres
    stype = string.join(pres["type"])
    size = 0
    body = pres["body"]
    return stype, size, body

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

class oldCDefine(object):
    def __init__(self, cdecl):
        tp = defineBlock.parseString(cdecl).asList()
        self.lookup = {}                # For lookup
        for (name, val) in tp:
            if (type(val) == type('')):
                # This string should already be in a dictionary
                val = self.lookup[val]
            self.lookup[name] = val
            self.__dict__[name] = val
    def __str__(self):
        return pp.pformat(self.lookup)

# Globals updated by parsing actions

attrs = Bunch()
attrstack = []


# ........... Actions .................................................
def actionStar(s,loc, toks):
    attrs["star"] = toks[0]
    return []

def actionBitfield(s,loc, toks):
    attrs["bitfield"] = int(toks[0],0)
    return []

def actionFunc(s,loc, toks):
    attrs["func"] = True

# We can have multidimensional arrays, e.g. [32][8]. We set attr to an integer
# for 1-dim arrays (this is the most frequent case) and to list of integers
# for multidim arrays

def actionArray(s,loc, toks):
    dim = int(toks[0],0)
    if (attrs.has_key("array")):
        val = attrs.array
        # Multidim
        if (type(val) == type([])):
            attrs.array.append(dim)
        else:
            attrs.array = [val, dim]
    else:
        attrs["array"] = dim
    return []

def actionOffset(s,loc, toks):
    attrs["offset"] = int(toks[0],0)
    return []

def actionFieldname(s,loc, toks):
    attrs["fname"] = toks[0]
    return []

def actionFieldtype(s,loc, toks):
    global attrs
    attrs = FieldInfo()
    attrs["type"] = toks.asList()
    return [attrs]

# Special case: enum values belong to one level up
def actionEnumvals(s,loc, toks):
    attrs["enumvals"] = toks.asList()
    return []

def actionPush(s, loc, toks):
    global attrs
    oldattrs = attrs
    attrstack.append(attrs)
    #print '--- Push', len(attrstack), toks
    attrs = FieldInfo()

def actionPop(s, loc, toks):
    global attrs
    attrs = attrstack.pop()
    #print '--- Pop', len(attrstack)


# This action is called at the end of simple statement - everything
# is in attrs, there should be nothing interesting in toks
def actionSimpleStmt(s,loc, toks):
    global attrs
    #print toks, "attrs=", attrs
    oldattrs = attrs
    attrs = FieldInfo()
    return [oldattrs]

def actionSize(s,loc, toks):
    attrs["size"] = int(toks[0],0)
    return []

def actionBody(s,loc, toks):
    attrs["body"] = toks.asList()[0]
    return []

def actionSUEStmt(s,loc, toks):
    global attrs
    #print toks, "attrs=", attrs
    oldattrs = attrs
    attrs = FieldInfo()
    return [toks.asList(), oldattrs]

def actionToInt(s,l,t):
    return int(t[0], 0)

def actionToHex(s,l,t):
    return int(t[0], 16)

def actionToString(s,l,t):
    # Normalize strings stripping quotes and terminating on \000 if any
    s = t[0][1:-1]
    s = s.split(r'\000')[0]
    return s.decode('string_escape')

def actionFull(s,loc, toks):
    global attrs
    oldattrs = attrs
    attrs = FieldInfo()
    #return [oldattrs]

def actionDebug(s,l,t):
    global attrs
    print "--Debug--", t, attrs

    
# Literals
Stars = Word("*").setParseAction(actionStar)
#Stars = OneOrMore("*").setParseAction(actionStar)
lsqb = Literal("[").suppress()
rsqb = Literal("]").suppress()
lpar = Literal("(").suppress()
rpar = Literal(")").suppress()
eqsign = Suppress("=")
pars = CharsNotIn("()")
Lbracket = Suppress("{").setParseAction(actionPush)
Rbracket = Suppress("}").setParseAction(actionPop)
dStruct = Literal("struct")
dEnum = Literal("enum")
dUnion = Literal("union")
EndSimple = Literal(";").suppress()

balancedParens = Forward()
balancedParens << lpar + Optional(pars) + \
               Optional(balancedParens) + Optional(pars) + rpar

Integer  = Word( nums )
Offset = (lsqb + Integer + rsqb).setParseAction(actionOffset)
Array = lsqb + Integer + rsqb
Cid = Word(alphas+"_", alphanums+"_")
Bitfield = (Cid + Suppress(':') + Integer.copy().setParseAction(actionBitfield))
varID = Bitfield | Cid
fargs = balancedParens.suppress()
extraSpecifiers = Literal("unsigned") | Literal("long") | Literal("short") \
    | Literal("volatile") | Literal("const")
simpleType = ZeroOrMore(extraSpecifiers)+ Optional(Cid)
simpleType.setParseAction(actionFieldtype)

enumType = dEnum + Optional(Cid)
enumType.setParseAction(actionFieldtype)

suType = ZeroOrMore(extraSpecifiers) + (dStruct|dUnion) + Optional(Cid)
suType.setParseAction(actionFieldtype)

fieldType = (enumType|suType|simpleType)

funcID = lpar+Suppress('*')+Cid+rpar+fargs
funcID.setParseAction(actionFunc)

#endOfStmt = Optional(Array.setParseAction(actionArray))+EndSimple+Optional(Offset)
endOfStmt = ZeroOrMore(Array.setParseAction(actionArray))+EndSimple+Optional(Offset)
            

VarDecl =fieldType+Optional(Stars)+(varID|funcID).setParseAction(actionFieldname)

simpleStmt = VarDecl + endOfStmt
#simpleStmt.setParseAction(actionSimpleStmt)

suBody = Forward()
enumBody = Lbracket + delimitedList(Cid) + Rbracket
enumBody.setParseAction(actionEnumvals)

enumStmt = enumType + enumBody + \
           Optional(Cid).setParseAction(actionFieldname) + endOfStmt
              
suStmt = suType + suBody + Optional(Stars) + \
           Optional(Cid).setParseAction(actionFieldname) + endOfStmt

complexStmt = enumStmt | suStmt

OneStatement =  complexStmt | simpleStmt


# crash does not show multiple nested structs/unions properly, e.g.
#     union {
#        struct {...} vm_set;
#        struct prio_tree_node prio_tree_node;
#    } shared;
Crashsp = Literal("...")

suBody << Lbracket + Group(OneOrMore(OneStatement|Crashsp)) + Rbracket
suBody.setParseAction(actionBody)

Size = Suppress("SIZE:") + Integer
fullStmt = fieldType + suBody + Size.setParseAction(actionSize)
GDBfullStmt = Suppress("type =") + fieldType + suBody
#fullStmt.setParseAction(actionFull)

# .......................................................................
noprefix_hexval =  Word(pyp.hexnums).setParseAction(actionToHex)
hexval = Combine("0x" + Word(pyp.hexnums)).setParseAction(actionToInt)
decval = Word(pyp.nums+'-', pyp.nums).setParseAction(actionToInt)
intval = hexval | decval
gdbid = Word('$', pyp.nums)

# Simple pointer array as got from 'px chrdevs'
# hrdevs = $16 =
# {0x0, 0xf7c0aee0, 0x0, 0x0, 0xf7de6640, 0xf7de6720, 0xf77443c0,
#   0x0, 0x0, 0x0, 0x0, 0x0}
parray = Cid.suppress() + Suppress('=' + gdbid + '=') + \
    Lbracket + delimitedList(intval) + Rbracket

# .......................................................................
# Output format of struct addr command
# Simple statement is id = val optionally followed by string, e.g.
#   name = 0xc02e2c4b "mem",
#   cdev = 0xf7f4f380

stringval = pyp.quotedString.copy()
stringval.setParseAction(actionToString)
funcval = Suppress('<' + Cid + '>')
simple1val = Group(Cid + eqsign + (intval|stringval) + Optional(stringval|funcval))
arrayval = Group(Cid + eqsign + Lbracket + Group(delimitedList(intval)) + Rbracket)
structval = Forward()
structbody = Forward()
structlistval = Forward()
vallist = Forward()
vallist << delimitedList(simple1val|arrayval|structval|structlistval)
structbody << Lbracket +  Group(vallist) + Rbracket
structval << Group(Cid + eqsign + structbody)
structlistval << Group(Cid + eqsign + Lbracket + delimitedList(structbody) + Rbracket)
fullstructval = Suppress(dStruct + Cid) + Lbracket + vallist + Rbracket

# .......................................................................
# Output format of list command like
# list -H all_bdevs block_device.bd_list -s block_device
#

List_of_structval = OneOrMore(Group(noprefix_hexval + Group(fullstructval)))

List_of_fieldval = delimitedList(Group(noprefix_hexval + simple1val))

# Now for deference operator, i.e. p ((struct aaa *)0x1234)->a->b
derefstmt = Suppress(gdbid + '=') + (stringval|intval)


# .............. A special aid for converting C-enum declarations to Python ......
#ccomment = Regex(r'/\*.*\*/').suppress()
ccomment = Suppress(Literal('/*') + SkipTo('*/') + Literal('*/'))
enumval = Group(Cid + Optional(Suppress('=') + intval))
enumline =  enumval + Suppress(',') + Optional(ccomment)
lastenumline = enumval + Optional(ccomment)
enumlines = ZeroOrMore(enumline) + lastenumline
Cenumdecl =  Suppress(dEnum) +  Suppress(Optional(Cid)) + \
            Lbracket + enumlines + Rbracket + Optional(Cid) + EndSimple

# .............. A special aid for converting C #define block to Python ......

defineStmt = Optional(ccomment) +  Suppress("#define")+ \
             Group(Cid + (Cid|intval))+Optional(ccomment)
defineBlock = OneOrMore(defineStmt)

# --------- Main for testing purposes ------------
if __name__ == '__main__':
    import os, time
    t_start = os.times()[0]
    t_starta = time.time()
    def cleanup():
        print "Execution took %6.2fs (real) %6.2fs (CPU)" % (time.time() - t_starta,
                                                         os.times()[0] - t_start)
    atexit.register(cleanup)

    print OneStatement.parseString("struct list_head  nf_hooks[32][8];")
    #print VarDecl.parseString("struct igmphdr *igmph")
    #print simpleStmt.parseString("struct igmphdr *igmph;")
    #print suStmt.parseString(test)
    #res = fullstructval.parseString(open("vm_area_struct.txt").read()).asList()
    #res = fullstructval.parseString(open("tcp_hashinfo.list").read()).asList()
    #res = fullstructval.parseString(open("test.out").read()).asList()
    #res = List_of_structval.parseString(open("block_device.list").read()).asList()
    #res = List_of_fieldval.parseString(open("simple.list").read()).asList()

    #res = OneStatement.parseString("struct ipv6_pinfo *pinet6;").asList();
    #res = OneStatement.parseString("struct sock sk;").asList();
    #print res

    #res = GDBfullStmt.parseString(open("gdbsock.out").read()).asList()

    #(stype, size, body) = GDBStructInfo(open("inetsock.out").read())
    #print stype, size
    #pp.pprint(body)
    
    #import wrapcrash
    #print wrapcrash.StructResult("sock", flattenSresult(res))
    #pp.pprint(res)
    #pp.pprint(flattenSresult(res))
    #print vallist.parseString(test6)
    #print structval.parseString(test8)
    #print fullstructval.parseString(test7)
    #rstr = open("socklist.txt").read()
    #for addr, res in List_of_structval.parseString(rstr).asList():
	#print '='*20
        #fr = flattenSresult(res)
	#pp.pprint(fr)

    #print CDefine(RTN_defs)
    #print CEnum(RTN_c)
    sys.exit(0)

    names = ("task_struct.out", "tcp_hashinfo.out", "sock.out", "block_device.out",
             "blk_queue_tag.out", "open_request.out", "sk_buff.out",
             "vm_area_struct.out")

    for fn in names[0:]:
        print '-' * 30, fn, '-' * 30
        str = open(fn, 'r').read()
        (stype, size, body) = StructInfo(str)
	print stype, size
        pp.pprint(body)



    #print Union.parseString(test)

    #for l in test.splitlines()[2:-1]:
    #    print l
    #    print SimpleStatement.parseString(l)
