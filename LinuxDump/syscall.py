#!/usr/bin/env python
#
# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.

# Decode system call args

from pykdump.API import *
from LinuxDump.BTstack import exec_bt

import re
import crash

def get_SysCallTable():
# Get syscall table names
    sys_call_table = sym2addr("sys_call_table")
    psz = sys_info.pointersize
    out = []
    for i in range(crash.get_NR_syscalls()):
	ptr = readPtr(sys_call_table + i * psz)
	out.append(addr2sym(ptr))
    return out

sct = get_SysCallTable()

def __getRegs(data):
    # The data consists of lines like that:
    #   RAX: 00000000000000db  RBX: ffffffff8026111e  RCX: ffffffffffffffff
    regs = {}
    for l in data:
        for rname, v in re.findall(r"\s*([A-Z0-9_]+):\s+([\da-f]+)", l):
	    regs[rname] = int(v, 16)
    return regs

# asmlinkage on X86 guarantees that we have all arguments on
# the stack. We assume our args are either integers or pointers,
# so they all will be 4-byte. The frame starts from RA, then 
# we have args
#
# System Call number is in EAX

def getSyscallArgs_x86(stack):
    # Check whether the last frame is 'system_call'
    lastf = stack.frames[-1]
    if (not lastf.func in ('system_call', 'sysenter_entry')):
	raise IndexError, "this is not a system_call stack" + lastf
    # The data of interest is Frame Pointer from
    #  #4 [e6d2bfc0] system_call at c02b0068
    sp = lastf.frame + 4
    
    # Read from stack 6 args
    args = []
    mem = readmem(sp, 24)
    args = crash.mem2long(mem, array=6)
#     for i in range(6):
# 	arg = readUInt(sp + 4 * i)
# 	#print i, hexl(sp + 4 * i), hexl(arg)
# 	args.append(arg)
    regs = __getRegs(lastf.data)
    nscall = regs["EAX"]
    #print args
    return (nscall, args)
    
    
# * Register setup:	
# * rax  system call number
# * rdi  arg0
# * rcx  return address for syscall/sysret, C arg3 
# * rsi  arg1
# * rdx  arg2	
# * r10  arg3 	(--> moved to rcx for C)
# * r8   arg4
# * r9   arg5

def getSyscallArgs_x8664(stack):
    # Check whether the last frame is 'system_call'
    lastf = stack.frames[-1]
    if (not lastf.func in ('system_call', 'sysenter_entry')):
	raise IndexError, "this is not a system_call stack" + lastf
    regs = __getRegs(lastf.data)
    #print regs
    # arg0-arg5
    args = [regs["RDI"], regs["RSI"], regs["RDX"], 
        regs["R10"], regs["R8"], regs["R9"]]
    nscall = regs["RAX"]
    return (nscall, args)

__mach = sys_info.machine

if (__mach in ("i386", "i686", "athlon")):
    getSyscallArgs = getSyscallArgs_x86
elif (__mach == "x86_64"):
    getSyscallArgs = getSyscallArgs_x8664
else:
    getSyscallArgs = None

def fdset2list(nfds, addr):
    fileparray = readmem(addr, struct_size("fd_set"))
    out = []
    for i in range(nfds):
	if (FD_ISSET(i, fileparray)):
	    out.append(i)
    return out

def decode_poll(args):
    # int poll(struct pollfd *fds, nfds_t nfds, int timeout);
    #struct pollfd {
    #  int fd;
    #  short int events;
    #  short int revents;
    #}

    start = args[0]
    nfds = args[1]
    timeout = args[2]
    # Read array of fds
    sz = struct_size("struct pollfd")
    print "  nfds=%d,"% nfds, 
    if ((timeout + 1) & INT_MASK == 0):
	print " no timeout"
    else:
        print " timeout=%d ms" % timeout
    for i in range(nfds):
	pfd = readSU("struct pollfd", start + sz * i)
	print pfd.fd
    
def decode_select(args):
#       int select(int nfds, fd_set *readfds, fd_set *writefds,
#                  fd_set *exceptfds, struct timeval *timeout); 
    nfds = args[0]
    indent = '  '
    print indent, "nfds=%d" % nfds
    names = ("readfds", "writefds", "exceptfds")
    for i, name in enumerate(names):
	addr = args[i+1]
	if (addr):
	    # Convert it tp physical
	    fds = fdset2list(nfds, addr)
	    print indent, name, fds

    timeout = readSU("struct timeval", args[4])
    if (not timeout):
	print indent, "No timeout"
    else:
        print indent, "timeout=%d s, %d usec" %(timeout.tv_sec,
                                                timeout.tv_usec)
    

# WARNING: this does not work well on fast live hosts as arguments
# are changing too fast and we can easily get bogus values
def decode_Stacks(stacks):
    for stack in stacks:
	print stack
	#print hexl(stack.addr)
	nscall, args = getSyscallArgs(stack)
	sc = sct[nscall]
	print nscall, sc,
        # Print args assuming that small ints are ints, big ones are
        # pointers. Finally, if we have it slightly below INTMASK, this
        # is a negative integer
        def smartint(i):
            if (i < 8192):
                return "%d" % i
            elif ( i <= INT_MASK and i > INT_MASK-1000):
                return "%d" % (-(INT_MASK - i) - 1)
            else:
                return "0x%x" %i

        sargs = []
        for i in args:
            sargs.append(smartint(i))
        print "(%s)" % string.join(sargs, ', ')

        #continue
	set_readmem_task(stack.addr)

        try:
            if (sc == "sys_select"):
                decode_select(args)
            if (sc == "sys_poll"):
                decode_poll(args)
            else:
                set_readmem_task(0)
                continue
        except crash.error:
            print "  Cannot read userspace args"
	set_readmem_task(0)
	continue
    
	addr = args[0]
	
    
	s = readSU("struct timespec", addr)
	print "tv_sec=", s.tv_sec
	set_readmem_task(0)
