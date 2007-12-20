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
    if (lastf.func != 'system_call'):
	raise IndexError, "this is not a system_call stack" + lastf
    regs = {}
    # The data consists of lines like that:
    #   RAX: 00000000000000db  RBX: ffffffff8026111e  RCX: ffffffffffffffff
    for l in lastf.data:
        for rname, v in re.findall(r"\s*([A-Z0-9_]+):\s+([\da-f]+)", l):
	    regs[rname] = int(v, 16)
    #print regs
    # arg0-arg5
    args = [regs["RDI"], regs["RSI"], regs["RDX"], 
        regs["R10"], regs["R8"], regs["R9"]]
    nscall = regs["RAX"]
    return (nscall, args)


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
    print "nfds=%d" % nfds
    names = ("readfds", "writefds", "exceptfds")
    for i, name in enumerate(names):
	addr = args[i+1]
	if (addr):
	    # Convert it tp physical
	    fds = fdset2list(nfds, addr)
	    print name, fds

    timeout = readSU("struct timeval", args[4])
    if (not timeout):
	print "No timeout"
    else:
        print "timeout=%d s, %d usec" %(timeout.tv_sec, timeout.tv_usec)
    

def decode_Stacks(stacks):
    for stack in stacks:
	if (not stack.hasfunc(r"^system_call$")):
	    continue
	print stack
	print hexl(stack.addr)
	nscall, args = getSyscallArgs_x8664(stack)
	sc = sct[nscall]
	print nscall, sc, args
	set_readmem_task(stack.addr)
	
	if (sc == "sys_select"):
	    decode_select(args)
	if (sc == "sys_poll"):
	    decode_poll(args)
	else:
	    set_readmem_task(0)
	    continue
	set_readmem_task(0)
	continue
    
	addr = args[0]
	
    
	s = readSU("struct timespec", addr)
	print "tv_sec=", s.tv_sec
	set_readmem_task(0)
