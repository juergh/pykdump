#!/usr/bin/env python
#
# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.

# Decode system call args

from pykdump.API import *
from LinuxDump.BTstack import exec_bt

debug = API_options.debug

import re
import crash

pointersize = sys_info.pointersize

def get_SysCallTable():
# Get syscall table names
    sys_call_table = sym2addr("sys_call_table")
    psz = sys_info.pointersize
    out = []
    for i in range(crash.get_NR_syscalls()):
	ptr = readPtr(sys_call_table + i * pointersize)
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
	raise IndexError, "this is not a system_call stack!"
    # The data of interest is Frame Pointer from
    #  #4 [e6d2bfc0] system_call at c02b0068
    sp = lastf.frame + 4
    
    # Read from stack 6 args
    args = []
    try:
        mem = readmem(sp, 24)
    except crash.error:
        "Cannot read stack on x86 - have you loaded crash-driver?"
        return (-1, [])
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
    if (not lastf.func in ('system_call', 'sysenter_entry',
                           'system_call_fastpath')):
	raise IndexError, "this is not a system_call stack!"
    regs = __getRegs(lastf.data)
    #print regs
    # arg0-arg5
    args = [regs["RDI"], regs["RSI"], regs["RDX"], 
        regs["R10"], regs["R8"], regs["R9"]]
    nscall = regs["RAX"]
    return (nscall, args)

# On IA64 syscall number + 1024 is in R15, args start from BSP
def getSyscallArgs_ia64(stack):
    # Depending on kernel, we can reach ia64_ret_from_syscall via
    # __kernel_syscall_via_break. In this case, we are interested in 
    # the frame with ia64_ret_from_syscall
    lastf = stack.frames[-1]
    if (not lastf.data):
	lastf = stack.frames[-2]
    print lastf
    regs = __getRegs(lastf.data)
    nscall = regs["R15"]- 1024
    bsp = lastf.frame
    # Read from stack 6 args
    args = []
    try:
        mem = readmem(bsp, 6*pointersize)
    except crash.error:
        "Cannot read stack on ia64 - have you loaded crash-driver?"
        return (-1, [])
    args = crash.mem2long(mem, array=6)
    return (nscall, args)
    
__mach = sys_info.machine

if (__mach in ("i386", "i686", "athlon")):
    getSyscallArgs = getSyscallArgs_x86
elif (__mach == "x86_64"):
    getSyscallArgs = getSyscallArgs_x8664
elif (__mach == "ia64"):
    getSyscallArgs = getSyscallArgs_ia64
else:
    getSyscallArgs = None


def generic_decoder(sc, args):
    ti = whatis(sc).ti
    prototype = ti.prototype[1:]
    print "   ", sc,
    # Print args assuming that small ints are ints, big ones are
    # pointers. Finally, if we have it slightly below INTMASK, this
    # is a negative integer
    def smartint(i):
	if ( i <= INT_MASK and i > INT_MASK-1000):
	    return "%d" % (-(INT_MASK - i) - 1)
	else:
	    return "%d" % i
    
    sargs = []
    for a, ti  in zip(args, prototype):
	if (ti.ptrlev == None):
	    darg = smartint(a)
	else:
	    # A pointer
	    ptrtype = ti.fullstr()[:-1]
	    # Convert pointer from userspace to kernel space
	    #if (a !=0):
		#print hexl(a)
		#a = uvtop(taskaddr, a)
	    darg = "(%s) 0x%x" % (ptrtype, a)
	sargs.append(darg)
	    
    print "(%s)" % string.join(sargs, ',\n\t')
    

# WARNING: this does not work well on fast live hosts as arguments
# are changing too fast and we can easily get bogus values
def decode_Stacks(stacks):
    for stack in stacks:
	print stack
	#print hexl(stack.addr)
	print "    ....... Decoding Syscall Args ......."
	try:
	   nscall, args = getSyscallArgs(stack)
	except IndexError, val:
	    print val
	    continue
        if (nscall == -1):
            return
	try:
	   sc = sct[nscall]
	except IndexError:
	    print "     ", WARNING, "Bad system call number=%d" % nscall
	    continue
	
	# On 2.4 socket calls are implemented via sys_socketcall

        #continue
	set_readmem_task(stack.addr)
        generic_decoder(sc, args)
        try:
	    exec '__decode_%s(args)' % sc in globals(), locals()
        except crash.error:
            print "  Cannot read userspace args"
	except NameError, val:
	    # There is no syscall-specific decoder defined
	    pass
	if (debug):
	    print " nnnnnnnnnnnnnnn ", val
	set_readmem_task(0)


# =================================================================
#
# syscall-specific decoders
#
#  If you want to add another decoder, write a function with the name
#  __decode_sys_XXXXX

def __decode_sys_poll(args):
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
    
def __decode_sys_select(args):
#       int select(int nfds, fd_set *readfds, fd_set *writefds,
#                  fd_set *exceptfds, struct timeval *timeout); 
    def fdset2list(nfds, addr):
	fileparray = readmem(addr, struct_size("fd_set"))
	maxfds = struct_size("fd_set") * 8
	out = []
	for i in range(min(nfds, maxfds)):
	    if (FD_ISSET(i, fileparray)):
		out.append(i)
	return out

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
    


def __decode_sys_rmdir(args):
    # The only arg is a directory name
    s = readmem(args[0], 256)
    print "\t rmdir(%s)" % s.split('\0')[0]
    
def __decode_sys_mount(args):
    # long sys_mount(char __user * dev_name, char __user * dir_name,
    #   	  char __user * type, unsigned long flags,
    #		  void __user * data)
    print hexl(args[0])
    dev_name = readmem(args[0], 256).split('\0')[0]
    dir_name = readmem(args[1], 256).split('\0')[0]
    print "\t dev_name=%s, dir_name=%s" % (dev_name, dir_name)
    

def __decode_sys_nanosleep(args):
    # nanosleep(const struct timespec *req, struct timespec *rem)
    for i, name in enumerate(("req", "rem")):
	if (args[i] == 0):
	    print "\t %s  NULL" % name
	else:
	    ts = readSU("struct timespec", args[i])
	    sec = ts.tv_sec
	    nsec = ts.tv_nsec
	    print "\t %s  %dsec, %dnsec" % (name, sec, nsec)


    

__C_SOCKET_SYSCALLS = '''
#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/
'''

__SOCKET_SYSCALLS = CDefine(__C_SOCKET_SYSCALLS)
def __decode_sys_socketcall(args):
    nsc = args[0]
    name = __SOCKET_SYSCALLS.value2key(nsc).lower()
    start = args[1]
    sargs = wrapcrash.intDimensionlessArray(start, pointersize, False)
    print "    ~~~~~~~ Decoding SocketCall Args ~~~~~~~"    
    generic_decoder(name, sargs)
