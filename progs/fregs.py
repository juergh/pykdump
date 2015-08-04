# frameregs.py - Python extension for crash utility that attempts to
# determine register contents at entry to each routine in stack frame

# --------------------------------------------------------------------
# (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Author: Martin Moore (martin.moore@hp.com)
#
# --------------------------------------------------------------------

#
# Usage: Load pykdump extension, then "epython frameregs.py <options>"
#
# General philosophy: try to find register contents that can be determined
# with a high degree of confidence and not too much work.  Don't try to
# figure everything out (which is probably impossible); this is a debugging
# aid, not a tool that attempts to do all crash analysis automatically.

__version__ = "1.01"

import argparse
from pykdump.API import *

from LinuxDump.BTstack import exec_bt

# ARG_REG is a list of the registers used to pass arguments

ARG_REG = ['RDI','RSI','RDX','RCX','R8','R9']


# Function parse_whatis - Parse whatis output from crash.
#
# Returns a dictionary of the argument types.

def parse_whatis (finfo):
    "Parse whatis output from crash into a dictionary of argument types"

    argdict = {}
    lparen = finfo.find("(")
    rparen = finfo.find(")")
    arginfo = finfo[(lparen+1):rparen]

    if len(arginfo) == 0:
        return argdict     # Probably an unnecessary check

    fields = arginfo.split(",")
    fields = [field.lstrip() for field in fields]
    argdict = dict(zip(ARG_REG,fields))

    return argdict

def funcargs_dict(funcname):
    fields = funcargs(funcname)
    if (fields is None):
        print "Can't identify arguments for", funcname
        return {}
    return dict(zip(ARG_REG,fields))

@memoize_cond(CU_LIVE)
def disasm(cmd):
    #print(" === dis {}".format(cmd))
    return exec_crash_command("dis {}".format(cmd))

# Function look_for_reg - Look for saved registers
#
# This function is the heart of this program.  Don't call this for routines
# entered via exception; for those, we just save and display the exception
# frame, which contains all register values at the time of exception.

def look_for_reg (fname, sp, stack):
    "Try to find register contents at time of function entry"

    # If we're getting arguments, get information from crash

    if False and showargs:
        try:
            finfo = exec_crash_command("whatis " + fname)
            arg_types = parse_whatis(finfo)
        except crash.error:
            print "Can't identify arguments for", fname
            arg_types = {}

    if True and showargs:
        arg_types = funcargs_dict(fname)
    # Start by finding registers saved on the stack at routine entry (this
    # is fairly straightforward).  Build a dictionary of the found values.

    regval = {}

    rsp = sp     # Initialize stack pointer
    if debug:
        print "Initial stack pointer is {:#x}".format(rsp)

    # Disassemble the first 12 instructions in the routine.  This should be
    # more than enough to handle the initial register saving.

    disout = disasm("-x " + fname + " 12")

    # Parse the entry sequence where registers are saved on the stack.
    # We're only interested in push, sub, and mov instructions.  When we
    # find something else, we've presumably finished the entry, so stop looking.

    for line in disout.splitlines():
        if debug:
            print line
        fields = line.split()
        opcode = fields[2]
        try:
            operand = fields[3]
        except IndexError:
            break

        if opcode == "push":
            rsp -= 8
            if debug:
                print "After push, SP is {:#x}".format(rsp)

            # If we're pushing a register, print the saved value from the stack
            if operand.startswith("%"):
                register = operand.lstrip("%").upper()
                try:
                    val = stack[rsp]
                    if verbose:
                        print "  {:s}: {:#x} from {:#x} (push)".format(
                            register,val,rsp)
                    elif showargs and register in arg_types:
                        argno = ARG_REG.index(register)
                        print "  {:s}: {:#x} arg{:d} {:s}".format(
                            register,val,argno,arg_types[register])
                    else:
                        print "  {:s}: {:#x}".format(register,val)

                    regval[register] = val

                except KeyError:
                    if debug:
                        print "Don't have stack entry at {:#x}".format(rsp)

        elif opcode == "sub":
            # SUB instruction - make sure we're subtracting a constant
            if not operand.startswith("$"):
                continue

            fields = operand.split(",")

            # We're only interested in subtractions from RSP or (shouldn't happen) RBP

            if fields[1] == "%rsp":
                val = int(fields[0].lstrip("$"),16)
                rsp -= val
                if debug:
                    print "Subtracted {:#x} from SP, now = {:#x}".format(
                           val,rsp)
            elif fields[1] == "%rbp":
                val = int(fields[0].lstrip("$"),16)
                rbp -= val
                if debug:
                    print "Subtracted {:#x} from RBP, now = {:#x}".format(
                           val,rbp)

        elif opcode == "mov":
            fields = operand.split(",")
            if operand == "%rsp,%rbp":
                rbp = rsp
                if debug:
                    print "Setting RBP (from SP) to {:#x}".format(rbp)
            elif operand.startswith("%"):
                register = fields[0].lstrip("%").upper()
                dest = fields[1]
                paren = dest.find("(")
                if paren < 0:
                    continue
                elif paren == 0:
                    offset = 0
                else:
                    offset = int(dest[:paren],16)
                basereg = dest[(paren+2):-1]

                if basereg == "rbp":
                    addr = rbp + offset
                elif basereg == "rsp":
                    addr = rsp + offset

                try:
                    val = stack[addr]
                    if verbose:
                        print "  {:s}: {:#x} from {:#x} {:s}".format(
                            register,val,addr,dest)
                    elif showargs and register in arg_types:
                        argno = ARG_REG.index(register)
                        print "  {:s}: {:#x} arg{:d} {:s}".format(
                            register,val,argno,arg_types[register])
                    else:
                        print "  {:s}: {:#x}".format(register,val)

                    regval[register] = val

                except KeyError:
                    if debug:
                        print "Don't have stack entry at {:#x}".format(rsp)

        else:
            break # from for loop (done with routine entry processing)

    if debug:
        print "Register dictionary:"
        for key in sorted(regval):
            print "{:s}: {:#x}".format(key, regval[key])
        
    # Now that we've picked the low-hanging fruit, can we get anything more?
    # At this point, we can disassemble the last few instructions in the caller
    # and see if we can determine any other registers.  This is trickier.

    if sp not in stack:    # If we don't have the stack data, give up
        return

    rsp = stack[sp] + 8    # SP before call
    rip = stack[sp]
    ripstr = "{:#x}".format(rip)
    disout = disasm("-r " + ripstr)

    # Run through the disassembled instructions in reverse up to a limit,
    # since the further back we go the more likely it is that control flow
    # will make the results less certain.  Skip the first (i.e. last) line,
    # since it's the instruction after the call and won't have been executed.

    lines_parsed = 0
    for line in reversed(disout.splitlines()):
        if debug:
            print line

        if lines_parsed == 0:
            lines_parsed = 1
            continue           # skip this line

        if lines_parsed == 10:
            break              # quit after 10 lines

        lines_parsed += 1

        # Parse the instruction and see if we can learn any new information.
        # Let's think about the register dictionary we built above.  On entry
        # to this loop, it contained definitely known register:value pairs.
        # But as we parse the caller's instructions, we may see an update to a 
        # known register value.  This invalidates the register contents for 
        # use later in the loop (as we process earlier instructions) because
        # we have no idea what the register contained before this modification. 
        #
        # That is, there are three possible states for a register:
        #
        # Unknown - No information known for register (not in dictionary)
        # Known - Register contents are valid because they were loaded from
        # the stack (current value in dictionary)
        # Invalid - Contents have been set, but aren't valid for use (because
        # the register is modified at a later point in time than we're looking)

        fields = line.split()
        opcode = fields[2]
        try:
            operand = fields[3]
        except IndexError:
            continue		# Ignore instructions with no operand

        if opcode.startswith("nop") or opcode == "test":
            continue		# Skip NOP instructions

        # Parse MOV instruction.  There are 5 possible cases:
        #
        #     MOV reg,reg
        #     MOV mem,reg
        #     MOV const,reg
        #     MOV reg,mem
        #     MOV const,mem
        #
        # We don't need to worry about the writes to memory.

        if opcode == "mov":
            fields = operand.split(",")
            src = fields[0]
            dst = fields[1]
            if dst.startswith("%"):

                # Destination is a register.  If it's already invalid, just continue.
                # Otherwise, determine the source type.

                dstreg = dst.lstrip("%").upper()
                try:
                    if regval[dstreg] == "invalid":
                        continue
                except KeyError:
                    pass

                if src.startswith("%"):

                    # MOV regA,regB
                    #
                    # If both registers are the same (can this happen?), skip this one.

                    srcreg = src.lstrip("%").upper()
                    if srcreg == dstreg:
                        continue

                    # What happens next depends on what we already know about the registers.
                    #
                    # If dst is unknown:
                    #    If src is known, report its value as the dst value.  Then
                    #       invalidate dst (regarldess of src state).
                    # If dst is known:
                    #    If src is unknown, report src contents as dst value.  Set src
                    #       to dst (regardless of src state).
                    # If dst is invalid:
                    #    Do nothing (we can't learn anything new).

                    if dstreg not in regval:  # dst is unknown
                        if srcreg not in regval: # src is unknown 
                            regval[dstreg] = "invalid"
                        elif regval[srcreg] == "invalid":
                            regval[dstreg] = "invalid"
                        else:
                            val = regval[srcreg]
                            regval[dstreg] = "invalid"
                            if verbose:
                                print "  {:s}: {:#x} from caller: {:s} {:s}".format(
                                    dstreg,val,opcode,operand)
                            elif showargs and dstreg in arg_types:
                                argno = ARG_REG.index(dstreg)
                                print "  {:s}: {:#x} arg{:d} {:s}".format(
                                    dstreg,val,argno,arg_types[dstreg])
                            else:
                                print "  {:s}: {:#x}".format(dstreg,val)

                    elif regval[dstreg] != "invalid":  # dst is known
                        if srcreg == "RSP":  # Don't do this for RSP
                            continue         # (handled separately)
                        val = regval[dstreg]
                        if srcreg not in regval: # src is unknown
                            if verbose:
                                print "  {:s}: {:#x} from caller: {:s} {:s}".format(
                                    srcreg,val,opcode,operand)
                            elif showargs and srcreg in arg_types:
                                argno = ARG_REG.index(srcreg)
                                print "  {:s}: {:#x} arg{:d} {:s}".format(
                                    srcreg,val,argno,arg_types[srcreg])
                            else:
                                print "  {:s}: {:#x}".format(srcreg,val)
                        regval[srcreg] = val

                # MOV const,reg
                #
                # If this is a new register, display it; either way, set/update the value 
                # for this register in the dictionary.

                elif src.startswith("$"):
                    val = int(src.lstrip("$"),16)
                    if dstreg in regval:
                        if debug:
                            print "Updated {:s} to {:#x}".format(dstreg,val)
                    else:
                        if verbose:
                            print "  {:s}: {:#x} from caller: {:s} {:s}".format(
                                dstreg,val,opcode,operand)
                        elif showargs and dstreg in arg_types:
                            argno = ARG_REG.index(dstreg)
                            print "  {:s}: {:#x} arg{:d} {:s}".format(
                                dstreg,val,argno,arg_types[dstreg])
                        else:
                            print "  {:s}: {:#x}".format(dstreg,val)

                    regval[dstreg] = val

                # MOV mem,reg
                #
                # If the base register for the mem ref isn't known, invalidate dest.
                # If it's known then we can compute the memory address; if we don't
                # have this address in the stack dictionary, try to get it with
                # crash's "rd" command (note that this could be stale data).  If
                # this fails, invalidate dst.
                # If we successfully get the memory contents from the stack or rd, then
                # if dst is unknown, report the new dst valuex and then invalidate it.

                # We also look for only simple memory fetches: "mov (reg),reg" or
                # of "mov offset(reg),reg" and ignore the more complex addressing formats.
                # Maybe change this later if it seems worthwhile.

                else:
                    paren = src.find("(")
                    if paren == 0:
                        offset = 0
                    else:
                        offset = int(src[:paren],16)

                    basereg = src[(paren+2):-1].upper()
                    if basereg == "RSP":
                        addr = rsp + offset
                    elif basereg in regval:
                        val = regval[basereg]
                        if val == "invalid":
                            regval[dstreg] = "invalid"
                            continue
                        else:
                            addr = regval[basereg] + offset
                    else:
                        regval[dstreg] = "invalid"
                        continue

                    # We know the address; look up the data in the stack dictionary.
                    # If not there, try to get it with "rd".

                    if addr in stack:
                        val = stack[addr]
                    else:
                        if (True):
                            rdcmd = "rd {:#x}".format(addr)
                            try:
                                rdout = memoize_cond(CU_LIVE)(exec_crash_command)(rdcmd)
                            except crash.error:
                                print "rd failed",addr,line,basereg,dstreg
                                regval[dstreg] = "invalid"
                                continue
                            if not rdout.startswith("ffff"):
                                regval[dstreg] = "invalid"
                                continue
                            if debug:
                                print rdout
                            fields = rdout.split()
                            val = int(fields[1],16)
                        else:
                            # Read using direct pydkump API
                            val = readULong(addr)

                    if dstreg not in regval:

                        if verbose:
                            print "  {:s}: {:#x} from caller: {:s} {:s}".format(
                                dstreg,val,opcode,operand)
                        elif showargs and dstreg in arg_types:
                            argno = ARG_REG.index(dstreg)
                            print "  {:s}: {:#x} arg{:d} {:s}".format(
                                dstreg,val,argno,arg_types[dstreg])
                        else:
                            print "  {:s}: {:#x}".format(dstreg,val)
                        regval[dstreg] = "invalid"

                    else:
                        regval[dstreg] = "invalid"
                        continue

        # LEA instruction.  This is handled similarly to "MOV mem,reg" except
        # that we don't have to look up the memory location.  If the base
        # register is known, compute the effective address; if the destination
        # register is unknown, report the result as the new dst value.
        # In all cases, invalidate dst.
        #
        # We look only for the simple cases "lea offset(reg),reg" and 
        # "lea (reg),reg" (although the latter seems unlikely, since the compiler
        # could do the same thing with a mov) and ignore more complex address
        # formats.  Maybe change this later if it seems worthwhile.

        elif opcode == "lea":
            fields = operand.split(",")
            src = fields[0]
            dst = fields[1]
            if not dst.startswith("%"):
                continue     # sanity check (shouldn't happen)
            dstreg = dst.lstrip("%").upper()
            paren = src.find("(")
            if paren == 0:
                offset = 0
            else:
                offset = int(src[:paren],16)

            basereg = src[(paren+2):-1].upper()
            if basereg == "RSP":
                addr = rsp + offset
            elif basereg in regval:
                val = regval[basereg]
                if val == "invalid":
                    regval[dstreg] = "invalid"
                    continue
                else:
                    addr = regval[basereg] + offset
            else:
                regval[dstreg] = "invalid"
                continue

            if dstreg not in regval:

                if verbose:
                    print "  {:s}: {:#x} from caller: {:s} {:s}".format(
                           dstreg,addr,opcode,operand)
                elif showargs and dstreg in arg_types:
                    argno = ARG_REG.index(dstreg)
                    print "  {:s}: {:#x} arg{:d} {:s}".format(
                        dstreg,addr,argno,arg_types[dstreg])
                else:
                    print "  {:s}: {:#x}".format(dstreg,addr)

                regval[dstreg] = "invalid"

            else:
                regval[dstreg] = "invalid"
                continue

        # For any other instruction that modified the contents of a register,
        # invalid the register.

        elif opcode in ['add','sub','inc','dec','imul','idiv','and',
            'or','xor','not','neg','shl','shr']:
            fields = operand.split(",")
            dst = fields[-1]
            if dst.startswith("%"):
                dstreg = dst.lstrip("%").upper()
                regval[dstreg] = "invalid"

    return

# A context manager to change disassembly flavor if needed and then to restore it
class DisasmFlavor():
    def __init__(self, flavor):
        s = exec_gdb_command("show disassembly-flavor")
        m = re.search(r'"([^"]+)"', s)
        if (m):
            self.oldflavor = m.group(1)
        self.flavor = flavor
    def __enter__(self):
        if (self.oldflavor != self.flavor):
            print("Setting flavor to {}".format(self.flavor))
            exec_gdb_command("set disassembly-flavor {}".format(self.flavor))
    def __exit__(self, exc_type, exc_value, traceback):
        if (self.flavor != self.oldflavor):
            print("Restoring flavor to {}".format(self.oldflavor))
            exec_gdb_command("set disassembly-flavor {}".format(self.oldflavor))

#--------------------------------------------------------------
#   Main program begins here. 
#--------------------------------------------------------------

def olddecode_pid_args(pid):
    stack = {}    # Stack dictionary - address:value pairs
    # Make sure we're on an x86_64 vmcore, or this will fail miserably.
    if (sys_info.machine != "x86_64"):
        print "Supported on x86_64 dumps only, sorry."
        sys.exit(1)


    btfout = exec_crash_command("bt -f " + pid)

    # Look through the "bt -f" output for lines that show stack values.
    # Use these to build a dictionary of the stack contents.
    # Lines have the following form (with either 1 or 2 values):
    #
    #     ffff88200e7d7e08: ffffe8dfe8801648 ffff88200e7d7e30

    for line in btfout.splitlines():
        if line.lstrip().startswith("ffff"):
            fields = line.split()
            addr = int(fields[0].rstrip(':'),16)
            val1 = int(fields[1],16)
            stack[addr] = val1

            if len(fields) == 3:
                addr += 8
                val2 = int(fields[2],16)
                stack[addr] = val2

    if debug:
        print "Stack dictionary:"
        for key in sorted(stack):
            print "{:#x}: {:#x}".format(key, stack[key])

    # Now let's get just the basic bt output.  We'll use this to build three
    # parallel lists: 
    #   1. frames contains the list of entered routines
    #   2. stackptr contains either:
    #      if called, the stack address of the saved return address (caller)
    #      if entered via exception, a list containing the eframe output
    #   3. retaddr contains either:
    #      if called, the saved return address (caller)
    #      if entered via exception, the string "eframe"
    #
    # Note that frames is one element longer than the others, since the bottom
    # routine doesn't have anything to return to.  To expand on this:
    #
    # frames[i] contains the routine name and is set on interation [i].
    # stackptr[i] and retaddr[i] contain the address and value of the RA
    # when frames[i] is entered.  Since these come from the caller, they are
    # set on iteration [i+1].  Or looking at the other way, on iteration [i]
    # we set frames[i], stackptr[i-1], and retaddr[i-1].  We do this by skipping
    # the latter two on the first time through and letting the lists build
    # by appending to them.  As such, stackptr and retaddr will each
    # have one fewer element than frames.

    frames = []
    stackptr = []
    retaddr = []
    btout = exec_crash_command("bt " + pid)
    top = True
    elist_remaining = 0

    for line in btout.splitlines():
        if line.lstrip().startswith("#"):
            if debug:
                print line
            fields = line.split()
            fname = fields[2]

    # See comments below for reason we need to check for duplicate names
    # in consecutive entries.  

            if top:
                frames.append(fname)
                top = False
            else:
                saddr = int(fields[1].strip("[]"),16)
                raddr = int(fields[4],16)
                if fname != frames[-1]:
                    frames.append(fname)
                    stackptr.append(saddr)
                    retaddr.append(raddr)

    # Process exception entries.  This is a little tricky because sometimes
    # crash shows a separate frame for the routine in which the exception
    # occurred, and sometimes it doesn't.  So we try to deal with both cases
    # here by immediately setting up an entry for the routine that hit the 
    # exception.  But in the call frame entry processing above, we have to
    # check for consecutive calls to the same routine, and when this happens
    # we just update the entries for that routine instead of appending new
    # ones to the lists.

        elif line.lstrip().startswith("[exception RIP:"):
            if debug:
                print line
            fields = line.split()
            rip = fields[2]
            fname = rip.split("+")[0]
            frames.append(fname)
            retaddr.append("eframe")

    # Build a list containing the exception frame lines from the bt output.
    # This includes the current and next 7 lines.

            elist = []
            elist.append(line)
            elist_remaining = 7

        elif elist_remaining > 0:
            elist.append(line)
            elist_remaining -= 1
            if elist_remaining == 0:
                stackptr.append(elist)

    if debug:
        for i in range(len(retaddr)):
            if retaddr[i] == "eframe":
                print "{:s} eframe".format(frames[i])
            else:
                print "{:s} {:#x}".format(frames[i],retaddr[i])

    # Now loop through our lists to print each routine entered and
    # whatever we can determine about register contents at the time of entry.

    for i in range(len(stackptr)):
        fname = frames[i]

        if type(stackptr[i]) is list:
            print "\n{:s} entered by exception".format(fname)
            elist = stackptr[i]
            for efline in elist:
                print efline
        else:
            rip = retaddr[i]
            out = disasm("{:#x}".format(rip))
            inst = out.split()[1].rstrip(":")
            print "\n{:s} called from {:#x} {:s}".format(fname, rip, inst)
            look_for_reg(fname, stackptr[i], stack)

def decode_pid_args(pid):
    # Make sure we're on an x86_64 vmcore, or this will fail miserably.
    if (sys_info.machine != "x86_64"):
        print "Supported on x86_64 dumps only, sorry."
        sys.exit(1)        
    s = exec_bt("bt " + pid)[0]

    # For last frame, empty string for from_func
    lastf = s.frames[-1]
    stackdict = {}
    
    for f, nf in zip(s.frames[:-1], s.frames[1:]):
        calledfrom = nf.func
        
        if (f.level != -1 and nf.level != -1 and f is not lastf):
            #print f.fullstr()
            start = f.frame + LONG_SIZE
            end = nf.frame
            arrsize = (end-start)//LONG_SIZE + 1

            if (arrsize > 0 and arrsize < 8192):
                #print("===reading {} longwords".format(arrsize))
                us = readmem(start, arrsize*LONG_SIZE)
                f.stackdata = stackdata = crash.mem2long(us, array=arrsize)
                for addr in range(start,end+LONG_SIZE, 8):
                    stackdict[addr] = readULong(addr)

        if (nf.level == -1):
            f.from_func = "entered by exception"
            f.lookup_regs = False
        else:
            f.from_func = "called from {:#x} <{}+{}>".format(nf.addr, nf.func, nf.offset)
            f.lookup_regs = (f.level != -1)
        #print(f, f.from_func)
        f.sp = nf.frame
    
    lastf.from_func = ''
    lastf.lookup_regs = False
 
    stack = stackdict
    for f in s.frames:
        #print f.fullstr()
        #for k in stack:
        #    print("  {:#x}".format(k))
        print "\n{:s} {:s}".format(f.func, f.from_func)
        if (f.lookup_regs):
            look_for_reg(f.func, f.sp, stack)
        else:
            for l in f.data:
                print l
            
    
if ( __name__ == '__main__'):

    parser = argparse.ArgumentParser(description='Show register contents at routine entry.')

    parser.add_argument('pid',metavar='pid|taskp',type=str,nargs='?',
        help='PID or taskp (if omitted, defaults to current context)')

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-a", "--args", 
                        help="identify arguments (with types) where possible",
                        action="store_true")
    group.add_argument("-v", "--verbose", 
                        help="show where register information was found",
                        action="store_true")

    parser.add_argument("-V", "--version", help="show version and exit",
                        action="store_true")
    parser.add_argument("-d", "--debug", help="enable debugging output",
                        action="store_true")

    parser.add_argument("--old", help="use old subroutines, for testing purposes",
                        action="store_true")

    args = parser.parse_args()

    showargs = args.args
    verbose = args.verbose
    debug = args.debug

    if args.version:
        print "Version", __version__
        sys.exit()

    if args.pid == None:
        pid = ''
    else:
        pid = args.pid

    with DisasmFlavor('att'):
        if (args.old):
            olddecode_pid_args(pid)
        else:
            decode_pid_args(pid)



