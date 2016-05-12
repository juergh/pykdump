# fregs.py - Python extension for crash utility that attempts to
# determine register contents at entry to each routine in stack frame

# --------------------------------------------------------------------
# (C) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
#
# Author: Martin Moore (martin.moore@hpe.com)
#
# --------------------------------------------------------------------

#
# Usage: Load pykdump extension, then "freg <options>"
#
# General philosophy: try to find register contents that can be determined
# with a high degree of confidence and not too much work.  Don't try to
# figure everything out (which is probably impossible); this is a debugging
# aid, not a tool that attempts to do all crash analysis automatically.

__version__ = "1.05"

import argparse
from pykdump.API import *

from LinuxDump.BTstack import exec_bt

# ARG_REG is a list of the registers used to pass arguments

ARG_REG = ['RDI','RSI','RDX','RCX','R8','R9']

REG64 = ['RAX','RBX','RCX','RDX','RSI','RDI','RBP','RSP','R8','R9','R10',
         'R11','R12','R13','R14','R15']
REG32 = ['EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','R8D','R9D','R10D',
         'R11D','R12D','R13D','R14D','R15D']
REG16 = ['AX','BX','CX','DX','SI','DI','BP','SP','R8W','R9W','R10W',
         'R11W','R12W','R13W','R14W','R15W']
REG8 = ['AL','BL','CL','DL','SIL','DIL','BPL','SPL','R8B','R9B','R10B',
         'R11B','R12B','R13B','R14B','R15B']

def funcargs_dict(funcname):
    fields = funcargs(funcname)
    if (fields is None):
        print "Can't identify arguments for", funcname
        return {}
    return dict(zip(ARG_REG,fields))

@memoize_cond(CU_LIVE|CU_LOAD)
def disasm(addr,nlines) :
    return exec_gdb_command("x/{}i {}".format(nlines,addr))

@memoize_cond(CU_LIVE|CU_LOAD)
def dentry_to_filename (dentry) :
    try:
        crashout = exec_crash_command ("files -d {:#x}".format(dentry))
        filename = crashout.split()[-1]
        if filename == "DIR" :
            filename = "<blank>"
        return filename
    except:
        return "<invalid>"

@memoize_cond(CU_LIVE|CU_LOAD)
def get_argdata (addr, type) :
    #if type == "char *" :
    #    try:
    #        crashout = exec_crash_command ("rd -a {:#x}".format(addr))
    #        return "= " + crashout
    #    except:
    #        return ""
    if type == "struct dentry *" :
        return "= " + dentry_to_filename (addr)
    elif type == "struct file *" :
        offset = member_offset ("struct file", "f_path.dentry")
        dentry = readULong (addr + offset)
        return "= " + dentry_to_filename (dentry)
    elif type == "struct path *" :
        offset = member_offset ("struct path", "dentry")
        dentry = readULong (addr + offset)
        return "= " + dentry_to_filename (dentry)
    elif type == "struct nameidata *" :
        offset = member_offset ("struct nameidata", "path.dentry")
        dentry = readULong (addr + offset)
        return "= " + dentry_to_filename (dentry)
    elif type == "struct filename *" :
        crashout = exec_crash_command("filename.name {:#x}".format(addr))
        filename = crashout.split()[-1]
        return "= " + filename
    elif type == "struct qstr *" :
        crashout = exec_crash_command("qstr.name {:#x}".format(addr))
        filename = crashout.split()[-1]
        return "= " + filename
    elif type == "struct vfsmount *" :
        offset = member_offset ("struct vfsmount", "mnt_mountpoint")
        dentry = readULong (addr + offset)
        return "= " + dentry_to_filename (dentry)
    elif type == "struct task_struct *" :
        crashout = exec_crash_command("task_struct.pid {:#x}".format(addr))
        pid = crashout.split()[-1]
        return "= pid " + pid
    elif type == "struct device *" :
        crashout = exec_crash_command("device.kobj.name {:#x}".format(addr))
        devname = crashout.split()[-1]
        return "= " + devname
    elif type == "struct scsi_device *" :
        crashout = exec_crash_command(
                   "scsi_device.sdev_gendev.kobj.name {:#x}".format(addr))
        devname = crashout.split()[-1]
        crashout = exec_crash_command(
                   "scsi_device.sdev_state {:#x}".format(addr))
        state = crashout.split()[-1]
        return "({:s} {:s})".format(devname,state)
    elif type == "struct scsi_target *" :
        crashout = exec_crash_command(
                   "scsi_target.dev.kobj.name {:#x}".format(addr))
        devname = crashout.split()[-1]
        crashout = exec_crash_command(
                   "scsi_target.state {:#x}".format(addr))
        state = crashout.split()[-1]
        return "({:s} {:s})".format(devname,state)
    elif type == "struct Scsi_Host *" :
        offset = member_offset ("struct Scsi_Host", "host_no")
        hostno = readU32 (addr + offset)
        return "(host{})".format(hostno)
    elif type == "struct bio *" :
        offset = member_offset ("struct bio", "bi_bdev")
        bdev = readULong (addr + offset)
        #print "bdev={:#x}".format(bdev)
        dev = readU32 (bdev)	# dev has offset 0
        major = dev // 1048576
        minor = dev % 1048576
        return "(device {}:{})".format(major,minor)        
    elif type == "struct mutex *" :
        offset = member_offset ("struct mutex", "owner")
        owner_thread = readULong (addr + offset)
        owner_task = readULong (owner_thread) # task has offset 0
        offset = member_offset ("struct task_struct", "pid")
        pid = readU32 (owner_task + offset)
        return "(owner pid: {})".format(pid)
    elif type == "struct linux_binprm *" :
        crashout = exec_crash_command("linux_binprm.filename {:#x}".format(addr))
        filename = crashout.split()[-1]
        return "= " + filename
    else:
        return ""

def show_reg_from_caller (conf, reg, val, opcode, operand) :
    "Display register contents based on format options"

    if verbose:
        print "{} {:s}: {:#x} from caller: {:s} {:s}".format(
            conf,reg,val,opcode,operand)

    elif arglevel == 0 or reg not in arg_types:
        print "{} {:s}: {:#x}".format(conf,reg,val)

    else:
        argno = ARG_REG.index(reg)
        argtype = arg_types[reg]
        if arglevel == 1:
            argdata = ""
        else:
            try:
                argdata = get_argdata (val, argtype)
            except:
                argdata = "<invalid>"
        print "{} {:s}: {:#x} arg{:d} {:s} {:s}".format(
                                          conf,reg,val,argno,argtype,argdata)
    return {}

# Function look_for_reg - Look for saved registers
#
# This function is the heart of this program.  Don't call this for routines
# entered via exception; for those, we just save and display the exception
# frame, which contains all register values at the time of exception.

def look_for_reg (fname, sp, stack):
    "Try to find register contents at time of function entry"

    # If we're getting arguments, get information from crash

    global arg_types
    if arglevel > 0:
        arg_types = funcargs_dict(fname)

    # Start by finding registers saved on the stack at routine entry (this
    # is fairly straightforward).  Build a dictionary of the found values.

    regval = {}

    rsp = sp     # Initialize stack pointer
    if debug:
        print "Initial stack pointer is {:#x}".format(rsp)

    # Disassemble the first 12 instructions in the routine.  This should be
    # more than enough to handle the initial register saving.

    disout = disasm(fname,12)
    try:
        disinst = disout.splitlines()
    except AttributeError:
        symout = exec_crash_command("sym " + fname)
        addr = symout.split()[0]
        #print("Trying disasm {} for {}".format(addr,fname))
        disout = disasm("0x"+addr,12)
        disinst = disout.splitlines()


    # Parse the entry sequence where registers are saved on the stack.
    # We're only interested in push, sub, and mov instructions.  When we
    # find something else, we've presumably finished the entry, so stop looking.

    for line in disinst:
        colon = line.index(":")
        inst = line[colon+1:]
        if debug:
            print line, inst
        fields = inst.split()
        opcode = fields[0]
        try:
            operand = fields[1]
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
                        print " +{:s}: {:#x} from {:#x} (push)".format(
                            register,val,rsp)
                    elif arglevel == 0 or register not in arg_types:
                        print " +{:s}: {:#x}".format(register,val)
                    else:
                        argno = ARG_REG.index(register)
                        argtype = arg_types[register]
                        if arglevel == 1:
                            argdata = ""
                        else:
                            argdata = get_argdata (val, argtype)
                        print " +{:s}: {:#x} arg{:d} {:s} {:s}".format(
                            register,val,argno,argtype,argdata)

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
                else:
                    continue

                try:
                    val = stack[addr]
                    if verbose:
                        print " +{:s}: {:#x} from {:#x} {:s}".format(
                            register,val,addr,dest)
                    elif arglevel == 0 or register not in arg_types:
                       print " +{:s}: {:#x}".format(register,val)
                    else:
                        argno = ARG_REG.index(register)
                        argtype = arg_types[register]
                        if arglevel == 1:
                            argdata = ""
                        else:
                            argdata = get_argdata (val,argtype)
                        print " +{:s}: {:#x} arg{:d} {:s} {:s}".format(
                            register,val,argno,argtype,argdata)

                    regval[register] = val

                except KeyError:
                    if debug:
                        print "Don't have stack entry at {:#x}".format(rsp)

        elif opcode.startswith(("nop","data32")):
            continue   # Ignore NOP instructions

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

    # To disassemble, we use the gdb "x/i" command, which is much faster
    # than using crash's "dis" command (especially "dis -r)".  However,
    # since instructions are variable length, we can't just ask for the
    # last N instructions before the RIP.  We have to go from the beginning
    # of the routine and guess how many instructions to disassemble.  We
    # guess by assuming an average instruction length of 5 bytes (which
    # seems optimal by empirical testing.)

    rsp = stack[sp] + 8    # SP before call
    rip = stack[sp]
    ripstr = "{:#x}".format(rip)

    symout = exec_crash_command("sym " + ripstr)
    sym = symout.split()[2]
    fields = sym.split("+")
    func = fields[0]
    try:
        offset = int(fields[1])
    except IndexError:
        offset = 0

    start = rip - offset   # start address of this routine

    # Guess number of instructions to disassemble

    nlines = offset // 5 + 1
    dstr = "{:#x}".format(start)
    disout = disasm(dstr,nlines)
    disinst = disout.splitlines()

    # Did we find the RIP yet?  This check takes advantage of the fact that
    # fixed-length hex numbers with consistent case sort the same way 
    # lexically and numerically.

    # If we haven't found the RIP yet, guess again for the remaining 
    # instructions; keep going until we reach the RIP.  Note that we
    # add an extra instruction (+2 below) to avoid asking for only one
    # and getting stuck in a loop.

    addr = disinst[-1].split()[0].rstrip(":")

    while addr < ripstr:
        disinst.pop()  # discard last line, since it will come back
        nlines = (rip - int(addr,16)) // 5 + 2
        disout = disasm(addr,nlines)
        disinst.extend(disout.splitlines())
        addr = disinst[-1].split()[0].rstrip(":")

    # Discard everything after the ripstr

    while addr > ripstr:
        line = disinst.pop()
        addr = disinst[-1].split()[0].rstrip(":")


    # At this point, list disinst contains the disassembled instructions.
    # Run through the disassembled instructions in reverse up to a limit,
    # since the further back we go the more likely it is that control flow
    # will make the results less certain.  Skip the first (i.e. last) 2 lines,
    # since they should be the call to this routine and the next instruction.

    lines_parsed = 0
    for line in reversed(disinst):
        if debug:
            print line

        lines_parsed += 1

        if lines_parsed < 3:
            continue           # skip this line

        if lines_parsed > 10:
            break              # quit after 10 lines

        conf = lines_parsed - 2	# confidence value (distance from call)

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

        colon = line.index(":")
        inst = line[colon+1:]
        fields = inst.split()
        opcode = fields[0]
        try:
            operand = fields[1]
        except IndexError:
            continue		# Ignore instructions with no operand

        # Process the various opcodes

        # Parse MOV instruction.  There are 5 possible cases:
        #
        #     MOV reg,reg
        #     MOV mem,reg
        #     MOV const,reg
        #     MOV reg,mem
        #     MOV const,mem
        #
        # We don't need to worry about the writes to memory.

        if opcode.startswith("mov"):
            fields = operand.split(",")
            src = fields[0]
            dst = fields[1]
            if dst.startswith("%"):

                # Destination is a register.  If it's already invalid, just continue.
                # Otherwise, determine the source type.

                rawdstreg = dst.lstrip("%").upper()

                if rawdstreg in REG64:
                    dstreg = rawdstreg
                    dstmask = 0xffffffffffffffff
                elif rawdstreg in REG32:
                    dstreg = REG64[REG32.index(rawdstreg)]
                    dstmask = 0xffffffff
                elif rawdstreg in REG16:
                    dstreg = REG64[REG16.index(rawdstreg)]
                    dstmask = 0xffff
                elif rawdstreg in REG8:
                    dstreg = REG64[REG8.index(rawdstreg)]
                    dstmask = 0xff
                else:
                    continue    # Must be a control register, ignore

                try:
                    if regval[dstreg] == "invalid":
                        continue
                except KeyError:
                    pass

                if src.startswith("%"):

                    # MOV regA,regB
                    #
                    # If both registers are the same (can this happen?), skip this one.

                    rawsrcreg = src.lstrip("%").upper()

                    if rawsrcreg in REG64:
                        srcreg = rawsrcreg
                        srcmask = 0xffffffffffffffff
                    elif rawsrcreg in REG32:
                        srcreg = REG64[REG32.index(rawsrcreg)]
                        srcmask = 0xffffffff
                    elif rawsrcreg in REG16:
                        srcreg = REG64[REG16.index(rawsrcreg)]
                        srcmask = 0xffff
                    elif rawsrcreg in REG8:
                        srcreg = REG64[REG8.index(rawsrcreg)]
                        srcmask = 0xff
                    else:
                        continue    # Must be a control register, ignore

                    if srcreg == dstreg:
                        continue

                    # What happens next depends on what we already know about the registers.
                    #
                    # If dst is unknown:
                    #    If src is known, report its value as the dst value.  Then
                    #       invalidate dst (regarldess of src state).
                    # If dst is known:
                    #    If src is unknown, report dst contents as src value.  Set src
                    #       to dst (regardless of src state).
                    # If dst is invalid:
                    #    Do nothing (we can't learn anything new).

                    if dstreg not in regval:  # dst is unknown
                        if srcreg not in regval: # src is unknown 
                            regval[dstreg] = "invalid"
                        elif regval[srcreg] == "invalid":
                            regval[dstreg] = "invalid"
                        else:
                            val = regval[srcreg] & srcmask

                            regval[dstreg] = "invalid"
                            show_reg_from_caller (conf,dstreg,val,opcode,operand)

                    elif regval[dstreg] != "invalid":  # dst is known
                        if srcreg == "RSP":  # Don't do this for RSP
                            continue         # (handled separately)
                        val = regval[dstreg] & dstmask
                        if srcreg not in regval: # src is unknown
                            show_reg_from_caller (conf,srcreg,val,opcode,operand)
                        regval[srcreg] = val

                # MOV const,reg
                #
                # If this is a new register, display it; either way,
                # invalidate it.

                elif src.startswith("$"):
                    val = int(src.lstrip("$"),16) & dstmask

                    if dstreg not in regval:
                        show_reg_from_caller (conf,dstreg,val,opcode,operand)

                    regval[dstreg] = "invalid"

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
                    if basereg in regval:
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
                        if (False):
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
                            if debug:
                                val2 = readULong(addr)
                                print "val={:x} val2={:x}".format(val,val2)
                        else:
                            # Read using direct pydkump API
                            try:
                                val = readULong(addr)
                            except:
                                if debug:
                                    print "rd failed",addr,line,basereg,dstreg
                                regval[dstreg] = "invalid"
                                continue

                    if dstreg not in regval:

                        val &= dstmask
                        show_reg_from_caller (conf,dstreg,val,opcode,operand)
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
        # We also assume this will only come up for 64-bit registers in
        # a 64-bit kernel; is this a valid assumption?

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
            if basereg in regval:
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
                show_reg_from_caller (conf,dstreg,addr,opcode,operand)
                regval[dstreg] = "invalid"

            else:
                regval[dstreg] = "invalid"
                continue

        # XCHG instruction.

        elif opcode.startswith('xchg'):
            fields = operand.split(",")
            src = fields[0]
            dst = fields[1]

            # If src and dst are the same, this is a common no-op.

            if src == dst:
                continue

            # Now we should have either XCHG reg,mem or XCHG regA,regB.
            # We'll just invalidate the registers, although we could possibly
            # learn a little more from them in some cases.

            if not src.startswith("%"):
                continue     # sanity check (shouldn't happen)

            rawsrcreg = src.lstrip("%").upper()

            if rawsrcreg in REG64:
                srcreg = rawsrcreg
                srcmask = 0xffffffffffffffff
            elif rawsrcreg in REG32:
                srcreg = REG64[REG32.index(rawsrcreg)]
                srcmask = 0xffffffff
            elif rawsrcreg in REG16:
                srcreg = REG64[REG16.index(rawsrcreg)]
                srcmask = 0xffff
            elif rawsrcreg in REG8:
                srcreg = REG64[REG8.index(rawsrcreg)]
                srcmask = 0xff
            else:
                continue    # Must be a control register, ignore

            regval[srcreg] = "invalid"

            if dst.startswith("%"):
                rawdstreg = dst.lstrip("%").upper()

                if rawdstreg in REG64:
                    dstreg = rawdstreg
                    dstmask = 0xffffffffffffffff
                elif rawdstreg in REG32:
                    dstreg = REG64[REG32.index(rawdstreg)]
                    dstmask = 0xffffffff
                elif rawdstreg in REG16:
                    dstreg = REG64[REG16.index(rawdstreg)]
                    dstmask = 0xffff
                elif rawdstreg in REG8:
                    dstreg = REG64[REG8.index(rawdstreg)]
                    dstmask = 0xff
                else:
                    continue    # Must be a control register, ignore

                regval[dstreg] = "invalid"


        # For any other instruction that modified the contents of a register,
        # invalidate the register.

        elif opcode.startswith(('add','sub','inc','dec','imul','idiv','and',
            'or','xor','not','sbb','adc','neg','shl','shr','pop','bt')):
            fields = operand.split(",")
            dst = fields[-1]
            if dst.startswith("%"):
                rawdstreg = dst.lstrip("%").upper()
                if rawdstreg in REG64:
                    dstreg = rawdstreg
                elif rawdstreg in REG32:
                    dstreg = REG64[REG32.index(rawdstreg)]
                elif rawdstreg in REG16:
                    dstreg = REG64[REG16.index(rawdstreg)]
                elif rawdstreg in REG8:
                    dstreg = REG64[REG8.index(rawdstreg)]
                else:
                    continue    # Must be a control register, ignore

                regval[dstreg] = "invalid"

        # Instructions whose effect on registers is indeterminate. 
        # Stop parsing.

        elif opcode.startswith(("call","cmov")):
            break

        # Instructions that don't change registers.  Ignore.

        elif opcode.startswith(("nop","j","test","cmp","push","data32",
             "lock","prefetch")):
            continue		# Skip NOP instructions

        else:
            print("Unparsed: {}".format(inst))

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

def decode_pid_args(pid):
    # Make sure we're on an x86_64 vmcore, or this will fail miserably.
    if (sys_info.machine != "x86_64"):
        print "Supported on x86_64 dumps only, sorry."
        sys.exit(1)        

    try:
        s = exec_bt("bt " + pid,MEMOIZE=False)[0]
    except:
        print "Unable to get stack trace"
        sys.exit(1)

    for f in s.frames:
        print f

    # For last frame, empty string for from_func
    lastf = s.frames[-1]
    stackdict = {}
    
    for f, nf in zip(s.frames[:-1], s.frames[1:]):
        calledfrom = nf.func
        
        if (f is not lastf):
            # Keep previous start if in a routine that resulted in exception
            if (f.level != -1):
                start = f.frame + LONG_SIZE

            end = nf.frame
            arrsize = (end-start)//LONG_SIZE + 1

            for l in f.data:
                if (l.startswith("---")):
                    print l

            if (arrsize > 0 and arrsize < 8192):
                #print("===reading {} longwords at level {}".format(arrsize,nf.level))
                us = readmem(start, arrsize*LONG_SIZE)
                f.stackdata = stackdata = crash.mem2long(us, array=arrsize)
                if (arrsize == 1):
                    stackdict[start] = stackdata
                else:
                    addr = start
                    for val in stackdata:
                        stackdict[addr] = val
                        addr += 8

        if (nf.level == -1):
            f.from_func = "entered by exception at <{}+{}>".format(
                nf.func, nf.offset)
            f.lookup_regs = False
            f.data = nf.data
        else:
            f.from_func = "called from {:#x} <{}+{}>".format(nf.addr, nf.func, nf.offset)
            f.lookup_regs = True
        #print(f, f.from_func)
        f.sp = nf.frame
    
    lastf.from_func = ''
    lastf.lookup_regs = False
 
    stack = stackdict
    for f in s.frames:
        #print f.fullstr()
        #for k in stack:
        #    print("  {:#x}".format(k))
        #print "\n{:s} {:s}".format(f.func, f.from_func)
        print "\n{:s} {:s}".format(f.func, f.from_func)
        if (f.lookup_regs):
            look_for_reg(f.func, f.sp, stack)
        else:
            for l in f.data:
                print l
            
#--------------------------------------------------------------
#   Main program begins here. 
#--------------------------------------------------------------
    
if ( __name__ == '__main__'):

    parser = argparse.ArgumentParser(description='Show register contents at routine entry.')

    parser.add_argument('pid',metavar='pid|taskp',type=str,nargs='?',
        help='PID or taskp (if omitted, defaults to current context)')

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-a", "--args", 
                        help="identify arguments (-aa for more detail)",
                        action="count", default=0)
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

    arglevel = args.args
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
        decode_pid_args(pid)

