# fregsapi.py - API for the fregs crash extension that attempts to
# determine register contents at entry to each routine in stack frame

# --------------------------------------------------------------------
# (C) Copyright 2015-2017 Hewlett Packard Enterprise Development LP
#
# Author: Martin Moore (martin.moore@hpe.com)
#
# --------------------------------------------------------------------

#
# Usage: search_for_registers(s)
#  
# The argument s is a BTstack object.  The function adds several attributes 
# to each frame in s.frames.  The key attribute is .reg, which is a (possibly 
# empty) dictionary of tuples of the form (contents, confidence), indexed by 
# the register name in upper case ("RDI", etc.)  Each tuple contains the 
# register contents and its confidence value; confidence ranges from 0 to 9, 
# with lower being better (0 is certainty).  So for a given frame f, 
# f.reg[REG][0] will contain the contents of REG upon entry to that routine, 
# with a confidence level of f.reg[REG][1].
#  
# Caveats: search_for_registers requires x86_64 architecture and att 
# disassembly flavor.  It checks the architecture and exits with an error 
# if not x86_64.  The caller is responsible for ensuring att disassembly 
# flavor; example usage is:
#  
#     with DisasmFlavor('att'):
#         try:
#             s = exec_bt("bt " + pid,MEMOIZE=False)[0]
#         except:
#             print "Unable to get stack trace"
#             sys.exit(1)
#         search_for_registers(s)
#
# The context handler DisasmFlavor will also set the output radix to 10 and restore it if needed,
# as the code assumes decimal outputs in some cases.

#
# General philosophy: try to find register contents that can be determined
# with a high degree of confidence and not too much work.  Don't try to
# figure everything out (which is probably impossible); this is a debugging
# aid, not a tool that attempts to do all crash analysis automatically.

__version__ = "1.02"

from pykdump.API import *

REG64 = ('RAX','RBX','RCX','RDX','RSI','RDI','RBP','RSP','R8','R9','R10',
         'R11','R12','R13','R14','R15')
REG32 = ('EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','R8D','R9D','R10D',
         'R11D','R12D','R13D','R14D','R15D')
REG16 = ('AX','BX','CX','DX','SI','DI','BP','SP','R8W','R9W','R10W',
         'R11W','R12W','R13W','R14W','R15W')
REG8 = ('AL','BL','CL','DL','SIL','DIL','BPL','SPL','R8B','R9B','R10B',
         'R11B','R12B','R13B','R14B','R15B')

@memoize_cond(CU_LIVE|CU_LOAD)
def disasm(addr,nlines) :
    return exec_gdb_command("x/{}i {}".format(nlines,addr))

# Function extract_registers - Look for saved registers
#
# This function is the heart of this program.  Don't call this for routines
# entered via exception; for those, we just save and display the exception
# frame, which contains all register values at the time of exception.

def extract_registers (frame, stack):
    "Try to find register contents at time of function entry"

    fname = frame.func
    sp = frame.sp

    # Start by finding registers saved on the stack at routine entry (this
    # is fairly straightforward).  Build a dictionary of the found values.

    regval = {}

    rsp = sp     # Initialize stack pointer

    # Disassemble the first 12 instructions in the routine.  This should be
    # more than enough to handle the initial register saving.

    # We have to be a little careful here because there can be duplicate
    # routine names.  We call sym2alladdr() to get a list of all addresses
    # for the funtion name's symbol.  If there's only one, we're done.
    # But if there's more than one, we have to search through the list to 
    # find the symbol that's closest to, but not larger than, the return
    # address in the stack frame.

    addrlist = sym2alladdr(fname)
    if len(addrlist) == 1:
        addr = addrlist[0]
    else:
        for nextaddr in sorted(addrlist):
            if nextaddr <= frame.addr:
                addr = nextaddr
            else:
                break
    
    # Get the disassembled instructions.  This can fail for various
    # corner cases where libunwind does odd things around exceptions.
    # If so, just return.

    try:
        disout = disasm(hexl(addr),12)
        disinst = disout.splitlines()
    except:
        return

    # Parse the entry sequence where registers are saved on the stack.
    # We're only interested in push, sub, and mov instructions.  When we
    # find something else, we've presumably finished the entry, so stop looking.

    for line in disinst:
        colon = line.index(":")
        inst = line[colon+1:]
        fields = inst.split()
        opcode = fields[0]
        try:
            operand = fields[1]
        except IndexError:
            break

        if opcode == "push":
            rsp -= 8

            # If we're pushing a register, save its value from the stack
            if operand.startswith("%"):
                register = operand.lstrip("%").upper()
                try:
                    val = stack[rsp]
                    regval[register] = val
                    frame.reg[register] = (val,0)

                except KeyError:
                    continue

        elif opcode == "sub":
            # SUB instruction - make sure we're subtracting a constant
            if not operand.startswith("$"):
                continue

            fields = operand.split(",")

            # We're only interested in subtractions from RSP or (shouldn't happen) RBP

            if fields[1] == "%rsp":
                val = int(fields[0].lstrip("$"),16)
                rsp -= val
            elif fields[1] == "%rbp":
                val = int(fields[0].lstrip("$"),16)
                rbp -= val

        elif opcode == "mov":
            fields = operand.split(",")
            if operand == "%rsp,%rbp":
                rbp = rsp
            elif operand.startswith("%"):
                register = fields[0].lstrip("%").upper()
                dest = fields[1]
                paren = dest.find("(")
                if paren < 0:
                    continue
                elif paren == 0:
                    offset = 0
                else:
                    try:
                        offset = int(dest[:paren],16)

                    # This exception occurs if the instruction is of
                    # a form like "mov %reg,%gs:0xsomething(%reg):

                    except ValueError:
                        continue

                basereg = dest[(paren+2):-1]

                if basereg == "rbp":
                    addr = rbp + offset
                elif basereg == "rsp":
                    addr = rsp + offset
                else:
                    continue

                try:
                    val = stack[addr]
                    regval[register] = val
                    frame.reg[register] = (val,0)

                except KeyError:
                    continue

        elif opcode.startswith(("nop","data32")):
            continue   # Ignore NOP instructions

        else:
            break # from for loop (done with routine entry processing)

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
    try:
        disinst = disout.splitlines()
    except:
        return

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

        lines_parsed += 1

        if lines_parsed < 3:
            continue           # skip first (i.e. last) 2 instructions

        if lines_parsed > 11:
            break              # go no more than 9 instructions before call

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
                            frame.reg[dstreg] = (val,conf)

                    elif regval[dstreg] != "invalid":  # dst is known
                        if srcreg == "RSP":  # Don't do this for RSP
                            continue         # (handled separately)
                        val = regval[dstreg] & dstmask
                        if srcreg not in regval: # src is unknown
                            frame.reg[srcreg] = (val,conf)
                        regval[srcreg] = val

                # MOV const,reg
                #
                # If this is a new register, display it; either way,
                # invalidate it.

                elif src.startswith("$"):
                    val = int(src.lstrip("$"),16) & dstmask

                    if dstreg not in regval:
                        frame.reg[dstreg] = (val,conf)

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
                                #print "rd failed",addr,line,basereg,dstreg
                                regval[dstreg] = "invalid"
                                continue
                            if not rdout.startswith("ffff"):
                                regval[dstreg] = "invalid"
                                continue

                            fields = rdout.split()
                            val = int(fields[1],16)

                        else:
                            # Read using direct pydkump API
                            try:
                                val = readULong(addr)
                            except:
                                regval[dstreg] = "invalid"
                                continue

                    if dstreg not in regval:

                        val &= dstmask
                        frame.reg[dstreg] = (val,conf)
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
                frame.reg[dstreg] = (addr,conf)
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

        # STOSx (Store String) instructions invalidate RDI

        elif opcode.startswith('stos'):
             regval['RDI'] = "invalid"

        # For any other instruction that modified the contents of a register,
        # invalidate the register.

        elif opcode.startswith(('add','sub','inc','dec','imul','idiv','and',
            'or','xor','not','sbb','adc','neg','sh','pop','bt','sa','set',
            'cmov','ro','rc')):
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

        elif opcode.startswith(("call","rep")):
            break

        # Instructions that don't change registers.  Ignore.

        elif opcode.startswith(("nop","j","test","cmp","push","data32",
             "lock","prefetch","out")):
            continue		# Skip NOP instructions

        else:
            print("Unparsed: {}".format(inst))

    return

# A context manager to change disassembly flavor and output radix if needed, and then to restore them
class DisasmFlavor():
    def __init__(self, flavor):
        s = exec_gdb_command("show disassembly-flavor")
        m = re.search(r'"([^"]+)"', s)
        if (m):
            self.oldflavor = m.group(1)
        self.flavor = flavor
        s = exec_gdb_command("show output-radix")
        m = s.splitlines()[0].rstrip('.')
        self.radix = m.split()[-1]
        #print("Current radix is {}".format(self.radix))
    def __enter__(self):
        if (self.oldflavor != self.flavor):
            #print("Setting flavor to {}".format(self.flavor))
            exec_gdb_command("set disassembly-flavor {}".format(self.flavor))
        if (self.radix != "10"):
            #print("Setting output radix to 10")
            exec_gdb_command("set output-radix 10")
    def __exit__(self, exc_type, exc_value, traceback):
        if (self.flavor != self.oldflavor):
            #print("Restoring flavor to {}".format(self.oldflavor))
            exec_gdb_command("set disassembly-flavor {}".format(self.oldflavor))
        if (self.radix != "10"):
            #print("Restoring output radix to {}".format(self.radix))
            exec_gdb_command("set output-radix {}".format(self.radix))

# search_for_registers(s) - s is a BTstack object. 

def search_for_registers(s):

    # Make sure we're on an x86_64 vmcore, or this will fail miserably.
    if (sys_info.machine != "x86_64"):
        return 1

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

        f.sp = nf.frame
        f.reg = {}
        if (nf.level == -1):
            f.from_func = "entered by exception at <{}+{}>".format(
                nf.func, nf.offset)
            f.lookup_regs = False
            f.data = nf.data
        else:
            f.from_func = "called from {:#x} <{}+{}>".format(nf.addr, nf.func, nf.offset)
            f.lookup_regs = True
            extract_registers(f, stackdict)
    
    # For last frame, empty string for from_func
    lastf.from_func = ''
    lastf.lookup_regs = False
    lastf.reg = {}
 
