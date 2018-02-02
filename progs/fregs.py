# fregs.py - Python extension for crash utility that attempts to
# determine register contents at entry to each routine in stack frame

# --------------------------------------------------------------------
# (C) Copyright 2015-2017 Hewlett Packard Enterprise Development LP
#
# Author: Martin Moore (martin.moore@hpe.com)
#
# --------------------------------------------------------------------

#
# Usage: Load pykdump extension, then "fregs <options>"
#
# General philosophy: try to find register contents that can be determined
# with a high degree of confidence and not too much work.  Don't try to
# figure everything out (which is probably impossible); this is a debugging
# aid, not a tool that attempts to do all crash analysis automatically.

__version__ = "1.11"

import argparse
from pykdump.API import *
from LinuxDump.fregsapi import *

from LinuxDump.BTstack import exec_bt

# ARG_REG is a list of the registers used to pass arguments

ARG_REG = ('RDI','RSI','RDX','RCX','R8','R9')

@memoize_cond(CU_LIVE|CU_LOAD)
def funcargs_dict(funcname):
    fields = funcargs(funcname)
    if (fields is None):
        print ("Can't identify arguments for {}".format(funcname))
        return {}
    return dict(zip(ARG_REG,fields))

@memoize_cond(CU_LIVE)
def dentry_to_filename (dentry) :
    try:
        crashout = exec_crash_command ("files -d {:#x}".format(dentry))
        filename = crashout.split()[-1]
        if filename == "DIR" :
            filename = "<blank>"
        return filename
    except:
        return "<invalid>"

@memoize_cond(CU_LIVE)
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

#--------------------------------------------------------------
#   Main program begins here. 
#--------------------------------------------------------------
    
if ( __name__ == '__main__'):

    parser = argparse.ArgumentParser(
             description='Show register contents at routine entry.')

    parser.add_argument('pid',metavar='pid|taskp|cmd',type=str,nargs='?',
        help='PID or task struct pointer or command (if omitted, use current context)')

    parser.add_argument("-V", "--version", action="version", 
                        version=__version__)

    parser.add_argument("-a", "--args", 
                        help="identify arguments (-aa for more detail)",
                        action="count", default=0)

    parser.add_argument("-l", "--lines",
                        help="show source code line numbers",
                        action="store_true")

    parser.add_argument("-r", "--routine", default="",
                        help="only show routines whose names include ROUTINE")

    #parser.add_argument("-V", "--version", help="show version and exit",
    #                    action="store_true")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-u", "--unint", help="do all uninterruptible tasks",
                        action="store_true")
    group.add_argument("-A", "--all", 
                        help="do ALL tasks (this may take a while!)",
                        action="store_true")

    args = parser.parse_args()

    arglevel = args.args
    showlines = args.lines
    routine = args.routine

    if showlines :
        bts = "bt -l"
    else:
        bts = "bt"

    if args.all :
        btcmd = "foreach " + bts
    elif args.unint :
        btcmd = "foreach UN " + bts
    elif args.pid == None :
        btcmd = bts
    else:
        btcmd = "foreach " + args.pid + " " + bts

    # Make sure we're on an x86_64 vmcore, or this will fail miserably.
    if (sys_info.machine != "x86_64"):
        print ("Register decoding is supported on x86_64 dumps only.")
        sys.exit()        

    # Purge the memoize cache if a 'mod' command has been done since
    # our last invocation, since new symbols may not be available

    purge_memoize_cache(CU_LOAD)

    with DisasmFlavor('att'):
        try:
            stacklist = exec_bt(btcmd, MEMOIZE=False)
        except:
            print ("Unable to get stack trace")
            sys.exit()

        for s in stacklist:

            search_for_registers(s,routine)

            print ("\nPID: {}  TASK: {:x}  CPU: {}  COMMAND: {}".format(
                   s.pid, s.addr, s.cpu, s.cmd))

            for f in s.frames:

                # Skip frame if it doesn't match routine name pattern.
                # If no routine was specified, the frame will print because
                # the argument is initialized to an empty string, which by
                # definition is a substring of all strings.

                if routine not in f.func:
                    continue

                print()    # Skip a line for readability

                if f.level >= 0:
                    print ("#{} {:s} {:s}".format(f.level,f.func, f.from_func))
                else:
                    print ("{:s} {:s}".format(f.func, f.from_func))

                if (f.lookup_regs):

                    if showlines:
                        try:
                            print ("{:s}".format(f.data[-1]))
                        except:
                            print ("    <No line numbers; possibly you need to load a module>")

                    # If we're getting arguments, get information from crash

                    if arglevel > 0:
                        arg_types = funcargs_dict(f.func)

                    for reg in sorted(f.reg):
                        val = f.reg[reg][0]
                        conf = f.reg[reg][1]
                        if arglevel == 0 or reg not in arg_types:
                            if conf == 0:
                                print (" +{:s}: {:#x}".format(reg,val))
                            else:
                                print ("{} {:s}: {:#x}".format(conf,reg,val))
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
                            if conf == 0:
                                print (" +{:s}: {:#x} arg{:d} {:s} {:s}".format(
                                      reg,val,argno,argtype,argdata))
                            else:
                                print("{} {:s}: {:#x} arg{:d} {:s} {:s}".format(
                                      conf,reg,val,argno,argtype,argdata))
                else:
                    for l in f.data:
                        print (l)

