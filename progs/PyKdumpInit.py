
# This script is run once when pykdump extension is loaded
#
# This can be used to register extra commands or anything else
# (C) Copyright 2006-2017 Hewlett Packard Enterprise Development LP


from crash import register_epython_prog as rprog

help = '''
The detailed documentation is available on the WEB. Here are most useful
options:

--summary
    prints a summary of connections and warnings about unusual situations

-iv
    prints information about interfaces

-a
    prints information about connections. You can use extra specifiers
    similar to 'netstat' command, e.g. choose TCP only by adding -t

--everything
    prints most things, useful for sending the output to someone with
    networking expertise
'''    

rprog("xportshow",
      "Networking stuff",
      "-h   - list available options",
      help)


help = '''
The detailed documentation is available on the WEB. Here are most useful
options:

-q
    Run quietly printing WARNINGS if anything

-v
    Increase verbosity

--stacksummary
    print a categorized stack summary
     
--sysctl
    emulates 'sysctl -a' output
'''
 
rprog("crashinfo", "1st-pass analysis",
      "-h   - list available options",
      help)


help = '''
Print information about tasks in more details as the built-in 'ps'
command
'''

rprog("taskinfo", "Detailed info about tasks",
      "-h   - list available optoions",
      help)

help = '''
Print information about NFS subsystem, both client and server.
As NFS functionality is implemented in DLKMs, we need to access
debuginfo for some of these modules. Depending on kernel version
these modules are different. Sometimes just one or two files are
enough; sometimes we need four of them:
   "nfs", "lockd", "nfsd", "sunrpc".
On a live kernel they are found automatically. With vmcore, you
need to extract them and put in the same directory where vmcore
is located.
'''

rprog("nfsshow", "Information about NFS subsystem",
      "-h   - list available optoions",
      help)

help = '''
Print information about UNINTERRUPTIBLE threads.
This is mosly useful when you have a hang and many Un threads. This program
will try to categorize them - for example, PIDs of all processes waiting for
mutexes/sempahores.

WARNING:
--------
Algorithms for finding addresses of mutexes/sempahores are
kernel-dependent and as a result, they are not 100% reliable for some
kernels. Still, they are quite useful for many 'production'
distributions such as RHEL{6,7} and SLES11.
'''

rprog("hanginfo", "Information about hanging threads",
      "-h   - list available optoions",
      help)

help = '''
Decode and print information about subroutines registers and arguments,
as available from stack frames. 

This is very useful when you are trying to find arguments of subroutines.
'''

rprog("fregs", "Decode and print stack frame registers",
      "-h   - list available options",
      help)

help = '''
If there are timestamps in dmesg buffer ('log' command output), 
convert these timestams to date/time according to current TZ
and display result prepending this data to each line. 
'''

rprog("tslog", "The same thing as 'log', but with real date/time",
      "-h   - list available options",
      help)

help = '''
Print information about SCSI subsystem. It used to be a subcommand
of crashinfo, but it makes sense to put it into a separate command
with its own options
'''

rprog("scsi", "Print information about SCSI subsystem",
      "-h   - list available options", 
      help)
