
# This script is run once when pykdump extension is loaded
#
# This can be used to register extra commands or anything else

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