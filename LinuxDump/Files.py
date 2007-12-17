#!/usr/bin/env python
#
# Copyright (C) 2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2007 Hewlett-Packard Co., All rights reserved.
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
This is a module for working with files. Some information is parsed from
built-in 'files' command and some is extracted directly from structures
'''

import crash
from pykdump.API import *

# A wrapper for 'files' command
#PID: 12705  TASK: da91e000  CPU: 2   COMMAND: "fsearchctrl"
#ROOT: /    CWD: /var/factiva/tmplatform2/san/pindex2/instream/bin
# FD    FILE     DENTRY    INODE    TYPE  PATH
#  0  db172e00  e6030600  f4af3300  PIPE
#  1  f1927980  dfdc3e00  e68bba90  REG   /var/factiva/tmplatform2/san/pindex2/in

class crashFiles(object):
    def __init__(self, pid):
	lines = exec_crash_command("files %d" % pid).splitlines()
	self.files = {}
	for l in lines[3:]:
	    fields = l.split()
	    if (len(fields) == 6):
	       fd, file, dentry, inode, ftype, path = fields
	    elif (len(fields) == 5):
	       fd, file, dentry, inode, ftype = fields
	       path = ""
	    else:
		continue
	    fd= int(fd)
	    self.files[fd] = ftype, path
    def fileInfo(fd):
	return self.files[fd]
    def printFiles(self, fds):
	for f in fds:
	    print "     %3d" %f, self.files[f]

	
	
	
