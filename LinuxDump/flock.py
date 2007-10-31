#
# -*- coding: latin-1 -*-
# Time-stamp: <07/10/11 12:16:51 alexs>

# File-locking functions

from pykdump.API import *

def print_locks():
    file_lock_list = readSymbol("file_lock_list")
    blocked_list = readSymbol("blocked_list")
    
    print "Active locks"
    for fl in  readSUListFromHead(file_lock_list, "fl_link", 
	"struct file_lock"):
	print fl
	
    print "Blocked list"
    for fl in  readSUListFromHead(blocked_list, "fl_link", 
	"struct file_lock"):
	print fl