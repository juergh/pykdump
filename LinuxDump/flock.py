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
	file = fl.fl_file
	try:
	    dentry = file.f_dentry
	except KeyError:
	    dentry = file.f_path.dentry
	inode = dentry.d_inode
	print fl, file, dentry, "\n\tpid=%d inode=0x%x" % (fl.fl_pid, inode)
	
    print "\nBlocked list"
    for fl in  readSUListFromHead(blocked_list, "fl_link", 
	"struct file_lock"):
	file = fl.fl_file
	inode = file.f_dentry.d_inode
	print fl, file, "pid=%d inode=0x%x" % (fl.fl_pid, inode)