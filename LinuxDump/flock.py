#
# -*- coding: latin-1 -*-
# Time-stamp: <12/03/20 12:23:05 alexs>

# File-locking functions

from __future__ import print_function

from pykdump.API import *

def print_lock(fl):
    file = fl.fl_file
    flags = fl.fl_flags
    fltype = fl.fl_type
    try:
        dentry = file.f_dentry
    except KeyError:
        dentry = file.f_path.dentry
    inode = dentry.d_inode
    print (fl, dbits2str(flags, FL_flags), dbits2str(fltype, FL_types))
    print ("\t", file, dentry)
    print ("\tpid=%d inode=0x%x" % (fl.fl_pid, inode))
    print ('-' * 30)
    
def print_locks():
    file_lock_list = readSymbol("file_lock_list")
    blocked_list = readSymbol("blocked_list")
    
    print ("Active locks")
    for fl in  readSUListFromHead(file_lock_list, "fl_link", 
        "struct file_lock"):
        print_lock(fl)

        
    print ("\nBlocked list")
    for fl in  readSUListFromHead(blocked_list, "fl_link", 
        "struct file_lock"):
        print_lock(fl)

        
__FL_flags_c = '''
#define FL_POSIX        1
#define FL_FLOCK        2
#define FL_ACCESS       8       /* not trying to lock, just looking */
#define FL_LOCKD        16      /* lock held by rpc.lockd */
#define FL_LEASE        32      /* lease held on this file */
#define FL_SLEEP        128     /* A blocking lock */
'''

FL_flags = CDefine(__FL_flags_c)

__FL_type_c = '''
#define F_RDLCK         1
#define F_WRLCK         2
#define F_UNLCK         8

/* for old implementation of bsd flock () */
#define F_EXLCK         16      /* or 3 */
#define F_SHLCK         32      /* or 4 */

#define F_INPROGRESS    64
'''

FL_types = CDefine(__FL_type_c)
