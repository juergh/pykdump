# module LinuxDump.fs.dcache
#
# Time-stamp: <11/02/16 09:37:05 alexs>
#
# Copyright (C) 2011 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2011 Hewlett-Packard Co., All rights reserved.
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
This is a package providing  access to dcache. For example, you
can look at partial directory contents 
'''
from pykdump.API import *
from LinuxDump.fs import *

import time

# Mode bits

__c_mode= '''

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

/*
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)
*/

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001
'''

__MODE_BITS = CDefine(__c_mode)

# Add all these bits to our module's namespace
for k,v in __MODE_BITS.items():
    g = globals()
    g[k] = v


# Generate functions instead of using multiple definitions

__nblist = ["LNK", "REG", "DIR", "CHR", "BLK","FIFO", "SOCK"]

for b in __nblist:
    if (b == 'FIFO'):
        b1 = 'IFO'
    else:
        b1 = b
    s = 'def S_IS%s(m): return (m & S_IFMT) == S_IF%s' % (b, b1)
    exec s

#           0       1      2      3      4      5      6      7
__mbits = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx']


#  Convert mode-times 2011-02-11 13:40
def __mode_time(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))
    

# Print info about dentry
def print_dentry(dentry, v = 0, vfsmnt = 0):
    inode = dentry.d_inode
    if (vfsmnt):
        # For top-level entries we print their full name
        fname = get_pathname(dentry, vfsmnt)
    else:
        # While listing dir contents, use short names
        fname = get_dentry_name(dentry)
    if (not inode):
        if (v > 1):
            print " --", dentry, " (stale)", fname
    else:
        mode = inode.i_mode
        extrasp = ''
        if (v):
            print " --", dentry, fname
            print "      ", inode, "  mode=%08o" % mode
            extrasp = "      "

        itype = mode & S_IFMT
        obits = mode ^ itype
        s_t = '?'
        if (S_ISREG(mode)): s_t = '-'
        elif (S_ISSOCK(mode)): s_t = 's'
        elif (S_ISLNK(mode)): s_t = 'l'
        elif (S_ISBLK(mode)): s_t = 'b'
        elif (S_ISDIR(mode)): s_t = 'd'
        elif (S_ISCHR(mode)): s_t = 'c'
        elif (S_ISFIFO(mode)): s_t = 'p'

        # Convert obits to rwsx notation
        # 'S' means just 'set' bit, 's' both 'set' and user/group 'x'
        p_o = list(__mbits[obits&7])
        p_g = list(__mbits[(obits>>3)&7])
        p_u =  list(__mbits[(obits>>6)&7])
        # Do we have a sticky bit set?
        if (obits & S_ISVTX):
            if (p_o[2] == 'x'): p_o[2] = 't'
            else: p_o[2] = 'T'
        # SUID
        if (obits & S_ISUID):
            if (p_u[2] == 'x'): p_u[2] = 's'
            else: p_u[2] = 'S'
        # SGID
        if (obits & S_ISGID):
            if (p_g[2] == 'x'): p_g[2] = 's'
            else: p_g[2] = 'S'

        print  extrasp, s_t+string.join(p_u+p_g+p_o,''),\
              "%5d %5d" %(inode.i_uid, inode.i_gid),\
              "%10d" % (inode.i_size), \
              __mode_time(inode.i_mtime.tv_sec),\
              fname


def __ls_sname(n):
    if ((not n in ('.', '..')) and n[0] == '.' ): n = n[1:]
    return n.upper()

# Read directory contents, returning  dentries . Do not sort
def read_dir(dentry):
    # Is dentry empty?
    if (not dentry):
        return []
    # Is this a directory?
    inode = dentry.d_inode
    if ((not inode) or (not S_ISDIR(inode.i_mode))):
        return []
    dlist = ListHead(Addr(dentry.d_subdirs), dsn).D_child
    return dlist
    

def __print_directory_contents(dentry, v = 0):
    dlist = read_dir(dentry)
    print "=== Listing Directory Contents"
    
    # Linux's ls sorts without case sensitivity and skiiping the leading . for
    # hidden files
    
        
    dsorted = [(__ls_sname(get_dentry_name(d)), d) for d in dlist]

    dsorted.sort()

    for n,d in dsorted:
        print_dentry(d, v)



# Try to resolve pathname to dentry, if we have enough dcache entries to walk

# Returns (None, vfsmnt) or (dentry, vfsmnt)

def pathname2dentry(pn):
    # Normalize pn
    pn = os.path.normpath(pn)
    pmnt = ''
    for mlist in getMount():
        mnt = mlist[-1]
        pref = os.path.normpath(os.path.commonprefix([pn, mnt]))
        #print mnt, pref
        if (pref == mnt and len(pref) >= len(pmnt)):
            pmnt = mnt
            vfsmount = mlist[0]
    # OK, now try to walk starting from the root directory we found
    if (not pmnt):
        return (None, None)

    vfsmnt = readSU("struct vfsmount", vfsmount)
    dentry_mnt_root = vfsmnt.mnt_root
    dcur = dentry_mnt_root
    #print pmnt, hexl(vfsmount)
    # Split the remainder of our path and try to walk
    #print "pn=%s pmnt=%s" % (pn, pmnt)
    spl = pn[len(pmnt):].split('/')[1:]
    #print dcur, spl
    d = dcur
    for n in spl:
        found = False
        #print "dcur=", get_dentry_name(dcur), "search for", n
        for d in read_dir(dcur):
            dn = get_dentry_name(d)
            #print " ...", dn
            if (dn == n):
                dcur = d
                found = True
                break
        if (not found):
            return False
        print "   found", n
    return (d, vfsmnt)

# Analog of 'ls' command. 

# ls_patname(path).
# If path looks as a hexadecimal number, we intepret it as dentry addr

def ls_pathname(pn, v = 0):
    try:
        daddr = int(pn, 16)
        dentry = readSU("struct dentry", daddr)
        vfsmnt = 0
    except ValueError:
        dentry, vfsmnt = pathname2dentry(pn)
    if (not dentry):
        print "Cannot list", pn
        return
    inode = dentry.d_inode
    if (not inode):
        print "Inode is unavailable"
        return
    # Is this a directory?

    isdir = S_ISDIR(inode.i_mode)
    # If this is a directory and we have 'd' option set, do not
    # list the contents, just directory itself
    print_dentry(dentry, v, vfsmnt)
    if (isdir):
        __print_directory_contents(dentry, v)
    


# Return (retcode, remainder)
def __lcsubdir(mnt, d):
    # If mnt is longer than our directory, it's no good
    if (len(mnt) > len(d)):
        return (False, d)
    # if mnt=/, it shoukd match anything
    lm = mnt.split("/")
    ld = d.split("/")
    #print lm, ld
    # if mnt=/, it should match anything
    if (mnt == '/'):
        if (d == '/'):
            return (True, [])
        else:
            return (True, ld[1:])
    rc = 0
    for i in range(min(len(lm), len(ld))):
        #print i, lm[i], ld[i]
        if (lm[i] != ld[i]):
            break
        rc = i+1
    return (rc == len(lm), ld[rc:])
    


# Try to resolve pathname to dentry, if we have enough dcache entries to walk

# Returns (None, vfsmnt) or (dentry, vfsmnt)

def pathname2dentry(pn):
    # Normalize pn
    pn = os.path.normpath(pn)
    pmnt = ''
    spl = []
    lpn = len(pn)
    for mlist in getMount():
        mnt = mlist[-1]
        (rc, remainder) = __lcsubdir(mnt, pn)
        if (rc and len(mnt) >= len(pmnt)):
            pmnt = mnt
            vfsmount = mlist[0]
            spl = remainder
    # OK, now try to walk starting from the root directory we found
    if (not pmnt):
        return (None, None)

    vfsmnt = readSU("struct vfsmount", vfsmount)
    dentry_mnt_root = vfsmnt.mnt_root
    dcur = dentry_mnt_root

    if (spl):
        d = None
    else:
        d = dcur
    #print dcur, spl
    for n in spl:
        found = False
        #print "dcur=", get_dentry_name(dcur), "search for", n
        for d in read_dir(dcur):
            dn = get_dentry_name(d)
            #print " ...", dn
            if (dn == n):
                dcur = d
                found = True
                break
        if (not found):
            return (None, vfsmnt)
        #print "   found", n
    return (d, vfsmnt)


# Initialization    

dsn = "struct dentry"
structSetAttr(dsn, "D_child", ["d_child", "d_u.d_child"])
