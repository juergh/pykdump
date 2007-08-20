# module LinuxDump.fs
#
# Time-stamp: <07/08/20 10:40:14 alexs>
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

# Vversion number
__version__ = '0.1'

# Copyright notice string
__copyright__ = """\
Copyright (c) 2006,2007 Alex Sidorenko; mailto:asid@hp.com
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.
"""

from pykdump.API import *

#__all__ = ["proto", "routing"]


# Generic FS stuff, used by all FS
#----------------------------------------------------------------------
def getMount():
    rc = exec_crash_command("mount")
    mounts = rc.splitlines()[1:]
    mlist = []
    for l in mounts:
        vfsmount, superblk, fstype, devname, mnt = l.split()
        vfsmount = long(vfsmount, 16)
        superblk = long(superblk, 16)

        mlist.append((vfsmount, superblk, fstype, devname, mnt))
    return mlist
