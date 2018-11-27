# module LinuxDump.dlkm
#
# --------------------------------------------------------------------
# (C) Copyright 2018 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------
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
This is a package to test different things about loaded DLKMs
'''

from pykdump.API import *

# Return loaded modules as dictionary, modname:addr
#     MODULE       NAME                     SIZE  OBJECT FILE
#ffffffffa00085c0  autofs4                 45056  (not loaded)  [CONFIG_KALLSYMS]
#ffffffffa000e040  usb_common              16384  (not loaded)  [CONFIG_KALLSYMS]
def lsmod():
    d = {}
    for m in exec_crash_command_bg('mod').splitlines()[1:]:
        addr, mname, *dummy = m.split()
        d[mname] = int(addr, 16)
    return d
        
