"""Crashlib Python API for CRASH Dumps Tool
"""
# Vversion number
__version__ = '0.2'

# Copyright notice string
__copyright__ = """\
Copyright (c) 2006,2007 Alex Sidorenko; mailto:asid@lhp.com
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.
"""

#__all__ = ["proto", "routing"]

import socket, struct
from socket import ntohs

# Generic stuff, used both by all INET packages
#----------------------------------------------------------------------
def ntodots(n, printzeroes=True):
    if (n == 0):
        if (printzeroes):
            return "0.0.0.0"
        else:
            return "*"
    # 'I' is 'unsigned int' which is 4 bytes both on i386 and AMD64
    return socket.inet_ntoa(struct.pack("I", n))

# IPv6 version. We accept both 'struct in6_addr' and .in6u_u6_addr32
def ntodots6(n4, printzeroes=True):
    # 'I' is 'unsigned int' which is 4 bytes both on i386 and AMD64
    if (type(n4) != type([])):
        n4 = n4.in6_u.u6_addr32
    return socket.inet_ntop(socket.AF_INET6,
                            struct.pack("IIII",
                                        n4[0], n4[1], n4[2], n4[3]))

